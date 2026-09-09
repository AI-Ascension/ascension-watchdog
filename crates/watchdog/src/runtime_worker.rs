//! Supervisor-owned orchestration for the authenticated harness worker.
//!
//! This module is intentionally an adapter around the already durable worker
//! store and [`WorkerClient`].  It does not own a second queue or worker
//! protocol.  A client is rebuilt for every reconciliation phase from the
//! in-memory, currently supervised harness child; persisted process identity
//! is never used as transport authority.

use super::Supervisor;
use super::runtime_process::RuntimeObservation;
use crate::config::{DesiredMode, WorkerConfig};
use crate::error::{Result, WatchdogError};
use crate::policy::ComponentState;
use crate::storage::{WorkerBinding, WorkerControlMode, WorkerControlWitness};
use crate::worker_client::{
    WorkerClient, WorkerClientConfig, WorkerPeerIdentity, WorkerPhaseError, storage_receipt,
};
use crate::worker_protocol::{
    AcknowledgeStatus, ControlScope, ControlStatus, DispatchStatus, LookupStatus,
    MAX_ATTEMPT_NUMBER, WorkerMode,
};
use std::time::{Duration, Instant};

/// The worker phase is bounded to one historical recovery and one fresh claim
/// per reconciliation.  The store itself is the second line of defense and
/// refuses claims while any unresolved handoff remains.
const MAX_RECOVERIES_PER_RECONCILE: usize = 1;

#[derive(Clone, Copy, Debug)]
pub(crate) struct WorkerPhaseBudget {
    deadline: Instant,
}

impl WorkerPhaseBudget {
    /// Share one configured worker-exchange budget across the pre/post phases.
    /// If systemd advertises a shorter watchdog interval, reserve half of it
    /// for component reconciliation and progress notification.  This keeps
    /// the worker budget derived from live configuration rather than from an
    /// arbitrary service deadline constant.
    pub(crate) fn new(worker: Option<&WorkerConfig>) -> Self {
        let exchange_budget = worker.map_or(Duration::ZERO, |config| {
            Duration::from_millis(config.timeout_ms)
        });
        let watchdog_budget = std::env::var("WATCHDOG_USEC")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_micros)
            .map(|duration| duration / 2);
        let budget =
            watchdog_budget.map_or(exchange_budget, |watchdog| exchange_budget.min(watchdog));
        Self {
            deadline: Instant::now()
                .checked_add(budget)
                .unwrap_or_else(Instant::now),
        }
    }

    fn deadline(self) -> Instant {
        self.deadline
    }

    fn expired(self) -> bool {
        Instant::now() >= self.deadline
    }
}

impl Supervisor {
    /// Persist the approved worker binding before any worker transport effect.
    /// Repeating the exact binding is idempotent; a changed binding remains an
    /// owner-local immutable-store conflict.
    pub(crate) fn configure_worker_binding(&mut self, now_ms: u64) -> Result<()> {
        let Some(binding) = self.config.worker_binding()? else {
            return Ok(());
        };
        self.store.configure_worker_binding_at(&binding, now_ms)?;
        Ok(())
    }

    /// Reconcile a worker before component scheduling.  This is the ordering
    /// barrier for an existing live harness: desired pause/stop/drain intent
    /// is sent and durably acknowledged before the component stop path runs.
    pub(crate) fn reconcile_worker_before_components(
        &mut self,
        desired_mode: DesiredMode,
        now_ms: u64,
        budget: WorkerPhaseBudget,
        report: &mut super::ReconcileReport,
    ) -> Result<()> {
        self.worker_phase_pre_failed = false;
        self.reconcile_worker(desired_mode, now_ms, false, true, budget, report)
    }

    /// Repeat worker control after component scheduling.  A newly launched
    /// harness has a new live process identity and therefore receives a fresh
    /// client built from that handle before recovery or claim admission.
    pub(crate) fn reconcile_worker_after_components(
        &mut self,
        desired_mode: DesiredMode,
        now_ms: u64,
        budget: WorkerPhaseBudget,
        report: &mut super::ReconcileReport,
    ) -> Result<()> {
        self.reconcile_worker(desired_mode, now_ms, true, false, budget, report)
    }

    /// Draining may settle to stopped only after all retained worker rows have
    /// either been terminally acknowledged or explicitly rejected.  A pending
    /// prepared/uncertain/admitted row remains a durable barrier.
    pub(crate) fn worker_drain_complete(&self) -> Result<bool> {
        Ok(self
            .store
            .next_worker_handoff_for_reconciliation()?
            .is_none())
    }

    fn reconcile_worker(
        &mut self,
        desired_mode: DesiredMode,
        now_ms: u64,
        allow_claim: bool,
        pre_phase: bool,
        budget: WorkerPhaseBudget,
        report: &mut super::ReconcileReport,
    ) -> Result<()> {
        let Some(worker_config) = self.config.worker.clone() else {
            return Ok(());
        };
        if budget.expired() {
            return self.defer_worker_error(
                "budget",
                WorkerPhaseError::Unavailable(WatchdogError::Timeout(
                    "worker reconciliation budget expired".to_owned(),
                )),
                now_ms,
                pre_phase,
                report,
            );
        }
        let client = match self.worker_client(&worker_config, budget) {
            Ok(client) => client,
            Err(error) => {
                return self.defer_worker_error("client", error, now_ms, pre_phase, report);
            }
        };
        let Some(client) = client else {
            // A paused/stopped controller does not start a missing worker. A
            // running controller will get another attempt after component
            // scheduling, where a newly launched child can be adopted only
            // through its in-memory RuntimeChild handle.
            return Ok(());
        };
        self.worker_phase_succeeded("client");

        let probe = match client.probe_phase() {
            Ok(probe) => probe,
            Err(error) => {
                return self.defer_worker_error("probe", error, now_ms, pre_phase, report);
            }
        };
        self.worker_phase_succeeded("probe");
        let worker_boot_id = probe.header.worker_boot_id.clone().ok_or_else(|| {
            WatchdogError::IdentityMismatch("worker probe omitted its live boot".to_owned())
        })?;
        let control =
            match self.ensure_worker_control(&client, &worker_boot_id, desired_mode, now_ms) {
                Ok(control) => control,
                Err(error) => {
                    return self.defer_worker_error("control", error, now_ms, pre_phase, report);
                }
            };
        self.worker_phase_succeeded("control");

        // Every retained row is resolved by read-only lookup before a new
        // queue claim.  In particular, a prepared or uncertain row is never
        // converted into a replacement dispatch by this phase.  Keep the
        // recovery loop explicit even though the store query is itself
        // bounded to the oldest one: this is the per-round work cap.
        let mut recoveries = 0;
        while recoveries < MAX_RECOVERIES_PER_RECONCILE {
            let Some(pending) = self.store.next_worker_handoff_for_reconciliation()? else {
                break;
            };
            recoveries += 1;
            if self
                .store
                .lookup_worker_handoff(&pending.tuple())?
                .is_none()
            {
                return Err(WatchdogError::NotFound(format!(
                    "worker handoff {}",
                    pending.handoff_id
                )));
            }
            let response = match client.lookup_phase(&pending.tuple(), &control.worker_boot_id) {
                Ok(response) => response,
                Err(error) => {
                    return self.defer_worker_error("lookup", error, now_ms, pre_phase, report);
                }
            };
            self.worker_phase_succeeded("lookup");
            if response.status == LookupStatus::Terminal {
                let receipt = response.terminal.as_ref().ok_or_else(|| {
                    WatchdogError::Conflict("terminal lookup response has no receipt".to_owned())
                })?;
                let completion = self.store.complete_worker_handoff_with_recovery_at(
                    &pending.tuple(),
                    &storage_receipt(receipt),
                    &control,
                    now_ms,
                )?;
                let ack_response = match client.acknowledge_phase(
                    &pending.tuple(),
                    &control.worker_boot_id,
                    &completion.terminal_digest,
                ) {
                    Ok(response) => response,
                    Err(error) => {
                        return self.defer_worker_error(
                            "acknowledge",
                            error,
                            now_ms,
                            pre_phase,
                            report,
                        );
                    }
                };
                self.worker_phase_succeeded("acknowledge");
                if !matches!(
                    ack_response.status,
                    AcknowledgeStatus::Acknowledged | AcknowledgeStatus::AlreadyAcknowledged
                ) {
                    return Err(WatchdogError::Conflict(
                        "worker rejected terminal acknowledgment".to_owned(),
                    ));
                }
                self.store.acknowledge_worker_handoff_with_recovery_at(
                    &pending.tuple(),
                    &completion.terminal_digest,
                    &control,
                    now_ms,
                )?;
            }
            // A running/unknown/rejected lookup leaves the original row held;
            // it is not safe to claim a second job in this pass. A terminal
            // lookup may have completed and acknowledged the row, in which
            // case one fresh claim is allowed below only when no other
            // retained row remains.
            if self
                .store
                .next_worker_handoff_for_reconciliation()?
                .is_some()
            {
                return Ok(());
            }
        }

        if !allow_claim
            || self.worker_phase_pre_failed
            || desired_mode != DesiredMode::Running
            || !probe.ready
        {
            return Ok(());
        }
        // A live child that the component reconciler retained in quarantine is
        // still an exact cleanup authority, but it is not a claim authority.
        // Only the post-scheduling durable Running state admits a fresh job.
        let Some(component) = self.store.component(&worker_config.component_id)? else {
            return Ok(());
        };
        if component.state != ComponentState::Running {
            return Ok(());
        }
        // This read is deliberately after control/recovery and is the only
        // path that can supply the exact worker binding/control witness to the
        // client claim API. The client performs its own fresh ready probe and
        // durable pre-send marker checks.
        let Some(witness) = self.store.current_worker_claim_witness()? else {
            return Ok(());
        };
        if witness.worker_boot_id != worker_boot_id {
            // The worker replaced itself between probe and claim preparation;
            // retain the queue and wait for the next live-identity phase.
            return Ok(());
        }
        // This second probe is the admission barrier. The initial probe may
        // have been followed by a worker replacement or a readiness change;
        // no fresh claim is created until this live response is ready and
        // still names the same worker boot.
        let claim_probe = match client.probe_phase() {
            Ok(probe) => probe,
            Err(error) => {
                return self.defer_worker_error("claim_probe", error, now_ms, pre_phase, report);
            }
        };
        self.worker_phase_succeeded("claim_probe");
        if !claim_probe.ready {
            return self.defer_worker_error(
                "claim_probe",
                WorkerPhaseError::Unavailable(WatchdogError::Conflict(
                    "worker probe is not ready for admission".to_owned(),
                )),
                now_ms,
                pre_phase,
                report,
            );
        }
        if claim_probe.header.worker_boot_id.as_deref() != Some(worker_boot_id.as_str()) {
            return Err(WatchdogError::IdentityMismatch(
                "worker claim probe boot differs from the control witness".to_owned(),
            ));
        }
        let Some(claim) = self.store.claim_next_worker_handoff(&witness, now_ms)? else {
            return Ok(());
        };
        let tuple = claim.tuple();
        let marked = self
            .store
            .mark_worker_handoff_may_have_been_dispatched_at(&tuple, now_ms)?;
        let response = match client.dispatch_phase(&marked) {
            Ok(response) => response,
            Err(error) => {
                return self.defer_worker_error("dispatch", error, now_ms, pre_phase, report);
            }
        };
        self.worker_phase_succeeded("dispatch");
        match response.status {
            DispatchStatus::Accepted => {
                self.store.mark_worker_handoff_admitted_at(&tuple, now_ms)?;
            }
            DispatchStatus::Terminal | DispatchStatus::AlreadyCompleted => {
                let receipt = response.terminal.as_ref().ok_or_else(|| {
                    WatchdogError::Conflict(
                        "terminal worker dispatch response has no receipt".to_owned(),
                    )
                })?;
                let completion = self.store.complete_worker_handoff_at(
                    &tuple,
                    &storage_receipt(receipt),
                    now_ms,
                )?;
                let ack_response = match client.acknowledge_phase(
                    &tuple,
                    &witness.worker_boot_id,
                    &completion.terminal_digest,
                ) {
                    Ok(response) => response,
                    Err(error) => {
                        return self.defer_worker_error(
                            "acknowledge",
                            error,
                            now_ms,
                            pre_phase,
                            report,
                        );
                    }
                };
                self.worker_phase_succeeded("acknowledge");
                if !matches!(
                    ack_response.status,
                    AcknowledgeStatus::Acknowledged | AcknowledgeStatus::AlreadyAcknowledged
                ) {
                    return Err(WatchdogError::Conflict(
                        "worker rejected terminal acknowledgment".to_owned(),
                    ));
                }
                self.store.acknowledge_worker_handoff_at(
                    &tuple,
                    &completion.terminal_digest,
                    now_ms,
                )?;
            }
            DispatchStatus::Busy | DispatchStatus::Rejected => {
                // The request was authorized and may have reached the worker;
                // retain the durable may-have-been-dispatched reservation.
            }
        }
        Ok(())
    }

    /// Build a worker client only from the currently owned child.  Durable
    /// component identity rows are intentionally not consulted here: a PID or
    /// persisted creation token without a live RuntimeChild is not authority.
    fn worker_client(
        &mut self,
        worker: &WorkerConfig,
        budget: WorkerPhaseBudget,
    ) -> std::result::Result<Option<WorkerClient>, WorkerPhaseError> {
        let Some(child) = self.children.get_mut(&worker.component_id) else {
            return Ok(None);
        };
        if !self.config.allow_synthetic_children {
            let binding = self.store.worker_bootstrap_binding(child.intent_id())?;
            if !super::runtime_worker_bootstrap::current_binding(
                child.worker_bootstrap_binding(),
                binding.as_ref(),
                &self.worker_boot_id,
            ) {
                return Err(WorkerPhaseError::Unavailable(WatchdogError::Conflict(
                    "worker bootstrap is not owned by the current supervisor".to_owned(),
                )));
            }
        }
        // Do not construct transport authority from a durable row or from a
        // stale in-memory identity. The platform adapter's point-in-time
        // observation must first prove that this exact owned child is live;
        // each WorkerClient exchange repeats the peer identity check.
        if !matches!(
            self.process_manager.inspect(child)?,
            RuntimeObservation::Running
        ) {
            return Ok(None);
        }
        let identity = child.identity().clone();
        #[cfg(target_os = "linux")]
        let peer = if child.is_native() {
            WorkerPeerIdentity::from_owned_linux_process(
                &identity,
                std::time::Instant::now() + std::time::Duration::from_secs(5),
            )?
        } else {
            WorkerPeerIdentity::from_process_identity(&identity)?
        };
        #[cfg(not(target_os = "linux"))]
        let peer = WorkerPeerIdentity::from_process_identity(&identity)?;
        #[cfg(windows)]
        let peer = {
            let (account, session) = child.worker_account_identity()?;
            if worker
                .allowed_peer_sid
                .as_ref()
                .is_some_and(|allowed| allowed != &account)
            {
                return Err(WatchdogError::IdentityMismatch(
                    "owned worker account does not match configured SID".to_owned(),
                )
                .into());
            }
            peer.with_windows_account(account, session)?
        };
        let binding = self.config.worker_binding()?.ok_or_else(|| {
            WatchdogError::Conflict("worker configuration disappeared".to_owned())
        })?;
        let config = WorkerClientConfig::new(
            worker.endpoint_for_launch(&identity.launch_nonce)?,
            worker.credential_path.clone(),
            binding,
            peer,
        )?
        .with_timeout(Duration::from_millis(worker.timeout_ms))?;
        WorkerClient::new(config, self.worker_boot_id.clone())
            .map(|client| Some(client.with_deadline(budget.deadline())))
            .map_err(WorkerPhaseError::from_client_error)
    }

    fn ensure_worker_control(
        &mut self,
        client: &WorkerClient,
        worker_boot_id: &str,
        desired_mode: DesiredMode,
        now_ms: u64,
    ) -> std::result::Result<WorkerControlWitness, WorkerPhaseError> {
        let mode = worker_mode(desired_mode);
        if let Some(current) = self.store.current_worker_control()?
            && current.watchdog_boot_id == self.worker_boot_id
            && current.worker_boot_id == worker_boot_id
            && current.mode == storage_worker_mode(mode)
        {
            return Ok(current);
        }
        let sequence = self
            .store
            .current_worker_control()?
            .map_or(Ok(1), |current| {
                current.mode_sequence.checked_add(1).ok_or_else(|| {
                    WatchdogError::Conflict("worker control sequence exhausted".to_owned())
                })
            })?;
        if sequence > MAX_ATTEMPT_NUMBER {
            return Err(WorkerPhaseError::Fatal(WatchdogError::Conflict(
                "worker control sequence exceeds the wire bound".to_owned(),
            )));
        }
        let binding: &WorkerBinding = client.config().binding();
        let scope = ControlScope {
            deployment_id: binding.deployment_id.clone(),
            worker_owner_id: binding.worker_owner_id.clone(),
            worker_profile_digest: binding.worker_profile_digest.clone(),
            mode,
            mode_sequence: sequence,
        };
        let response = client.set_control_mode_phase(worker_boot_id, scope)?;
        if response.status != ControlStatus::Accepted {
            return Err(WorkerPhaseError::Unavailable(WatchdogError::Conflict(
                "worker rejected the requested control mode".to_owned(),
            )));
        }
        let control = WorkerControlWitness {
            deployment_id: response.scope.deployment_id,
            worker_owner_id: response.scope.worker_owner_id,
            worker_profile_digest: response.scope.worker_profile_digest,
            watchdog_boot_id: self.worker_boot_id.clone(),
            worker_boot_id: worker_boot_id.to_owned(),
            mode: storage_worker_mode(response.scope.mode),
            mode_sequence: response.scope.mode_sequence,
        };
        self.store
            .set_worker_control_at(&control, now_ms)
            .map_err(Into::into)
    }

    fn defer_worker_error(
        &mut self,
        phase: &str,
        error: WorkerPhaseError,
        now_ms: u64,
        pre_phase: bool,
        report: &mut super::ReconcileReport,
    ) -> Result<()> {
        match error {
            WorkerPhaseError::Unavailable(error) => {
                if pre_phase {
                    self.worker_phase_pre_failed = true;
                }
                // This edge-triggered audit is the only durable effect of a
                // transport outage; no stop/unknown/claim state is changed
                // and the next pass may retry the same exact IDs. Keep one
                // bounded report entry for the current loop so health is
                // honestly blocked without making a stop intent unfinishable.
                if self.worker_deferred_phases.insert(phase.to_owned()) {
                    self.store.audit(
                        "worker_phase_deferred",
                        &format!("{phase}: {error}"),
                        now_ms,
                    )?;
                }
                let marker = format!("worker phase {phase}:");
                if !report
                    .errors
                    .iter()
                    .any(|existing| existing.starts_with(&marker))
                {
                    report.errors.push(format!("{marker} {error}"));
                }
                Ok(())
            }
            WorkerPhaseError::Fatal(error) => Err(error),
        }
    }

    fn worker_phase_succeeded(&mut self, phase: &str) {
        self.worker_deferred_phases.remove(phase);
    }
}

fn worker_mode(mode: DesiredMode) -> WorkerMode {
    match mode {
        DesiredMode::Stopped => WorkerMode::Stopped,
        DesiredMode::Paused => WorkerMode::Paused,
        DesiredMode::Running => WorkerMode::Running,
        DesiredMode::Draining => WorkerMode::Draining,
    }
}

fn storage_worker_mode(mode: WorkerMode) -> WorkerControlMode {
    match mode {
        WorkerMode::Stopped => WorkerControlMode::Stopped,
        WorkerMode::Paused => WorkerControlMode::Paused,
        WorkerMode::Running => WorkerControlMode::Running,
        WorkerMode::Draining => WorkerControlMode::Draining,
    }
}
