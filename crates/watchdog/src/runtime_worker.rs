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
use crate::worker_client::{WorkerClient, WorkerClientConfig, WorkerPeerIdentity};
use crate::worker_protocol::{ControlScope, MAX_ATTEMPT_NUMBER, WorkerMode};
use std::time::Duration;

/// The worker phase is bounded to one historical recovery and one fresh claim
/// per reconciliation.  The store itself is the second line of defense and
/// refuses claims while any unresolved handoff remains.
const MAX_RECOVERIES_PER_RECONCILE: usize = 1;

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
    ) -> Result<()> {
        self.reconcile_worker(desired_mode, now_ms, false)
    }

    /// Repeat worker control after component scheduling.  A newly launched
    /// harness has a new live process identity and therefore receives a fresh
    /// client built from that handle before recovery or claim admission.
    pub(crate) fn reconcile_worker_after_components(
        &mut self,
        desired_mode: DesiredMode,
        now_ms: u64,
    ) -> Result<()> {
        self.reconcile_worker(desired_mode, now_ms, true)
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
    ) -> Result<()> {
        let Some(worker_config) = self.config.worker.clone() else {
            return Ok(());
        };
        let Some(client) = self.worker_client(&worker_config)? else {
            // A paused/stopped controller does not start a missing worker. A
            // running controller will get another attempt after component
            // scheduling, where a newly launched child can be adopted only
            // through its in-memory RuntimeChild handle.
            return Ok(());
        };

        let probe = client.probe()?;
        let worker_boot_id = probe.header.worker_boot_id.clone().ok_or_else(|| {
            WatchdogError::IdentityMismatch("worker probe omitted its live boot".to_owned())
        })?;
        let control = self.ensure_worker_control(&client, &worker_boot_id, desired_mode, now_ms)?;

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
            let _result =
                client.reconcile_handoff(&mut self.store, &pending.tuple(), &control, now_ms)?;
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

        if !allow_claim || desired_mode != DesiredMode::Running || !probe.ready {
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
        let _ = client.claim_and_dispatch(&mut self.store, &witness, now_ms)?;
        Ok(())
    }

    /// Build a worker client only from the currently owned child.  Durable
    /// component identity rows are intentionally not consulted here: a PID or
    /// persisted creation token without a live RuntimeChild is not authority.
    fn worker_client(&mut self, worker: &WorkerConfig) -> Result<Option<WorkerClient>> {
        let Some(child) = self.children.get_mut(&worker.component_id) else {
            return Ok(None);
        };
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
        let peer = WorkerPeerIdentity::from_process_identity(&identity)?;
        let binding = self.config.worker_binding()?.ok_or_else(|| {
            WatchdogError::Conflict("worker configuration disappeared".to_owned())
        })?;
        let config = WorkerClientConfig::new(
            worker.endpoint.clone(),
            worker.credential_path.clone(),
            binding,
            peer,
        )?
        .with_timeout(Duration::from_millis(worker.timeout_ms))?;
        WorkerClient::new(config, self.worker_boot_id.clone()).map(Some)
    }

    fn ensure_worker_control(
        &mut self,
        client: &WorkerClient,
        worker_boot_id: &str,
        desired_mode: DesiredMode,
        now_ms: u64,
    ) -> Result<WorkerControlWitness> {
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
            return Err(WatchdogError::Conflict(
                "worker control sequence exceeds the wire bound".to_owned(),
            ));
        }
        let binding: &WorkerBinding = client.config().binding();
        let scope = ControlScope {
            deployment_id: binding.deployment_id.clone(),
            worker_owner_id: binding.worker_owner_id.clone(),
            worker_profile_digest: binding.worker_profile_digest.clone(),
            mode,
            mode_sequence: sequence,
        };
        client.set_control_mode_and_persist(&mut self.store, worker_boot_id, scope, now_ms)
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
