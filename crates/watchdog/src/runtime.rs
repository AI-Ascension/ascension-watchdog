//! Reconciliation loop and approved child supervision.

use crate::config::{ComponentConfig, DesiredMode, WatchdogConfig};
use crate::error::{Result, WatchdogError};
use crate::policy::{
    ComponentObservation, ComponentState, ReconcileAction, ReconcileDecision, SupervisorPolicy,
};
use crate::process::{OwnedChild, ProcessIdentity, ensure_identity};
use crate::storage::{ComponentRecord, SingletonLock, Store, now_unix_ms};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;
use uuid::Uuid;

const CHILD_STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// A single loop's bounded result, useful for diagnostics and tests.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ReconcileReport {
    pub observed_at_ms: u64,
    pub desired_mode: DesiredMode,
    pub decisions: Vec<ReconcileDecision>,
    pub started: Vec<String>,
    pub stopped: Vec<String>,
    pub quarantined: Vec<String>,
    pub errors: Vec<String>,
}

/// A running watchdog controller.  Status/config commands do not construct
/// this type with a lock, so they remain side-effect free.
pub struct Supervisor {
    pub(crate) store: Store,
    config: WatchdogConfig,
    policy: SupervisorPolicy,
    children: BTreeMap<String, OwnedChild>,
    lock: Option<SingletonLock>,
    worker_id: String,
    initialized_runtime: bool,
}

impl std::fmt::Debug for Supervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Supervisor")
            .field("database", &self.store.path())
            .field("components", &self.config.components.len())
            .field("children", &self.children.keys().collect::<Vec<_>>())
            .field("worker_id", &self.worker_id)
            .finish_non_exhaustive()
    }
}

impl Supervisor {
    /// Initialize a new owner-local store using the configuration's initial
    /// desired mode.
    pub fn initialize(config: WatchdogConfig) -> Result<Self> {
        config.validate()?;
        // Initialization creates durable state, so take the same owner-local
        // singleton before opening or mutating SQLite.  A competing daemon
        // cannot race schema/bootstrap work and then both believe it owns the
        // deployment.
        let lock = SingletonLock::acquire(&config.database)?;
        let store = Store::initialize(&config.database, &config)?;
        let mut supervisor = Self::from_store(store, config);
        lock.write_owner_hint(&format!("worker_id={}", supervisor.worker_id))?;
        supervisor.lock = Some(lock);
        Ok(supervisor)
    }

    /// Open existing state.  It never creates a missing database.
    pub fn open(config: WatchdogConfig) -> Result<Self> {
        config.validate()?;
        let store = Store::open(&config.database, &config)?;
        Ok(Self::from_store(store, config))
    }

    fn from_store(store: Store, config: WatchdogConfig) -> Self {
        let policy = SupervisorPolicy::from_config(&config);
        Self {
            store,
            config,
            policy,
            children: BTreeMap::new(),
            lock: None,
            worker_id: format!("watchdog-{}", Uuid::new_v4()),
            initialized_runtime: false,
        }
    }

    /// Access the read-only store status.
    pub fn status(&self) -> Result<crate::storage::StoreStatus> {
        self.store.status()
    }

    /// Acquire the singleton mutating controller lock.
    pub fn acquire_lock(&mut self) -> Result<()> {
        if self.lock.is_none() {
            let lock = SingletonLock::acquire(self.store.path())?;
            lock.write_owner_hint(&format!("worker_id={}", self.worker_id))?;
            self.lock = Some(lock);
        }
        Ok(())
    }

    /// Reconcile once at a supplied timestamp.  Effects occur only after the
    /// corresponding intent/audit and restart-budget records commit.
    pub fn reconcile_once(&mut self, now_ms: u64) -> Result<ReconcileReport> {
        self.acquire_lock()?;
        let first_reconcile = !self.initialized_runtime;
        if first_reconcile {
            self.store.quarantine_interrupted_jobs(now_ms)?;
            self.store.establish_new_generation(now_ms)?;
            self.store
                .audit("reconciler_started", &self.worker_id, now_ms)?;
            self.reconcile_persisted_identities(now_ms)?;
            self.initialized_runtime = true;
        }
        let desired_mode = self.store.desired_mode()?;
        let mut report = ReconcileReport {
            observed_at_ms: now_ms,
            desired_mode,
            ..ReconcileReport::default()
        };
        for component in self.config.components.clone() {
            let decision =
                self.reconcile_component(&component, desired_mode, now_ms, &mut report)?;
            report.decisions.push(decision);
        }
        if desired_mode == DesiredMode::Draining && self.children.is_empty() {
            self.store
                .set_desired_mode_at(DesiredMode::Stopped, now_ms)?;
        }
        self.store.audit(
            "reconciler_progress",
            &format!("mode={desired_mode:?};children={}", self.children.len()),
            now_ms,
        )?;
        Ok(report)
    }

    /// Reconcile identities left by an earlier controller generation without
    /// adopting a process into a new `Child` handle.  A live orphan is
    /// quarantined for an authority-aware operator path; a stale identity is
    /// cleared only after its creation fingerprint proves that the process is
    /// gone.  This prevents a daemon restart from starting a duplicate child
    /// or issuing a PID-only cleanup.
    fn reconcile_persisted_identities(&mut self, now_ms: u64) -> Result<()> {
        for component in self.config.components.clone() {
            if self.children.contains_key(&component.id) {
                continue;
            }
            let Some(record) = self.store.component(&component.id)? else {
                continue;
            };
            let identity = self.store.component_identity(&component.id)?;
            if identity.is_none() && record.pid.is_none() {
                continue;
            }
            let Some(identity) = identity else {
                self.store.upsert_component(
                    &ComponentRecord {
                        id: component.id.clone(),
                        state: ComponentState::Quarantined,
                        launch_nonce: record.launch_nonce,
                        pid: record.pid,
                        executable_digest: record.executable_digest,
                        started_at_ms: record.started_at_ms,
                        restart_attempts: record.restart_attempts,
                        last_restart_at_ms: record.last_restart_at_ms,
                        last_error: Some(
                            "persisted process has no complete launch identity; relaunch blocked"
                                .to_string(),
                        ),
                    },
                    now_ms,
                )?;
                self.store
                    .audit("orphan_identity_incomplete", &component.id, now_ms)?;
                continue;
            };
            match ensure_identity(&identity) {
                Ok(()) => {
                    self.store.upsert_component(
                        &ComponentRecord {
                            id: component.id.clone(),
                            state: ComponentState::Quarantined,
                            launch_nonce: Some(identity.launch_nonce),
                            pid: Some(identity.pid),
                            executable_digest: Some(identity.executable_digest),
                            started_at_ms: Some(identity.started_at_ms),
                            restart_attempts: record.restart_attempts,
                            last_restart_at_ms: record.last_restart_at_ms,
                            last_error: Some(
                                "live persisted child has no owned handle; relaunch blocked"
                                    .to_string(),
                            ),
                        },
                        now_ms,
                    )?;
                    self.store
                        .audit("orphan_child_quarantined", &component.id, now_ms)?;
                }
                Err(WatchdogError::IdentityMismatch(_)) => {
                    self.store.clear_component_identity(&component.id, now_ms)?;
                    self.store.upsert_component(
                        &ComponentRecord {
                            id: component.id.clone(),
                            state: ComponentState::Stopped,
                            launch_nonce: None,
                            pid: None,
                            executable_digest: None,
                            started_at_ms: None,
                            restart_attempts: record.restart_attempts,
                            last_restart_at_ms: record.last_restart_at_ms,
                            last_error: Some("persisted child identity is stale".to_string()),
                        },
                        now_ms,
                    )?;
                    self.store
                        .audit("orphan_identity_stale", &component.id, now_ms)?;
                }
                Err(error) => {
                    self.store.upsert_component(
                        &ComponentRecord {
                            id: component.id.clone(),
                            state: ComponentState::Quarantined,
                            launch_nonce: Some(identity.launch_nonce),
                            pid: Some(identity.pid),
                            executable_digest: Some(identity.executable_digest),
                            started_at_ms: Some(identity.started_at_ms),
                            restart_attempts: record.restart_attempts,
                            last_restart_at_ms: record.last_restart_at_ms,
                            last_error: Some(format!(
                                "persisted child identity could not be verified: {error}"
                            )),
                        },
                        now_ms,
                    )?;
                    self.store
                        .audit("orphan_identity_unverified", &component.id, now_ms)?;
                }
            }
        }
        Ok(())
    }

    fn reconcile_component(
        &mut self,
        component: &ComponentConfig,
        desired_mode: DesiredMode,
        now_ms: u64,
        report: &mut ReconcileReport,
    ) -> Result<ReconcileDecision> {
        let mut exited = None;
        if let Some(child) = self.children.get_mut(&component.id) {
            match child.try_wait() {
                Ok(Some(status)) => {
                    exited = Some(
                        status
                            .code()
                            .map_or_else(|| "signal".to_string(), |code| code.to_string()),
                    )
                }
                Ok(None) => {}
                Err(error) => {
                    self.store.upsert_component(
                        &ComponentRecord {
                            id: component.id.clone(),
                            state: ComponentState::Quarantined,
                            launch_nonce: Some(child.identity().launch_nonce.clone()),
                            pid: Some(child.identity().pid),
                            executable_digest: Some(child.identity().executable_digest.clone()),
                            started_at_ms: Some(child.identity().started_at_ms),
                            restart_attempts: self
                                .store
                                .component(&component.id)?
                                .map_or(0, |record| record.restart_attempts),
                            last_restart_at_ms: self
                                .store
                                .component(&component.id)?
                                .and_then(|record| record.last_restart_at_ms),
                            last_error: Some(error.to_string()),
                        },
                        now_ms,
                    )?;
                    report.quarantined.push(component.id.clone());
                    self.children.remove(&component.id);
                    return Ok(ReconcileDecision {
                        component_id: component.id.clone(),
                        action: ReconcileAction::Quarantine,
                        resulting_state: ComponentState::Quarantined,
                        reason: format!("exact child identity could not be verified: {error}"),
                        retry_at_ms: None,
                    });
                }
            }
        }
        if let Some(exit_code) = exited {
            if let Some(child) = self.children.remove(&component.id) {
                let output = child.output();
                let detail = format!(
                    "component={} exit={} stdout_bytes={} stderr_bytes={}",
                    component.id,
                    exit_code,
                    output.stdout.len(),
                    output.stderr.len()
                );
                self.store.audit("component_exited", &detail, now_ms)?;
                let prior = self.store.component(&component.id)?;
                self.store.upsert_component(
                    &ComponentRecord {
                        id: component.id.clone(),
                        state: ComponentState::Stopped,
                        launch_nonce: prior
                            .as_ref()
                            .and_then(|record| record.launch_nonce.clone()),
                        pid: prior.as_ref().and_then(|record| record.pid),
                        executable_digest: prior
                            .as_ref()
                            .and_then(|record| record.executable_digest.clone()),
                        started_at_ms: prior.as_ref().and_then(|record| record.started_at_ms),
                        restart_attempts: prior
                            .as_ref()
                            .map_or(0, |record| record.restart_attempts),
                        last_restart_at_ms: prior
                            .as_ref()
                            .and_then(|record| record.last_restart_at_ms),
                        last_error: Some(format!("child exited ({exit_code})")),
                    },
                    now_ms,
                )?;
            }
        }

        let prior = self.store.component(&component.id)?;
        let is_running = self.children.contains_key(&component.id);
        let observation = ComponentObservation {
            component_id: component.id.clone(),
            state: if is_running {
                ComponentState::Running
            } else {
                prior
                    .as_ref()
                    .map_or(ComponentState::Stopped, |record| record.state)
            },
            observed_at_ms: prior
                .as_ref()
                .and_then(|record| record.started_at_ms)
                .unwrap_or(now_ms),
            heartbeat_age_ms: None,
            progress_age_ms: None,
            consecutive_misses: 0,
            restart_attempts: prior.as_ref().map_or(0, |record| record.restart_attempts),
        };
        let restart_count = self.store.restart_count(
            &component.id,
            now_ms,
            self.config.restart_budget_window_secs.saturating_mul(1_000),
        )?;
        let decision = self.policy.decide(
            desired_mode,
            component.restart,
            &observation,
            now_ms,
            restart_count,
            prior.as_ref().and_then(|record| record.last_restart_at_ms),
        );
        match decision.action {
            ReconcileAction::Stop => {
                self.stop_component(component, now_ms, report)?;
            }
            ReconcileAction::Start => {
                // Re-read intent immediately before launch.  An operator may
                // have committed stop/pause after the initial snapshot.
                if self.store.desired_mode()? == DesiredMode::Running {
                    self.start_component(component, now_ms, report)?;
                }
            }
            ReconcileAction::Quarantine => {
                self.store.upsert_component(
                    &ComponentRecord {
                        id: component.id.clone(),
                        state: ComponentState::Quarantined,
                        launch_nonce: prior
                            .as_ref()
                            .and_then(|record| record.launch_nonce.clone()),
                        pid: prior.as_ref().and_then(|record| record.pid),
                        executable_digest: prior
                            .as_ref()
                            .and_then(|record| record.executable_digest.clone()),
                        started_at_ms: prior.as_ref().and_then(|record| record.started_at_ms),
                        restart_attempts: prior
                            .as_ref()
                            .map_or(0, |record| record.restart_attempts),
                        last_restart_at_ms: prior
                            .as_ref()
                            .and_then(|record| record.last_restart_at_ms),
                        last_error: Some(decision.reason.clone()),
                    },
                    now_ms,
                )?;
                report.quarantined.push(component.id.clone());
            }
            ReconcileAction::Wait | ReconcileAction::Noop | ReconcileAction::MarkSuspect => {
                let state = if desired_mode == DesiredMode::Paused {
                    ComponentState::Paused
                } else if desired_mode.stops_children() {
                    ComponentState::Stopped
                } else if is_running {
                    ComponentState::Running
                } else {
                    decision.resulting_state
                };
                if let Some(child) = self.children.get(&component.id) {
                    self.store.upsert_component(
                        &ComponentRecord {
                            id: component.id.clone(),
                            state,
                            launch_nonce: Some(child.identity().launch_nonce.clone()),
                            pid: Some(child.identity().pid),
                            executable_digest: Some(child.identity().executable_digest.clone()),
                            started_at_ms: Some(child.identity().started_at_ms),
                            restart_attempts: observation.restart_attempts,
                            last_restart_at_ms: prior
                                .as_ref()
                                .and_then(|record| record.last_restart_at_ms),
                            last_error: None,
                        },
                        now_ms,
                    )?;
                } else if desired_mode.stops_children() {
                    self.store.upsert_component(
                        &ComponentRecord {
                            id: component.id.clone(),
                            state: ComponentState::Stopped,
                            launch_nonce: None,
                            pid: None,
                            executable_digest: None,
                            started_at_ms: None,
                            restart_attempts: observation.restart_attempts,
                            last_restart_at_ms: prior
                                .as_ref()
                                .and_then(|record| record.last_restart_at_ms),
                            last_error: None,
                        },
                        now_ms,
                    )?;
                }
            }
        }
        Ok(decision)
    }

    fn start_component(
        &mut self,
        component: &ComponentConfig,
        now_ms: u64,
        report: &mut ReconcileReport,
    ) -> Result<()> {
        if self.store.desired_mode()? != DesiredMode::Running {
            return Ok(());
        }
        // Persist-before-effect: this audit row is the launch intent.  A crash
        // after it and before spawn is recoverable without claiming a child.
        self.store
            .audit("component_start_intent", &component.id, now_ms)?;
        let restart_count = self.store.record_restart(
            &component.id,
            now_ms,
            self.config.restart_budget_window_secs.saturating_mul(1_000),
        )?;
        let prior = self.store.component(&component.id)?;
        let attempts = prior
            .as_ref()
            .map_or(0, |record| record.restart_attempts)
            .saturating_add(1);
        self.store.upsert_component(
            &ComponentRecord {
                id: component.id.clone(),
                state: ComponentState::Starting,
                launch_nonce: None,
                pid: None,
                executable_digest: None,
                started_at_ms: Some(now_ms),
                restart_attempts: attempts,
                last_restart_at_ms: Some(now_ms),
                last_error: None,
            },
            now_ms,
        )?;
        match OwnedChild::spawn(component, now_ms) {
            Ok(child) => {
                let identity = child.identity().clone();
                self.store.upsert_component(
                    &component_record(component, &identity, attempts, now_ms, None),
                    now_ms,
                )?;
                self.store
                    .persist_component_identity(&component.id, &identity, now_ms)?;
                self.store.audit(
                    "component_started",
                    &format!(
                        "{}:pid={};restart_count={restart_count}",
                        component.id, identity.pid
                    ),
                    now_ms,
                )?;
                self.children.insert(component.id.clone(), child);
                report.started.push(component.id.clone());
            }
            Err(error) => {
                self.store.upsert_component(
                    &ComponentRecord {
                        id: component.id.clone(),
                        state: ComponentState::Stopped,
                        launch_nonce: None,
                        pid: None,
                        executable_digest: None,
                        started_at_ms: Some(now_ms),
                        restart_attempts: attempts,
                        last_restart_at_ms: Some(now_ms),
                        last_error: Some(error.to_string()),
                    },
                    now_ms,
                )?;
                self.store.clear_component_identity(&component.id, now_ms)?;
                report.errors.push(format!("{}: {error}", component.id));
            }
        }
        Ok(())
    }

    fn stop_component(
        &mut self,
        component: &ComponentConfig,
        now_ms: u64,
        report: &mut ReconcileReport,
    ) -> Result<()> {
        if !self.children.contains_key(&component.id) {
            let prior = self.store.component(&component.id)?;
            if let Some(record) = prior.as_ref()
                && (record.pid.is_some() || self.store.component_identity(&component.id)?.is_some())
            {
                // A restarted controller cannot safely reconstruct a Child
                // handle.  Preserve the opaque identity and quarantine the
                // component rather than erasing evidence or issuing a PID
                // kill against an ambiguous orphan.
                self.store.upsert_component(
                    &ComponentRecord {
                        id: component.id.clone(),
                        state: ComponentState::Quarantined,
                        launch_nonce: record.launch_nonce.clone(),
                        pid: record.pid,
                        executable_digest: record.executable_digest.clone(),
                        started_at_ms: record.started_at_ms,
                        restart_attempts: record.restart_attempts,
                        last_restart_at_ms: record.last_restart_at_ms,
                        last_error: Some(
                            "owned child handle unavailable; exact orphan identity retained"
                                .to_string(),
                        ),
                    },
                    now_ms,
                )?;
                report.quarantined.push(component.id.clone());
                return Ok(());
            }
            self.store.upsert_component(
                &ComponentRecord {
                    id: component.id.clone(),
                    state: ComponentState::Stopped,
                    launch_nonce: None,
                    pid: None,
                    executable_digest: None,
                    started_at_ms: None,
                    restart_attempts: prior.as_ref().map_or(0, |record| record.restart_attempts),
                    last_restart_at_ms: prior.as_ref().and_then(|record| record.last_restart_at_ms),
                    last_error: None,
                },
                now_ms,
            )?;
            return Ok(());
        }
        self.store
            .audit("component_stop_intent", &component.id, now_ms)?;
        let result = match self.children.get_mut(&component.id) {
            Some(child) => child.terminate(CHILD_STOP_TIMEOUT),
            None => {
                return Err(WatchdogError::Conflict(
                    "owned child disappeared during termination".to_string(),
                ));
            }
        };
        match result {
            Ok(status) => {
                // The exact child has exited; only now release the owned
                // handle and clear its persisted identity.
                self.children.remove(&component.id);
                self.store.audit(
                    "component_stopped",
                    &format!("{}:status={status:?}", component.id),
                    now_ms,
                )?;
                self.store.upsert_component(
                    &ComponentRecord {
                        id: component.id.clone(),
                        state: ComponentState::Stopped,
                        launch_nonce: None,
                        pid: None,
                        executable_digest: None,
                        started_at_ms: None,
                        restart_attempts: self
                            .store
                            .component(&component.id)?
                            .map_or(0, |record| record.restart_attempts),
                        last_restart_at_ms: self
                            .store
                            .component(&component.id)?
                            .and_then(|record| record.last_restart_at_ms),
                        last_error: None,
                    },
                    now_ms,
                )?;
                self.store.clear_component_identity(&component.id, now_ms)?;
                report.stopped.push(component.id.clone());
            }
            Err(error) => {
                // Keep the handle owned after a bounded termination failure so
                // a later reconciliation can retry exact cleanup.  Dropping
                // it here would detach the process and leave only an unsafe
                // PID-shaped breadcrumb in durable state.
                let identity = self
                    .children
                    .get(&component.id)
                    .map(|child| child.identity().clone())
                    .ok_or_else(|| {
                        WatchdogError::Conflict(
                            "owned child disappeared during termination".to_string(),
                        )
                    })?;
                self.store.upsert_component(
                    &ComponentRecord {
                        id: component.id.clone(),
                        state: ComponentState::Quarantined,
                        launch_nonce: Some(identity.launch_nonce),
                        pid: Some(identity.pid),
                        executable_digest: Some(identity.executable_digest),
                        started_at_ms: Some(identity.started_at_ms),
                        restart_attempts: self
                            .store
                            .component(&component.id)?
                            .map_or(0, |record| record.restart_attempts),
                        last_restart_at_ms: self
                            .store
                            .component(&component.id)?
                            .and_then(|record| record.last_restart_at_ms),
                        last_error: Some(error.to_string()),
                    },
                    now_ms,
                )?;
                report.quarantined.push(component.id.clone());
                report.errors.push(format!("{}: {error}", component.id));
            }
        }
        Ok(())
    }

    /// Run until durable stop is observed and all children have been removed.
    pub(crate) fn has_no_owned_children(&self) -> bool {
        self.children.is_empty()
    }

    /// Run until durable stop is observed and all children have been removed.
    pub fn run_until_stopped(&mut self) -> Result<()> {
        self.acquire_lock()?;
        loop {
            let report = self.reconcile_once(now_unix_ms())?;
            if report.desired_mode == DesiredMode::Stopped && self.children.is_empty() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(self.config.probe_interval_ms));
        }
    }

    /// Expose the worker's child identity for integration diagnostics.
    pub fn child_identity(&self, component_id: &str) -> Option<&ProcessIdentity> {
        self.children.get(component_id).map(OwnedChild::identity)
    }

    /// Submit a job through the durable store.
    pub fn submit_job(&mut self, kind: &str, payload: &Value) -> Result<crate::storage::JobRecord> {
        self.store.submit_job(kind, payload)
    }

    /// Claim a job when running intent is durable.
    pub fn claim_job(
        &mut self,
        worker_id: &str,
        now_ms: u64,
    ) -> Result<Option<crate::storage::JobClaim>> {
        self.store.claim_next_job(worker_id, now_ms)
    }

    /// Complete a job atomically before the caller acknowledges it.
    pub fn complete_job(
        &mut self,
        job_id: &str,
        attempt_id: &str,
        result: &Value,
    ) -> Result<crate::storage::Completion> {
        self.store.complete_job(job_id, attempt_id, result)
    }
}

fn component_record(
    component: &ComponentConfig,
    identity: &ProcessIdentity,
    attempts: u32,
    now_ms: u64,
    error: Option<String>,
) -> ComponentRecord {
    ComponentRecord {
        id: component.id.clone(),
        state: ComponentState::Running,
        launch_nonce: Some(identity.launch_nonce.clone()),
        pid: Some(identity.pid),
        executable_digest: Some(identity.executable_digest.clone()),
        started_at_ms: Some(identity.started_at_ms),
        restart_attempts: attempts,
        last_restart_at_ms: Some(now_ms),
        last_error: error,
    }
}

/// A placeholder-neutral runtime adapter hook for future native Windows/WSL
/// integration.  The vertical slice uses the direct process adapter above.
pub trait RuntimeAdapter {
    /// Validate that the adapter can launch this exact approved component.
    fn validate_component(&self, component: &ComponentConfig) -> Result<()>;
}

/// The portable adapter validates paths but performs no host-specific actions.
#[derive(Debug, Default)]
pub struct DirectRuntimeAdapter;

impl RuntimeAdapter for DirectRuntimeAdapter {
    fn validate_component(&self, component: &ComponentConfig) -> Result<()> {
        if !component.executable.is_absolute() || !Path::new(&component.executable).is_file() {
            return Err(WatchdogError::InvalidInput(format!(
                "approved executable is unavailable: {}",
                component.executable.display()
            )));
        }
        Ok(())
    }
}
