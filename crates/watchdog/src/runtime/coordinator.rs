//! Runtime construction and reconciliation coordination.
//!
//! This child module owns the supervisor entry points and the single
//! reconciliation pass: owner-local construction and opening, singleton lock
//! acquisition, the reconcile-once orchestration, the durable
//! run-until-stopped loop, and the read-only status and job facade.
//!
//! The ordering is load-bearing and is preserved exactly: a supplied
//! timestamp drives the pass, persisted intents and identities reconcile
//! before any new effect, the worker binding is persisted before scheduling,
//! and a durable stop/pause intent is admitted before component cleanup.
//! Behaviour, visibility and error semantics are unchanged from the previous
//! single-file layout; `runtime.rs` remains the facade that declares and
//! re-exports this module.

use super::{
    BTreeMap, BTreeSet, DesiredMode, Duration, ProcessIdentity, ReconcileReport, Result,
    RuntimeChild, RuntimeProcessManager, SingletonLock, Store, Supervisor, SupervisorPolicy, Uuid,
    Value, WatchdogConfig, WatchdogError, now_unix_ms, runtime_worker,
};

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
        let store = Store::initialize_for_owner(&config.database, &config, &lock)?;
        let mut supervisor = Self::from_store(store, config);
        lock.write_owner_hint(&format!("worker_id={}", supervisor.worker_id))?;
        supervisor.lock = Some(lock);
        Ok(supervisor)
    }

    /// Open existing state.  It never creates a missing database.
    pub fn open(config: WatchdogConfig) -> Result<Self> {
        config.validate()?;
        let lock = SingletonLock::acquire(&config.database)?;
        let store = Store::open_for_owner(&config.database, &config, &lock)?;
        let mut supervisor = Self::from_store(store, config);
        lock.write_owner_hint(&format!("worker_id={}", supervisor.worker_id))?;
        supervisor.lock = Some(lock);
        Ok(supervisor)
    }

    /// Persist the operator's stop intent before the service performs any
    /// corresponding cleanup. Windows SCM delivers stop on a control thread;
    /// the owning reconciliation loop calls this method before its next
    /// observation so a restart cannot mistake an interrupted stop for a
    /// request to relaunch children.
    pub(crate) fn request_stop(&mut self, now_ms: u64) -> Result<()> {
        self.acquire_lock()?;
        self.store.set_desired_mode_at(DesiredMode::Stopped, now_ms)
    }

    fn from_store(store: Store, config: WatchdogConfig) -> Self {
        let policy = SupervisorPolicy::from_config(&config);
        let process_manager = RuntimeProcessManager::new(&config);
        Self {
            store,
            config,
            policy,
            children: BTreeMap::new(),
            process_manager,
            lock: None,
            worker_id: format!("watchdog-{}", Uuid::new_v4()),
            worker_boot_id: Uuid::new_v4().to_string(),
            #[cfg(windows)]
            windows_controller_identity: None,
            worker_deferred_phases: BTreeSet::new(),
            worker_heartbeat: None,
            worker_phase_pre_failed: false,
            gateway_health_witness: None,
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
        // Worker liveness is a same-pass proof.  Never let an authenticated
        // response from an earlier loop survive a child replacement or a
        // failed probe/control exchange.
        self.worker_heartbeat = None;
        self.gateway_health_witness = None;
        let first_reconcile = !self.initialized_runtime;
        if first_reconcile {
            self.store.quarantine_interrupted_jobs(now_ms)?;
            self.store.establish_new_generation(now_ms)?;
            self.store
                .audit("reconciler_started", &self.worker_id, now_ms)?;
            self.reconcile_persisted_launch_intents(now_ms)?;
            self.reconcile_persisted_identities(now_ms)?;
            self.initialized_runtime = true;
        }
        // A configured worker binding is immutable owner-local state. Persist
        // it before any worker control or queue effect, while leaving the
        // first-reconcile quarantine/generation/orphan-proof ordering above
        // intact.
        self.configure_worker_binding(now_ms)?;
        // Both worker interactions in this reconciliation share one absolute
        // budget. Rebuilding a client after component scheduling must not
        // restart the full per-exchange timeout and miss the service watchdog.
        let worker_budget = runtime_worker::WorkerPhaseBudget::new(self.config.worker.as_ref());
        let desired_mode = self.store.desired_mode()?;
        let mut report = ReconcileReport {
            observed_at_ms: now_ms,
            desired_mode,
            ..ReconcileReport::default()
        };
        // Existing live harnesses must receive the freshly observed durable
        // desired mode before component stop/cleanup can run.
        let worker_identity_blocked = match self.reconcile_worker_before_components(
            desired_mode,
            now_ms,
            worker_budget,
            &mut report,
        ) {
            Err(WatchdogError::IdentityMismatch(message))
                if desired_mode == DesiredMode::Stopped =>
            {
                // Failed worker authentication cannot veto durable operator stop.
                // Only the independently owned process authority performs cleanup;
                // pending handoffs remain unresolved and no worker command is sent.
                report
                    .errors
                    .push(format!("worker identity blocked during stop: {message}"));
                true
            }
            result => {
                result?;
                false
            }
        };
        for component in self.config.components.clone() {
            let decision =
                self.reconcile_component(&component, desired_mode, now_ms, &mut report)?;
            report.decisions.push(decision);
        }
        // Repeat control/recovery after a possible new launch.  Claims are
        // admitted only by this post-scheduling Running phase.
        if !worker_identity_blocked {
            self.reconcile_worker_after_components(
                desired_mode,
                now_ms,
                worker_budget,
                &mut report,
            )?;
        }
        if desired_mode == DesiredMode::Draining
            && self.children.is_empty()
            && self.worker_drain_complete()?
        {
            self.store
                .set_desired_mode_at(DesiredMode::Stopped, now_ms)?;
        }
        self.store.record_reconciliation_progress(now_ms)?;
        Ok(report)
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
        self.children.get(component_id).map(RuntimeChild::identity)
    }

    /// The watchdog worker-session identity for this Supervisor instance.
    /// A reopened Supervisor receives a new value; durable handoffs retain the
    /// original value and can only be reconciled through current control.
    #[must_use]
    pub fn worker_boot_id(&self) -> &str {
        &self.worker_boot_id
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
