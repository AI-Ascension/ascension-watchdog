//! Reconciliation loop and approved child supervision.

#[path = "runtime_admin.rs"]
pub(crate) mod runtime_admin;
#[path = "runtime_process.rs"]
pub(crate) mod runtime_process;
#[path = "runtime_worker.rs"]
pub(crate) mod runtime_worker;

use self::runtime_process::{
    RuntimeChild, RuntimeLaunchError, RuntimeObservation, RuntimeProcessManager,
    RuntimeStopOutcome, platform_component_kind, runtime_incarnation,
};
use crate::config::{ComponentConfig, DesiredMode, WatchdogConfig, hex_digest};
use crate::error::{Result, WatchdogError};
use crate::policy::{
    ComponentObservation, ComponentState, ReconcileAction, ReconcileDecision, SupervisorPolicy,
};
use crate::process::{ProcessIdentity, ensure_identity};
use crate::storage::{
    ComponentRecord, LaunchIntent, LaunchIntentState, SingletonLock, Store, now_unix_ms,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

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

/// The proof returned by the platform runtime is intentionally decoded at
/// this boundary.  Generic storage retains the bounded JSON for durability,
/// but it must not decide which incarnation or launch context a proof belongs
/// to.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeOwnershipProof {
    version: u32,
    backend: String,
    intent_id: String,
    deployment_id: String,
    instance_id: String,
    component: String,
    incarnation: String,
    launch_nonce: String,
    containment_id: String,
    pid: u32,
    creation_token: String,
    executable: PathBuf,
    executable_sha256: String,
    session_id: Option<u32>,
    started_at_ms: u64,
}

#[derive(Serialize)]
struct LaunchSpecBinding<'a> {
    deployment_id: &'a str,
    instance_id: &'a str,
    component: &'static str,
    incarnation: &'a str,
    launch_nonce: &'a str,
    executable: &'a str,
    executable_sha256: &'a str,
    arguments: &'a [String],
    working_directory: Option<&'a str>,
    environment: &'a [(String, String)],
    session: String,
    graceful_timeout_ms: u64,
    force_timeout_ms: u64,
    planned_containment_id: &'a str,
}

/// A running watchdog controller.  Status/config commands do not construct
/// this type with a lock, so they remain side-effect free.
pub struct Supervisor {
    pub(crate) store: Store,
    config: WatchdogConfig,
    policy: SupervisorPolicy,
    children: BTreeMap<String, RuntimeChild>,
    process_manager: RuntimeProcessManager,
    lock: Option<SingletonLock>,
    worker_id: String,
    /// One fresh watchdog worker-session identity per Supervisor instance.
    /// It is never restored from durable state or regenerated per request.
    worker_boot_id: String,
    initialized_runtime: bool,
}

impl std::fmt::Debug for Supervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Supervisor")
            .field("database", &self.store.path())
            .field("components", &self.config.components.len())
            .field("children", &self.children.keys().collect::<Vec<_>>())
            .field("worker_id", &self.worker_id)
            .field("worker_boot_id", &self.worker_boot_id)
            .finish_non_exhaustive()
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        // Synthetic fixtures retain their direct Child drop semantics. Native
        // handles carry only the durable platform identity after launch, so
        // the platform authority must perform exact containment cleanup before
        // those handles are discarded.
        let ids = self
            .children
            .iter()
            .filter_map(|(id, child)| child.is_native().then_some(id.clone()))
            .collect::<Vec<_>>();
        for id in ids {
            if let Some(child) = self.children.get_mut(&id) {
                let _ = self.process_manager.stop(child);
            }
        }
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
            initialized_runtime: false,
        }
    }

    fn quarantine_component(
        &mut self,
        component: &ComponentConfig,
        launch_nonce: Option<String>,
        pid: Option<u32>,
        executable_digest: Option<String>,
        started_at_ms: Option<u64>,
        error: String,
        now_ms: u64,
    ) -> Result<()> {
        let prior = self.store.component(&component.id)?;
        self.store.upsert_component(
            &ComponentRecord {
                id: component.id.clone(),
                state: ComponentState::Quarantined,
                launch_nonce,
                pid,
                executable_digest,
                started_at_ms,
                restart_attempts: prior.as_ref().map_or(0, |record| record.restart_attempts),
                last_restart_at_ms: prior.as_ref().and_then(|record| record.last_restart_at_ms),
                last_error: Some(error),
            },
            now_ms,
        )
    }

    fn retain_quarantined_child(
        &mut self,
        component: &ComponentConfig,
        intent_id: &str,
        child: RuntimeChild,
        error: String,
        now_ms: u64,
    ) -> Result<()> {
        let identity = child.identity().clone();
        self.children.insert(component.id.clone(), child);
        self.quarantine_component(
            component,
            Some(identity.launch_nonce),
            Some(identity.pid),
            Some(identity.executable_digest),
            Some(identity.started_at_ms),
            error,
            now_ms,
        )?;
        self.store.audit(
            "launch_intent_quarantined",
            &format!("{intent_id}:owned_child_retained"),
            now_ms,
        )
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
            self.reconcile_persisted_launch_intents(now_ms)?;
            self.reconcile_persisted_identities(now_ms)?;
            self.initialized_runtime = true;
        }
        // A configured worker binding is immutable owner-local state. Persist
        // it before any worker control or queue effect, while leaving the
        // first-reconcile quarantine/generation/orphan-proof ordering above
        // intact.
        self.configure_worker_binding(now_ms)?;
        let desired_mode = self.store.desired_mode()?;
        let mut report = ReconcileReport {
            observed_at_ms: now_ms,
            desired_mode,
            ..ReconcileReport::default()
        };
        // Existing live harnesses must receive the freshly observed durable
        // desired mode before component stop/cleanup can run.
        self.reconcile_worker_before_components(desired_mode, now_ms)?;
        for component in self.config.components.clone() {
            let decision =
                self.reconcile_component(&component, desired_mode, now_ms, &mut report)?;
            report.decisions.push(decision);
        }
        // Repeat control/recovery after a possible new launch.  Claims are
        // admitted only by this post-scheduling Running phase.
        self.reconcile_worker_after_components(desired_mode, now_ms)?;
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

    /// Reconcile launch intents before looking at legacy component rows.  A
    /// proof-recorded/active native intent is the only durable route by which
    /// a restarted supervisor may reconstruct an owned process handle.
    #[allow(clippy::if_not_else)]
    fn reconcile_persisted_launch_intents(&mut self, now_ms: u64) -> Result<()> {
        let intents = self.store.unsettled_launch_intents()?;
        for intent in intents {
            let Some(component) = self
                .config
                .components
                .iter()
                .find(|component| component.id == intent.component_id)
                .cloned()
            else {
                self.store.audit(
                    "launch_intent_quarantined",
                    &format!("{}:component_not_configured", intent.id),
                    now_ms,
                )?;
                continue;
            };
            if intent.expected_incarnation.is_none() || intent.expected_launch_spec_digest.is_none()
            {
                // Schema-v1 rows cannot be rebound from their proof (or from
                // the current restart generation).  Keep the durable intent
                // and quarantine the component until an explicit operator
                // migration/review resolves the original launch context.
                self.quarantine_component(
                    &component,
                    Some(intent.launch_nonce.clone()),
                    None,
                    None,
                    None,
                    "legacy launch intent has no persisted launch binding".to_owned(),
                    now_ms,
                )?;
                self.store.audit(
                    "launch_intent_quarantined",
                    &format!("{}:legacy_unbound", intent.id),
                    now_ms,
                )?;
                continue;
            }
            if intent.state == LaunchIntentState::Prepared {
                let Some(planned_containment) = intent.planned_containment_id.as_deref() else {
                    self.quarantine_component(
                        &component,
                        Some(intent.launch_nonce.clone()),
                        None,
                        None,
                        None,
                        "prepared launch intent has no planned containment authority".to_owned(),
                        now_ms,
                    )?;
                    self.store.audit(
                        "launch_intent_quarantined",
                        &format!("{}:prepared_without_containment", intent.id),
                        now_ms,
                    )?;
                    continue;
                };
                match self
                    .process_manager
                    .cleanup_planned_containment(&self.config, planned_containment)
                {
                    Ok(RuntimeStopOutcome::Exited(_) | RuntimeStopOutcome::AlreadyExited) => {
                        self.store.clean_launch_intent(&intent.id, now_ms)?;
                        self.store.clear_component_identity(&component.id, now_ms)?;
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
                                last_restart_at_ms: Some(now_ms),
                                last_error: Some(
                                    "prepared launch intent was reconciled by exact containment"
                                        .to_owned(),
                                ),
                            },
                            now_ms,
                        )?;
                        self.store.audit(
                            "launch_intent_reconciled",
                            &format!("{}:prepared_containment_cleaned", intent.id),
                            now_ms,
                        )?;
                    }
                    Ok(RuntimeStopOutcome::TimedOut) | Err(_) => {
                        self.quarantine_component(
                            &component,
                            Some(intent.launch_nonce.clone()),
                            None,
                            None,
                            None,
                            "prepared launch containment cleanup remains uncertain".to_owned(),
                            now_ms,
                        )?;
                        self.store.audit(
                            "launch_intent_quarantined",
                            &format!("{}:prepared_containment_uncertain", intent.id),
                            now_ms,
                        )?;
                    }
                }
                continue;
            }
            let expected_incarnation = intent.expected_incarnation.as_deref().ok_or_else(|| {
                WatchdogError::Conflict("bound launch intent lost its incarnation".to_owned())
            })?;
            let specification = launch_spec_for(
                &self.config,
                &component,
                intent.launch_nonce.clone(),
                expected_incarnation.to_owned(),
            )?;
            let planned_containment =
                intent.planned_containment_id.as_deref().ok_or_else(|| {
                    WatchdogError::Conflict(
                        "launch intent has no planned containment for proof recovery".to_owned(),
                    )
                })?;
            let proof_value = intent.ownership_proof_json.as_ref().ok_or_else(|| {
                WatchdogError::Conflict(format!(
                    "launch intent {} has no ownership proof for recovery",
                    intent.id
                ))
            })?;
            if let Err(error) = validate_persisted_launch_binding(
                &intent,
                &specification,
                planned_containment,
                proof_value,
                expected_runtime_backend(self.config.allow_synthetic_children),
            ) {
                self.quarantine_component(
                    &component,
                    Some(intent.launch_nonce.clone()),
                    None,
                    None,
                    None,
                    format!("persisted launch proof failed original binding: {error}"),
                    now_ms,
                )?;
                self.store.audit(
                    "launch_intent_quarantined",
                    &format!("{}:binding_mismatch", intent.id),
                    now_ms,
                )?;
                continue;
            }
            let recovered = match self.process_manager.recover_intent(&self.config, &intent) {
                Ok(child) => child,
                Err(error) => {
                    self.quarantine_component(
                        &component,
                        Some(intent.launch_nonce.clone()),
                        None,
                        None,
                        None,
                        format!("persisted launch authority could not be recovered: {error}"),
                        now_ms,
                    )?;
                    self.store.audit(
                        "launch_intent_quarantined",
                        &format!("{}:recovery_failed", intent.id),
                        now_ms,
                    )?;
                    continue;
                }
            };
            let Some(mut child) = recovered else {
                // A prepared intent has no proof, and a synthetic proof cannot
                // reconstruct a Child handle.  Neither case authorizes a
                // guessed PID cleanup or an immediate replacement launch.
                let prior = self.store.component(&component.id)?;
                self.store.upsert_component(
                    &ComponentRecord {
                        id: component.id.clone(),
                        state: ComponentState::Quarantined,
                        launch_nonce: Some(intent.launch_nonce.clone()),
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
                        last_error: Some(
                            "unreconstructable launch intent retained for operator quarantine"
                                .to_owned(),
                        ),
                    },
                    now_ms,
                )?;
                self.store.audit(
                    "launch_intent_quarantined",
                    &format!("{}:unreconstructable", intent.id),
                    now_ms,
                )?;
                continue;
            };
            let observation = match self.process_manager.inspect(&mut child) {
                Ok(observation) => observation,
                Err(error) => {
                    self.retain_quarantined_child(
                        &component,
                        &intent.id,
                        child,
                        format!("persisted process authority could not be inspected: {error}"),
                        now_ms,
                    )?;
                    continue;
                }
            };
            match observation {
                RuntimeObservation::Running => {
                    if self.store.desired_mode()? != DesiredMode::Running {
                        match self.process_manager.stop(&mut child) {
                            Ok(
                                RuntimeStopOutcome::Exited(_) | RuntimeStopOutcome::AlreadyExited,
                            ) => {
                                if let Err(error) =
                                    self.store.clean_launch_intent(&intent.id, now_ms)
                                {
                                    self.retain_quarantined_child(
                                        &component,
                                        &intent.id,
                                        child,
                                        format!("stopped launch intent cleanup failed: {error}"),
                                        now_ms,
                                    )?;
                                    continue;
                                }
                                if let Err(error) =
                                    self.store.clear_component_identity(&component.id, now_ms)
                                {
                                    self.retain_quarantined_child(
                                        &component,
                                        &intent.id,
                                        child,
                                        format!(
                                            "stopped component identity cleanup failed: {error}"
                                        ),
                                        now_ms,
                                    )?;
                                    continue;
                                }
                                if let Err(error) = self.store.upsert_component(
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
                                        last_restart_at_ms: Some(now_ms),
                                        last_error: None,
                                    },
                                    now_ms,
                                ) {
                                    self.retain_quarantined_child(
                                        &component,
                                        &intent.id,
                                        child,
                                        format!("stopped component state cleanup failed: {error}"),
                                        now_ms,
                                    )?;
                                }
                            }
                            Ok(RuntimeStopOutcome::TimedOut) | Err(_) => {
                                self.children.insert(component.id.clone(), child);
                                self.store.audit(
                                    "launch_intent_quarantined",
                                    &format!("{}:stop_uncertain", intent.id),
                                    now_ms,
                                )?;
                            }
                        }
                    } else {
                        if intent.state == LaunchIntentState::ProofRecorded {
                            let proof = match RuntimeProcessManager::ownership_proof(&child) {
                                Ok(proof) => proof,
                                Err(error) => {
                                    self.retain_quarantined_child(
                                        &component,
                                        &intent.id,
                                        child,
                                        format!(
                                            "recovered launch proof could not be materialized: {error}"
                                        ),
                                        now_ms,
                                    )?;
                                    continue;
                                }
                            };
                            if let Err(error) = validate_persisted_launch_binding(
                                &intent,
                                &specification,
                                planned_containment,
                                &proof,
                                expected_runtime_backend(self.config.allow_synthetic_children),
                            ) {
                                self.retain_quarantined_child(
                                    &component,
                                    &intent.id,
                                    child,
                                    format!(
                                        "recovered launch proof changed before activation: {error}"
                                    ),
                                    now_ms,
                                )?;
                                continue;
                            }
                            if let Err(error) =
                                self.store.activate_launch_intent(&intent.id, now_ms)
                            {
                                self.retain_quarantined_child(
                                    &component,
                                    &intent.id,
                                    child,
                                    format!("persisted launch activation failed: {error}"),
                                    now_ms,
                                )?;
                                continue;
                            }
                        }
                        let identity = child.identity().clone();
                        if let Err(error) =
                            self.store
                                .persist_component_identity(&component.id, &identity, now_ms)
                        {
                            self.retain_quarantined_child(
                                &component,
                                &intent.id,
                                child,
                                format!("persisted process identity could not be stored: {error}"),
                                now_ms,
                            )?;
                            continue;
                        }
                        self.children.insert(component.id.clone(), child);
                        self.store.audit(
                            "launch_intent_recovered",
                            &format!("{}:pid={}", intent.id, identity.pid),
                            now_ms,
                        )?;
                    }
                }
                RuntimeObservation::Exited { .. } | RuntimeObservation::Missing => {
                    match self.process_manager.stop(&mut child) {
                        Ok(RuntimeStopOutcome::Exited(_) | RuntimeStopOutcome::AlreadyExited) => {}
                        Ok(RuntimeStopOutcome::TimedOut) | Err(_) => {
                            self.children.insert(component.id.clone(), child);
                            self.store.audit(
                                "launch_intent_quarantined",
                                &format!("{}:exited_cleanup_uncertain", intent.id),
                                now_ms,
                            )?;
                            continue;
                        }
                    }
                    if let Err(error) = self.store.clean_launch_intent(&intent.id, now_ms) {
                        self.retain_quarantined_child(
                            &component,
                            &intent.id,
                            child,
                            format!("exited launch intent cleanup failed: {error}"),
                            now_ms,
                        )?;
                        continue;
                    }
                    if let Err(error) = self.store.clear_component_identity(&component.id, now_ms) {
                        self.retain_quarantined_child(
                            &component,
                            &intent.id,
                            child,
                            format!("exited component identity cleanup failed: {error}"),
                            now_ms,
                        )?;
                        continue;
                    }
                    let prior = self.store.component(&component.id)?;
                    if let Err(error) = self.store.upsert_component(
                        &ComponentRecord {
                            id: component.id.clone(),
                            state: ComponentState::Stopped,
                            launch_nonce: None,
                            pid: None,
                            executable_digest: None,
                            started_at_ms: None,
                            restart_attempts: prior
                                .as_ref()
                                .map_or(0, |record| record.restart_attempts),
                            last_restart_at_ms: prior
                                .as_ref()
                                .and_then(|record| record.last_restart_at_ms),
                            last_error: Some("persisted launch exited before recovery".to_owned()),
                        },
                        now_ms,
                    ) {
                        self.retain_quarantined_child(
                            &component,
                            &intent.id,
                            child,
                            format!("exited component state cleanup failed: {error}"),
                            now_ms,
                        )?;
                    }
                }
                RuntimeObservation::IdentityMismatch | RuntimeObservation::Ambiguous => {
                    let identity = child.identity().clone();
                    self.children.insert(component.id.clone(), child);
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
                            last_error: Some(
                                "persisted process authority is ambiguous during recovery"
                                    .to_owned(),
                            ),
                        },
                        now_ms,
                    )?;
                    self.store.audit(
                        "launch_intent_quarantined",
                        &format!("{}:authority_ambiguous", intent.id),
                        now_ms,
                    )?;
                }
            }
        }
        Ok(())
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
            // An unsettled launch intent owns the admission decision for this
            // component.  Do not let the legacy identity pass (or a proof
            // mismatch) be rewritten as a stale stopped row in the fallback
            // identity reconciler; that would erase the quarantine boundary
            // and allow a replacement launch attempt.
            if self
                .store
                .unsettled_launch_intents()?
                .iter()
                .any(|intent| intent.component_id == component.id)
            {
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
            match self.process_manager.inspect(child) {
                Ok(RuntimeObservation::Running) => {}
                Ok(RuntimeObservation::Exited { code }) => {
                    exited =
                        Some(code.map_or_else(|| "signal".to_string(), |value| value.to_string()));
                }
                Ok(RuntimeObservation::Missing) => {
                    exited = Some("missing".to_owned());
                }
                Ok(RuntimeObservation::IdentityMismatch | RuntimeObservation::Ambiguous) => {
                    let identity = child.identity().clone();
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
                            last_error: Some(
                                "native process authority reported an ambiguous identity"
                                    .to_owned(),
                            ),
                        },
                        now_ms,
                    )?;
                    report.quarantined.push(component.id.clone());
                    // Retain the exact child authority while quarantined so a
                    // later pass can retry containment-aware cleanup.  A PID
                    // record alone cannot safely replace this handle.
                    return Ok(ReconcileDecision {
                        component_id: component.id.clone(),
                        action: ReconcileAction::Quarantine,
                        resulting_state: ComponentState::Quarantined,
                        reason: "native process identity is ambiguous".to_owned(),
                        retry_at_ms: None,
                    });
                }
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
                    // Keep the authority-bearing handle after an inspection
                    // error; dropping it would turn an exact failure into an
                    // unsafe orphan identity.
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
            if let Some(mut child) = self.children.remove(&component.id) {
                let cleanup = self.process_manager.stop(&mut child);
                if !matches!(
                    cleanup,
                    Ok(RuntimeStopOutcome::Exited(_) | RuntimeStopOutcome::AlreadyExited)
                ) {
                    let cleanup_error = cleanup.err().map_or_else(
                        || "native containment cleanup timed out".to_owned(),
                        |value| value.to_string(),
                    );
                    let identity = child.identity().clone();
                    self.children.insert(component.id.clone(), child);
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
                            last_error: Some(format!(
                                "exited process containment cleanup failed: {cleanup_error}"
                            )),
                        },
                        now_ms,
                    )?;
                    report.quarantined.push(component.id.clone());
                    return Ok(ReconcileDecision {
                        component_id: component.id.clone(),
                        action: ReconcileAction::Quarantine,
                        resulting_state: ComponentState::Quarantined,
                        reason: cleanup_error,
                        retry_at_ms: None,
                    });
                }
                let output = child.output();
                let identity = child.identity().clone();
                let intent_id = child.intent_id().to_owned();
                let detail = if child.captures_output() {
                    format!(
                        "component={} exit={} stdout_bytes={} stderr_bytes={}",
                        component.id,
                        exit_code,
                        output.stdout.len(),
                        output.stderr.len()
                    )
                } else {
                    // Native launchers own null standard streams today.  Do
                    // not represent an empty snapshot as captured evidence.
                    format!(
                        "component={} exit={} stdout_capture=disabled stderr_capture=disabled",
                        component.id, exit_code
                    )
                };
                self.store.audit("component_exited", &detail, now_ms)?;
                if let Err(error) = self.store.clean_launch_intent(&intent_id, now_ms) {
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
                            last_error: Some(format!(
                                "child exited but launch intent cleanup failed: {error}"
                            )),
                        },
                        now_ms,
                    )?;
                    report.quarantined.push(component.id.clone());
                    return Ok(ReconcileDecision {
                        component_id: component.id.clone(),
                        action: ReconcileAction::Quarantine,
                        resulting_state: ComponentState::Quarantined,
                        reason: format!("launch intent cleanup failed: {error}"),
                        retry_at_ms: None,
                    });
                }
                self.store.clear_component_identity(&component.id, now_ms)?;
                let prior = self.store.component(&component.id)?;
                self.store.upsert_component(
                    &ComponentRecord {
                        id: component.id.clone(),
                        state: ComponentState::Stopped,
                        launch_nonce: None,
                        pid: None,
                        executable_digest: None,
                        started_at_ms: None,
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
        let retained_quarantine = is_running
            && prior
                .as_ref()
                .is_some_and(|record| record.state == ComponentState::Quarantined);
        let stop_requested = desired_mode.stops_children() || desired_mode == DesiredMode::Draining;
        let observation = ComponentObservation {
            component_id: component.id.clone(),
            // A live owned child does not erase a durable quarantine. In
            // particular, a timed-out/error stop must not be reclassified as
            // healthy merely because the next probe can still see the handle.
            state: if retained_quarantine {
                ComponentState::Quarantined
            } else if is_running {
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
        let mut decision = self.policy.decide(
            desired_mode,
            component.restart,
            &observation,
            now_ms,
            restart_count,
            prior.as_ref().and_then(|record| record.last_restart_at_ms),
        );
        if retained_quarantine && !stop_requested {
            // Running or Paused intent cannot authorize revival or erase the
            // exact cleanup error. A stop/drain request still reaches the
            // normal authority-aware stop path above.
            decision.action = ReconcileAction::Quarantine;
            decision.resulting_state = ComponentState::Quarantined;
            if let Some(error) = prior.as_ref().and_then(|record| record.last_error.clone()) {
                decision.reason = error;
            } else {
                "owned process remains quarantined pending authority-aware recovery"
                    .clone_into(&mut decision.reason);
            }
            decision.retry_at_ms = None;
        } else if is_running && decision.action == ReconcileAction::Start {
            // Never overwrite a still-owned child with a replacement merely
            // because a deadline or health observation became suspect.
            // Authority-aware drain/cleanup must complete before relaunch.
            decision.action = ReconcileAction::MarkSuspect;
            decision.resulting_state = ComponentState::Suspect;
            "owned process retained pending authority-aware recovery; duplicate launch blocked"
                .clone_into(&mut decision.reason);
            decision.retry_at_ms = None;
        }
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
                        last_error: if retained_quarantine {
                            prior.as_ref().and_then(|record| record.last_error.clone())
                        } else {
                            Some(decision.reason.clone())
                        },
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
                } else if decision.action == ReconcileAction::MarkSuspect {
                    ComponentState::Suspect
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
        let status = self.store.status()?;
        let incarnation = runtime_incarnation(status.restart_generation)?;
        let launch_nonce = Uuid::new_v4().to_string();
        let specification =
            launch_spec_for(&self.config, component, launch_nonce.clone(), incarnation)?;
        // Native capability is established before the durable intent.  This
        // prevents a permanently prepared row from being created for a host
        // where containment is unavailable.
        self.process_manager.ensure_ready(&self.config)?;
        let planned_containment = self
            .process_manager
            .planned_containment(&self.config, &specification)?;
        let launch_spec_digest = launch_spec_binding_digest(&specification, &planned_containment)?;
        let intent = self.store.prepare_launch_intent(
            &component.id,
            &launch_nonce,
            &specification.incarnation,
            &launch_spec_digest,
            Some(&planned_containment),
            now_ms,
        )?;
        // Stop/pause may have committed while capability probing and intent
        // preparation were in flight.  The fresh durable read is the final
        // admission barrier.
        if self.store.desired_mode()? != DesiredMode::Running {
            self.store.clean_launch_intent(&intent.id, now_ms)?;
            return Ok(());
        }
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
        let child = match self.process_manager.launch(
            &self.config,
            component,
            &specification,
            &planned_containment,
            &intent.id,
            now_ms,
        ) {
            Ok(child) => child,
            Err(RuntimeLaunchError::CleanupUncertain(error)) => {
                // The Linux adapter retained the exact planned cgroup but
                // could not prove it empty/removed.  Keep the prepared intent
                // and quarantine the component; cleaning it here would permit
                // a duplicate launch against an unresolved authority.
                self.quarantine_component(
                    component,
                    Some(launch_nonce.clone()),
                    None,
                    None,
                    Some(now_ms),
                    format!("{error}; exact launch containment cleanup is uncertain"),
                    now_ms,
                )?;
                self.store.audit(
                    "launch_intent_quarantined",
                    &format!("{}:linux-launch-cleanup-uncertain", intent.id),
                    now_ms,
                )?;
                report.errors.push(format!("{}: {error}", component.id));
                return Ok(());
            }
            Err(RuntimeLaunchError::Ordinary(error)) => {
                let cleanup = self.store.clean_launch_intent(&intent.id, now_ms);
                if let Err(clean_error) = &cleanup {
                    self.quarantine_component(
                        component,
                        Some(launch_nonce.clone()),
                        None,
                        None,
                        Some(now_ms),
                        format!("{error}; launch-intent cleanup failed: {clean_error}"),
                        now_ms,
                    )?;
                } else {
                    self.store.clear_component_identity(&component.id, now_ms)?;
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
                }
                report.errors.push(format!("{}: {error}", component.id));
                return Ok(());
            }
        };
        let identity = child.identity().clone();
        let proof = match RuntimeProcessManager::ownership_proof(&child) {
            Ok(proof) => proof,
            Err(error) => {
                return self
                    .abort_launched_child(component, &intent.id, child, attempts, now_ms, error);
            }
        };
        if let Err(error) = validate_persisted_launch_binding(
            &intent,
            &specification,
            &planned_containment,
            &proof,
            expected_runtime_backend(self.config.allow_synthetic_children),
        ) {
            return self
                .abort_launched_child(component, &intent.id, child, attempts, now_ms, error);
        }
        if let Err(error) = self.store.record_launch_proof(&intent.id, &proof, now_ms) {
            return self
                .abort_launched_child(component, &intent.id, child, attempts, now_ms, error);
        }
        if let Err(error) = self.store.upsert_component(
            &component_record(component, &identity, attempts, now_ms, None),
            now_ms,
        ) {
            return self
                .abort_launched_child(component, &intent.id, child, attempts, now_ms, error);
        }
        if let Err(error) = self
            .store
            .persist_component_identity(&component.id, &identity, now_ms)
        {
            return self
                .abort_launched_child(component, &intent.id, child, attempts, now_ms, error);
        }
        if let Err(error) = self.store.activate_launch_intent(&intent.id, now_ms) {
            return self
                .abort_launched_child(component, &intent.id, child, attempts, now_ms, error);
        }
        if let Err(error) = self.store.audit(
            "component_started",
            &format!(
                "{}:pid={};restart_count={restart_count}",
                component.id, identity.pid
            ),
            now_ms,
        ) {
            return self
                .abort_launched_child(component, &intent.id, child, attempts, now_ms, error);
        }
        self.children.insert(component.id.clone(), child);
        report.started.push(component.id.clone());
        Ok(())
    }

    fn abort_launched_child(
        &mut self,
        component: &ComponentConfig,
        intent_id: &str,
        mut child: RuntimeChild,
        attempts: u32,
        now_ms: u64,
        error: WatchdogError,
    ) -> Result<()> {
        let identity = child.identity().clone();
        let cleanup = self.process_manager.stop(&mut child);
        let cleanup_ok = matches!(
            &cleanup,
            Ok(RuntimeStopOutcome::Exited(_) | RuntimeStopOutcome::AlreadyExited)
        );
        let intent_cleanup = if cleanup_ok {
            self.store.clean_launch_intent(intent_id, now_ms).err()
        } else {
            None
        };
        let durable_cleanup_ok = cleanup_ok && intent_cleanup.is_none();
        let clear_identity = if durable_cleanup_ok {
            self.store
                .clear_component_identity(&component.id, now_ms)
                .err()
        } else {
            None
        };
        let cleanup_error = cleanup.err().map_or_else(
            || {
                intent_cleanup.as_ref().map_or_else(
                    || {
                        clear_identity.as_ref().map_or_else(
                            || "launch cleanup or durable cleanup failed".to_owned(),
                            ToString::to_string,
                        )
                    },
                    ToString::to_string,
                )
            },
            |value| value.to_string(),
        );
        if durable_cleanup_ok && clear_identity.is_none() {
            if let Err(store_error) = self.store.upsert_component(
                &ComponentRecord {
                    id: component.id.clone(),
                    state: ComponentState::Stopped,
                    launch_nonce: None,
                    pid: None,
                    executable_digest: None,
                    started_at_ms: Some(identity.started_at_ms),
                    restart_attempts: attempts,
                    last_restart_at_ms: Some(now_ms),
                    last_error: Some(error.to_string()),
                },
                now_ms,
            ) {
                // The platform child is already stopped, but retain its
                // exact handle until the durable component state can be
                // reconciled; dropping it would erase the only in-memory
                // authority available to the current supervisor.
                self.children.insert(component.id.clone(), child);
                return Err(store_error);
            }
        } else {
            // A cleanup, intent transition, or identity clear was uncertain.
            // Keep the exact RuntimeChild in memory so the next pass can retry
            // platform cleanup without guessing from the persisted PID.
            self.children.insert(component.id.clone(), child);
            let _ = self.store.upsert_component(
                &ComponentRecord {
                    id: component.id.clone(),
                    state: ComponentState::Quarantined,
                    launch_nonce: Some(identity.launch_nonce),
                    pid: Some(identity.pid),
                    executable_digest: Some(identity.executable_digest),
                    started_at_ms: Some(identity.started_at_ms),
                    restart_attempts: attempts,
                    last_restart_at_ms: Some(now_ms),
                    last_error: Some(format!("{error}; exact cleanup failed: {cleanup_error}")),
                },
                now_ms,
            );
        }
        Err(error)
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
            Some(child) => self.process_manager.stop(child),
            None => {
                return Err(WatchdogError::Conflict(
                    "owned child disappeared during termination".to_string(),
                ));
            }
        };
        match result {
            Ok(RuntimeStopOutcome::Exited(_) | RuntimeStopOutcome::AlreadyExited) => {
                let intent_id = self
                    .children
                    .get(&component.id)
                    .map(RuntimeChild::intent_id)
                    .ok_or_else(|| {
                        WatchdogError::Conflict(
                            "owned child disappeared during intent cleanup".to_owned(),
                        )
                    })?
                    .to_owned();
                if let Err(error) = self.store.clean_launch_intent(&intent_id, now_ms) {
                    let identity = self
                        .children
                        .get(&component.id)
                        .map(RuntimeChild::identity)
                        .ok_or_else(|| {
                            WatchdogError::Conflict(
                                "owned child disappeared during intent cleanup".to_owned(),
                            )
                        })?
                        .clone();
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
                            last_error: Some(format!(
                                "exact process stopped but launch intent cleanup failed: {error}"
                            )),
                        },
                        now_ms,
                    )?;
                    report.quarantined.push(component.id.clone());
                    report.errors.push(format!("{}: {error}", component.id));
                    return Ok(());
                }
                // The exact authority is gone and the durable intent is now
                // cleaned; only then release the in-memory handle/identity.
                self.children.remove(&component.id);
                self.store.audit(
                    "component_stopped",
                    &format!("{}:status=exited", component.id),
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
            Ok(RuntimeStopOutcome::TimedOut) => {
                let identity = self
                    .children
                    .get(&component.id)
                    .map(RuntimeChild::identity)
                    .ok_or_else(|| {
                        WatchdogError::Conflict(
                            "owned child disappeared during termination".to_owned(),
                        )
                    })?
                    .clone();
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
                        last_error: Some("owned containment stop timed out".to_owned()),
                    },
                    now_ms,
                )?;
                report.quarantined.push(component.id.clone());
                report.errors.push(format!(
                    "{}: owned containment stop timed out",
                    component.id
                ));
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

/// Dispatch the hidden Linux launch-helper mode before ordinary CLI parsing.
/// Normal invocations return Ok(None) and continue through the CLI.
pub fn run_linux_helper_if_requested() -> Result<Option<i32>> {
    runtime_process::run_linux_helper_if_requested()
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

fn launch_component_kind_name(component: crate::platform::ComponentKind) -> &'static str {
    match component {
        crate::platform::ComponentKind::Gateway => "gateway",
        crate::platform::ComponentKind::Harness => "harness",
        crate::platform::ComponentKind::HostBroker => "host_broker",
        crate::platform::ComponentKind::Synthetic => "synthetic",
    }
}

fn launch_session_name(session: crate::platform::SessionSelector) -> String {
    match session {
        crate::platform::SessionSelector::ActiveUser => "active_user".to_owned(),
        crate::platform::SessionSelector::Explicit(value) => format!("explicit:{value}"),
    }
}

/// Digest the exact request admitted before spawning.  The full request is
/// hashed rather than retained so environment values and other launch inputs
/// do not become durable watchdog state, while a changed configuration cannot
/// silently rebind a recovered proof.
fn launch_spec_binding_digest(
    specification: &crate::platform::LaunchSpec,
    planned_containment_id: &str,
) -> Result<String> {
    specification
        .validate()
        .map_err(|error| WatchdogError::InvalidInput(error.to_string()))?;
    let working_directory = specification
        .working_directory
        .as_deref()
        .map(|path| path.to_string_lossy().into_owned());
    let executable = specification.executable.to_string_lossy().into_owned();
    let binding = LaunchSpecBinding {
        deployment_id: &specification.deployment_id,
        instance_id: &specification.instance_id,
        component: launch_component_kind_name(specification.component),
        incarnation: &specification.incarnation,
        launch_nonce: &specification.launch_nonce,
        executable: &executable,
        executable_sha256: &specification.executable_sha256,
        arguments: &specification.arguments,
        working_directory: working_directory.as_deref(),
        environment: &specification.environment,
        session: launch_session_name(specification.session),
        graceful_timeout_ms: specification
            .graceful_timeout
            .as_millis()
            .try_into()
            .map_err(|_| {
                WatchdogError::InvalidInput("graceful timeout exceeds digest bound".to_owned())
            })?,
        force_timeout_ms: specification
            .force_timeout
            .as_millis()
            .try_into()
            .map_err(|_| {
                WatchdogError::InvalidInput("force timeout exceeds digest bound".to_owned())
            })?,
        planned_containment_id,
    };
    Ok(hex_digest(&serde_json::to_vec(&binding)?))
}

fn expected_runtime_backend(synthetic: bool) -> &'static str {
    if synthetic {
        "synthetic"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(windows) {
        "windows"
    } else {
        "unsupported"
    }
}

fn validate_persisted_launch_binding(
    intent: &LaunchIntent,
    specification: &crate::platform::LaunchSpec,
    planned_containment_id: &str,
    proof_value: &Value,
    expected_backend: &str,
) -> Result<()> {
    let Some(expected_incarnation) = intent.expected_incarnation.as_deref() else {
        return Err(WatchdogError::Conflict(format!(
            "launch intent {} has no original incarnation binding",
            intent.id
        )));
    };
    let Some(expected_digest) = intent.expected_launch_spec_digest.as_deref() else {
        return Err(WatchdogError::Conflict(format!(
            "launch intent {} has no original launch specification binding",
            intent.id
        )));
    };
    if specification.incarnation != expected_incarnation {
        return Err(WatchdogError::IdentityMismatch(
            "launch specification incarnation differs from persisted intent".to_owned(),
        ));
    }
    let actual_digest = launch_spec_binding_digest(specification, planned_containment_id)?;
    if actual_digest != expected_digest {
        return Err(WatchdogError::IdentityMismatch(
            "launch specification differs from the persisted launch intent".to_owned(),
        ));
    }
    let proof: RuntimeOwnershipProof =
        serde_json::from_value(proof_value.clone()).map_err(|_| {
            WatchdogError::IdentityMismatch(
                "launch ownership proof has an invalid shape".to_owned(),
            )
        })?;
    // Select the backend from trusted runtime configuration, never from a
    // persisted proof: relabeling a native proof must not opt out of checks.
    if proof.backend != expected_backend
        || !matches!(expected_backend, "synthetic" | "linux" | "windows")
    {
        return Err(WatchdogError::IdentityMismatch(
            "launch proof backend differs from configured process authority".to_owned(),
        ));
    }
    let session_matches = match (expected_backend, specification.session) {
        // Linux has no Windows session ID. Its adapter only accepts the
        // service selector Explicit(0), and persists that as None.
        ("linux", crate::platform::SessionSelector::Explicit(0)) => proof.session_id.is_none(),
        ("linux", _) => false,
        // ActiveUser is a selector, not a proof value.  The platform resolves
        // it during launch, so recovery must require a concrete non-service
        // session rather than comparing against `None`.
        (_, crate::platform::SessionSelector::ActiveUser) => {
            proof.session_id.is_some_and(|session| session != 0)
        }
        (_, crate::platform::SessionSelector::Explicit(expected)) => {
            proof.session_id == Some(expected)
        }
    };
    let executable_matches = proof.executable == specification.executable
        || std::fs::canonicalize(&proof.executable)
            .ok()
            .zip(std::fs::canonicalize(&specification.executable).ok())
            .is_some_and(|(actual, expected)| actual == expected);
    // The platform timestamp is part of the closed proof shape, but it is
    // not an authority binding: the persisted launch nonce/incarnation and
    // platform creation token provide that identity.
    let _ = proof.started_at_ms;
    if proof.version != 1
        || proof.intent_id != intent.id
        || proof.deployment_id != intent.deployment_id
        || proof.deployment_id != specification.deployment_id
        || proof.instance_id != specification.instance_id
        || proof.component != intent.component_id
        || proof.component != specification.instance_id
        || proof.incarnation != expected_incarnation
        || proof.launch_nonce != intent.launch_nonce
        || proof.launch_nonce != specification.launch_nonce
        || proof.containment_id != planned_containment_id
        || !executable_matches
        || (proof.backend != "synthetic"
            && proof.executable_sha256 != specification.executable_sha256)
        || (proof.backend != "synthetic" && !session_matches)
        || !matches!(proof.backend.as_str(), "synthetic" | "linux" | "windows")
        || proof.pid == 0
        || proof.creation_token.is_empty()
    {
        return Err(WatchdogError::IdentityMismatch(
            "launch ownership proof differs from the original launch intent".to_owned(),
        ));
    }
    Ok(())
}

fn launch_spec_for(
    config: &WatchdogConfig,
    component: &ComponentConfig,
    launch_nonce: String,
    incarnation: String,
) -> Result<crate::platform::LaunchSpec> {
    Ok(crate::platform::LaunchSpec {
        deployment_id: config.deployment_id.clone(),
        instance_id: component.id.clone(),
        component: platform_component_kind(&component.id).or_else(|error| {
            if config.allow_synthetic_children {
                Ok(crate::platform::ComponentKind::Synthetic)
            } else {
                Err(error)
            }
        })?,
        incarnation,
        launch_nonce,
        executable: component.executable.clone(),
        executable_sha256: component
            .executable_sha256
            .clone()
            .unwrap_or_else(|| "0".repeat(64)),
        arguments: component.args.clone(),
        working_directory: component.cwd.clone(),
        environment: component
            .environment
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        // Native watchdog components are service-side background processes;
        // Explicit(0) is deliberately the service session.  This runtime
        // does not launch HostBroker, which would require a separately
        // approved nonzero interactive session.
        session: crate::platform::SessionSelector::Explicit(0),
        graceful_timeout: Duration::from_secs(5),
        force_timeout: Duration::from_secs(10),
    })
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

#[cfg(test)]
#[path = "runtime_stop_uncertainty_tests.rs"]
mod runtime_stop_uncertainty_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{ComponentKind, LaunchSpec, SessionSelector};
    use serde_json::json;

    fn session_spec(session: SessionSelector) -> LaunchSpec {
        LaunchSpec {
            deployment_id: "deployment".to_owned(),
            instance_id: "host-broker".to_owned(),
            component: ComponentKind::HostBroker,
            incarnation: "incarnation-1".to_owned(),
            launch_nonce: "nonce-1".to_owned(),
            executable: std::env::current_exe().expect("test executable"),
            executable_sha256: "a".repeat(64),
            arguments: Vec::new(),
            working_directory: None,
            environment: Vec::new(),
            session,
            graceful_timeout: Duration::from_secs(5),
            force_timeout: Duration::from_secs(10),
        }
    }

    fn bound_intent(specification: &LaunchSpec, containment: &str) -> LaunchIntent {
        LaunchIntent {
            id: "intent-1".to_owned(),
            deployment_id: specification.deployment_id.clone(),
            component_id: specification.instance_id.clone(),
            launch_nonce: specification.launch_nonce.clone(),
            expected_incarnation: Some(specification.incarnation.clone()),
            expected_launch_spec_digest: Some(
                launch_spec_binding_digest(specification, containment)
                    .expect("launch binding digest"),
            ),
            planned_containment_id: Some(containment.to_owned()),
            state: LaunchIntentState::ProofRecorded,
            ownership_proof_json: None,
            created_at_ms: 1,
            updated_at_ms: 1,
        }
    }

    fn windows_proof(
        intent: &LaunchIntent,
        specification: &LaunchSpec,
        containment: &str,
        session_id: Option<u32>,
    ) -> Value {
        json!({
            "version": 1,
            "backend": "windows",
            "intent_id": &intent.id,
            "deployment_id": &intent.deployment_id,
            "instance_id": &specification.instance_id,
            "component": &intent.component_id,
            "incarnation": &specification.incarnation,
            "launch_nonce": &specification.launch_nonce,
            "containment_id": containment,
            "pid": 42,
            "creation_token": "creation-1",
            "executable": &specification.executable,
            "executable_sha256": &specification.executable_sha256,
            "session_id": session_id,
            "started_at_ms": 1,
        })
    }

    #[test]
    fn linux_service_session_requires_absent_platform_session() {
        let mut specification = session_spec(SessionSelector::Explicit(0));
        specification.component = ComponentKind::Gateway;
        let containment = "linux-cgroup:nonce-1";
        let intent = bound_intent(&specification, containment);
        let mut proof = windows_proof(&intent, &specification, containment, None);
        proof["backend"] = json!("linux");
        assert!(
            validate_persisted_launch_binding(
                &intent,
                &specification,
                containment,
                &proof,
                "linux"
            )
            .is_ok()
        );
        for invalid_session in [Some(0), Some(7)] {
            proof["session_id"] = json!(invalid_session);
            assert!(
                validate_persisted_launch_binding(
                    &intent,
                    &specification,
                    containment,
                    &proof,
                    "linux"
                )
                .is_err()
            );
        }
        proof["session_id"] = Value::Null;
        for invalid_selector in [SessionSelector::Explicit(7), SessionSelector::ActiveUser] {
            specification.session = invalid_selector;
            specification.component = ComponentKind::HostBroker;
            let intent = bound_intent(&specification, containment);
            assert!(
                validate_persisted_launch_binding(
                    &intent,
                    &specification,
                    containment,
                    &proof,
                    "linux"
                )
                .is_err()
            );
        }
    }

    #[test]
    fn persisted_proof_cannot_select_synthetic_or_foreign_backend() {
        let mut specification = session_spec(SessionSelector::Explicit(0));
        specification.component = ComponentKind::Gateway;
        let containment = "containment:nonce-1";
        let intent = bound_intent(&specification, containment);
        for expected in ["linux", "windows"] {
            let mut proof = windows_proof(&intent, &specification, containment, None);
            proof["backend"] = json!("synthetic");
            proof["executable_sha256"] = json!("unverified-synthetic");
            assert!(matches!(
                validate_persisted_launch_binding(
                    &intent,
                    &specification,
                    containment,
                    &proof,
                    expected
                ),
                Err(WatchdogError::IdentityMismatch(_))
            ));
            // Native proof relabeling cannot cross the platform boundary either.
            proof["backend"] = json!(if expected == "linux" {
                "windows"
            } else {
                "linux"
            });
            assert!(
                validate_persisted_launch_binding(
                    &intent,
                    &specification,
                    containment,
                    &proof,
                    expected
                )
                .is_err()
            );
        }
    }

    #[test]
    fn synthetic_proof_requires_explicit_synthetic_configuration() {
        let mut specification = session_spec(SessionSelector::Explicit(0));
        specification.component = ComponentKind::Synthetic;
        let containment = "synthetic:nonce-1";
        let intent = bound_intent(&specification, containment);
        let mut proof = windows_proof(&intent, &specification, containment, None);
        proof["backend"] = json!("synthetic");
        proof["executable_sha256"] = json!("unverified-synthetic");
        assert_eq!(expected_runtime_backend(true), "synthetic");
        assert_ne!(expected_runtime_backend(false), "synthetic");
        assert!(
            validate_persisted_launch_binding(
                &intent,
                &specification,
                containment,
                &proof,
                expected_runtime_backend(true)
            )
            .is_ok()
        );
        assert!(
            validate_persisted_launch_binding(
                &intent,
                &specification,
                containment,
                &proof,
                expected_runtime_backend(false)
            )
            .is_err()
        );
    }

    #[test]
    fn active_user_windows_proof_requires_resolved_nonzero_session() {
        let specification = session_spec(SessionSelector::ActiveUser);
        let containment = "windows-job:nonce-1";
        let intent = bound_intent(&specification, containment);
        let valid = windows_proof(&intent, &specification, containment, Some(7));
        assert!(
            validate_persisted_launch_binding(
                &intent,
                &specification,
                containment,
                &valid,
                "windows"
            )
            .is_ok()
        );

        for unresolved in [None, Some(0)] {
            let proof = windows_proof(&intent, &specification, containment, unresolved);
            assert!(matches!(
                validate_persisted_launch_binding(
                    &intent,
                    &specification,
                    containment,
                    &proof,
                    "windows"
                ),
                Err(WatchdogError::IdentityMismatch(_))
            ));
        }
    }

    #[test]
    fn explicit_session_proof_mismatch_is_rejected() {
        let specification = session_spec(SessionSelector::Explicit(7));
        let containment = "windows-job:nonce-1";
        let intent = bound_intent(&specification, containment);
        let matching = windows_proof(&intent, &specification, containment, Some(7));
        assert!(
            validate_persisted_launch_binding(
                &intent,
                &specification,
                containment,
                &matching,
                "windows"
            )
            .is_ok()
        );
        let mismatched = windows_proof(&intent, &specification, containment, Some(8));
        assert!(matches!(
            validate_persisted_launch_binding(
                &intent,
                &specification,
                containment,
                &mismatched,
                "windows"
            ),
            Err(WatchdogError::IdentityMismatch(_))
        ));
    }
}
