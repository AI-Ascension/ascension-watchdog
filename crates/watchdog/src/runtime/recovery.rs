//! Persisted launch and identity recovery.
//!
//! This child module owns the two recovery passes that run before any new
//! launch effect in the first reconciliation: reconstructing an owned handle
//! for a proof-recorded native launch intent, and fencing identities left by
//! an earlier controller generation.
//!
//! The guarantees are unchanged.  An unknown launch outcome is retained and
//! quarantined rather than guessed: a legacy or unbound intent, a planned
//! containment whose cleanup is uncertain, a proof that fails its original
//! binding, or an ambiguous platform authority all end in a durable
//! quarantine instead of a PID-only cleanup or a replacement launch.  The
//! identity pass never adopts a live orphan into a new `Child` handle and
//! clears a stale identity only after its creation fingerprint proves the
//! process is gone.  `runtime.rs` remains the facade that declares and
//! re-exports this module.

use super::{
    ComponentRecord, ComponentState, DesiredMode, LaunchIntentState, ReconcileReport, Result,
    RuntimeObservation, RuntimeProcessManager, RuntimeStopOutcome, Supervisor, WatchdogError,
    ensure_identity, expected_runtime_backend, launch_spec_for, validate_persisted_launch_binding,
};

impl Supervisor {
    /// Reconcile launch intents before looking at legacy component rows.  A
    /// proof-recorded/active native intent is the only durable route by which
    /// a restarted supervisor may reconstruct an owned process handle.
    #[allow(clippy::if_not_else)]
    pub(super) fn reconcile_persisted_launch_intents(&mut self, now_ms: u64) -> Result<()> {
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
            if self
                .config
                .worker
                .as_ref()
                .is_some_and(|worker| worker.component_id == component.id)
            {
                self.retire_recovered_worker(&component, &intent, child, now_ms)?;
                continue;
            }
            if self
                .config
                .gateway_health
                .as_ref()
                .is_some_and(|health| health.component_id == component.id)
            {
                // Health keys and sequence state cannot be restored. A recovered
                // native handle is exact cleanup authority only, never a new
                // authenticated health session for a surviving gateway.
                self.retain_quarantined_child(
                    &component,
                    &intent.id,
                    child,
                    "recovered gateway has no current in-memory health key".to_owned(),
                    now_ms,
                )?;
                self.stop_component(&component, now_ms, &mut ReconcileReport::default())?;
                continue;
            }
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
    pub(super) fn reconcile_persisted_identities(&mut self, now_ms: u64) -> Result<()> {
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
}
