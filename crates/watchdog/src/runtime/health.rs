//! Component health, policy decisions and quarantine.
//!
//! This child module owns the per-component reconciliation decision, the
//! authenticated worker heartbeat age that feeds it, and the quarantine
//! bookkeeping used whenever health, retry or launch decisions must be
//! withheld.
//!
//! The guarantees are unchanged.  Health and retry decisions stay explicit
//! and ordered, a retained quarantined child keeps its exact owned identity,
//! and missing or unauthenticated telemetry never grants authority: it yields
//! the missing-heartbeat quarantine path rather than a restart.  `runtime.rs`
//! remains the facade that declares and re-exports this module.

use super::{
    ComponentConfig, ComponentObservation, ComponentRecord, ComponentState, DesiredMode,
    ReconcileAction, ReconcileDecision, ReconcileReport, Result, RuntimeChild, RuntimeObservation,
    RuntimeStopOutcome, Supervisor,
};

impl Supervisor {
    pub(super) fn quarantine_component(
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

    pub(super) fn retain_quarantined_child(
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

    pub(super) fn reconcile_component(
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

        self.probe_gateway_health(component, desired_mode, report);
        let prior = self.store.component(&component.id)?;
        let is_running = self.children.contains_key(&component.id);
        let mut observation = ComponentObservation {
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
            heartbeat_age_ms: self
                .worker_heartbeat_age_ms(&component.id)
                .or_else(|| self.gateway_heartbeat_age_ms(&component.id)),
            progress_age_ms: None,
            consecutive_misses: 0,
            restart_attempts: prior.as_ref().map_or(0, |record| record.restart_attempts),
        };
        let restart_count = self.store.restart_count(
            &component.id,
            now_ms,
            self.config.restart_budget_window_secs.saturating_mul(1_000),
        )?;
        // A configured release catalog is an admission boundary, not merely
        // an inspection aid.  Do not launch any component until the exact
        // protected release identity has been durably activated.  A blocked
        // component becomes eligible again after that selector is activated;
        // no process or authority is reused across the boundary.
        if desired_mode == DesiredMode::Running && !is_running {
            if let Err(reason) = self.release_start_gate() {
                let prior = self.store.component(&component.id)?;
                self.store.upsert_component(
                    &ComponentRecord {
                        id: component.id.clone(),
                        state: ComponentState::Blocked,
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
                        last_error: Some(reason.clone()),
                    },
                    now_ms,
                )?;
                self.store.audit(
                    "component_launch_blocked_release",
                    &format!("{}:{reason}", component.id),
                    now_ms,
                )?;
                return Ok(ReconcileDecision {
                    component_id: component.id.clone(),
                    action: ReconcileAction::Wait,
                    resulting_state: ComponentState::Blocked,
                    reason,
                    retry_at_ms: None,
                });
            }
            if prior
                .as_ref()
                .is_some_and(|record| record.state == ComponentState::Blocked)
            {
                // The only automatic release from this blocked state is a
                // fresh protected selector check above. Treat the old marker
                // as stopped so the normal restart budget and launch-intent
                // admission still apply.
                observation.state = ComponentState::Stopped;
            }
        }
        let mut decision = self.policy.decide(
            desired_mode,
            component.restart,
            &observation,
            now_ms,
            restart_count,
            prior.as_ref().and_then(|record| record.last_restart_at_ms),
        );
        if is_running && decision.action == ReconcileAction::Start {
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
                        last_error: Some(decision.reason.clone()),
                    },
                    now_ms,
                )?;
                report.quarantined.push(component.id.clone());
            }
            ReconcileAction::Wait | ReconcileAction::Noop | ReconcileAction::MarkSuspect => {
                // A durable quarantine is not cleared by a passive pass.  The
                // owned-but-unsettled child still reports `Running` to the
                // observation layer, so a `Paused` (or stale-heartbeat
                // `Running`) pass must not re-stamp the record: doing so
                // erases both the `Quarantined` state and the cleanup reason
                // that explains why no replacement was launched.
                let quarantined = prior
                    .as_ref()
                    .is_some_and(|record| record.state == ComponentState::Quarantined);
                let state = if quarantined {
                    ComponentState::Quarantined
                } else if desired_mode == DesiredMode::Paused {
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
                            last_error: if quarantined {
                                prior.as_ref().and_then(|record| record.last_error.clone())
                            } else {
                                None
                            },
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

    /// Return the monotonic age of the authenticated worker proof for this
    /// exact currently-owned child.  A missing or mismatched proof remains
    /// `None`, preserving the policy's missing-heartbeat quarantine behavior.
    pub(super) fn worker_heartbeat_age_ms(&self, component_id: &str) -> Option<u64> {
        let witness = self.worker_heartbeat.as_ref()?;
        let child = self.children.get(component_id)?;
        if witness.component_id != component_id
            || witness.identity.launch_nonce != child.identity().launch_nonce
            || witness.identity != *child.identity()
        {
            return None;
        }
        u64::try_from(witness.observed_at.elapsed().as_millis()).ok()
    }
}
