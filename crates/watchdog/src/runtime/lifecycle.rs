//! Start, abort and stop component lifecycle.
//!
//! This child module owns the process-effect side of reconciliation: the
//! release activation gate, starting an approved component, aborting a launch
//! whose binding cannot be proven, and stopping an owned child within bounded
//! timeouts.
//!
//! The ordering and uncertainty handling are unchanged: the launch intent and
//! its binding are persisted before any process effect, activation checks run
//! before a spawn is admitted, an unverifiable launch is aborted rather than
//! adopted, and a stop that cannot be confirmed leaves cleanup uncertain
//! instead of reporting success.  `runtime.rs` remains the facade that
//! declares and re-exports this module.

use super::{
    ComponentConfig, ComponentRecord, ComponentState, DesiredMode, ReconcileReport, Result,
    RuntimeChild, RuntimeLaunchError, RuntimeProcessManager, RuntimeStopOutcome, Supervisor, Uuid,
    WatchdogError, component_record, expected_runtime_backend, launch_spec_binding_digest,
    launch_spec_for, runtime_incarnation, validate_persisted_launch_binding,
};

impl Supervisor {
    pub(super) fn release_start_gate(&self) -> std::result::Result<(), String> {
        if self.config.release_catalog.is_none() {
            return Ok(());
        }
        let selection = self
            .store
            .release_selection()
            .map_err(|error| format!("release selector unavailable: {error}"))?;
        let active = selection
            .active
            .ok_or_else(|| "no release has been explicitly activated".to_owned())?;
        let inspection = self
            .inspect_release(&active.release_id)
            .map_err(|error| format!("active release failed protected verification: {error:?}"))?;
        if inspection.manifest_digest != active.release_digest {
            return Err("active release selector digest differs from protected bytes".to_owned());
        }
        if !inspection.compatible {
            return Err("active release is incompatible with current configuration".to_owned());
        }
        Ok(())
    }

    pub(super) fn start_component(
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
        let worker_bootstrap = self.prepare_worker_bootstrap(component, &launch_nonce)?;
        let specification =
            launch_spec_for(&self.config, component, launch_nonce.clone(), incarnation)?;
        let gateway_health = self.prepare_gateway_health(component, &specification)?;
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
        if let Some(worker) = worker_bootstrap.as_ref() {
            self.bind_prepared_worker_bootstrap(component, &intent, worker, now_ms)?;
        }
        if let Some(health) = gateway_health.as_ref() {
            self.bind_prepared_gateway_health(component, &intent, health, now_ms)?;
        }
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
        let mut child = match self.process_manager.launch(
            &self.config,
            component,
            &specification,
            &planned_containment,
            &intent.id,
            now_ms,
            worker_bootstrap.as_ref(),
            gateway_health.as_ref().map(|health| &health.bootstrap),
            &self.worker_boot_id,
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
        child.set_gateway_health_client(gateway_health.map(|health| health.client));
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

    pub(super) fn abort_launched_child(
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

    pub(super) fn stop_component(
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
}
