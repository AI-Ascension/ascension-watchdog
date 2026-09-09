//! Fresh durable admission immediately before resuming a Windows worker.
//!
//! The platform boundary owns handles and bounded pipe delivery. This module
//! owns config, schema, frame digest, and prepared-intent authorization. It
//! grants no authority from an endpoint or a caller-provided frame alone.

use crate::config::{DesiredMode, WatchdogConfig};
use crate::error::{Result, WatchdogError};
use crate::platform::LaunchSpec;
use crate::storage::{LaunchIntentState, Store};
use crate::worker_bootstrap::{ExpectedPeer, WorkerBootstrapLaunch};
use std::time::Instant;

pub(super) fn authorize(
    config: &WatchdogConfig,
    specification: &LaunchSpec,
    planned: &str,
    worker: &WorkerBootstrapLaunch,
    deadline: Instant,
) -> Result<Store> {
    check_deadline(deadline)?;
    let source = config.source_path.as_ref().ok_or_else(|| {
        WatchdogError::Unauthorized(
            "native worker requires a protected source configuration".to_owned(),
        )
    })?;
    let current = WatchdogConfig::from_file(source)?;
    check_deadline(deadline)?;
    if current.digest()? != config.digest()? || current.allow_synthetic_children {
        return Err(WatchdogError::IdentityMismatch(
            "worker launch configuration changed before resumption".to_owned(),
        ));
    }
    let store = Store::open(&current.database, &current)?.reserve_launch_admission()?;
    check_deadline(deadline)?;
    authorize_stored(&current, &store, specification, planned, worker)?;
    check_deadline(deadline)?;
    Ok(store)
}

fn authorize_stored(
    config: &WatchdogConfig,
    store: &Store,
    specification: &LaunchSpec,
    planned: &str,
    worker: &WorkerBootstrapLaunch,
) -> Result<()> {
    let status = store.status()?;
    if status.desired_mode != DesiredMode::Running {
        return Err(WatchdogError::Unauthorized(
            "durable running intent was revoked before worker resumption".to_owned(),
        ));
    }
    let component = config
        .components
        .iter()
        .find(|component| {
            component.id == specification.instance_id
                && config
                    .worker
                    .as_ref()
                    .is_some_and(|worker| worker.component_id == component.id)
        })
        .ok_or_else(|| {
            WatchdogError::IdentityMismatch("worker component is not approved".to_owned())
        })?;
    let frame = worker.bootstrap();
    let expected = super::launch_spec_for(
        config,
        component,
        specification.launch_nonce.clone(),
        super::runtime_incarnation(status.restart_generation)?,
    )?;
    if specification != &expected
        || planned != format!("windows-job:{}", specification.launch_nonce)
        || frame.component_id != component.id
        || frame.launch_nonce.to_string() != specification.launch_nonce
        || !matches!(frame.expected_peer, ExpectedPeer::Windows(_))
    {
        return Err(WatchdogError::IdentityMismatch(
            "worker frame or specification differs from its approved launch".to_owned(),
        ));
    }
    let digest = super::launch_spec_binding_digest(specification, planned)?;
    let intents = store.launch_admission_intents(&component.id)?;
    if intents.len() != 1 {
        return Err(WatchdogError::IdentityMismatch(
            "worker component must have exactly one unsettled launch intent".to_owned(),
        ));
    }
    let matches = intents
        .iter()
        .filter(|intent| {
            intent.deployment_id == status.deployment_id
                && intent.component_id == component.id
                && intent.launch_nonce == specification.launch_nonce
                && intent.planned_containment_id.as_deref() == Some(planned)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1
        || matches[0].state != LaunchIntentState::Prepared
        || matches[0].expected_incarnation.as_deref() != Some(specification.incarnation.as_str())
        || matches[0].expected_launch_spec_digest.as_deref() != Some(digest.as_str())
    {
        return Err(WatchdogError::IdentityMismatch(
            "worker has no exact prepared durable launch intent".to_owned(),
        ));
    }
    let binding = store.worker_bootstrap_binding(&matches[0].id)?;
    if !binding.is_some_and(|binding| {
        binding.watchdog_boot_id == frame.watchdog_boot_id.to_string()
            && binding.frame_sha256 == worker.frame_sha256()
    }) {
        return Err(WatchdogError::IdentityMismatch(
            "worker bootstrap differs from the prepared durable binding".to_owned(),
        ));
    }
    let final_status = store.status()?;
    if final_status.desired_mode != DesiredMode::Running
        || final_status.restart_generation != status.restart_generation
    {
        return Err(WatchdogError::Unauthorized(
            "worker authority changed during pre-resume admission".to_owned(),
        ));
    }
    Ok(())
}

fn check_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(WatchdogError::Timeout(
            "worker pre-resume admission deadline elapsed".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::config::{ComponentConfig, WorkerConfig};
    use crate::worker_bootstrap::{WindowsPeer, WorkerBootstrap};
    use std::collections::BTreeMap;
    use std::time::Duration;
    use uuid::Uuid;

    fn fixture(
        root: &std::path::Path,
    ) -> Result<(
        WatchdogConfig,
        Store,
        LaunchSpec,
        String,
        WorkerBootstrapLaunch,
    )> {
        let namespace = root.join("ipc");
        let mut config = WatchdogConfig {
            database: root.join("state.sqlite"),
            desired_mode: DesiredMode::Running,
            components: vec![ComponentConfig {
                id: "harness".to_owned(),
                executable: root.join("harness"),
                args: Vec::new(),
                cwd: None,
                environment: BTreeMap::from([(
                    "STS2_WORKER_ENDPOINT_NAMESPACE".to_owned(),
                    namespace.to_string_lossy().into_owned(),
                )]),
                executable_sha256: Some("a".repeat(64)),
                restart: true,
            }],
            worker: Some(WorkerConfig {
                component_id: "harness".to_owned(),
                endpoint_namespace: namespace,
                credential_path: root.join("credential"),
                allowed_peer_sid: None,
                worker_profile_digest: "b".repeat(64),
                release_digest: "c".repeat(64),
                worker_config_digest: "d".repeat(64),
                schema_digest: crate::worker_protocol::SCHEMA_DIGEST.to_owned(),
                timeout_ms: 5000,
            }),
            ..WatchdogConfig::default()
        };
        let source = root.join("watchdog.json");
        config.to_file(&source)?;
        config.source_path = Some(source);
        let mut store = Store::initialize(&config.database, &config)?;
        let nonce = Uuid::new_v4();
        let spec = super::super::launch_spec_for(
            &config,
            &config.components[0],
            nonce.to_string(),
            super::super::runtime_incarnation(store.status()?.restart_generation)?,
        )?;
        let planned = format!("windows-job:{nonce}");
        let digest = super::super::launch_spec_binding_digest(&spec, &planned)?;
        let intent = store.prepare_launch_intent(
            "harness",
            &nonce.to_string(),
            &spec.incarnation,
            &digest,
            Some(&planned),
            1,
        )?;
        let frame = WorkerBootstrap::windows(
            nonce,
            Uuid::new_v4(),
            "harness",
            WindowsPeer::new(
                42,
                "7",
                r"C:\approved\watchdog.exe",
                "e".repeat(64),
                0,
                "S-1-5-18",
            )
            .map_err(|error| WatchdogError::InvalidInput(error.to_string()))?,
        )
        .map_err(|error| WatchdogError::InvalidInput(error.to_string()))?;
        store.bind_worker_bootstrap(&intent.id, &frame, 2)?;
        let worker = WorkerBootstrapLaunch::new(frame)
            .map_err(|error| WatchdogError::InvalidInput(error.to_string()))?;
        Ok((config, store, spec, planned, worker))
    }

    #[test]
    fn pre_resume_requires_current_running_prepared_exact_frame_and_configuration() -> Result<()> {
        let root = tempfile::tempdir()?;
        let (config, mut store, spec, planned, worker) = fixture(root.path())?;
        let deadline = Instant::now() + Duration::from_secs(5);
        authorize(&config, &spec, &planned, &worker, deadline)?;
        let mut changed_spec = spec.clone();
        changed_spec.arguments.push("changed".to_owned());
        assert!(authorize(&config, &changed_spec, &planned, &worker, deadline).is_err());
        assert!(authorize(&config, &spec, "windows-job:wrong", &worker, deadline).is_err());
        let mut changed_frame = worker.bootstrap().clone();
        changed_frame.watchdog_boot_id = Uuid::new_v4();
        let changed_frame = WorkerBootstrapLaunch::new(changed_frame)
            .map_err(|error| WatchdogError::InvalidInput(error.to_string()))?;
        assert!(authorize(&config, &spec, &planned, &changed_frame, deadline).is_err());
        assert!(authorize(&config, &spec, &planned, &worker, Instant::now()).is_err());
        store.set_desired_mode_at(DesiredMode::Stopped, 3)?;
        assert!(authorize(&config, &spec, &planned, &worker, deadline).is_err());
        store.set_desired_mode_at(DesiredMode::Running, 4)?;
        let intent = store.unsettled_launch_intents()?.remove(0);
        store.clean_launch_intent(&intent.id, 5)?;
        assert!(authorize(&config, &spec, &planned, &worker, deadline).is_err());
        Ok(())
    }

    #[test]
    fn admission_rejects_a_second_component_intent_even_without_unique_index() -> Result<()> {
        let root = tempfile::tempdir()?;
        let (config, _store, spec, planned, worker) = fixture(root.path())?;
        let connection = rusqlite::Connection::open(&config.database)?;
        connection.execute_batch(
            "DROP INDEX launch_intents_one_unsettled_component_idx;
             INSERT INTO launch_intents
             SELECT 'conflicting-intent', deployment_id, component_id,
                    'different-nonce', expected_incarnation, expected_launch_spec_digest,
                    planned_containment_id, state, ownership_proof_json,
                    created_at_ms, updated_at_ms FROM launch_intents LIMIT 1;",
        )?;
        let error = authorize(
            &config,
            &spec,
            &planned,
            &worker,
            Instant::now() + Duration::from_secs(5),
        )
        .expect_err("a conflicting component intent must block admission");
        assert!(
            error
                .to_string()
                .contains("exactly one unsettled launch intent")
        );
        Ok(())
    }

    #[test]
    fn admission_reservation_serializes_operator_stop_until_guard_drop() -> Result<()> {
        let root = tempfile::tempdir()?;
        let (config, mut operator, spec, planned, worker) = fixture(root.path())?;
        let guard = authorize(
            &config,
            &spec,
            &planned,
            &worker,
            Instant::now() + Duration::from_secs(5),
        )?;
        assert!(
            operator
                .set_desired_mode_at(DesiredMode::Stopped, 3)
                .is_err()
        );
        assert_eq!(operator.status()?.desired_mode, DesiredMode::Running);
        drop(guard);
        operator.set_desired_mode_at(DesiredMode::Stopped, 4)?;
        assert!(
            authorize(
                &config,
                &spec,
                &planned,
                &worker,
                Instant::now() + Duration::from_secs(5),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn pre_resume_rejects_changed_or_missing_source_configuration() -> Result<()> {
        let root = tempfile::tempdir()?;
        let (mut config, _store, spec, planned, worker) = fixture(root.path())?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut changed = config.clone();
        changed.components[0].args.push("changed".to_owned());
        changed.to_file(
            config
                .source_path
                .as_ref()
                .ok_or_else(|| WatchdogError::InvalidInput("missing test source".to_owned()))?,
        )?;
        assert!(authorize(&config, &spec, &planned, &worker, deadline).is_err());
        config.source_path = None;
        assert!(authorize(&config, &spec, &planned, &worker, deadline).is_err());
        Ok(())
    }
}
