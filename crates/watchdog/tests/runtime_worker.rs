// SPDX-License-Identifier: MIT

//! Supervisor-level worker-phase gates.
//!
//! These tests deliberately do not stand up a pretend worker endpoint.  A
//! worker claim is only meaningful with the real child/server integration;
//! this file covers the owner/session and durable drain barriers that can be
//! proven without manufacturing native process authority.

use ascension_watchdog::Supervisor;
use ascension_watchdog::config::{
    ComponentConfig, DesiredMode, WatchdogConfig, WorkerConfig, hex_digest,
};
use ascension_watchdog::service::ServiceLoop;
use ascension_watchdog::storage::{
    Store, WORKER_HANDOFF_OPERATION, WORKER_HANDOFF_PAYLOAD_DIGEST, WORKER_HANDOFF_SCHEMA_DIGEST,
    WorkerClaimWitness, WorkerControlMode, WorkerControlWitness,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use tempfile::TempDir;
use uuid::Uuid;

const WATCHDOG_BOOT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const WORKER_BOOT: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

fn worker_config(temp: &TempDir, desired_mode: DesiredMode) -> WatchdogConfig {
    let root = temp.path();
    let executable = synthetic_executable();
    let executable_digest = hex_digest(&std::fs::read(&executable).expect("synthetic executable"));
    WatchdogConfig {
        database: root.join("watchdog.sqlite"),
        desired_mode,
        allow_synthetic_children: true,
        components: vec![
            ComponentConfig {
                id: "harness".to_owned(),
                executable: executable.clone(),
                args: vec!["30".to_owned()],
                cwd: None,
                environment: BTreeMap::new(),
                executable_sha256: Some(executable_digest.clone()),
                restart: true,
            },
            ComponentConfig {
                id: "gateway".to_owned(),
                executable,
                args: vec!["30".to_owned()],
                cwd: None,
                environment: BTreeMap::new(),
                executable_sha256: Some(executable_digest),
                restart: true,
            },
        ],
        worker: Some(WorkerConfig {
            component_id: "harness".to_owned(),
            endpoint: root.join("worker.sock"),
            credential_path: root.join("worker.token"),
            allowed_peer_sid: None,
            worker_profile_digest: "b".repeat(64),
            release_digest: "c".repeat(64),
            worker_config_digest: "d".repeat(64),
            schema_digest: WORKER_HANDOFF_SCHEMA_DIGEST.to_owned(),
            timeout_ms: 5000,
        }),
        ..WatchdogConfig::default()
    }
}

fn synthetic_executable() -> PathBuf {
    if cfg!(target_os = "windows") {
        PathBuf::from(r"C:\Windows\System32\timeout.exe")
    } else {
        PathBuf::from("/bin/sleep")
    }
}

fn seed_pending_handoff(config: &WatchdogConfig) -> Result<(), Box<dyn std::error::Error>> {
    let binding = config.worker_binding()?.expect("worker binding");
    let mut store = Store::initialize(&config.database, config)?;
    store.configure_worker_binding_at(&binding, 1)?;
    store.set_worker_control_at(
        &WorkerControlWitness {
            deployment_id: binding.deployment_id.clone(),
            worker_owner_id: binding.worker_owner_id.clone(),
            worker_profile_digest: binding.worker_profile_digest.clone(),
            watchdog_boot_id: WATCHDOG_BOOT.to_owned(),
            worker_boot_id: WORKER_BOOT.to_owned(),
            mode: WorkerControlMode::Running,
            mode_sequence: 1,
        },
        2,
    )?;
    store.submit_job_at(WORKER_HANDOFF_OPERATION, &json!({}), 3)?;
    let witness = WorkerClaimWitness {
        deployment_id: binding.deployment_id,
        worker_owner_id: binding.worker_owner_id,
        worker_profile_digest: binding.worker_profile_digest,
        release_digest: binding.release_digest,
        config_digest: binding.config_digest,
        schema_digest: binding.schema_digest,
        watchdog_boot_id: WATCHDOG_BOOT.to_owned(),
        worker_boot_id: WORKER_BOOT.to_owned(),
        mode_sequence: 1,
    };
    let pending = store
        .claim_next_worker_handoff(&witness, 4)?
        .expect("ready job should become a prepared handoff");
    assert_eq!(pending.payload_digest, WORKER_HANDOFF_PAYLOAD_DIGEST);
    assert_eq!(
        pending.state,
        ascension_watchdog::storage::WorkerHandoffState::Prepared
    );
    store.set_desired_mode_at(DesiredMode::Draining, 5)?;
    Ok(())
}

#[test]
fn supervisor_boot_identity_is_one_fresh_uuid_per_instance()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let config = WatchdogConfig {
        database: temp.path().join("watchdog.sqlite"),
        ..WatchdogConfig::default()
    };
    let mut first = Supervisor::initialize(config.clone())?;
    let first_boot = first.worker_boot_id().to_owned();
    assert_eq!(Uuid::parse_str(&first_boot)?.get_version_num(), 4);
    first.reconcile_once(1_000)?;
    assert_eq!(first.worker_boot_id(), first_boot);
    drop(first);

    let reopened = Supervisor::open(config)?;
    assert_ne!(reopened.worker_boot_id(), first_boot);
    assert_eq!(
        Uuid::parse_str(reopened.worker_boot_id())?.get_version_num(),
        4
    );
    Ok(())
}

#[test]
fn configured_worker_without_live_child_does_not_create_control_or_claim()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let config = worker_config(&temp, DesiredMode::Paused);
    let mut supervisor = Supervisor::initialize(config.clone())?;
    let report = supervisor.reconcile_once(1_000)?;

    assert!(report.started.is_empty());
    assert!(supervisor.child_identity("harness").is_none());
    let store = Store::open_read_only(&config.database, &config)?;
    assert!(store.current_worker_control()?.is_none());
    assert!(store.current_worker_claim_witness()?.is_none());
    Ok(())
}

#[test]
fn draining_keeps_pending_handoff_barrier_without_live_child()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let running_config = worker_config(&temp, DesiredMode::Running);
    seed_pending_handoff(&running_config)?;

    // The config digest intentionally remains the Running-config digest: the
    // durable desired mode is an operator-controlled mutable field, while the
    // immutable configuration identity remains unchanged across that update.
    let mut supervisor = Supervisor::open(running_config.clone())?;
    let report = supervisor.reconcile_once(6)?;
    assert_eq!(report.desired_mode, DesiredMode::Draining);
    assert_eq!(supervisor.status()?.desired_mode, DesiredMode::Draining);
    assert!(supervisor.child_identity("harness").is_none());
    let store = Store::open_read_only(&running_config.database, &running_config)?;
    assert!(store.next_worker_handoff_for_reconciliation()?.is_some());
    Ok(())
}

fn assert_missing_worker_endpoint_does_not_abort_stop(
    config: WatchdogConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    std::fs::set_permissions(
        config.database.parent().expect("database parent"),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    std::fs::write(
        config
            .worker
            .as_ref()
            .expect("worker config")
            .credential_path
            .clone(),
        b"worker-test-credential",
    )?;
    #[cfg(unix)]
    std::fs::set_permissions(
        config
            .worker
            .as_ref()
            .expect("worker config")
            .credential_path
            .clone(),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )?;

    let database = config.database.clone();
    let mut service = ServiceLoop::new(
        Supervisor::initialize(config.clone())?,
        std::time::Duration::from_millis(1),
    )?;
    let first = service.reconcile(1_000)?;
    assert!(first.started.iter().any(|id| id == "harness"));
    assert!(first.started.iter().any(|id| id == "gateway"));
    assert!(
        first
            .errors
            .iter()
            .any(|error| error.starts_with("worker phase probe:")),
        "missing endpoint must be visible as a bounded worker-phase diagnostic"
    );
    assert!(service.health().snapshot().ready);
    let running = Store::open_read_only(&database, &config)?;
    for id in ["harness", "gateway"] {
        let record = running.component(id)?.expect("component record");
        assert_eq!(
            record.state,
            ascension_watchdog::policy::ComponentState::Running
        );
        assert!(record.pid.is_some(), "{id} must have a live owned identity");
    }

    // Change only the durable operator intent through a second owner-local
    // SQLite connection. The ServiceLoop remains the sole process-cleanup
    // authority and must still run its stop path after the worker outage.
    let mut intent = Store::open(&database, &config)?;
    intent.set_desired_mode_at(DesiredMode::Stopped, 1_001)?;
    drop(intent);
    let stopped = service.reconcile(1_002)?;
    assert!(stopped.started.is_empty());
    assert!(stopped.stopped.iter().any(|id| id == "harness"));
    assert!(stopped.stopped.iter().any(|id| id == "gateway"));

    let settled = service.reconcile(1_003)?;
    assert!(settled.started.is_empty());
    assert!(settled.errors.is_empty());
    let read_only = Store::open_read_only(&database, &config)?;
    for id in ["harness", "gateway"] {
        let record = read_only.component(id)?.expect("component record");
        assert_eq!(
            record.state,
            ascension_watchdog::policy::ComponentState::Stopped
        );
        assert!(record.pid.is_none());
        assert!(record.launch_nonce.is_none());
    }
    Ok(())
}

#[test]
fn missing_worker_endpoint_does_not_abort_loop_or_skip_owned_stop_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    assert_missing_worker_endpoint_does_not_abort_stop(worker_config(&temp, DesiredMode::Running))
}

#[cfg(unix)]
#[test]
fn unready_worker_socket_does_not_abort_loop_or_skip_owned_stop_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let config = worker_config(&temp, DesiredMode::Running);
    let endpoint = config
        .worker
        .as_ref()
        .expect("worker config")
        .endpoint
        .clone();
    let listener = std::os::unix::net::UnixListener::bind(&endpoint)?;
    drop(listener);
    assert_missing_worker_endpoint_does_not_abort_stop(config)
}

#[test]
fn durable_claim_persistence_failure_cannot_create_a_worker_handoff()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let config = worker_config(&temp, DesiredMode::Running);
    let binding = config.worker_binding()?.expect("worker binding");
    let mut store = Store::initialize(&config.database, &config)?;
    store.configure_worker_binding_at(&binding, 1)?;
    store.set_worker_control_at(
        &WorkerControlWitness {
            deployment_id: binding.deployment_id.clone(),
            worker_owner_id: binding.worker_owner_id.clone(),
            worker_profile_digest: binding.worker_profile_digest.clone(),
            watchdog_boot_id: WATCHDOG_BOOT.to_owned(),
            worker_boot_id: WORKER_BOOT.to_owned(),
            mode: WorkerControlMode::Running,
            mode_sequence: 1,
        },
        2,
    )?;
    let job = store.submit_job_at(WORKER_HANDOFF_OPERATION, &json!({}), 3)?;
    let fault = rusqlite::Connection::open(&config.database)?;
    fault.execute_batch(
        "CREATE TRIGGER reject_worker_handoff_insert
         BEFORE INSERT ON worker_handoffs
         BEGIN SELECT RAISE(ABORT, 'worker handoff persistence outage'); END;",
    )?;
    let witness = ascension_watchdog::storage::WorkerClaimWitness {
        deployment_id: binding.deployment_id,
        worker_owner_id: binding.worker_owner_id,
        worker_profile_digest: binding.worker_profile_digest,
        release_digest: binding.release_digest,
        config_digest: binding.config_digest,
        schema_digest: binding.schema_digest,
        watchdog_boot_id: WATCHDOG_BOOT.to_owned(),
        worker_boot_id: WORKER_BOOT.to_owned(),
        mode_sequence: 1,
    };
    assert!(store.claim_next_worker_handoff(&witness, 4).is_err());
    let handoffs: i64 =
        fault.query_row("SELECT COUNT(*) FROM worker_handoffs", [], |row| row.get(0))?;
    assert_eq!(handoffs, 0);
    let job_after = store.get_job(&job.id)?.expect("job after failed claim");
    assert_eq!(
        job_after.status,
        ascension_watchdog::storage::JobStatus::Queued
    );
    assert_eq!(job_after.attempt_count, 0);
    Ok(())
}
