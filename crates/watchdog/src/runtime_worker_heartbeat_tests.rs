// SPDX-License-Identifier: MIT

//! Linux-only tests for the private worker-heartbeat witness seam.
//!
//! These tests use the explicitly synthetic `/bin/sleep` child authority. They
//! cover only the in-memory witness contract; transport integration is outside
//! this module.

use super::super::{Supervisor, WorkerHeartbeatWitness};
use crate::config::{ComponentConfig, DesiredMode, WatchdogConfig, hex_digest};
use crate::error::{Result, WatchdogError};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

const COMPONENT_ID: &str = "harness";
const WORKER_BOOT: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

fn synthetic_config(database: PathBuf) -> Result<WatchdogConfig> {
    let executable = PathBuf::from("/bin/sleep");
    let digest = hex_digest(&std::fs::read(&executable)?);
    Ok(WatchdogConfig {
        database,
        desired_mode: DesiredMode::Running,
        allow_synthetic_children: true,
        components: vec![ComponentConfig {
            id: COMPONENT_ID.to_owned(),
            executable,
            args: vec!["30".to_owned()],
            cwd: None,
            environment: BTreeMap::new(),
            executable_sha256: Some(digest),
            restart: true,
        }],
        ..WatchdogConfig::default()
    })
}

fn started_supervisor() -> Result<(tempfile::TempDir, Supervisor)> {
    let temp = tempfile::tempdir()?;
    let config = synthetic_config(temp.path().join("watchdog.sqlite"))?;
    let mut supervisor = Supervisor::initialize(config)?;
    supervisor.reconcile_once(1_000)?;
    Ok((temp, supervisor))
}

fn stop_supervisor(supervisor: &mut Supervisor) -> Result<()> {
    supervisor.request_stop(2_000)?;
    let report = supervisor.reconcile_once(2_001)?;
    assert!(report.stopped.iter().any(|id| id == COMPONENT_ID));
    assert!(supervisor.child_identity(COMPONENT_ID).is_none());
    Ok(())
}

#[test]
fn heartbeat_capture_rejects_when_no_child_is_owned() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let config = synthetic_config(temp.path().join("watchdog.sqlite"))?;
    let mut supervisor = Supervisor::initialize(config)?;
    let error = supervisor
        .capture_worker_heartbeat(COMPONENT_ID, WORKER_BOOT, Instant::now())
        .expect_err("a missing child cannot supply a worker witness");
    assert!(matches!(error, WatchdogError::IdentityMismatch(_)));
    assert!(supervisor.worker_heartbeat.is_none());
    Ok(())
}

#[test]
fn heartbeat_witness_is_bound_to_current_child_and_boot() -> Result<()> {
    let (_temp, mut supervisor) = started_supervisor()?;
    let identity = supervisor
        .child_identity(COMPONENT_ID)
        .ok_or_else(|| WatchdogError::Conflict("test child was not started".to_owned()))?
        .clone();
    supervisor.capture_worker_heartbeat(COMPONENT_ID, WORKER_BOOT, Instant::now())?;
    assert!(supervisor.worker_heartbeat_matches_current(COMPONENT_ID, WORKER_BOOT));
    assert!(supervisor.worker_heartbeat_age_ms(COMPONENT_ID).is_some());
    supervisor
        .worker_heartbeat
        .as_mut()
        .ok_or_else(|| WatchdogError::Conflict("witness was not captured".to_owned()))?
        .identity
        .launch_nonce = format!("stale-{}", identity.launch_nonce);
    assert!(!supervisor.worker_heartbeat_matches_current(COMPONENT_ID, WORKER_BOOT));
    assert!(supervisor.worker_heartbeat_age_ms(COMPONENT_ID).is_none());
    supervisor.worker_heartbeat = Some(WorkerHeartbeatWitness {
        component_id: COMPONENT_ID.to_owned(),
        identity,
        worker_boot_id: WORKER_BOOT.to_owned(),
        observed_at: Instant::now(),
    });
    assert!(
        !supervisor
            .worker_heartbeat_matches_current(COMPONENT_ID, "cccccccc-cccc-4ccc-8ccc-cccccccccccc")
    );
    supervisor.clear_worker_heartbeat();
    assert!(supervisor.worker_heartbeat.is_none());
    stop_supervisor(&mut supervisor)
}

#[test]
fn heartbeat_witness_rejects_wrong_launch_nonce() -> Result<()> {
    let (_temp, mut supervisor) = started_supervisor()?;
    let identity = supervisor
        .child_identity(COMPONENT_ID)
        .ok_or_else(|| WatchdogError::Conflict("test child was not started".to_owned()))?
        .clone();
    supervisor.capture_worker_heartbeat(COMPONENT_ID, WORKER_BOOT, Instant::now())?;
    supervisor
        .worker_heartbeat
        .as_mut()
        .ok_or_else(|| WatchdogError::Conflict("witness was not captured".to_owned()))?
        .identity
        .launch_nonce = format!("stale-{}", identity.launch_nonce);
    assert!(!supervisor.worker_heartbeat_matches_current(COMPONENT_ID, WORKER_BOOT));
    assert!(supervisor.worker_heartbeat_age_ms(COMPONENT_ID).is_none());
    stop_supervisor(&mut supervisor)
}

#[test]
fn heartbeat_witness_rejects_wrong_worker_boot() -> Result<()> {
    let (_temp, mut supervisor) = started_supervisor()?;
    supervisor.capture_worker_heartbeat(COMPONENT_ID, WORKER_BOOT, Instant::now())?;
    assert!(supervisor.worker_heartbeat_matches_current(COMPONENT_ID, WORKER_BOOT));
    assert!(
        !supervisor
            .worker_heartbeat_matches_current(COMPONENT_ID, "cccccccc-cccc-4ccc-8ccc-cccccccccccc")
    );
    stop_supervisor(&mut supervisor)
}

#[test]
fn reconcile_resets_worker_heartbeat_before_each_pass() -> Result<()> {
    let (_temp, mut supervisor) = started_supervisor()?;
    supervisor.capture_worker_heartbeat(COMPONENT_ID, WORKER_BOOT, Instant::now())?;
    assert!(supervisor.worker_heartbeat.is_some());
    let report = supervisor.reconcile_once(1_001)?;
    assert_eq!(
        report.decisions[0].resulting_state,
        crate::policy::ComponentState::Suspect
    );
    assert!(supervisor.worker_heartbeat.is_none());
    stop_supervisor(&mut supervisor)
}
