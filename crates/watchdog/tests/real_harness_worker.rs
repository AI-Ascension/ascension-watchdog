// SPDX-License-Identifier: MIT

//! Opt-in process-boundary coverage for the native watchdog-to-harness worker.
//!
//! This test is intentionally ignored. It needs an independently built
//! `sts2-harness-runtime` image and a Linux service environment with a
//! delegated cgroup-v2 subtree. The test does not manufacture a worker
//! endpoint or mutate a handoff into a terminal state: it observes the real
//! watchdog child, real worker protocol, and durable admission transition.

#![cfg(target_os = "linux")]

#[path = "support/real_harness_worker_fixture.rs"]
mod real_harness_worker_fixture;
#[path = "support/real_harness_worker_gateway.rs"]
mod real_harness_worker_gateway;
#[path = "support/real_harness_worker_process.rs"]
mod real_harness_worker_process;

use ascension_watchdog::config::{DesiredMode, WatchdogConfig};
use ascension_watchdog::policy::ComponentState;
use ascension_watchdog::storage::{
    JobStatus, Store, WORKER_HANDOFF_OPERATION, WorkerHandoff, WorkerHandoffState,
};
use real_harness_worker_fixture::Fixture;
use real_harness_worker_process::{
    DAEMON_STOP_TIMEOUT, DaemonGuard, unix_now_ms, wait_for_cleanup,
};
use serde_json::json;
use std::io;

const NATIVE_GATE_ENV: &str = "ASCENSION_WATCHDOG_REAL_HARNESS_SMOKE";

#[test]
#[ignore = "requires explicit native cgroup gate, built harness binary, and delegated Linux cgroup-v2"]
fn real_watchdog_native_launch_reaches_built_harness_worker()
-> Result<(), Box<dyn std::error::Error>> {
    require_exact_gate()?;
    let mut fixture = Fixture::from_environment()?;

    // Load the protected config before initialization so the production
    // native launcher receives the same source-path binding as the daemon.
    // The database remains watchdog-owned and separate from the harness
    // execution store.
    let config = WatchdogConfig::from_file(fixture.config_path())?;
    ascension_watchdog::Supervisor::initialize(config.clone())?;
    let mut daemon = DaemonGuard::start(&config, fixture.daemon_image())?;

    let (worker_pid, endpoint) = daemon.wait_for_worker(&config)?;
    let job = {
        let mut store = Store::open(&config.database, &config)?;
        let job = store.submit_job(WORKER_HANDOFF_OPERATION, &json!({}))?;
        drop(store);
        job
    };

    // The helper captures the durable handoff identity before polling its
    // outcome, so an immediate terminal ACK remains inspectable by ID.
    let handoff = daemon.wait_for_dispatch_outcome(&config, &job.id)?;
    assert_eq!(handoff.job_id, job.id);
    let handoff_id = handoff.handoff_id.clone();

    // Stop is a durable operator intent. It is written through a separate
    // owner-local store connection after the worker has accepted the exact
    // handoff. No test helper completes, fails, or clears this row.
    {
        let mut store = Store::open(&config.database, &config)?;
        store.set_desired_mode_at(DesiredMode::Stopped, unix_now_ms())?;
        drop(store);
    }
    daemon.wait_for_successful_exit(DAEMON_STOP_TIMEOUT)?;

    wait_for_cleanup(&config, &endpoint, worker_pid)?;
    let final_store = Store::open_read_only(&config.database, &config)?;
    let final_component = final_store
        .component("harness")?
        .ok_or_else(|| io::Error::other("harness component record disappeared after stop"))?;
    assert_eq!(final_component.state, ComponentState::Stopped);
    assert!(final_component.pid.is_none());
    assert!(final_component.launch_nonce.is_none());
    let retained = final_store
        .worker_handoff(&handoff_id)?
        .ok_or_else(|| io::Error::other("worker handoff disappeared during native stop"))?;
    assert_eq!(retained.job_id, job.id);
    assert_valid_final_handoff(&retained);
    fixture.mark_cleanup_verified();
    Ok(())
}

fn assert_valid_final_handoff(handoff: &WorkerHandoff) {
    match handoff.state {
        // A stop can race the next reconciliation pass. Both an unresolved
        // running row and a validated quarantine are legitimate retained
        // evidence; Store::worker_handoff has already checked their
        // cross-table job/attempt invariants.
        WorkerHandoffState::Admitted => assert!(matches!(
            handoff.job.status,
            JobStatus::Running | JobStatus::Quarantined
        )),
        WorkerHandoffState::Completed
        | WorkerHandoffState::Failed
        | WorkerHandoffState::Acknowledged => {
            assert!(
                handoff.terminal.is_some(),
                "terminal worker handoff is missing its validated receipt"
            );
        }
        WorkerHandoffState::Prepared | WorkerHandoffState::MayHaveBeenDispatched => panic!(
            "worker dispatch did not reach an admitted or validated terminal state: {:?}",
            handoff.state
        ),
        WorkerHandoffState::Rejected => {
            panic!("real worker dispatch was rejected before admission")
        }
    }
}

fn require_exact_gate() -> Result<(), Box<dyn std::error::Error>> {
    match std::env::var(NATIVE_GATE_ENV) {
        Ok(value) if value == "1" => Ok(()),
        Ok(value) => Err(io::Error::other(format!(
            "{NATIVE_GATE_ENV} must be exactly 1, got {value:?}"
        ))
        .into()),
        Err(std::env::VarError::NotPresent) => Err(io::Error::other(format!(
            "{NATIVE_GATE_ENV}=1 is required for the native smoke"
        ))
        .into()),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(io::Error::other(format!("{NATIVE_GATE_ENV} is not valid UTF-8")).into())
        }
    }
}
