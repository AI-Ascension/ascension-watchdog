//! End-to-end-in-the-runtime regressions for uncertain owned-child cleanup.
//!
//! These tests exercise the real [`Supervisor`] launch and stop paths while
//! injecting only the platform stop result.  The injection is compiled only
//! for the unit-test build; production binaries always use the platform
//! authority in `runtime_process`.

#[cfg(windows)]
mod windows_tests {
    use super::super::*;
    use crate::config::{ComponentConfig, WorkerConfig, hex_digest};
    use std::collections::BTreeMap;

    #[test]
    #[ignore = "owned subprocess fixture"]
    fn fixture_child() {
        std::thread::sleep(std::time::Duration::from_secs(30));
    }

    #[test]
    fn identity_rejection_and_stop_timeout_retain_exact_child_for_retry()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let executable = std::env::current_exe()?;
        let digest = hex_digest(&std::fs::read(&executable)?);
        let config = WatchdogConfig {
            database: directory.path().join("watchdog.sqlite"),
            desired_mode: DesiredMode::Running,
            allow_synthetic_children: true,
            components: vec![ComponentConfig {
                id: "harness".to_owned(),
                executable,
                executable_sha256: Some(digest),
                args: vec![
                    "--exact".to_owned(),
                    "runtime::runtime_stop_uncertainty_tests::windows_tests::fixture_child"
                        .to_owned(),
                    "--ignored".to_owned(),
                ],
                cwd: None,
                environment: BTreeMap::from([(
                    "STS2_WORKER_ENDPOINT_NAMESPACE".to_owned(),
                    crate::worker_endpoint::WINDOWS_NAMESPACE.to_owned(),
                )]),
                restart: true,
            }],
            worker: Some(WorkerConfig {
                component_id: "harness".to_owned(),
                endpoint_namespace: std::path::PathBuf::from(
                    crate::worker_endpoint::WINDOWS_NAMESPACE,
                ),
                credential_path: directory.path().join("credential"),
                allowed_peer_sid: None,
                worker_profile_digest: "b".repeat(64),
                release_digest: "c".repeat(64),
                worker_config_digest: "d".repeat(64),
                schema_digest: crate::worker_protocol::SCHEMA_DIGEST.to_owned(),
                timeout_ms: 5000,
            }),
            ..WatchdogConfig::default()
        };
        let mut supervisor = Supervisor::initialize(config)?;
        assert!(matches!(
            supervisor.reconcile_once(1000),
            Err(WatchdogError::IdentityMismatch(_))
        ));
        let identity = supervisor
            .child_identity("harness")
            .ok_or("missing child")?
            .clone();
        supervisor.request_stop(1001)?;
        supervisor
            .process_manager
            .inject_stop_result(Ok(RuntimeStopOutcome::TimedOut));
        let report = supervisor.reconcile_once(1002)?;
        assert!(report.started.is_empty());
        assert!(report.stopped.is_empty());
        assert_eq!(supervisor.child_identity("harness"), Some(&identity));
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.starts_with("worker identity blocked during stop:"))
        );
        let retry = supervisor.reconcile_once(1003)?;
        assert!(retry.started.is_empty());
        assert!(supervisor.child_identity("harness").is_none());
        assert_eq!(supervisor.store.desired_mode()?, DesiredMode::Stopped);
        assert_eq!(
            supervisor
                .store
                .component("harness")?
                .ok_or("missing durable component")?
                .state,
            crate::policy::ComponentState::Stopped,
        );
        assert!(supervisor.store.unsettled_launch_intents()?.is_empty());
        Ok(())
    }
}

#[cfg(unix)]
use super::*;

#[cfg(unix)]
use crate::config::{ComponentConfig, DesiredMode, WatchdogConfig};
#[cfg(unix)]
use crate::process::ensure_identity;
#[cfg(unix)]
use crate::storage::{LaunchIntent, LaunchIntentState, Store};
#[cfg(unix)]
use std::collections::BTreeMap;
#[cfg(unix)]
use std::error::Error;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::process::{Child, Command, Stdio};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::{Duration, Instant};
#[cfg(unix)]
use tempfile::TempDir;

#[cfg(unix)]
const COMPONENT_ID: &str = "synthetic";
#[cfg(unix)]
const ABORT_HELPER_ENV: &str = "ASCENSION_WATCHDOG_STOP_UNCERTAINTY_ABORT_HELPER";
#[cfg(unix)]
const ABORT_CONFIG_ENV: &str = "ASCENSION_WATCHDOG_STOP_UNCERTAINTY_CONFIG";
#[cfg(unix)]
const HELPER_EXIT_CODE: i32 = 91;
#[cfg(unix)]
// Initialization includes synchronous SQLite/WAL schema bootstrap and can be
// delayed by hosted-runner I/O contention. This fixture-only budget is kept
// separate from the measured post-initialization stop phase and does not alter
// any production startup or stop timeout.
const HELPER_INITIALIZATION_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(unix)]
const HELPER_POST_INITIALIZATION_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(unix)]
struct HelperProcessGuard {
    child: Option<Child>,
}

#[cfg(unix)]
impl HelperProcessGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn wait_bounded(
        &mut self,
        deadline: Instant,
    ) -> std::io::Result<Option<std::process::ExitStatus>> {
        loop {
            let Some(child) = self.child.as_mut() else {
                return Ok(None);
            };
            if let Some(status) = child.try_wait()? {
                self.child = None;
                return Ok(Some(status));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(unix)]
impl Drop for HelperProcessGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        // This is the exact Child handle returned by spawn, never a numeric
        // PID lookup. Keep the fallback bounded if the helper failed before
        // reaching its deliberate abrupt exit.
        let _ = child.kill();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => thread::sleep(Duration::from_millis(10)),
            }
        }
    }
}

#[cfg(unix)]
fn config(directory: &TempDir) -> WatchdogConfig {
    WatchdogConfig {
        database: directory.path().join("watchdog.sqlite3"),
        deployment_id: "stop-uncertainty-regression".to_owned(),
        desired_mode: DesiredMode::Running,
        allow_synthetic_children: true,
        components: vec![ComponentConfig {
            id: COMPONENT_ID.to_owned(),
            executable: PathBuf::from("/bin/sleep"),
            // The abrupt-supervisor test intentionally leaves this child to
            // finish naturally.  It is long enough to cover reopen/reconcile
            // while bounded so a failed test cannot leak it indefinitely.
            args: vec!["10".to_owned()],
            cwd: None,
            environment: BTreeMap::new(),
            executable_sha256: None,
            restart: true,
        }],
        ..WatchdogConfig::default()
    }
}

#[cfg(unix)]
fn launch_snapshot(
    supervisor: &Supervisor,
) -> std::result::Result<(crate::process::ProcessIdentity, LaunchIntent), Box<dyn Error>> {
    let identity = supervisor
        .child_identity(COMPONENT_ID)
        .ok_or("supervisor did not retain the launched child")?
        .clone();
    let intents = supervisor.store.unsettled_launch_intents()?;
    if intents.len() != 1 {
        return Err(format!(
            "expected one unsettled launch intent, found {}",
            intents.len()
        )
        .into());
    }
    let intent = intents
        .into_iter()
        .next()
        .ok_or("unsettled launch intent disappeared")?;
    if intent.component_id != COMPONENT_ID || intent.launch_nonce != identity.launch_nonce {
        return Err("launch intent was not bound to the exact child identity".into());
    }
    if intent.state != LaunchIntentState::Active {
        return Err(format!("launched intent was not active: {:?}", intent.state).into());
    }
    Ok((identity, intent))
}

#[cfg(unix)]
fn assert_quarantined_snapshot(
    supervisor: &Supervisor,
    expected_identity: &crate::process::ProcessIdentity,
    expected_intent: &LaunchIntent,
    expected_error: &str,
) -> std::result::Result<String, Box<dyn Error>> {
    let record = supervisor
        .store
        .component(COMPONENT_ID)?
        .ok_or("missing durable component record")?;
    assert_eq!(record.state, ComponentState::Quarantined);
    assert_eq!(
        record.launch_nonce.as_deref(),
        Some(expected_identity.launch_nonce.as_str())
    );
    assert_eq!(record.pid, Some(expected_identity.pid));
    assert_eq!(
        record.executable_digest.as_deref(),
        Some(expected_identity.executable_digest.as_str())
    );
    let observed_error = record
        .last_error
        .clone()
        .ok_or("quarantine record lost its cleanup error")?;
    assert!(
        observed_error.contains(expected_error),
        "quarantine error did not retain {expected_error:?}: {:?}",
        Some(&observed_error)
    );
    assert_eq!(
        supervisor.store.component_identity(COMPONENT_ID)?.as_ref(),
        Some(expected_identity)
    );
    let intents = supervisor.store.unsettled_launch_intents()?;
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0], *expected_intent);
    Ok(observed_error)
}

#[cfg(unix)]
fn assert_running_reconcile_does_not_replace(
    supervisor: &mut Supervisor,
    expected_identity: &crate::process::ProcessIdentity,
    expected_intent: &LaunchIntent,
    expected_error: &str,
    first_now_ms: u64,
) -> std::result::Result<(), Box<dyn Error>> {
    for now_ms in [
        first_now_ms,
        first_now_ms.saturating_add(1),
        first_now_ms.saturating_add(2),
    ] {
        let report = supervisor.reconcile_once(now_ms)?;
        assert!(
            report.started.is_empty(),
            "durable Running reconciliation launched a replacement: {report:?}"
        );
        assert!(report.stopped.is_empty());
        assert_eq!(
            supervisor
                .child_identity(COMPONENT_ID)
                .ok_or("owned child handle was discarded")?,
            expected_identity
        );
        let record = supervisor
            .store
            .component(COMPONENT_ID)?
            .ok_or("missing durable component record")?;
        assert_eq!(
            record.state,
            ComponentState::Quarantined,
            "uncertain cleanup must remain quarantined across durable Running reconciliation"
        );
        assert_eq!(
            record.launch_nonce.as_deref(),
            Some(expected_identity.launch_nonce.as_str())
        );
        assert_eq!(record.pid, Some(expected_identity.pid));
        assert_eq!(record.last_error.as_deref(), Some(expected_error));
        assert_eq!(
            supervisor.store.component_identity(COMPONENT_ID)?.as_ref(),
            Some(expected_identity)
        );
        let intents = supervisor.store.unsettled_launch_intents()?;
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0], *expected_intent);
    }
    Ok(())
}

#[cfg(unix)]
fn assert_reopened_running_does_not_replace(
    supervisor: &mut Supervisor,
    expected_identity: &crate::process::ProcessIdentity,
    expected_intent: &LaunchIntent,
    first_now_ms: u64,
) -> std::result::Result<(), Box<dyn Error>> {
    // Reopening a synthetic proof intentionally normalizes the error to the
    // unreconstructable-authority diagnostic. Capture that first-pass value
    // and require it to remain byte-for-byte stable on every later pass.
    let mut retained_error = None;
    for now_ms in [
        first_now_ms,
        first_now_ms.saturating_add(1),
        first_now_ms.saturating_add(2),
    ] {
        let report = supervisor.reconcile_once(now_ms)?;
        assert!(
            report.started.is_empty(),
            "reopened Running reconciliation launched a replacement: {report:?}"
        );
        assert!(report.stopped.is_empty());
        assert!(
            supervisor.child_identity(COMPONENT_ID).is_none(),
            "synthetic proof recovery manufactured an owned handle"
        );
        let record = supervisor
            .store
            .component(COMPONENT_ID)?
            .ok_or("missing durable component record after reopen")?;
        assert_eq!(record.state, ComponentState::Quarantined);
        assert_eq!(
            record.launch_nonce.as_deref(),
            Some(expected_identity.launch_nonce.as_str())
        );
        assert_eq!(record.pid, Some(expected_identity.pid));
        let current_error = record
            .last_error
            .clone()
            .ok_or("reopened quarantine record lost its cleanup error")?;
        if let Some(expected_error) = retained_error.as_deref() {
            assert_eq!(current_error, expected_error);
        } else {
            retained_error = Some(current_error);
        }
        assert_eq!(
            supervisor.store.component_identity(COMPONENT_ID)?.as_ref(),
            Some(expected_identity)
        );
        let intents = supervisor.store.unsettled_launch_intents()?;
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0], *expected_intent);
    }
    Ok(())
}

#[cfg(unix)]
fn exercise_uncertain_stop(
    stop_result: std::result::Result<RuntimeStopOutcome, String>,
    expected_error: &str,
) -> std::result::Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let config = config(&directory);
    let mut supervisor = Supervisor::initialize(config)?;
    let start_report = supervisor.reconcile_once(1_000)?;
    assert_eq!(
        start_report.started,
        [COMPONENT_ID],
        "initial synthetic launch did not settle: report={start_report:?}; desired_mode={:?}; component={:?}; intents={:?}",
        supervisor.store.desired_mode()?,
        supervisor.store.component(COMPONENT_ID)?,
        supervisor.store.unsettled_launch_intents()?
    );
    let (expected_identity, expected_intent) = launch_snapshot(&supervisor)?;
    ensure_identity(&expected_identity)?;

    supervisor.process_manager.inject_stop_result(stop_result);
    supervisor.request_stop(2_000)?;
    let stop_report = supervisor.reconcile_once(2_001)?;
    assert_eq!(stop_report.desired_mode, DesiredMode::Stopped);
    assert!(stop_report.stopped.is_empty());
    assert_eq!(stop_report.quarantined, [COMPONENT_ID]);
    assert!(
        stop_report
            .errors
            .iter()
            .any(|error| error.contains(expected_error)),
        "stop report did not expose {expected_error:?}: {:?}",
        stop_report.errors
    );
    let expected_error = assert_quarantined_snapshot(
        &supervisor,
        &expected_identity,
        &expected_intent,
        expected_error,
    )?;

    // A later operator Running mode is not permission to discard an owned
    // child whose stop outcome is uncertain. The exact handle, identity, and
    // unsettled launch intent remain the duplicate-launch barrier.
    supervisor
        .store
        .set_desired_mode_at(DesiredMode::Paused, 2_500)?;
    assert_running_reconcile_does_not_replace(
        &mut supervisor,
        &expected_identity,
        &expected_intent,
        &expected_error,
        2_501,
    )?;
    supervisor
        .store
        .set_desired_mode_at(DesiredMode::Running, 3_000)?;
    assert_running_reconcile_does_not_replace(
        &mut supervisor,
        &expected_identity,
        &expected_intent,
        &expected_error,
        3_001,
    )?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn supervisor_stop_timeout_retains_owned_child_and_blocks_running_replacement()
-> std::result::Result<(), Box<dyn Error>> {
    exercise_uncertain_stop(
        Ok(RuntimeStopOutcome::TimedOut),
        "owned containment stop timed out",
    )
}

#[cfg(unix)]
#[test]
fn supervisor_stop_error_retains_owned_child_and_blocks_running_replacement()
-> std::result::Result<(), Box<dyn Error>> {
    exercise_uncertain_stop(
        Err("injected exact stop authority failure".to_owned()),
        "injected exact stop authority failure",
    )
}

#[cfg(unix)]
fn aborting_supervisor_process() -> std::result::Result<(), Box<dyn Error>> {
    let config_path = std::env::var_os(ABORT_CONFIG_ENV).ok_or("missing helper config path")?;
    let stage_path = PathBuf::from(&config_path).with_extension("stage");
    let initialized_path = PathBuf::from(&config_path).with_extension("initialized");
    std::fs::write(&stage_path, "reading-config")?;
    let config = WatchdogConfig::from_file(config_path)?;
    std::fs::write(&stage_path, "initializing-supervisor")?;
    let mut supervisor = Supervisor::initialize(config)?;
    // This marker is intentionally separate from the phase file: later phase
    // writes must not erase a readiness event before the parent observes it.
    std::fs::write(&initialized_path, "supervisor-initialized")?;
    std::fs::write(&stage_path, "launching-child")?;
    let start_report = supervisor.reconcile_once(4_000)?;
    assert_eq!(
        start_report.started,
        [COMPONENT_ID],
        "helper launch report: {start_report:?}"
    );
    std::fs::write(&stage_path, "checking-child-identity")?;
    let (expected_identity, _) = launch_snapshot(&supervisor)?;
    ensure_identity(&expected_identity)?;

    supervisor
        .process_manager
        .inject_stop_result(Ok(RuntimeStopOutcome::TimedOut));
    supervisor.request_stop(5_000)?;
    std::fs::write(&stage_path, "reconciling-stop")?;
    let stop_report = supervisor.reconcile_once(5_001)?;
    std::fs::write(&stage_path, "checking-quarantine")?;
    assert_eq!(stop_report.quarantined, [COMPONENT_ID]);
    let (_, expected_intent) = launch_snapshot(&supervisor)?;
    let _expected_error = assert_quarantined_snapshot(
        &supervisor,
        &expected_identity,
        &expected_intent,
        "owned containment stop timed out",
    )?;
    supervisor
        .store
        .set_desired_mode_at(DesiredMode::Running, 5_002)?;
    std::fs::write(&stage_path, "exiting-abruptly")?;

    // Deliberately bypass Drop. This models the fatal self-abort boundary and
    // leaves the synthetic child alive while the next controller reopens the
    // durable evidence. A distinctive exit code avoids generating an
    // unbounded core dump while still proving destructors did not run.
    std::process::exit(HELPER_EXIT_CODE);
}

#[cfg(unix)]
fn process_still_matches(identity: &crate::process::ProcessIdentity) -> bool {
    ensure_identity(identity).is_ok()
}

#[cfg(unix)]
fn read_helper_phase(path: &std::path::Path) -> String {
    use std::io::Read;
    let mut phase = String::new();
    if let Ok(file) = std::fs::File::open(path) {
        let _ = file.take(128).read_to_string(&mut phase);
    }
    phase
}

#[cfg(unix)]
fn wait_for_helper_initialization(
    initialized_path: &std::path::Path,
    stage_path: &std::path::Path,
    deadline: Instant,
) -> std::result::Result<(), Box<dyn Error>> {
    loop {
        if read_helper_phase(initialized_path) == "supervisor-initialized" {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let phase = read_helper_phase(stage_path);
            return Err(format!(
                "abrupt supervisor helper did not finish initialization before its bounded fixture deadline; phase={phase:?}"
            )
            .into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
#[test]
fn abrupt_supervisor_exit_reopens_uncertainty_without_replacement()
-> std::result::Result<(), Box<dyn Error>> {
    if std::env::var_os(ABORT_HELPER_ENV).is_some() {
        return aborting_supervisor_process();
    }

    let directory = tempfile::tempdir()?;
    let config = config(&directory);
    let config_path = directory.path().join("watchdog.json");
    let initialized_path = config_path.with_extension("initialized");
    let stage_path = config_path.with_extension("stage");
    config.to_file(&config_path)?;
    let helper = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "runtime::runtime_stop_uncertainty_tests::abrupt_supervisor_exit_reopens_uncertainty_without_replacement",
            "--nocapture",
        ])
        .env(ABORT_HELPER_ENV, "1")
        .env(ABORT_CONFIG_ENV, &config_path)
        // No output is needed for this fixed exit-witness helper. Avoid
        // buffering unbounded test output in the parent process.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut helper = HelperProcessGuard::new(helper);
    wait_for_helper_initialization(
        &initialized_path,
        &stage_path,
        Instant::now() + HELPER_INITIALIZATION_TIMEOUT,
    )?;
    let Some(helper_status) =
        helper.wait_bounded(Instant::now() + HELPER_POST_INITIALIZATION_TIMEOUT)?
    else {
        // This file contains only fixed fixture phase labels. Bound the
        // diagnostic read even if a failing fixture writes unexpected data.
        use std::io::Read;
        let mut stage = String::new();
        if let Ok(file) = std::fs::File::open(config_path.with_extension("stage")) {
            let _ = file.take(128).read_to_string(&mut stage);
        }
        return Err(format!(
            "abrupt supervisor helper exceeded its five-second deadline; phase={stage:?}"
        )
        .into());
    };
    assert!(
        helper_status.code() == Some(HELPER_EXIT_CODE),
        "fatal helper did not return the deliberate abrupt-exit code: {helper_status:?}"
    );

    let before = Store::open_read_only(&config.database, &config)?;
    let before_record = before
        .component(COMPONENT_ID)?
        .ok_or("helper did not persist a component record")?;
    assert_eq!(before_record.state, ComponentState::Quarantined);
    let before_identity = before
        .component_identity(COMPONENT_ID)?
        .ok_or("helper did not persist an exact process identity")?;
    ensure_identity(&before_identity)?;
    let before_intents = before.unsettled_launch_intents()?;
    assert_eq!(before_intents.len(), 1);
    let before_intent = before_intents
        .into_iter()
        .next()
        .ok_or("helper launch intent disappeared")?;
    assert_eq!(before_intent.state, LaunchIntentState::Active);

    let mut reopened = Supervisor::open(config.clone())?;
    let before_error = before_record
        .last_error
        .clone()
        .ok_or("helper quarantine record lost its cleanup error")?;
    assert!(before_error.contains("owned containment stop timed out"));
    assert_reopened_running_does_not_replace(
        &mut reopened,
        &before_identity,
        &before_intent,
        6_000,
    )?;
    assert!(
        reopened.child_identity(COMPONENT_ID).is_none(),
        "synthetic proof recovery unexpectedly manufactured an owned handle"
    );
    let after = reopened
        .store
        .component(COMPONENT_ID)?
        .ok_or("missing reopened record")?;
    assert_eq!(after.state, ComponentState::Quarantined);
    assert_eq!(
        reopened.store.component_identity(COMPONENT_ID)?.as_ref(),
        Some(&before_identity)
    );
    assert_eq!(reopened.store.unsettled_launch_intents()?, [before_intent]);

    // No PID kill is used here: the helper's finite synthetic child is allowed
    // to exit naturally. Bound the wait so a broken child cannot hang the
    // regression indefinitely.
    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline && process_still_matches(&before_identity) {
        thread::sleep(Duration::from_millis(25));
    }
    assert!(
        !process_still_matches(&before_identity),
        "abrupt helper child did not finish within the bounded natural-exit window"
    );
    Ok(())
}
