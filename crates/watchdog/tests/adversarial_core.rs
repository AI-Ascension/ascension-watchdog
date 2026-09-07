//! Safety regressions for the watchdog's durable supervision boundaries.
//!
//! These tests intentionally assert the required safe postconditions.  They
//! are expected to fail on the pre-repair baseline; a failure is evidence of a
//! safety regression, not a reason to weaken an assertion or ignore the test.

#[cfg(unix)]
use ascension_watchdog::config::ComponentConfig;
use ascension_watchdog::config::{DesiredMode, WatchdogConfig};
use ascension_watchdog::policy::{
    ComponentObservation, ComponentState, ReconcileAction, SupervisorPolicy,
};
#[cfg(unix)]
use ascension_watchdog::process::OwnedChild;
#[cfg(unix)]
use ascension_watchdog::runtime::Supervisor;
use ascension_watchdog::storage::Store;
use rusqlite::Connection;
use std::path::PathBuf;
#[cfg(unix)]
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[cfg(unix)]
use std::collections::BTreeMap;
#[cfg(unix)]
use std::process::Command;
#[cfg(unix)]
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
#[cfg(unix)]
use std::thread;

fn config(temp: &TempDir) -> WatchdogConfig {
    WatchdogConfig {
        database: temp.path().join("watchdog.sqlite3"),
        deployment_id: "adversarial-deployment".to_string(),
        desired_mode: DesiredMode::Running,
        allow_synthetic_children: true,
        ..WatchdogConfig::default()
    }
}

#[cfg(unix)]
fn sleep_component(id: &str) -> ComponentConfig {
    ComponentConfig {
        id: id.to_string(),
        executable: PathBuf::from("/bin/sleep"),
        args: vec!["30".to_string()],
        cwd: None,
        environment: BTreeMap::new(),
        executable_sha256: None,
        restart: true,
    }
}

#[cfg(unix)]
fn shell_component(id: &str, command: &str) -> ComponentConfig {
    ComponentConfig {
        id: id.to_string(),
        executable: PathBuf::from("/bin/sh"),
        args: vec!["-c".to_string(), command.to_string()],
        cwd: None,
        environment: BTreeMap::new(),
        executable_sha256: None,
        restart: true,
    }
}

#[cfg(unix)]
fn process_exists(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .is_ok_and(|status| status.success())
}

/// Cleanup for only PIDs created by this test.  This is a test safety net for
/// the intentionally failing baseline assertions; it never uses names or
/// wildcard process matching and prevents a failed test from leaking children.
#[cfg(unix)]
struct ExactProcessCleanup {
    pids: Vec<u32>,
}

#[cfg(unix)]
impl Drop for ExactProcessCleanup {
    fn drop(&mut self) {
        for pid in &self.pids {
            let _ = Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .status();
        }
    }
}

/// A persisted live child must be cleaned through its exact identity after a
/// controller restart and durable stop.  A quarantined in-memory row is not a
/// stopped deployment, and `run_until_stopped` must not return while this PID
/// is still alive.
#[test]
#[cfg(unix)]
fn persisted_live_child_is_cleaned_before_stop_reports_success() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut config = config(&temp);
    config.components = vec![sleep_component("synthetic")];
    let mut first = Supervisor::initialize(config.clone()).expect("initialize");
    first.reconcile_once(1_000).expect("start");
    let pid = first.child_identity("synthetic").expect("identity").pid;
    let _cleanup = ExactProcessCleanup { pids: vec![pid] };
    assert!(process_exists(pid));

    // A dropped controller models a crash: no ordinary Drop cleanup may be
    // assumed to have happened before the replacement controller starts.
    drop(first);
    {
        let mut store = Store::open(&config.database, &config).expect("store");
        store
            .set_desired_mode_at(DesiredMode::Stopped, 2_000)
            .expect("durable stop");
    }
    let mut reopened = Supervisor::open(config).expect("reopen");
    let report = reopened.reconcile_once(2_001).expect("stop reconcile");
    assert_eq!(report.desired_mode, DesiredMode::Stopped);
    assert!(
        !process_exists(pid),
        "stop reported success while exact persisted child {pid} remained alive"
    );
}

/// A failure to persist launch identity after a successful spawn must not drop
/// a live child.  The missing component row models the post-spawn persistence
/// error that occurs in `Supervisor::start_component` after the effect.
#[test]
#[cfg(unix)]
fn post_spawn_persistence_failure_cleans_the_child_before_returning() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = config(&temp);
    let mut store = Store::initialize(&config.database, &config).expect("initialize");
    let component = sleep_component("synthetic");
    let child = OwnedChild::spawn(&component, 1_000).expect("spawn synthetic child");
    let pid = child.identity().pid;
    let _cleanup = ExactProcessCleanup { pids: vec![pid] };
    let identity = child.identity().clone();
    let persistence_error = store.persist_component_identity("missing", &identity, 1_001);
    assert!(
        persistence_error.is_err(),
        "synthetic persistence failure was not injected"
    );
    drop(child);
    assert!(
        !process_exists(pid),
        "child {pid} remained alive after launch identity persistence failed"
    );
}

/// A process that is alive but has no fresh heartbeat/progress witness must be
/// suspected.  Liveness alone is not control-loop health.
#[test]
fn stale_health_witnesses_are_not_reported_as_running() {
    let config = WatchdogConfig {
        database: PathBuf::from("/tmp/adversarial-policy.sqlite3"),
        ..WatchdogConfig::default()
    };
    let policy = SupervisorPolicy::from_config(&config);
    let observation = ComponentObservation {
        component_id: "gateway".to_string(),
        state: ComponentState::Running,
        observed_at_ms: 1,
        heartbeat_age_ms: Some(u64::MAX),
        progress_age_ms: Some(u64::MAX),
        consecutive_misses: 0,
        restart_attempts: 0,
    };
    let decision = policy.decide(DesiredMode::Running, true, &observation, 2, 0, None);
    assert_eq!(decision.action, ReconcileAction::MarkSuspect);
    assert_eq!(decision.resulting_state, ComponentState::Suspect);
}

/// Restart budgets must remain conservative across an adjusted wall clock. A
/// forward jump is not proof that the old restart events have aged out.
#[test]
fn restart_budget_does_not_reset_after_wall_clock_jump() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = config(&temp);
    let mut store = Store::initialize(&config.database, &config).expect("initialize");
    for now in 1_000..1_005 {
        store
            .record_restart("gateway", now, 600_000)
            .expect("record restart");
    }
    let jumped = store.restart_count("gateway", 1_000_000_000, 600_000);
    if let Ok(count) = jumped {
        assert!(
            count >= 5,
            "wall-clock jump discarded restart budget history ({count} events remain)"
        );
    }
    // A fail-closed clock-discontinuity error is also safe; silently returning
    // zero is not.
}

/// Read-only inspection must never create an empty replacement database when
/// the path disappears between existence checking and opening. The writer
/// thread only renames this test's own temporary database.
#[test]
#[cfg(unix)]
fn read_only_open_never_creates_state_in_exists_open_race() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = config(&temp);
    let store = Store::initialize(&config.database, &config).expect("initialize");
    drop(store);
    let valid_path = config.database.clone();
    let hidden_path = temp.path().join("watchdog.sqlite3.hidden");
    let found_empty_database = Arc::new(AtomicBool::new(false));
    let writer_found = Arc::clone(&found_empty_database);
    let writer = thread::spawn(move || {
        for _ in 0..500 {
            if std::fs::rename(&valid_path, &hidden_path).is_err() {
                continue;
            }
            thread::sleep(Duration::from_micros(100));
            if let Ok(metadata) = std::fs::metadata(&valid_path)
                && metadata.len() == 0
            {
                writer_found.store(true, Ordering::SeqCst);
                let _ = std::fs::remove_file(&valid_path);
            }
            if std::fs::rename(&hidden_path, &valid_path).is_err() {
                if !valid_path.exists() {
                    let _ = std::fs::copy(&hidden_path, &valid_path);
                }
                let _ = std::fs::remove_file(&hidden_path);
            }
            if writer_found.load(Ordering::SeqCst) {
                break;
            }
        }
    });
    let mut readers = Vec::new();
    for _ in 0..4 {
        let path = config.database.clone();
        let reader_config = config.clone();
        readers.push(thread::spawn(move || {
            for _ in 0..2_500 {
                let _ = Store::open(&path, &reader_config);
            }
        }));
    }
    for reader in readers {
        reader.join().expect("reader");
    }
    writer.join().expect("writer");
    assert!(
        !found_empty_database.load(Ordering::SeqCst),
        "read-only inspection created an empty database during path replacement"
    );
    assert!(config.database.is_file(), "test database was not restored");
}

/// Terminating an owned process must contain its descendants and close all
/// inherited output pipes; direct-child termination is insufficient.
#[test]
#[cfg(unix)]
fn terminating_owned_child_cleans_background_descendants() {
    let temp = tempfile::tempdir().expect("tempdir");
    let pid_file = temp.path().join("grandchild.pid");
    let command = format!("sleep 30 & echo $! > {}; wait", pid_file.display());
    let component = shell_component("synthetic", &command);
    let mut child = OwnedChild::spawn(&component, 1_000).expect("spawn");
    let mut cleanup = ExactProcessCleanup {
        pids: vec![child.identity().pid],
    };
    let mut grandchild = None;
    for _ in 0..100 {
        if let Ok(text) = std::fs::read_to_string(&pid_file)
            && let Ok(pid) = text.trim().parse::<u32>()
        {
            grandchild = Some(pid);
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let grandchild = grandchild.expect("grandchild pid");
    cleanup.pids.push(grandchild);
    let termination = child.terminate(Duration::from_millis(100));
    assert!(
        termination.is_ok(),
        "owned direct child did not terminate: {termination:?}"
    );
    assert!(
        !process_exists(grandchild),
        "background descendant {grandchild} survived owned-child termination"
    );
}

/// A direct parent can exit while a descendant retains the inherited output
/// pipes.  The exact process-group authority must still clean that descendant
/// when terminate is called after the parent has exited, without waiting
/// indefinitely for the reader threads.
#[test]
#[cfg(unix)]
fn terminate_after_parent_exit_cleans_group_and_bounded_pipes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let pid_file = temp.path().join("parent-exit-grandchild.pid");
    let command = format!("sleep 30 & echo $! > {}; exit 0", pid_file.display());
    let component = shell_component("synthetic-parent-exit", &command);
    let mut child = OwnedChild::spawn(&component, 1_000).expect("spawn");
    let mut cleanup = ExactProcessCleanup { pids: Vec::new() };
    let grandchild = wait_for_pid_file(&pid_file);
    cleanup.pids.push(grandchild);
    let parent_exit_deadline = Instant::now() + Duration::from_secs(2);
    while child.is_running().expect("inspect parent") {
        assert!(
            Instant::now() < parent_exit_deadline,
            "direct parent did not exit before the bounded test deadline"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let started = Instant::now();
    let termination = child.terminate(Duration::from_millis(100));
    assert!(
        termination.is_ok(),
        "post-parent-exit exact cleanup failed: {termination:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "post-parent-exit cleanup waited unboundedly on inherited output pipes"
    );
    assert!(
        !process_exists(grandchild),
        "grandchild {grandchild} survived exact group cleanup"
    );
}

/// Drop is also an ownership boundary.  If the direct parent has already
/// exited, dropping `OwnedChild` must still terminate the exact group rather
/// than only attempting a stale direct PID cleanup.
#[test]
#[cfg(unix)]
fn drop_after_parent_exit_cleans_exact_group() {
    let temp = tempfile::tempdir().expect("tempdir");
    let pid_file = temp.path().join("drop-grandchild.pid");
    let command = format!("sleep 30 & echo $! > {}; exit 0", pid_file.display());
    let component = shell_component("synthetic-drop-parent-exit", &command);
    let grandchild;
    let mut cleanup = ExactProcessCleanup { pids: Vec::new() };
    {
        let mut child = OwnedChild::spawn(&component, 1_000).expect("spawn");
        grandchild = wait_for_pid_file(&pid_file);
        cleanup.pids.push(grandchild);
        let parent_exit_deadline = Instant::now() + Duration::from_secs(2);
        while child.is_running().expect("inspect parent") {
            assert!(
                Instant::now() < parent_exit_deadline,
                "direct parent did not exit before the bounded test deadline"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
    let cleanup_deadline = Instant::now() + Duration::from_secs(2);
    while process_exists(grandchild) && Instant::now() < cleanup_deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !process_exists(grandchild),
        "Drop left exact descendant {grandchild} alive after parent exit"
    );
}

#[cfg(unix)]
fn wait_for_pid_file(path: &std::path::Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Ok(pid) = text.trim().parse::<u32>()
        {
            return pid;
        }
        assert!(
            Instant::now() < deadline,
            "descendant PID file was not written before the bounded test deadline"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

/// Restore must not reactivate a stale Running intent or silently combine a
/// backup from one deployment with another deployment's configuration. An
/// explicit rejection is safe; an accepted restore must be stopped and
/// identity-consistent before any autonomous launch.
#[test]
fn restore_requires_stopped_identity_consistent_state() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut original = config(&temp);
    original.desired_mode = DesiredMode::Running;
    let mut store = Store::initialize(&original.database, &original).expect("initialize");
    let backup = temp.path().join("backup.sqlite3");
    store.backup_to(&backup).expect("backup");
    store
        .set_desired_mode_at(DesiredMode::Stopped, 2_000)
        .expect("stop source after backup");

    let same_path = temp.path().join("restored-same.sqlite3");
    let mut same_config = original.clone();
    same_config.database = same_path;
    let same_safe = match Store::restore_from(&backup, &same_config.database, &same_config) {
        Err(_) => true,
        Ok(restored) => {
            let status = restored.status().expect("restored status");
            status.desired_mode == DesiredMode::Stopped
                && status.deployment_id == same_config.deployment_id
        }
    };

    let cross_path = temp.path().join("restored-cross.sqlite3");
    let mut cross_config = original;
    cross_config.database = cross_path;
    cross_config.deployment_id = "other-deployment".to_string();
    let cross_safe = match Store::restore_from(&backup, &cross_config.database, &cross_config) {
        Err(_) => true,
        Ok(restored) => {
            let status = restored.status().expect("cross-restored status");
            status.desired_mode == DesiredMode::Stopped
                && status.deployment_id == cross_config.deployment_id
        }
    };
    assert!(same_safe, "restore reactivated stale Running intent");
    assert!(
        cross_safe,
        "restore mixed backup and requested deployment identity"
    );
}

/// Malformed durable metadata must block status/admission instead of being
/// converted to a plausible zero/default value.
#[test]
fn corrupt_metadata_is_reported_instead_of_defaulted() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = config(&temp);
    let store = Store::initialize(&config.database, &config).expect("initialize");
    drop(store);
    let conn = Connection::open(&config.database).expect("raw connection");
    conn.execute(
        "UPDATE metadata SET value='not-a-number' WHERE key='restart_generation'",
        [],
    )
    .expect("corrupt restart generation");
    drop(conn);
    let status = Store::open(&config.database, &config).and_then(|opened| opened.status());
    assert!(
        status.is_err(),
        "corrupt restart_generation was silently reported as a valid zero"
    );
}
