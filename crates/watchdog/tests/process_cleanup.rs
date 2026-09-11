#![cfg(target_os = "linux")]

use ascension_watchdog::{ComponentConfig, DesiredMode, Supervisor, WatchdogConfig};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn actual_reconciler_cleans_spawn_when_identity_commit_fails()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = WatchdogConfig {
        database: directory.path().join("state.sqlite"),
        desired_mode: DesiredMode::Running,
        allow_synthetic_children: true,
        components: vec![ComponentConfig {
            id: "synthetic".to_owned(),
            executable: PathBuf::from("/bin/sleep"),
            args: vec!["30".to_owned()],
            cwd: None,
            environment: BTreeMap::new(),
            executable_sha256: None,
            restart: true,
        }],
        ..WatchdogConfig::default()
    };
    let database = config.database.clone();
    let mut supervisor = Supervisor::initialize(config)?;
    let fault = rusqlite::Connection::open(database)?;
    // The real reconciler commits the child PID before its complete identity.
    // Abort only the subsequent identity write. Keep a separate test witness:
    // successful cleanup correctly clears the active component PID.
    fault.execute_batch(
        "CREATE TABLE test_pid_witness(pid INTEGER NOT NULL);
         CREATE TRIGGER test_capture_insert AFTER INSERT ON components
         WHEN NEW.id='synthetic' AND NEW.pid IS NOT NULL
         BEGIN INSERT INTO test_pid_witness VALUES(NEW.pid); END;
         CREATE TRIGGER test_capture_update AFTER UPDATE OF pid ON components
         WHEN NEW.id='synthetic' AND NEW.pid IS NOT NULL
         BEGIN INSERT INTO test_pid_witness VALUES(NEW.pid); END;
         CREATE TRIGGER test_identity_failure BEFORE UPDATE OF identity_json ON components
         WHEN NEW.identity_json IS NOT NULL
         BEGIN SELECT RAISE(ABORT, 'synthetic identity persistence outage'); END;",
    )?;
    assert!(supervisor.reconcile_once(1_000).is_err());
    let pid: u32 = fault.query_row("SELECT pid FROM test_pid_witness LIMIT 1", [], |row| {
        row.get(0)
    })?;
    let still_exists = PathBuf::from(format!("/proc/{pid}")).exists();
    if still_exists {
        // Fault-test safety net only: never leave this test's process alive
        // when running the regression against a broken implementation.
        let _ = std::process::Command::new("/bin/kill")
            .args(["-KILL", &pid.to_string()])
            .status();
    }
    assert!(
        !still_exists,
        "spawned child survived identity commit failure"
    );
    let active_pid: Option<u32> = fault.query_row(
        "SELECT pid FROM components WHERE id='synthetic'",
        [],
        |row| row.get(0),
    )?;
    assert!(
        active_pid.is_none(),
        "cleaned child retained active PID authority"
    );
    Ok(())
}
