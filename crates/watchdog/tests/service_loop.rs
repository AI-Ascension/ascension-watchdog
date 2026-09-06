use ascension_watchdog::admin::MainLoopPhase;
use ascension_watchdog::service::ServiceLoop;
use ascension_watchdog::{DesiredMode, Supervisor, WatchdogConfig};
use std::time::Duration;

#[test]
fn completed_paused_loop_advances_health_without_starting_children()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = WatchdogConfig {
        database: directory.path().join("state.sqlite"),
        desired_mode: DesiredMode::Paused,
        ..WatchdogConfig::default()
    };
    let supervisor = Supervisor::initialize(config)?;
    let mut service = ServiceLoop::new(supervisor, Duration::from_millis(20))?;
    let health = service.health();
    assert!(!health.snapshot().ready);
    assert_eq!(health.snapshot().heartbeat_seq, 0);
    let report = service.reconcile(1_000)?;
    assert!(report.started.is_empty());
    assert_eq!(health.snapshot().phase, MainLoopPhase::Paused);
    assert!(health.snapshot().ready);
    assert_eq!(health.snapshot().heartbeat_seq, 1);
    // Reading health is not progress.
    for _ in 0..10 {
        assert_eq!(health.snapshot().heartbeat_seq, 1);
    }
    service.reconcile(1_020)?;
    assert_eq!(health.snapshot().heartbeat_seq, 2);
    Ok(())
}

#[test]
fn failed_controller_ownership_never_reports_ready() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = WatchdogConfig {
        database: directory.path().join("state.sqlite"),
        ..WatchdogConfig::default()
    };
    let _owner = Supervisor::initialize(config.clone())?;
    let competing = Supervisor::open(config)?;
    let mut service = ServiceLoop::new(competing, Duration::from_millis(20))?;
    assert!(service.reconcile(1_000).is_err());
    let health = service.health().snapshot();
    assert!(!health.ready);
    assert_eq!(health.heartbeat_seq, 0);
    assert_eq!(health.phase, MainLoopPhase::Blocked);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn actual_daemon_notifies_only_after_reconciliation_and_marks_stop()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::net::UnixDatagram;
    use std::process::Command;
    let directory = tempfile::tempdir()?;
    let config_path = directory.path().join("config.json");
    let notify_path = directory.path().join("notify.sock");
    let config = WatchdogConfig {
        database: directory.path().join("state.sqlite"),
        desired_mode: DesiredMode::Stopped,
        ..WatchdogConfig::default()
    };
    config.to_file(&config_path)?;
    drop(Supervisor::initialize(config)?);
    let receiver = UnixDatagram::bind(&notify_path)?;
    receiver.set_read_timeout(Some(Duration::from_secs(5)))?;
    let output = Command::new(env!("CARGO_BIN_EXE_watchdog"))
        .args(["daemon", "--config"])
        .arg(config_path)
        .env("NOTIFY_SOCKET", notify_path)
        .env("WATCHDOG_USEC", "30000000")
        .output()?;
    assert!(output.status.success(), "{:?}", output.stderr);
    let mut bytes = [0_u8; 4096];
    let length = receiver.recv(&mut bytes)?;
    let message = std::str::from_utf8(&bytes[..length])?;
    assert!(message.contains("READY=1\n"));
    assert!(message.contains("WATCHDOG=1\n"));
    assert!(message.contains("watchdog_loop=Stopped;progress_sequence=1"));
    let length = receiver.recv(&mut bytes)?;
    assert_eq!(&bytes[..length], b"STOPPING=1\n");
    Ok(())
}

#[test]
fn persistence_failure_cannot_advance_completed_loop_health()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = WatchdogConfig {
        database: directory.path().join("state.sqlite"),
        desired_mode: DesiredMode::Paused,
        ..WatchdogConfig::default()
    };
    let fault_connection = config.database.clone();
    let supervisor = Supervisor::initialize(config)?;
    let mut service = ServiceLoop::new(supervisor, Duration::from_millis(20))?;
    service.reconcile(1_000)?;
    let fault = rusqlite::Connection::open(fault_connection)?;
    fault.execute_batch(
        "CREATE TRIGGER test_fail_audit BEFORE INSERT ON audit
         BEGIN SELECT RAISE(ABORT, 'test persistence outage'); END;",
    )?;
    assert!(service.reconcile(1_020).is_err());
    let health = service.health().snapshot();
    assert_eq!(health.heartbeat_seq, 1);
    assert_eq!(health.phase, MainLoopPhase::Blocked);
    assert!(!health.ready);
    Ok(())
}
