use ascension_watchdog::worker_bootstrap::{LinuxPeer, WorkerBootstrap};
use ascension_watchdog::{DesiredMode, Store, WatchdogConfig};
use sha2::{Digest, Sha256};
use std::fmt::Write;
use uuid::Uuid;

#[test]
fn migration_audit_failure_rolls_back_the_entire_extension()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = WatchdogConfig {
        database: directory.path().join("state.sqlite"),
        desired_mode: DesiredMode::Stopped,
        ..WatchdogConfig::default()
    };
    let mut store = Store::initialize(&config.database, &config)?;
    let owner = ascension_watchdog::storage::SingletonLock::acquire(&config.database)?;
    let raw = rusqlite::Connection::open(&config.database)?;
    raw.execute_batch("DROP TABLE worker_bootstrap_bindings; DELETE FROM metadata WHERE key='worker_bootstrap_schema'; CREATE TRIGGER reject_bootstrap_migration BEFORE INSERT ON audit WHEN NEW.action='worker_bootstrap_schema_installed' BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;")?;
    assert!(store.migrate_worker_bootstrap(&owner).is_err());
    let tables: i64 = raw.query_row(
        "SELECT count(*) FROM sqlite_master WHERE name IN ('worker_bootstrap_bindings','worker_bootstrap_binding_immutable')", [], |row| row.get(0),
    )?;
    assert_eq!(tables, 0);
    let markers: i64 = raw.query_row(
        "SELECT count(*) FROM metadata WHERE key='worker_bootstrap_schema'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(markers, 0);
    raw.execute_batch("DROP TRIGGER reject_bootstrap_migration;")?;
    store.migrate_worker_bootstrap(&owner)?;
    store.migrate_worker_bootstrap(&owner)?;
    let audits: i64 = raw.query_row(
        "SELECT count(*) FROM audit WHERE action='worker_bootstrap_schema_installed'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(audits, 1);
    Ok(())
}

#[test]
fn migration_rejects_wrong_owner_and_partial_schema() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = WatchdogConfig {
        database: directory.path().join("state.sqlite"),
        desired_mode: DesiredMode::Stopped,
        ..WatchdogConfig::default()
    };
    let mut store = Store::initialize(&config.database, &config)?;
    let wrong_owner =
        ascension_watchdog::storage::SingletonLock::acquire(directory.path().join("other.sqlite"))?;
    assert!(store.migrate_worker_bootstrap(&wrong_owner).is_err());
    let owner = ascension_watchdog::storage::SingletonLock::acquire(&config.database)?;
    let raw = rusqlite::Connection::open(&config.database)?;
    raw.execute(
        "DELETE FROM metadata WHERE key='worker_bootstrap_schema'",
        [],
    )?;
    assert!(store.migrate_worker_bootstrap(&owner).is_err());
    assert!(store.worker_bootstrap_binding("missing").is_err());
    raw.execute(
        "INSERT INTO metadata VALUES ('worker_bootstrap_schema','1')",
        [],
    )?;
    raw.execute_batch("DROP TRIGGER worker_bootstrap_binding_immutable;")?;
    assert!(store.migrate_worker_bootstrap(&owner).is_err());
    assert!(store.worker_bootstrap_binding("missing").is_err());
    raw.execute_batch("CREATE TRIGGER worker_bootstrap_binding_immutable BEFORE UPDATE ON worker_bootstrap_bindings BEGIN SELECT 1; END;")?;
    assert!(store.migrate_worker_bootstrap(&owner).is_err());
    assert!(store.worker_bootstrap_binding("missing").is_err());
    Ok(())
}

#[test]
fn binding_and_audit_are_atomic_and_late_binding_is_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = WatchdogConfig {
        database: directory.path().join("state.sqlite"),
        desired_mode: DesiredMode::Running,
        ..WatchdogConfig::default()
    };
    let mut store = Store::initialize(&config.database, &config)?;
    let nonce = Uuid::new_v4();
    let intent = store.prepare_launch_intent(
        "worker",
        &nonce.to_string(),
        "incarnation",
        &"a".repeat(64),
        None,
        1,
    )?;
    let frame = WorkerBootstrap::linux(
        nonce,
        Uuid::new_v4(),
        "worker",
        LinuxPeer::new(42, "7", "/approved/watchdog", "b".repeat(64), 1000, 1000)?,
    )?;
    let raw = rusqlite::Connection::open(&config.database)?;
    raw.execute_batch("CREATE TRIGGER reject_bootstrap_audit BEFORE INSERT ON audit WHEN NEW.action='worker_bootstrap_bound' BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;")?;
    assert!(store.bind_worker_bootstrap(&intent.id, &frame, 2).is_err());
    assert_eq!(store.worker_bootstrap_binding(&intent.id)?, None);
    raw.execute_batch("DROP TRIGGER reject_bootstrap_audit;")?;
    let binding = store.bind_worker_bootstrap(&intent.id, &frame, 3)?;
    store.bind_worker_bootstrap(&intent.id, &frame, 4)?;
    let count: i64 = raw.query_row(
        "SELECT count(*) FROM audit WHERE action='worker_bootstrap_bound'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);
    assert!(
        raw.execute(
            "UPDATE worker_bootstrap_bindings SET frame_sha256=?",
            [&"c".repeat(64)]
        )
        .is_err()
    );
    store.record_launch_proof(&intent.id, &serde_json::json!({"test": true}), 5)?;
    assert!(store.bind_worker_bootstrap(&intent.id, &frame, 6).is_err());
    assert_eq!(store.worker_bootstrap_binding(&intent.id)?, Some(binding));
    Ok(())
}

#[test]
fn migration_requires_stop_and_never_repairs_a_lost_installed_table()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = WatchdogConfig {
        database: directory.path().join("state.sqlite"),
        desired_mode: DesiredMode::Running,
        ..WatchdogConfig::default()
    };
    let mut store = Store::initialize(&config.database, &config)?;
    let owner = ascension_watchdog::storage::SingletonLock::acquire(&config.database)?;
    let raw = rusqlite::Connection::open(&config.database)?;
    raw.execute_batch("DROP TABLE worker_bootstrap_bindings; DELETE FROM metadata WHERE key='worker_bootstrap_schema';")?;
    assert!(store.worker_bootstrap_binding("missing").is_err());
    assert!(store.migrate_worker_bootstrap(&owner).is_err());
    store.set_desired_mode_at(DesiredMode::Stopped, 2)?;
    store.migrate_worker_bootstrap(&owner)?;
    store.migrate_worker_bootstrap(&owner)?;
    assert_eq!(store.worker_bootstrap_binding("missing")?, None);
    raw.execute_batch("DROP TABLE worker_bootstrap_bindings;")?;
    assert!(store.migrate_worker_bootstrap(&owner).is_err());
    assert!(store.worker_bootstrap_binding("missing").is_err());
    Ok(())
}

#[test]
fn binding_survives_reopen_and_rejects_replacement_and_stop()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = WatchdogConfig {
        database: directory.path().join("state.sqlite"),
        desired_mode: DesiredMode::Running,
        ..WatchdogConfig::default()
    };
    let mut store = Store::initialize(&config.database, &config)?;
    let nonce = Uuid::new_v4();
    let intent = store.prepare_launch_intent(
        "worker",
        &nonce.to_string(),
        "incarnation",
        &"a".repeat(64),
        None,
        1,
    )?;
    let mut frame = WorkerBootstrap::linux(
        nonce,
        Uuid::new_v4(),
        "worker",
        LinuxPeer::new(42, "7", "/approved/watchdog", "b".repeat(64), 1000, 1000)?,
    )?;
    let binding = store.bind_worker_bootstrap(&intent.id, &frame, 2)?;
    let encoded = ascension_watchdog::worker_bootstrap::encode_frame(&frame)?;
    let mut expected_digest = String::with_capacity(64);
    for byte in Sha256::digest(&encoded) {
        write!(&mut expected_digest, "{byte:02x}")?;
    }
    assert_eq!(binding.frame_sha256, expected_digest);
    let original_frame = frame.clone();
    assert_eq!(store.bind_worker_bootstrap(&intent.id, &frame, 3)?, binding);
    drop(store);
    let mut store = Store::open(&config.database, &config)?;
    assert_eq!(
        store.worker_bootstrap_binding(&intent.id)?,
        Some(binding.clone())
    );
    frame.watchdog_boot_id = Uuid::new_v4();
    assert!(store.bind_worker_bootstrap(&intent.id, &frame, 4).is_err());
    frame.component_id = "different-worker".to_owned();
    assert!(store.bind_worker_bootstrap(&intent.id, &frame, 5).is_err());
    store.set_desired_mode_at(DesiredMode::Stopped, 6)?;
    assert!(
        store
            .bind_worker_bootstrap(&intent.id, &original_frame, 7)
            .is_err()
    );
    assert_eq!(store.worker_bootstrap_binding(&intent.id)?, Some(binding));
    Ok(())
}
