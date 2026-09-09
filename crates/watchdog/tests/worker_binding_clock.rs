//! Clock rollback and immutable worker-binding storage regressions.

use ascension_watchdog::WatchdogConfig;
use ascension_watchdog::error::WatchdogError;
use ascension_watchdog::storage::{Store, WORKER_HANDOFF_SCHEMA_DIGEST, WorkerBinding};
use rusqlite::Connection;
use std::path::Path;
use tempfile::TempDir;

#[derive(Debug, Eq, PartialEq)]
struct BindingSnapshot {
    deployment_id: String,
    worker_owner_id: String,
    worker_profile_digest: String,
    release_digest: String,
    config_digest: String,
    schema_digest: String,
    updated_at_ms: i64,
    audit: Vec<(String, String, i64)>,
}

fn fixture() -> Result<(TempDir, WatchdogConfig, Store, WorkerBinding), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let config = WatchdogConfig {
        database: directory.path().join("watchdog.sqlite3"),
        deployment_id: "binding-clock".to_owned(),
        ..WatchdogConfig::default()
    };
    let binding = WorkerBinding {
        deployment_id: config.deployment_id.clone(),
        worker_owner_id: "harness-worker".to_owned(),
        worker_profile_digest: "a".repeat(64),
        release_digest: "b".repeat(64),
        config_digest: "c".repeat(64),
        schema_digest: WORKER_HANDOFF_SCHEMA_DIGEST.to_owned(),
    };
    let store = Store::initialize(&config.database, &config)?;
    Ok((directory, config, store, binding))
}

fn snapshot(path: &Path) -> Result<BindingSnapshot, Box<dyn std::error::Error>> {
    let connection = Connection::open(path)?;
    let binding = connection.query_row(
        "SELECT deployment_id, worker_owner_id, worker_profile_digest, release_digest, config_digest, schema_digest, updated_at_ms FROM worker_bindings WHERE singleton=1",
        [],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
            ))
        },
    )?;
    let mut statement =
        connection.prepare("SELECT action, detail, occurred_at_ms FROM audit ORDER BY id")?;
    let audit = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(BindingSnapshot {
        deployment_id: binding.0,
        worker_owner_id: binding.1,
        worker_profile_digest: binding.2,
        release_digest: binding.3,
        config_digest: binding.4,
        schema_digest: binding.5,
        updated_at_ms: binding.6,
        audit,
    })
}

#[test]
fn exact_binding_reconfiguration_is_a_noop_across_clock_rollback_and_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, config, mut store, binding) = fixture()?;
    store.configure_worker_binding_at(&binding, 100)?;
    let original = snapshot(&config.database)?;
    assert_eq!(original.updated_at_ms, 100);

    store.configure_worker_binding_at(&binding, 200)?;
    assert_eq!(snapshot(&config.database)?, original);
    store.configure_worker_binding_at(&binding, 50)?;
    assert_eq!(snapshot(&config.database)?, original);

    drop(store);
    let mut reopened = Store::open(&config.database, &config)?;
    reopened.configure_worker_binding_at(&binding, 75)?;
    assert_eq!(snapshot(&config.database)?, original);
    Ok(())
}

#[test]
fn changed_binding_fields_reject_even_when_the_clock_moves_backwards()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, config, mut store, binding) = fixture()?;
    store.configure_worker_binding_at(&binding, 100)?;
    let original = snapshot(&config.database)?;
    let mut changed_owner = binding.clone();
    changed_owner.worker_owner_id = "replacement-worker".to_owned();
    let mut changed_profile = binding.clone();
    changed_profile.worker_profile_digest = "d".repeat(64);
    let mut changed_release = binding.clone();
    changed_release.release_digest = "e".repeat(64);
    let mut changed_config = binding.clone();
    changed_config.config_digest = "f".repeat(64);

    for (name, changed) in [
        ("owner", changed_owner),
        ("profile digest", changed_profile),
        ("release digest", changed_release),
        ("config digest", changed_config),
    ] {
        let error = store
            .configure_worker_binding_at(&changed, 50)
            .expect_err(name);
        assert!(
            matches!(error, WatchdogError::Conflict(ref message) if message.contains("worker binding is immutable")),
            "{name} returned the wrong error: {error}"
        );
        assert_eq!(snapshot(&config.database)?, original);
    }
    Ok(())
}

#[test]
fn corrupt_stored_binding_timestamp_is_rejected_by_existing_row_validation()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, config, mut store, binding) = fixture()?;
    store.configure_worker_binding_at(&binding, 100)?;
    let connection = Connection::open(&config.database)?;
    connection.execute(
        "UPDATE worker_bindings SET updated_at_ms=? WHERE singleton=1",
        [-1_i64],
    )?;
    let error = store
        .configure_worker_binding_at(&binding, 0)
        .expect_err("negative stored timestamp must be rejected");
    assert!(
        error
            .to_string()
            .contains("worker binding updated_at_ms contains a negative or out-of-range integer"),
        "unexpected corruption error: {error}"
    );
    Ok(())
}
