#![cfg(target_os = "linux")]

use ascension_watchdog::config::{ComponentConfig, DesiredMode, WatchdogConfig};
use ascension_watchdog::policy::ComponentState;
use ascension_watchdog::storage::{LaunchIntentState, SingletonLock, Store};
use ascension_watchdog::{Supervisor, WatchdogError};
use rusqlite::params;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn synthetic_config(directory: &tempfile::TempDir) -> WatchdogConfig {
    WatchdogConfig {
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
    }
}

fn schema_shape(path: &std::path::Path) -> rusqlite::Result<(String, Vec<String>)> {
    let connection = rusqlite::Connection::open(path)?;
    let marker = connection.query_row(
        "SELECT value FROM metadata WHERE key='schema_version'",
        [],
        |row| row.get(0),
    )?;
    let mut statement = connection.prepare("PRAGMA table_info(launch_intents)")?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok((marker, columns))
}

#[test]
fn schema_v1_migration_keeps_legacy_intents_unbound_and_quarantined()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = synthetic_config(&directory);
    let store = Store::initialize(&config.database, &config)?;
    drop(store);

    // Recreate the shape of the pre-binding store.  The migration adds the
    // columns as NULL, preserving the fact that the original context is
    // unavailable instead of deriving one from the proof/current generation.
    let connection = rusqlite::Connection::open(&config.database)?;
    connection.execute_batch(
        "ALTER TABLE launch_intents DROP COLUMN expected_launch_spec_digest;
         ALTER TABLE launch_intents DROP COLUMN expected_incarnation;
         UPDATE metadata SET value='1' WHERE key='schema_version';
         INSERT INTO launch_intents
           (id, deployment_id, component_id, launch_nonce, planned_containment_id,
            state, ownership_proof_json, created_at_ms, updated_at_ms)
         VALUES
           ('legacy-intent', 'default', 'synthetic', 'old-nonce',
            'legacy-containment', 'prepared', NULL, 1, 1);",
    )?;
    drop(connection);

    let compatibility_error = Store::open(&config.database, &config)
        .expect_err("schema-v1 compatibility open must not migrate");
    assert!(matches!(compatibility_error, WatchdogError::Unsupported(_)));
    let read_only_error = Store::open_read_only(&config.database, &config)
        .expect_err("schema-v1 read-only open must not migrate");
    assert!(matches!(read_only_error, WatchdogError::Unsupported(_)));
    let before_rejected_opens = schema_shape(&config.database)?;
    assert_eq!(before_rejected_opens.0, "1");
    assert!(
        !before_rejected_opens
            .1
            .iter()
            .any(|column| column == "expected_incarnation")
    );

    let owner = SingletonLock::acquire(&config.database)?;
    let mut foreign_config = config.clone();
    foreign_config.deployment_id = "foreign-deployment".to_owned();
    let foreign_error = Store::open_for_owner(&config.database, &foreign_config, &owner)
        .expect_err("foreign deployment must not migrate");
    assert!(matches!(foreign_error, WatchdogError::Conflict(_)));
    assert_eq!(schema_shape(&config.database)?, before_rejected_opens);
    drop(owner);

    let other_database = directory.path().join("other.sqlite");
    let wrong_owner = SingletonLock::acquire(&other_database)?;
    let lock_error = Store::open_for_owner(&config.database, &config, &wrong_owner)
        .expect_err("a lock for another database must not migrate");
    assert!(matches!(lock_error, WatchdogError::Unauthorized(_)));
    assert_eq!(schema_shape(&config.database)?, before_rejected_opens);
    drop(wrong_owner);

    let owner = SingletonLock::acquire(&config.database)?;
    let reopened = Store::open_for_owner(&config.database, &config, &owner)?;
    let legacy = reopened
        .launch_intent("legacy-intent")?
        .expect("legacy row");
    assert_eq!(legacy.expected_incarnation, None);
    assert_eq!(legacy.expected_launch_spec_digest, None);
    assert_eq!(reopened.status()?.schema_version, 2);
    drop(reopened);
    drop(owner);

    let mut supervisor = Supervisor::open(config.clone())?;
    supervisor.reconcile_once(1_000)?;
    drop(supervisor);

    let inspection = Store::open(&config.database, &config)?;
    assert_eq!(
        inspection
            .launch_intent("legacy-intent")?
            .expect("legacy row")
            .state,
        LaunchIntentState::Prepared
    );
    assert_eq!(
        inspection
            .component("synthetic")?
            .expect("quarantined component")
            .state,
        ComponentState::Quarantined
    );
    Ok(())
}

#[test]
fn forged_nonempty_incarnation_is_rejected_against_original_binding()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = synthetic_config(&directory);
    let mut supervisor = Supervisor::initialize(config.clone())?;
    let report = supervisor.reconcile_once(1_000)?;
    assert_eq!(report.started, vec!["synthetic"]);
    drop(supervisor);

    let connection = rusqlite::Connection::open(&config.database)?;
    let (intent_id, encoded): (String, String) = connection.query_row(
        "SELECT id, ownership_proof_json FROM launch_intents WHERE component_id='synthetic'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let mut proof: Value = serde_json::from_str(&encoded)?;
    proof["incarnation"] = json!("watchdog-generation-forged");
    connection.execute(
        "UPDATE launch_intents SET ownership_proof_json=? WHERE id=?",
        params![serde_json::to_string(&proof)?, intent_id],
    )?;
    drop(connection);

    let mut reopened = Supervisor::open(config.clone())?;
    reopened.reconcile_once(2_000)?;
    drop(reopened);

    let inspection = Store::open(&config.database, &config)?;
    assert_eq!(
        inspection.launch_intent(&intent_id)?.expect("intent").state,
        LaunchIntentState::Active
    );
    assert_eq!(
        inspection.component("synthetic")?.expect("component").state,
        ComponentState::Quarantined
    );
    Ok(())
}

#[test]
fn forged_nonce_and_deployment_context_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = synthetic_config(&directory);
    let mut supervisor = Supervisor::initialize(config.clone())?;
    assert_eq!(supervisor.reconcile_once(1_000)?.started, vec!["synthetic"]);
    drop(supervisor);

    let connection = rusqlite::Connection::open(&config.database)?;
    let (intent_id, encoded): (String, String) = connection.query_row(
        "SELECT id, ownership_proof_json FROM launch_intents WHERE component_id='synthetic'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let mut proof: Value = serde_json::from_str(&encoded)?;
    proof["launch_nonce"] = json!("wrong-launch-nonce");
    proof["deployment_id"] = json!("wrong-deployment");
    connection.execute(
        "UPDATE launch_intents SET ownership_proof_json=? WHERE id=?",
        params![serde_json::to_string(&proof)?, intent_id],
    )?;
    drop(connection);

    let mut reopened = Supervisor::open(config.clone())?;
    reopened.reconcile_once(2_000)?;
    drop(reopened);

    let inspection = Store::open(&config.database, &config)?;
    assert_eq!(
        inspection.component("synthetic")?.expect("component").state,
        ComponentState::Quarantined
    );
    Ok(())
}

#[test]
fn historic_cleanup_uses_original_authority_after_restart_and_stop()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = WatchdogConfig {
        database: directory.path().join("state.sqlite"),
        desired_mode: DesiredMode::Running,
        ..WatchdogConfig::default()
    };
    let mut store = Store::initialize(&config.database, &config)?;
    let intent = store.prepare_launch_intent(
        "gateway",
        "historic-nonce",
        "watchdog-generation-1",
        &"b".repeat(64),
        Some("historic-containment"),
        1,
    )?;
    store.set_desired_mode_at(DesiredMode::Stopped, 2)?;
    store.establish_new_generation(3)?;
    let cleaned = store.clean_launch_intent(&intent.id, 4)?;
    assert_eq!(cleaned.state, LaunchIntentState::Cleaned);
    assert_eq!(store.status()?.restart_generation, 2);
    Ok(())
}

#[test]
fn schema_v1_proof_recording_fails_closed_after_migration() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let config = synthetic_config(&directory);
    let store = Store::initialize(&config.database, &config)?;
    drop(store);
    let connection = rusqlite::Connection::open(&config.database)?;
    connection.execute_batch(
        "ALTER TABLE launch_intents DROP COLUMN expected_launch_spec_digest;
         ALTER TABLE launch_intents DROP COLUMN expected_incarnation;
         UPDATE metadata SET value='1' WHERE key='schema_version';
         INSERT INTO launch_intents
           (id, deployment_id, component_id, launch_nonce, planned_containment_id,
            state, ownership_proof_json, created_at_ms, updated_at_ms)
         VALUES
           ('legacy-proof', 'default', 'synthetic', 'old-nonce',
            'legacy-containment', 'prepared', NULL, 1, 1);",
    )?;
    drop(connection);
    let owner = SingletonLock::acquire(&config.database)?;
    let mut reopened = Store::open_for_owner(&config.database, &config, &owner)?;
    let error = reopened
        .record_launch_proof("legacy-proof", &json!({"forged": true}), 2)
        .expect_err("legacy proof must not be recorded");
    assert!(matches!(error, WatchdogError::Conflict(_)));
    Ok(())
}
