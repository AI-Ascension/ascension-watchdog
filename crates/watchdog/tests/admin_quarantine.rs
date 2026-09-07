use ascension_watchdog::config::{DesiredMode, WatchdogConfig};
use ascension_watchdog::error::WatchdogError;
use ascension_watchdog::storage::{
    OperatorCapability, OperatorCommandContext, OperatorCommandOutcome, SingletonLock, Store,
};
use serde_json::json;
use tempfile::TempDir;

fn config(temp: &TempDir, deployment_id: &str) -> WatchdogConfig {
    WatchdogConfig {
        database: temp.path().join("watchdog.sqlite3"),
        deployment_id: deployment_id.to_string(),
        desired_mode: DesiredMode::Running,
        allow_synthetic_children: true,
        ..WatchdogConfig::default()
    }
}

fn context(key: &str, request_id: &str, fingerprint: char) -> OperatorCommandContext {
    OperatorCommandContext::new(
        request_id,
        key,
        "operator-a",
        OperatorCapability::Admin,
        fingerprint.to_string().repeat(64),
    )
    .expect("operator context")
}

fn owner_store(temp: &TempDir) -> (SingletonLock, Store, WatchdogConfig) {
    let config = config(temp, "quarantine-tests");
    let owner = SingletonLock::acquire(&config.database).expect("owner lock");
    let store = Store::initialize_for_owner(&config.database, &config, &owner)
        .expect("initialize owner store");
    (owner, store, config)
}

#[test]
fn admin_quarantine_preserves_unknown_attempt_and_is_replayable_after_restart() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (owner, mut store, config) = owner_store(&temp);
    let job = store
        .submit_job_at("synthetic", &json!({"private": "retained"}), 10)
        .expect("submit");
    let claim = store
        .claim_next_job("worker-a", 11)
        .expect("claim")
        .expect("claim exists");
    let context = context(
        "quarantine-once",
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        'a',
    );
    let response = json!({"kind": "Accepted", "value": {"command": "quarantine", "queued": true}});
    let accepted = store
        .admit_operator_quarantine(
            &owner,
            &context,
            &claim.attempt_id,
            "operator found an uncertain boundary",
            &response,
            12,
        )
        .expect("quarantine admission");
    assert!(matches!(accepted, OperatorCommandOutcome::Accepted(_)));
    assert_eq!(
        store.get_job(&job.id).expect("job").expect("row").status,
        ascension_watchdog::storage::JobStatus::Quarantined
    );
    assert_eq!(
        store
            .attempt_summary(&claim.attempt_id)
            .expect("attempt")
            .expect("attempt row")
            .status,
        "unknown"
    );
    assert_eq!(store.operator_command_count().expect("ledger count"), 1);

    drop(store);
    let mut reopened =
        Store::open_for_owner(&config.database, &config, &owner).expect("reopen owner store");
    let replay = reopened
        .admit_operator_quarantine(
            &owner,
            &context,
            &claim.attempt_id,
            "operator found an uncertain boundary",
            &json!({"different": "transient response is ignored"}),
            99,
        )
        .expect("replay quarantine");
    let OperatorCommandOutcome::Replayed(receipt) = replay else {
        panic!("expected durable replay");
    };
    assert!(receipt.replayed);
    assert_eq!(receipt.response, response);
    assert_eq!(reopened.operator_command_count().expect("ledger count"), 1);
    assert_eq!(
        reopened.get_job(&job.id).expect("job").expect("row").status,
        ascension_watchdog::storage::JobStatus::Quarantined
    );
}

#[test]
fn admin_quarantine_refuses_completed_attempt_without_a_receipt() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (owner, mut store, _config) = owner_store(&temp);
    let job = store
        .submit_job_at("synthetic", &json!({}), 10)
        .expect("submit");
    let claim = store
        .claim_next_job("worker-a", 11)
        .expect("claim")
        .expect("claim exists");
    store
        .complete_job_at(&job.id, &claim.attempt_id, &json!({"ok": true}), 12)
        .expect("complete");
    let context = context(
        "quarantine-completed",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        'b',
    );
    let error = store
        .admit_operator_quarantine(
            &owner,
            &context,
            &claim.attempt_id,
            "too late",
            &json!({"accepted": true}),
            13,
        )
        .expect_err("completed attempt must be immutable");
    assert!(matches!(error, WatchdogError::Conflict(_)));
    assert_eq!(store.operator_command_count().expect("ledger count"), 0);
    assert_eq!(
        store.get_job(&job.id).expect("job").expect("row").status,
        ascension_watchdog::storage::JobStatus::Completed
    );
}

#[test]
fn admin_quarantine_rolls_back_state_when_audit_persistence_fails() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (owner, mut store, config) = owner_store(&temp);
    let job = store
        .submit_job_at("synthetic", &json!({}), 10)
        .expect("submit");
    let claim = store
        .claim_next_job("worker-a", 11)
        .expect("claim")
        .expect("claim exists");
    let fault = rusqlite::Connection::open(&config.database).expect("fault connection");
    fault
        .execute_batch(
            "CREATE TRIGGER quarantine_audit_failure BEFORE INSERT ON audit
             WHEN NEW.action='operator_command_accepted'
             BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;",
        )
        .expect("fault trigger");
    let context = context(
        "quarantine-rollback",
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        'c',
    );
    let result = store.admit_operator_quarantine(
        &owner,
        &context,
        &claim.attempt_id,
        "persistence fault test",
        &json!({"accepted": true}),
        12,
    );
    assert!(result.is_err());
    assert_eq!(
        store.get_job(&job.id).expect("job").expect("row").status,
        ascension_watchdog::storage::JobStatus::Running
    );
    assert_eq!(
        store
            .attempt_summary(&claim.attempt_id)
            .expect("attempt")
            .expect("attempt row")
            .status,
        "running"
    );
    assert_eq!(store.operator_command_count().expect("ledger count"), 0);
    let accepted_audits: i64 = fault
        .query_row(
            "SELECT COUNT(*) FROM audit WHERE action='operator_command_accepted'",
            [],
            |row| row.get(0),
        )
        .expect("audit count");
    assert_eq!(accepted_audits, 0);
}
