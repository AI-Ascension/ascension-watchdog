use ascension_watchdog::config::{DesiredMode, WatchdogConfig};
use ascension_watchdog::error::WatchdogError;
use ascension_watchdog::storage::{
    MAX_AUDIT_RECORDS, MAX_OPERATOR_COMMANDS, MAX_OPERATOR_COMMANDS_WITH_STOP_RESERVE,
    OperatorCapability, OperatorCommand, OperatorCommandContext, OperatorCommandOutcome,
    RESERVED_CRITICAL_AUDIT_RECORDS, SingletonLock, Store,
};
use serde_json::json;
use std::fs;
use tempfile::TempDir;

fn config(temp: &TempDir, deployment_id: &str) -> WatchdogConfig {
    WatchdogConfig {
        database: temp.path().join("watchdog.sqlite3"),
        deployment_id: deployment_id.to_string(),
        desired_mode: DesiredMode::Stopped,
        allow_synthetic_children: true,
        ..WatchdogConfig::default()
    }
}

fn context(
    request_id: &str,
    key: &str,
    principal: &str,
    capability: OperatorCapability,
) -> OperatorCommandContext {
    OperatorCommandContext::new(request_id, key, principal, capability, "a".repeat(64))
        .expect("valid operator context")
}

fn owner_store(temp: &TempDir, deployment_id: &str) -> (SingletonLock, Store, WatchdogConfig) {
    let config = config(temp, deployment_id);
    let owner = SingletonLock::acquire(&config.database).expect("owner lock");
    let store = Store::initialize_for_owner(&config.database, &config, &owner)
        .expect("initialize owner store");
    (owner, store, config)
}

#[test]
fn lifecycle_admission_is_atomic_ordered_and_replay_does_not_revive_running() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (owner, mut store, config) = owner_store(&temp, "admin-order");
    let start = context(
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "start-once",
        "operator-a",
        OperatorCapability::Admin,
    );
    let stop = context(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "stop-once",
        "operator-a",
        OperatorCapability::Admin,
    );
    let start_outcome = store
        .admit_operator_command(
            &owner,
            &start,
            OperatorCommand::Start,
            &json!({"accepted": true, "mode": "running"}),
            10,
        )
        .expect("start admission");
    let start_receipt = match start_outcome {
        OperatorCommandOutcome::Accepted(receipt) => receipt,
        other => panic!("unexpected start outcome: {other:?}"),
    };
    assert_eq!(start_receipt.sequence, 1);
    assert_eq!(start_receipt.desired_mode, Some(DesiredMode::Running));
    assert_eq!(
        store.desired_mode().expect("running mode"),
        DesiredMode::Running
    );

    let stop_receipt = match store
        .admit_operator_command(
            &owner,
            &stop,
            OperatorCommand::Stop,
            &json!({"accepted": true, "mode": "stopped"}),
            20,
        )
        .expect("stop admission")
    {
        OperatorCommandOutcome::Accepted(receipt) => receipt,
        other => panic!("unexpected stop outcome: {other:?}"),
    };
    assert_eq!(stop_receipt.sequence, 2);
    assert_eq!(
        store.desired_mode().expect("stopped mode"),
        DesiredMode::Stopped
    );

    drop(store);
    let mut reopened =
        Store::open_for_owner(&config.database, &config, &owner).expect("reopen owner store");
    let replay = reopened
        .admit_operator_command(
            &owner,
            &start,
            OperatorCommand::Start,
            &json!({"accepted": false, "mode": "different"}),
            30,
        )
        .expect("replay start");
    let replayed = match replay {
        OperatorCommandOutcome::Replayed(receipt) => receipt,
        other => panic!("unexpected replay outcome: {other:?}"),
    };
    assert!(replayed.replayed);
    assert_eq!(replayed.sequence, start_receipt.sequence);
    assert_eq!(replayed.response, start_receipt.response);
    assert_eq!(
        reopened.desired_mode().expect("stop remains authoritative"),
        DesiredMode::Stopped
    );
}

#[test]
fn key_request_and_capability_conflicts_fail_closed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (owner, mut store, _config) = owner_store(&temp, "admin-conflicts");
    let first = context(
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "same-key",
        "operator-a",
        OperatorCapability::Admin,
    );
    store
        .admit_operator_command(
            &owner,
            &first,
            OperatorCommand::Start,
            &json!({"accepted": true}),
            10,
        )
        .expect("first admission");

    let different_fingerprint = OperatorCommandContext::new(
        first.request_id.clone(),
        first.idempotency_key.clone(),
        first.principal.clone(),
        first.capability,
        "b".repeat(64),
    )
    .expect("valid conflicting context");
    assert!(matches!(
        store.admit_operator_command(
            &owner,
            &different_fingerprint,
            OperatorCommand::Start,
            &json!({"accepted": true}),
            11,
        ),
        Err(WatchdogError::Conflict(_))
    ));

    let different_principal = OperatorCommandContext::new(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        first.idempotency_key.clone(),
        "operator-b",
        OperatorCapability::Admin,
        first.command_fingerprint.clone(),
    )
    .expect("valid principal conflict");
    assert!(matches!(
        store.admit_operator_command(
            &owner,
            &different_principal,
            OperatorCommand::Start,
            &json!({"accepted": true}),
            12,
        ),
        Err(WatchdogError::Unauthorized(_))
    ));

    let read_capability = context(
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        "read-cannot-start",
        "operator-a",
        OperatorCapability::Read,
    );
    assert!(matches!(
        store.admit_operator_command(
            &owner,
            &read_capability,
            OperatorCommand::Start,
            &json!({"accepted": true}),
            13,
        ),
        Err(WatchdogError::Unauthorized(_))
    ));
}

#[test]
fn read_only_admission_writes_zero_and_response_is_bounded() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (owner, mut store, config) = owner_store(&temp, "admin-read");
    let before_count = store.operator_command_count().expect("count");
    let read = context(
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "read-only",
        "operator-a",
        OperatorCapability::Read,
    );
    assert_eq!(
        store
            .admit_operator_command(
                &owner,
                &read,
                OperatorCommand::Status,
                &json!({"ignored": "no write"}),
                10,
            )
            .expect("read admission"),
        OperatorCommandOutcome::ReadOnly
    );
    assert_eq!(store.operator_command_count().expect("count"), before_count);
    assert_eq!(store.list_operator_commands(10).expect("list").len(), 0);
    assert_eq!(store.desired_mode().expect("mode"), DesiredMode::Stopped);

    let admin = context(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "oversized-response",
        "operator-a",
        OperatorCapability::Admin,
    );
    let oversized = json!({"body": "x".repeat(9 * 1024)});
    assert!(matches!(
        store.admit_operator_command(&owner, &admin, OperatorCommand::Start, &oversized, 11,),
        Err(WatchdogError::InvalidInput(_))
    ));
    assert_eq!(store.operator_command_count().expect("count"), 0);
    drop(store);
    assert!(Store::open_read_only(&config.database, &config).is_ok());
}

#[test]
#[allow(clippy::too_many_lines)]
fn lifecycle_reserve_backpressures_bulk_without_evicting_keys() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (owner, mut store, config) = owner_store(&temp, "admin-capacity");
    let bulk_limit = usize::try_from(MAX_OPERATOR_COMMANDS - 8).expect("platform usize");
    for index in 0..bulk_limit {
        let context = context(
            &format!("00000000-0000-4000-8000-{index:012x}"),
            &format!("bulk-{index}"),
            "operator-a",
            OperatorCapability::Admin,
        );
        store
            .admit_operator_command(
                &owner,
                &context,
                OperatorCommand::Backup,
                &json!({"accepted": true}),
                index as u64,
            )
            .expect("bulk admission within normal budget");
    }
    assert_eq!(
        store.operator_command_count().expect("count"),
        bulk_limit as u64
    );
    let lifecycle = context(
        "ffffffff-ffff-4fff-8fff-ffffffffffff",
        "reserved-start",
        "operator-a",
        OperatorCapability::Admin,
    );
    assert!(matches!(
        store.admit_operator_command(
            &owner,
            &lifecycle,
            OperatorCommand::Start,
            &json!({"accepted": true}),
            1000,
        ),
        Ok(OperatorCommandOutcome::Accepted(_))
    ));
    let rejected_bulk = context(
        "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        "bulk-after-reserve",
        "operator-a",
        OperatorCapability::Admin,
    );
    assert!(matches!(
        store.admit_operator_command(
            &owner,
            &rejected_bulk,
            OperatorCommand::Backup,
            &json!({"accepted": true}),
            1001,
        ),
        Err(WatchdogError::Busy(_))
    ));

    // Fill every one of the eight lifecycle slots with distinct, legitimate
    // transitions.  The normal row budget is now fully occupied; a fresh
    // stop must still be durably admissible in its explicit emergency slot.
    let remaining_lifecycle = [
        OperatorCommand::Pause,
        OperatorCommand::Resume,
        OperatorCommand::Drain,
        OperatorCommand::Start,
        OperatorCommand::Pause,
        OperatorCommand::Resume,
        OperatorCommand::Start,
    ];
    for (index, command) in remaining_lifecycle.into_iter().enumerate() {
        let lifecycle = context(
            &format!("11111111-1111-4111-8111-{index:012x}"),
            &format!("reserved-lifecycle-{index}"),
            "operator-a",
            OperatorCapability::Admin,
        );
        assert!(matches!(
            store.admit_operator_command(
                &owner,
                &lifecycle,
                command,
                &json!({"accepted": true}),
                1001 + index as u64,
            ),
            Ok(OperatorCommandOutcome::Accepted(_))
        ));
    }
    assert_eq!(
        store.operator_command_count().expect("full normal ledger"),
        MAX_OPERATOR_COMMANDS as u64
    );
    let lifecycle_after_full = context(
        "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeef",
        "lifecycle-after-full",
        "operator-a",
        OperatorCapability::Admin,
    );
    assert!(matches!(
        store.admit_operator_command(
            &owner,
            &lifecycle_after_full,
            OperatorCommand::Resume,
            &json!({"accepted": true}),
            1010,
        ),
        Err(WatchdogError::Busy(_))
    ));
    let stop = context(
        "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        "reserved-stop",
        "operator-a",
        OperatorCapability::Admin,
    );
    assert!(matches!(
        store.admit_operator_command(
            &owner,
            &stop,
            OperatorCommand::Stop,
            &json!({"accepted": true}),
            1002,
        ),
        Ok(OperatorCommandOutcome::Accepted(_))
    ));
    assert_eq!(
        store.operator_command_count().expect("count"),
        MAX_OPERATOR_COMMANDS_WITH_STOP_RESERVE as u64
    );
    let second_stop = context(
        "dddddddd-dddd-4ddd-8ddd-ddddddddddde",
        "second-stop-after-reserve",
        "operator-a",
        OperatorCapability::Admin,
    );
    assert!(matches!(
        store.admit_operator_command(
            &owner,
            &second_stop,
            OperatorCommand::Stop,
            &json!({"accepted": true}),
            1011,
        ),
        Err(WatchdogError::Busy(_))
    ));

    // The reserved stop row remains replayable after reopening the owner
    // store; replay must not consume another row or reapply the mode.
    drop(store);
    let mut reopened =
        Store::open_for_owner(&config.database, &config, &owner).expect("reopen full ledger");
    assert_eq!(
        reopened.operator_command_count().expect("reopened count"),
        MAX_OPERATOR_COMMANDS_WITH_STOP_RESERVE as u64
    );
    assert!(matches!(
        reopened
            .admit_operator_command(
                &owner,
                &stop,
                OperatorCommand::Stop,
                &json!({"accepted": false, "replayed": true}),
                1012,
            )
            .expect("replay reserved stop"),
        OperatorCommandOutcome::Replayed(_)
    ));
    assert_eq!(
        reopened.desired_mode().expect("stopped mode after replay"),
        DesiredMode::Stopped
    );
}

#[test]
fn owner_migration_adds_only_the_operator_table_and_transaction_fault_rolls_back_mode() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (owner, store, config) = owner_store(&temp, "admin-migration");
    drop(store);
    let raw = rusqlite::Connection::open(&config.database).expect("raw connection");
    raw.execute("DROP INDEX operator_commands_order_idx", [])
        .expect("drop index");
    raw.execute("DROP INDEX operator_commands_principal_idx", [])
        .expect("drop index");
    raw.execute("DROP TABLE operator_commands", [])
        .expect("drop ledger");
    raw.execute(
        "DELETE FROM metadata WHERE key='operator_ledger_schema_version'",
        [],
    )
    .expect("drop ledger marker");
    drop(raw);
    let mut migrated =
        Store::open_for_owner(&config.database, &config, &owner).expect("owner migration");
    assert_eq!(migrated.operator_command_count().expect("count"), 0);

    let trigger = rusqlite::Connection::open(&config.database).expect("trigger connection");
    trigger
        .execute_batch(
            "CREATE TRIGGER reject_operator_insert BEFORE INSERT ON operator_commands BEGIN SELECT RAISE(ABORT, 'injected persistence fault'); END;",
        )
        .expect("fault trigger");
    let request = context(
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "faulted-start",
        "operator-a",
        OperatorCapability::Admin,
    );
    assert!(matches!(
        migrated.admit_operator_command(
            &owner,
            &request,
            OperatorCommand::Start,
            &json!({"accepted": true}),
            10,
        ),
        Err(WatchdogError::Sqlite(_))
    ));
    assert_eq!(
        migrated.desired_mode().expect("rollback mode"),
        DesiredMode::Stopped
    );
    assert_eq!(
        migrated.operator_command_count().expect("rollback count"),
        0
    );
}

#[test]
fn audit_reserve_backpressures_ordinary_events_but_keeps_critical_mode_available() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (owner, mut store, config) = owner_store(&temp, "admin-audit-capacity");
    let ordinary_limit = usize::try_from(MAX_AUDIT_RECORDS - RESERVED_CRITICAL_AUDIT_RECORDS)
        .expect("platform usize");
    // Initialization contributes one audit row. Seed the remaining ordinary
    // rows in one owner-local transaction so this capacity test does not turn
    // into thousands of fsyncs; the public API is exercised at the boundary.
    let raw = rusqlite::Connection::open(&config.database).expect("audit seed connection");
    raw.execute_batch("BEGIN IMMEDIATE")
        .expect("begin audit seed");
    for index in 1..ordinary_limit {
        raw.execute(
            "INSERT INTO audit (action, detail, occurred_at_ms) VALUES ('diagnostic', ?, ?)",
            rusqlite::params![
                format!("event-{index}"),
                i64::try_from(index).expect("timestamp")
            ],
        )
        .expect("ordinary audit seed");
    }
    raw.execute_batch("COMMIT").expect("commit audit seed");
    drop(raw);
    assert!(matches!(
        store.audit("diagnostic", "ordinary-boundary", 10_000),
        Err(WatchdogError::Conflict(_))
    ));
    store
        .set_desired_mode_at(DesiredMode::Stopped, 10_001)
        .expect("critical mode audit uses reserve");
    assert_eq!(store.desired_mode().expect("mode"), DesiredMode::Stopped);
    let audit_count: i64 = rusqlite::Connection::open(&config.database)
        .expect("audit connection")
        .query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0))
        .expect("audit count");
    assert_eq!(
        audit_count,
        i64::try_from(ordinary_limit + 1).expect("count")
    );
    drop(owner);
}

#[cfg(unix)]
#[test]
fn symlink_database_alias_cannot_obtain_a_second_owner_lock() {
    let temp = tempfile::tempdir().expect("tempdir");
    let real = temp.path().join("real");
    let alias = temp.path().join("alias");
    fs::create_dir(&real).expect("real directory");
    std::os::unix::fs::symlink(&real, &alias).expect("directory alias");
    let database = real.join("watchdog.sqlite3");
    let owner = SingletonLock::acquire(&database).expect("real owner");
    assert!(matches!(
        SingletonLock::acquire(alias.join("watchdog.sqlite3")),
        Err(WatchdogError::InvalidInput(_))
    ));
    drop(owner);

    let lock_target = temp.path().join("untrusted-lock");
    fs::write(&lock_target, b"outside").expect("lock target");
    let lock_alias_dir = temp.path().join("lock-alias");
    fs::create_dir(&lock_alias_dir).expect("lock alias directory");
    let lock_database = lock_alias_dir.join("watchdog.sqlite3");
    std::os::unix::fs::symlink(&lock_target, lock_database.with_extension("sqlite3.lock"))
        .expect("lock alias");
    assert!(matches!(
        SingletonLock::acquire(&lock_database),
        Err(WatchdogError::InvalidInput(_))
    ));
}
