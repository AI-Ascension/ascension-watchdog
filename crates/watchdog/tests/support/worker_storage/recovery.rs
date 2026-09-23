//! Reopen, reconciliation, replacement and durable-stop handoff recovery.

use super::common::*;

#[test]
fn failed_terminal_acknowledgment_remains_readable_after_reopen() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (mut store, config) = fixture(&temp);
    let binding = binding(&config);
    let control = control(&binding);
    store
        .configure_worker_binding_at(&binding, 1)
        .expect("binding");
    store.set_worker_control_at(&control, 2).expect("control");
    let witness = claim_witness(&binding, &control);
    store
        .submit_job_at(WORKER_HANDOFF_OPERATION, &json!({}), 3)
        .expect("job");
    let claim = store
        .claim_next_worker_handoff(&witness, 3)
        .expect("claim")
        .expect("handoff");
    let tuple = claim.tuple();
    store
        .mark_worker_handoff_may_have_been_dispatched_at(&tuple, 4)
        .expect("dispatch");
    let receipt = WorkerTerminalReceipt {
        status: WorkerTerminalStatus::Failed,
        checkpoint_sequence: 1,
        terminal_ref: "failed-terminal-ref".to_owned(),
        result_digest: "f".repeat(64),
    };
    let completion = store
        .complete_worker_handoff_at(&tuple, &receipt, 5)
        .expect("failure");
    store
        .acknowledge_worker_handoff_at(&tuple, &completion.terminal_digest, 6)
        .expect("ack");
    let acknowledged = store
        .worker_handoff(&claim.handoff_id)
        .expect("acknowledged read")
        .expect("retained handoff");
    assert_eq!(acknowledged.state, WorkerHandoffState::Acknowledged);
    assert_eq!(
        acknowledged.job.status,
        ascension_watchdog::JobStatus::Failed
    );
    drop(store);
    let mut reopened = Store::open(&config.database, &config).expect("reopen");
    assert!(
        reopened
            .acknowledge_worker_handoff_at(&tuple, &completion.terminal_digest, 7)
            .expect("duplicate ack")
            .already_acknowledged
    );
    assert!(
        reopened
            .complete_worker_handoff_at(&tuple, &receipt, 8)
            .expect("duplicate failure")
            .already_completed
    );
    assert!(
        reopened
            .claim_next_worker_handoff(&witness, 9)
            .expect("no retry")
            .is_none()
    );
}

#[test]
fn owner_reopen_additively_migrates_a_core_store_without_worker_tables() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (store, config) = fixture(&temp);
    drop(store);
    let raw = rusqlite::Connection::open(&config.database).expect("raw store");
    raw.execute_batch(
        "DROP TABLE worker_handoffs; DROP TABLE worker_control; DROP TABLE worker_bindings; DELETE FROM metadata WHERE key='worker_handoff_schema_version';",
    )
    .expect("remove additive worker schema");
    drop(raw);
    let owner =
        ascension_watchdog::storage::SingletonLock::acquire(&config.database).expect("owner lock");
    let reopened =
        Store::open_for_owner(&config.database, &config, &owner).expect("owner migration");
    assert_eq!(reopened.status().expect("status").schema_version, 2);
    let marker: String = rusqlite::Connection::open(&config.database)
        .expect("inspect")
        .query_row(
            "SELECT value FROM metadata WHERE key='worker_handoff_schema_version'",
            [],
            |row| row.get(0),
        )
        .expect("worker marker");
    assert_eq!(marker, "1");
}

#[test]
fn quarantined_unknown_attempt_can_finish_matching_terminal_accounting() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (mut store, config) = fixture(&temp);
    let binding = binding(&config);
    let control = control(&binding);
    store
        .configure_worker_binding_at(&binding, 1)
        .expect("binding");
    store.set_worker_control_at(&control, 2).expect("control");
    let witness = claim_witness(&binding, &control);
    store
        .submit_job_at(WORKER_HANDOFF_OPERATION, &json!({}), 3)
        .expect("job");
    let claim = store
        .claim_next_worker_handoff(&witness, 3)
        .expect("claim")
        .expect("handoff");
    let tuple = claim.tuple();
    store
        .mark_worker_handoff_may_have_been_dispatched_at(&tuple, 4)
        .expect("dispatch marker");
    store
        .mark_worker_handoff_admitted_at(&tuple, 5)
        .expect("admit");
    assert_eq!(
        store
            .quarantine_interrupted_jobs(6)
            .expect("quarantine count"),
        1
    );
    let receipt = WorkerTerminalReceipt {
        status: WorkerTerminalStatus::Completed,
        checkpoint_sequence: 4,
        terminal_ref: "compact-terminal-ref".to_owned(),
        result_digest: "e".repeat(64),
    };
    let completion = store
        .complete_worker_handoff_at(&tuple, &receipt, 7)
        .expect("finish quarantined terminal");
    assert_eq!(completion.handoff.state, WorkerHandoffState::Completed);
    assert_eq!(
        completion.handoff.job.status,
        ascension_watchdog::JobStatus::Completed
    );
    assert_eq!(
        completion.handoff.job.result,
        Some(json!({
            "status": "completed",
            "checkpoint_sequence": 4,
            "terminal_ref": "compact-terminal-ref",
            "result_digest": "e".repeat(64),
        }))
    );
    assert!(
        store
            .claim_next_worker_handoff(&witness, 8)
            .expect("no redispatch")
            .is_none()
    );
    let raw = rusqlite::Connection::open(&config.database).expect("inspect");
    let retained_result_digest: String = raw
        .query_row(
            "SELECT result_digest FROM worker_handoffs WHERE handoff_id=?",
            [&claim.handoff_id],
            |row| row.get(0),
        )
        .expect("harness digest");
    assert_eq!(retained_result_digest, "e".repeat(64));
}

#[test]
fn terminal_duplicate_completion_is_historical_after_worker_replacement() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (mut store, config) = fixture(&temp);
    let binding = binding(&config);
    let first_control = control(&binding);
    store
        .configure_worker_binding_at(&binding, 1)
        .expect("binding");
    store
        .set_worker_control_at(&first_control, 2)
        .expect("control");
    let witness = claim_witness(&binding, &first_control);
    store
        .submit_job_at(WORKER_HANDOFF_OPERATION, &json!({}), 3)
        .expect("job");
    let claim = store
        .claim_next_worker_handoff(&witness, 3)
        .expect("claim")
        .expect("handoff");
    let tuple = claim.tuple();
    store
        .mark_worker_handoff_may_have_been_dispatched_at(&tuple, 4)
        .expect("dispatch");
    let receipt = WorkerTerminalReceipt {
        status: WorkerTerminalStatus::Completed,
        checkpoint_sequence: 1,
        terminal_ref: "replacement-terminal".to_owned(),
        result_digest: "d".repeat(64),
    };
    store
        .complete_worker_handoff_at(&tuple, &receipt, 5)
        .expect("completion");
    drop(store);

    let mut reopened = Store::open(&config.database, &config).expect("reopen");
    let mut replacement = first_control.clone();
    replacement.watchdog_boot_id = "44444444-4444-4444-8444-444444444444".to_owned();
    replacement.worker_boot_id = "55555555-5555-4555-8555-555555555555".to_owned();
    replacement.mode_sequence = 8;
    reopened
        .set_worker_control_at(&replacement, 6)
        .expect("replacement control");
    let repeated = reopened
        .complete_worker_handoff_at(&tuple, &receipt, 7)
        .expect("historical duplicate completion");
    assert!(repeated.already_completed);
    assert!(
        reopened
            .acknowledge_worker_handoff_at(&tuple, &repeated.terminal_digest, 8)
            .is_err()
    );
    let acknowledgment = reopened
        .acknowledge_worker_handoff_with_recovery_at(
            &tuple,
            &repeated.terminal_digest,
            &replacement,
            9,
        )
        .expect("historical acknowledgment");
    assert!(!acknowledgment.already_acknowledged);
    assert!(
        reopened
            .acknowledge_worker_handoff_at(&tuple, &repeated.terminal_digest, 10)
            .expect("historical duplicate acknowledgment")
            .already_acknowledged
    );
}

#[test]
fn current_recovery_completes_old_handoff_after_reopen_without_redispatch_or_resume() {
    with_reopened_replaced_pending_handoff(
        |reopened, binding, first_control, replacement, claim, tuple| {
            let receipt = WorkerTerminalReceipt {
                status: WorkerTerminalStatus::Completed,
                checkpoint_sequence: 2,
                terminal_ref: "recovered-terminal".to_owned(),
                result_digest: "e".repeat(64),
            };
            assert!(
                reopened
                    .complete_worker_handoff_at(tuple, &receipt, 7)
                    .is_err()
            );
            let completion = reopened
                .complete_worker_handoff_with_recovery_at(tuple, &receipt, replacement, 8)
                .expect("current recovery completion");
            assert!(!completion.already_completed);
            assert_eq!(completion.handoff.state, WorkerHandoffState::Completed);
            assert_eq!(
                completion.handoff.watchdog_boot_id,
                first_control.watchdog_boot_id
            );
            assert_eq!(
                completion.handoff.worker_boot_id,
                first_control.worker_boot_id
            );
            assert_eq!(reopened.desired_mode().expect("mode"), DesiredMode::Stopped);

            let replacement_witness = claim_witness(binding, replacement);
            assert!(
                reopened
                    .claim_next_worker_handoff(&replacement_witness, 9)
                    .is_err()
            );
            let repeated = reopened
                .complete_worker_handoff_with_recovery_at(tuple, &receipt, replacement, 10)
                .expect("repeated current recovery completion");
            assert!(repeated.already_completed);

            let mut wrong_tuple = tuple.clone();
            wrong_tuple.attempt_number += 1;
            assert!(
                reopened
                    .complete_worker_handoff_with_recovery_at(
                        &wrong_tuple,
                        &receipt,
                        replacement,
                        11,
                    )
                    .is_err()
            );
            let mut wrong_receipt = receipt.clone();
            wrong_receipt.result_digest = "f".repeat(64);
            assert!(
                reopened
                    .complete_worker_handoff_with_recovery_at(
                        tuple,
                        &wrong_receipt,
                        replacement,
                        11,
                    )
                    .is_err()
            );
            assert_eq!(
                reopened
                    .worker_handoff(&claim.handoff_id)
                    .expect("retained handoff")
                    .expect("handoff")
                    .state,
                WorkerHandoffState::Completed
            );

            let acknowledgment = reopened
                .acknowledge_worker_handoff_with_recovery_at(
                    tuple,
                    &completion.terminal_digest,
                    replacement,
                    12,
                )
                .expect("current recovery acknowledgment");
            assert!(!acknowledgment.already_acknowledged);
            assert_eq!(
                reopened
                    .worker_handoff(&claim.handoff_id)
                    .expect("acknowledged handoff")
                    .expect("handoff")
                    .state,
                WorkerHandoffState::Acknowledged
            );
        },
    );
}

#[test]
fn stop_after_dispatch_blocks_new_claims_but_allows_same_incarnation_settlement() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (mut store, config) = fixture(&temp);
    let binding = binding(&config);
    let control = control(&binding);
    store
        .configure_worker_binding_at(&binding, 1)
        .expect("binding");
    store.set_worker_control_at(&control, 2).expect("control");
    let witness = claim_witness(&binding, &control);
    store
        .submit_job_at(WORKER_HANDOFF_OPERATION, &json!({}), 3)
        .expect("job");
    let claim = store
        .claim_next_worker_handoff(&witness, 3)
        .expect("claim")
        .expect("handoff");
    let tuple = claim.tuple();
    store
        .mark_worker_handoff_may_have_been_dispatched_at(&tuple, 4)
        .expect("dispatch marker");
    store
        .set_desired_mode_at(DesiredMode::Stopped, 5)
        .expect("stop");
    let receipt = WorkerTerminalReceipt {
        status: WorkerTerminalStatus::Completed,
        checkpoint_sequence: 2,
        terminal_ref: "stopped-after-dispatch".to_owned(),
        result_digest: "e".repeat(64),
    };
    let completion = store
        .complete_worker_handoff_at(&tuple, &receipt, 6)
        .expect("settlement");
    assert_eq!(completion.handoff.state, WorkerHandoffState::Completed);
    assert!(
        store
            .submit_job_at(WORKER_HANDOFF_OPERATION, &json!({}), 7)
            .is_ok()
    );
    assert!(store.claim_next_worker_handoff(&witness, 7).is_err());
}
