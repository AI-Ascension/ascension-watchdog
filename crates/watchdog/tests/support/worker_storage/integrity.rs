//! Forged identity, stale boot and malformed-input refusal.

use super::common::*;

#[test]
fn worker_identity_and_payload_contract_rejects_forgeries() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (mut store, config) = fixture(&temp);
    let mut invalid_binding = binding(&config);
    invalid_binding.worker_owner_id = "härness-worker".to_owned();
    assert!(
        store
            .configure_worker_binding_at(&invalid_binding, 1)
            .is_err()
    );

    let binding = binding(&config);
    store
        .configure_worker_binding_at(&binding, 1)
        .expect("binding");
    let mut invalid_control = control(&binding);
    invalid_control.worker_boot_id = invalid_control.watchdog_boot_id.clone();
    assert!(store.set_worker_control_at(&invalid_control, 2).is_err());
    let control = control(&binding);
    store.set_worker_control_at(&control, 2).expect("control");
    let witness = claim_witness(&binding, &control);
    store
        .submit_job_at(WORKER_HANDOFF_OPERATION, &json!({}), 3)
        .expect("job");
    let claim = store
        .claim_next_worker_handoff(&witness, 3)
        .expect("claim")
        .expect("handoff");
    let mut forged = claim.tuple();
    forged.payload_digest = "a".repeat(64);
    assert!(
        store
            .mark_worker_handoff_may_have_been_dispatched_at(&forged, 4)
            .is_err()
    );
    let mut duplicate_ids = claim.tuple();
    duplicate_ids.episode_id = duplicate_ids.handoff_id.clone();
    assert!(
        store
            .mark_worker_handoff_may_have_been_dispatched_at(&duplicate_ids, 4)
            .is_err()
    );
}

#[test]
fn stale_worker_boot_cannot_admit_or_complete_an_old_handoff() {
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
        .expect("dispatch marker");

    let mut replacement = first_control.clone();
    replacement.worker_boot_id = "33333333-3333-4333-8333-333333333333".to_owned();
    replacement.mode_sequence = 8;
    store
        .set_worker_control_at(&replacement, 5)
        .expect("replacement control");
    assert!(store.mark_worker_handoff_admitted_at(&tuple, 6).is_err());
    let receipt = WorkerTerminalReceipt {
        status: WorkerTerminalStatus::Completed,
        checkpoint_sequence: 1,
        terminal_ref: "stale".to_owned(),
        result_digest: "d".repeat(64),
    };
    assert!(
        store
            .complete_worker_handoff_at(&tuple, &receipt, 7)
            .is_err()
    );
    assert_eq!(
        store
            .worker_handoff(&claim.handoff_id)
            .expect("lookup")
            .expect("retained")
            .state,
        WorkerHandoffState::MayHaveBeenDispatched
    );
}

#[test]
fn historical_terminal_recovery_rejects_every_changed_control_field_without_writes() {
    with_reopened_replaced_pending_handoff(|store, _, old, current, _, tuple| {
        let receipt = WorkerTerminalReceipt {
            status: WorkerTerminalStatus::Completed,
            checkpoint_sequence: 2,
            terminal_ref: "current-control-only".to_owned(),
            result_digest: "e".repeat(64),
        };
        let mut invalid = vec![old.clone()];
        for field in 0..7 {
            let mut witness = current.clone();
            match field {
                0 => witness.deployment_id.push('x'),
                1 => witness.worker_owner_id.push('x'),
                2 => witness.worker_profile_digest = "f".repeat(64),
                3 => witness.watchdog_boot_id = old.watchdog_boot_id.clone(),
                4 => witness.worker_boot_id = old.worker_boot_id.clone(),
                5 => witness.mode = WorkerControlMode::Running,
                _ => witness.mode_sequence += 1,
            }
            invalid.push(witness);
        }
        let before = store.worker_handoff(&tuple.handoff_id).expect("pending");
        for witness in &invalid {
            assert!(
                store
                    .complete_worker_handoff_with_recovery_at(tuple, &receipt, witness, 8,)
                    .is_err()
            );
            assert_eq!(
                store.worker_handoff(&tuple.handoff_id).expect("unchanged"),
                before
            );
        }
        let terminal = store
            .complete_worker_handoff_with_recovery_at(tuple, &receipt, current, 8)
            .expect("current completion");
        let before_ack = store.worker_handoff(&tuple.handoff_id).expect("terminal");
        for witness in &invalid {
            assert!(
                store
                    .acknowledge_worker_handoff_with_recovery_at(
                        tuple,
                        &terminal.terminal_digest,
                        witness,
                        9,
                    )
                    .is_err()
            );
            assert_eq!(
                store.worker_handoff(&tuple.handoff_id).expect("unchanged"),
                before_ack
            );
        }
        store
            .acknowledge_worker_handoff_with_recovery_at(
                tuple,
                &terminal.terminal_digest,
                current,
                9,
            )
            .expect("current acknowledgment");
        assert_eq!(
            store.desired_mode().expect("stop remains"),
            DesiredMode::Stopped
        );
    });
}

#[test]
fn malformed_optional_fields_and_phase_clocks_fail_closed() {
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
    drop(store);
    let raw = rusqlite::Connection::open(&config.database).expect("raw store");
    raw.execute(
        "UPDATE worker_handoffs SET terminal_ref=? WHERE handoff_id=?",
        rusqlite::params!["x".repeat(1_025), claim.handoff_id],
    )
    .expect("oversized terminal reference");
    drop(raw);
    let reopened = Store::open(&config.database, &config).expect("reopen");
    assert!(reopened.worker_handoff(&claim.handoff_id).is_err());

    let raw = rusqlite::Connection::open(&config.database).expect("raw store");
    raw.execute(
        "UPDATE worker_handoffs SET terminal_ref=NULL, updated_at_ms=created_at_ms-1 WHERE handoff_id=?",
        rusqlite::params![claim.handoff_id],
    )
    .expect("backward clock");
    drop(raw);
    assert!(reopened.worker_handoff(&claim.handoff_id).is_err());
}

#[test]
fn attempt_and_job_projection_injection_is_rejected() {
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
    drop(store);
    let raw = rusqlite::Connection::open(&config.database).expect("raw store");
    raw.execute(
        "UPDATE attempts SET sequence=sequence+1 WHERE id=?",
        rusqlite::params![claim.attempt_id],
    )
    .expect("attempt sequence injection");
    drop(raw);
    let reopened = Store::open(&config.database, &config).expect("reopen");
    assert!(reopened.worker_handoff(&claim.handoff_id).is_err());
}
