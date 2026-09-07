//! Owner-local worker handoff durability and uncertainty tests.

use ascension_watchdog::config::{DesiredMode, WatchdogConfig};
use ascension_watchdog::storage::{
    MAX_WORKER_WIRE_INTEGER, Store, WORKER_HANDOFF_OPERATION, WORKER_HANDOFF_PAYLOAD_DIGEST,
    WORKER_HANDOFF_SCHEMA_DIGEST, WorkerBinding, WorkerClaimWitness, WorkerControlMode,
    WorkerControlWitness, WorkerHandoffState, WorkerTerminalReceipt, WorkerTerminalStatus,
};
use serde_json::json;
use tempfile::TempDir;

fn fixture(temp: &TempDir) -> (Store, WatchdogConfig) {
    let config = WatchdogConfig {
        database: temp.path().join("state.sqlite"),
        desired_mode: DesiredMode::Running,
        ..WatchdogConfig::default()
    };
    let store = Store::initialize(&config.database, &config).expect("initialize store");
    (store, config)
}

fn binding(config: &WatchdogConfig) -> WorkerBinding {
    WorkerBinding {
        deployment_id: config.deployment_id.clone(),
        worker_owner_id: "harness-worker".to_owned(),
        worker_profile_digest: "a".repeat(64),
        release_digest: "b".repeat(64),
        config_digest: config.digest().expect("config digest"),
        schema_digest: WORKER_HANDOFF_SCHEMA_DIGEST.to_owned(),
    }
}

fn control(binding: &WorkerBinding) -> WorkerControlWitness {
    WorkerControlWitness {
        deployment_id: binding.deployment_id.clone(),
        worker_owner_id: binding.worker_owner_id.clone(),
        worker_profile_digest: binding.worker_profile_digest.clone(),
        watchdog_boot_id: "11111111-1111-4111-8111-111111111111".to_owned(),
        worker_boot_id: "22222222-2222-4222-8222-222222222222".to_owned(),
        mode: WorkerControlMode::Running,
        mode_sequence: 7,
    }
}

fn claim_witness(binding: &WorkerBinding, control: &WorkerControlWitness) -> WorkerClaimWitness {
    WorkerClaimWitness {
        deployment_id: binding.deployment_id.clone(),
        worker_owner_id: binding.worker_owner_id.clone(),
        worker_profile_digest: binding.worker_profile_digest.clone(),
        release_digest: binding.release_digest.clone(),
        config_digest: binding.config_digest.clone(),
        schema_digest: binding.schema_digest.clone(),
        watchdog_boot_id: control.watchdog_boot_id.clone(),
        worker_boot_id: control.worker_boot_id.clone(),
        mode_sequence: control.mode_sequence,
    }
}

#[test]
fn claim_persists_full_tuple_and_requires_exact_preflight() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (mut store, config) = fixture(&temp);
    let binding = binding(&config);
    let control = control(&binding);
    store
        .configure_worker_binding_at(&binding, 1)
        .expect("binding");
    store.set_worker_control_at(&control, 2).expect("control");
    let witness = claim_witness(&binding, &control);

    let future = store
        .submit_job_at(WORKER_HANDOFF_OPERATION, &json!({}), 50)
        .expect("future job");
    assert!(
        store
            .claim_next_worker_handoff(&witness, 49)
            .expect("future claim")
            .is_none()
    );
    let claim = store
        .claim_next_worker_handoff(&witness, 50)
        .expect("claim")
        .expect("eligible handoff");
    assert_eq!(claim.job.id, future.id);
    assert_eq!(claim.payload_digest, WORKER_HANDOFF_PAYLOAD_DIGEST);
    assert_eq!(claim.state, WorkerHandoffState::Prepared);
    assert_eq!(claim.operation, WORKER_HANDOFF_OPERATION);
    assert_eq!(claim.parameters, json!({}));
    let ids = [
        claim.handoff_id.as_str(),
        claim.attempt_id.as_str(),
        claim.run_id.as_str(),
        claim.episode_id.as_str(),
        claim.trajectory_id.as_str(),
    ];
    for (index, value) in ids.iter().enumerate() {
        assert!(ids[index + 1..].iter().all(|other| other != value));
    }
    let mut mismatched = witness.clone();
    mismatched.mode_sequence += 1;
    assert!(store.claim_next_worker_handoff(&mismatched, 50).is_err());
    assert!(
        store
            .claim_next_worker_handoff(&witness, 50)
            .expect("reservation")
            .is_none()
    );
}

#[test]
fn dispatch_marker_is_one_way_and_terminal_ack_is_idempotent() {
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
    let dispatched = store
        .mark_worker_handoff_may_have_been_dispatched_at(&tuple, 4)
        .expect("dispatch marker");
    assert_eq!(dispatched.state, WorkerHandoffState::MayHaveBeenDispatched);
    assert!(
        store
            .mark_worker_handoff_may_have_been_dispatched_at(&tuple, 5)
            .is_err()
    );
    store
        .mark_worker_handoff_admitted_at(&tuple, 6)
        .expect("admit");
    let result_digest = "d".repeat(64);
    let receipt = WorkerTerminalReceipt {
        status: WorkerTerminalStatus::Completed,
        checkpoint_sequence: 3,
        terminal_ref: "terminal-ref-1".to_owned(),
        result_digest,
    };
    let completion = store
        .complete_worker_handoff_at(&tuple, &receipt, 7)
        .expect("completion");
    assert!(!completion.already_completed);
    assert_eq!(completion.handoff.state, WorkerHandoffState::Completed);
    let repeated = store
        .complete_worker_handoff_at(&tuple, &receipt, 8)
        .expect("repeated completion");
    assert!(repeated.already_completed);
    let ack = store
        .acknowledge_worker_handoff_at(&tuple, &completion.terminal_digest, 9)
        .expect("ack");
    assert!(!ack.already_acknowledged);
    let repeated_ack = store
        .acknowledge_worker_handoff_at(&tuple, &completion.terminal_digest, 10)
        .expect("repeated ack");
    assert!(repeated_ack.already_acknowledged);
    assert_eq!(
        store
            .worker_handoff(&claim.handoff_id)
            .expect("lookup")
            .unwrap()
            .state,
        WorkerHandoffState::Acknowledged
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
fn claim_honors_desired_mode_and_single_reservation() {
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
        .set_desired_mode_at(DesiredMode::Stopped, 3)
        .expect("stop mode");
    store
        .submit_job_at(WORKER_HANDOFF_OPERATION, &json!({}), 4)
        .expect("stopped-mode job");
    assert!(store.claim_next_worker_handoff(&witness, 4).is_err());

    store
        .set_desired_mode_at(DesiredMode::Running, 5)
        .expect("running mode");
    let first = store
        .claim_next_worker_handoff(&witness, 5)
        .expect("first claim")
        .expect("first handoff");
    store
        .submit_job_at(WORKER_HANDOFF_OPERATION, &json!({}), 6)
        .expect("reserved second job");
    assert!(
        store
            .claim_next_worker_handoff(&witness, 6)
            .expect("occupied claim")
            .is_none()
    );
    assert_eq!(first.state, WorkerHandoffState::Prepared);
}

#[test]
fn terminal_ack_intent_survives_reopen_and_receipt_bounds_are_enforced() {
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

    let mut oversized_checkpoint = WorkerTerminalReceipt {
        status: WorkerTerminalStatus::Completed,
        checkpoint_sequence: MAX_WORKER_WIRE_INTEGER + 1,
        terminal_ref: "terminal-ref".to_owned(),
        result_digest: "f".repeat(64),
    };
    assert!(
        store
            .complete_worker_handoff_at(&tuple, &oversized_checkpoint, 5)
            .is_err()
    );
    oversized_checkpoint.checkpoint_sequence = 0;
    oversized_checkpoint.terminal_ref = "x".repeat(1_025);
    assert!(
        store
            .complete_worker_handoff_at(&tuple, &oversized_checkpoint, 5)
            .is_err()
    );

    let receipt = WorkerTerminalReceipt {
        status: WorkerTerminalStatus::Completed,
        checkpoint_sequence: MAX_WORKER_WIRE_INTEGER,
        terminal_ref: "terminal-ref".to_owned(),
        result_digest: "f".repeat(64),
    };
    let completion = store
        .complete_worker_handoff_at(&tuple, &receipt, 6)
        .expect("completion");
    drop(store);

    let owner =
        ascension_watchdog::storage::SingletonLock::acquire(&config.database).expect("owner lock");
    let mut reopened = Store::open_for_owner(&config.database, &config, &owner).expect("reopen");
    assert_eq!(
        reopened
            .worker_handoff(&claim.handoff_id)
            .expect("lookup")
            .expect("retained handoff")
            .state,
        WorkerHandoffState::Completed
    );
    let ack = reopened
        .acknowledge_worker_handoff_at(&tuple, &completion.terminal_digest, 7)
        .expect("ack after reopen");
    assert!(!ack.already_acknowledged);
    let repeated = reopened
        .acknowledge_worker_handoff_at(&tuple, &completion.terminal_digest, 8)
        .expect("repeated ack after reopen");
    assert!(repeated.already_acknowledged);
}
