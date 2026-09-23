//! Shared fixtures and witnesses for the worker-handoff storage suite.

#[allow(unused_imports)]
pub(super) use ascension_watchdog::config::{DesiredMode, WatchdogConfig};
#[allow(unused_imports)]
pub(super) use ascension_watchdog::storage::{
    MAX_WORKER_WIRE_INTEGER, Store, WORKER_HANDOFF_OPERATION, WORKER_HANDOFF_PAYLOAD_DIGEST,
    WORKER_HANDOFF_SCHEMA_DIGEST, WorkerBinding, WorkerClaimWitness, WorkerControlMode,
    WorkerControlWitness, WorkerHandoff, WorkerHandoffState, WorkerHandoffTuple,
    WorkerTerminalReceipt, WorkerTerminalStatus,
};
#[allow(unused_imports)]
pub(super) use serde_json::json;
#[allow(unused_imports)]
pub(super) use tempfile::TempDir;

pub(super) fn fixture(temp: &TempDir) -> (Store, WatchdogConfig) {
    let config = WatchdogConfig {
        database: temp.path().join("state.sqlite"),
        desired_mode: DesiredMode::Running,
        ..WatchdogConfig::default()
    };
    let store = Store::initialize(&config.database, &config).expect("initialize store");
    (store, config)
}

pub(super) fn binding(config: &WatchdogConfig) -> WorkerBinding {
    WorkerBinding {
        deployment_id: config.deployment_id.clone(),
        worker_owner_id: "harness-worker".to_owned(),
        worker_profile_digest: "a".repeat(64),
        release_digest: "b".repeat(64),
        config_digest: "d".repeat(64),
        schema_digest: WORKER_HANDOFF_SCHEMA_DIGEST.to_owned(),
    }
}

pub(super) fn control(binding: &WorkerBinding) -> WorkerControlWitness {
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

pub(super) fn claim_witness(
    binding: &WorkerBinding,
    control: &WorkerControlWitness,
) -> WorkerClaimWitness {
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

pub(super) fn with_reopened_replaced_pending_handoff(
    test: impl FnOnce(
        &mut Store,
        &WorkerBinding,
        &WorkerControlWitness,
        &WorkerControlWitness,
        &WorkerHandoff,
        &WorkerHandoffTuple,
    ),
) {
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
    let first_witness = claim_witness(&binding, &first_control);
    store
        .submit_job_at(WORKER_HANDOFF_OPERATION, &json!({}), 3)
        .expect("job");
    let claim = store
        .claim_next_worker_handoff(&first_witness, 3)
        .expect("claim")
        .expect("handoff");
    let tuple = claim.tuple();
    store
        .mark_worker_handoff_may_have_been_dispatched_at(&tuple, 4)
        .expect("dispatch marker");
    drop(store);

    let owner =
        ascension_watchdog::storage::SingletonLock::acquire(&config.database).expect("owner lock");
    let mut reopened = Store::open_for_owner(&config.database, &config, &owner).expect("reopen");
    let mut replacement = first_control.clone();
    "66666666-6666-4666-8666-666666666666".clone_into(&mut replacement.watchdog_boot_id);
    "77777777-7777-4777-8777-777777777777".clone_into(&mut replacement.worker_boot_id);
    replacement.mode = WorkerControlMode::Stopped;
    replacement.mode_sequence = 8;
    reopened
        .set_worker_control_at(&replacement, 5)
        .expect("replacement control");
    reopened
        .set_desired_mode_at(DesiredMode::Stopped, 6)
        .expect("durable stop");

    assert_eq!(
        reopened.current_worker_control().expect("control"),
        Some(replacement.clone())
    );
    assert_eq!(
        reopened
            .next_worker_handoff_for_reconciliation()
            .expect("pending")
            .expect("handoff")
            .tuple(),
        tuple
    );

    test(
        &mut reopened,
        &binding,
        &first_control,
        &replacement,
        &claim,
        &tuple,
    );
}
