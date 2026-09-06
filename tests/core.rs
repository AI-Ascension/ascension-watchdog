use ascension_watchdog::config::{ComponentConfig, DesiredMode, WatchdogConfig};
use ascension_watchdog::error::WatchdogError;
use ascension_watchdog::policy::{
    ComponentObservation, ComponentState, ReconcileAction, SupervisorPolicy,
};
use ascension_watchdog::runtime::Supervisor;
use ascension_watchdog::storage::{JobStatus, SingletonLock, Store};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

fn config(temp: &TempDir) -> WatchdogConfig {
    WatchdogConfig {
        database: temp.path().join("watchdog.sqlite3"),
        deployment_id: "test-deployment".to_string(),
        desired_mode: DesiredMode::Running,
        allow_synthetic_children: true,
        ..WatchdogConfig::default()
    }
}

fn shell_component(id: &str, command: &str) -> ComponentConfig {
    ComponentConfig {
        id: id.to_string(),
        executable: PathBuf::from("/bin/sh"),
        args: vec!["-c".to_string(), command.to_string()],
        cwd: None,
        environment: BTreeMap::default(),
        executable_sha256: None,
        restart: true,
    }
}

#[test]
fn store_is_explicitly_initialized_and_wal_full() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = config(&temp);
    let missing =
        Store::open(&config.database, &config).expect_err("missing state must not initialize");
    assert!(matches!(missing, WatchdogError::MissingState(_)));

    let mut store = Store::initialize(&config.database, &config).expect("initialize");
    assert!(store.durability().expect("pragmas").is_wal_full());
    assert!(store.integrity_check().expect("integrity"));
    assert_eq!(
        store.status().expect("status").desired_mode,
        DesiredMode::Running
    );
    assert!(matches!(
        Store::initialize(&config.database, &config),
        Err(WatchdogError::Conflict(_))
    ));

    store
        .set_desired_mode_at(DesiredMode::Stopped, 10)
        .expect("persist stop");
    assert_eq!(store.desired_mode().expect("mode"), DesiredMode::Stopped);
}

#[test]
fn claims_and_completion_are_atomic_and_idempotent() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = config(&temp);
    let mut store = Store::initialize(&config.database, &config).expect("initialize");
    let job = store
        .submit_job_at("synthetic", &json!({"value": 7}), 100)
        .expect("submit");
    let claim = store
        .claim_next_job("worker-a", 101)
        .expect("claim")
        .expect("one claim");
    assert_eq!(claim.job.id, job.id);
    assert_eq!(claim.job.attempt_count, 1);
    assert!(
        store
            .claim_next_job("worker-b", 102)
            .expect("second claim")
            .is_none()
    );

    let completion = store
        .complete_job_at(&job.id, &claim.attempt_id, &json!({"ok": true}), 200)
        .expect("complete");
    assert!(!completion.already_completed);
    let duplicate = store
        .complete_job_at(&job.id, &claim.attempt_id, &json!({"ok": true}), 201)
        .expect("idempotent completion");
    assert!(duplicate.already_completed);
    assert_eq!(
        store.get_job(&job.id).expect("job").expect("row").status,
        JobStatus::Completed
    );
    assert_eq!(store.status().expect("status").jobs_completed, 1);
}

#[test]
fn failed_job_without_retry_is_quarantined_and_wrong_completion_attempt_is_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = config(&temp);
    let mut store = Store::initialize(&config.database, &config).expect("initialize");
    let job = store
        .submit_job_at("synthetic", &json!({}), 10)
        .expect("submit");
    let claim = store
        .claim_next_job("worker-a", 11)
        .expect("claim")
        .expect("claim exists");
    assert!(matches!(
        store.complete_job_at(&job.id, "wrong-attempt", &json!({"ok": true}), 12),
        Err(WatchdogError::Conflict(_))
    ));
    assert_eq!(
        store
            .fail_job_at(&job.id, &claim.attempt_id, "known failure", None, 13)
            .expect("quarantine failure"),
        JobStatus::Quarantined
    );
    assert_eq!(
        store.get_job(&job.id).expect("job").expect("row").status,
        JobStatus::Quarantined
    );
}

#[test]
fn backup_restore_reestablishes_wal_full_and_rekeys_generation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = config(&temp);
    let mut store = Store::initialize(&config.database, &config).expect("initialize");
    let job = store
        .submit_job_at("synthetic", &json!({"value": 1}), 10)
        .expect("submit");
    let backup = temp.path().join("watchdog.backup.sqlite3");
    store.backup_to(&backup).expect("backup");
    let restored_path = temp.path().join("restored.sqlite3");
    let mut restored_config = config.clone();
    restored_config.database = restored_path.clone();
    let restored = Store::restore_from(&backup, &restored_path, &restored_config).expect("restore");
    assert!(restored.durability().expect("pragmas").is_wal_full());
    assert!(restored.status().expect("status").restart_generation > 1);
    assert_eq!(
        restored.get_job(&job.id).expect("job").expect("row").id,
        job.id
    );
}

#[test]
fn interruption_is_quarantined_and_not_requeued() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = config(&temp);
    let mut store = Store::initialize(&config.database, &config).expect("initialize");
    let job = store
        .submit_job_at("synthetic", &json!({}), 1)
        .expect("submit");
    let claim = store
        .claim_next_job("worker-a", 2)
        .expect("claim")
        .expect("claim exists");
    assert_eq!(claim.job.id, job.id);
    assert_eq!(store.quarantine_interrupted_jobs(3).expect("quarantine"), 1);
    assert_eq!(
        store.get_job(&job.id).expect("job").expect("row").status,
        JobStatus::Quarantined
    );
    assert!(
        store
            .claim_next_job("worker-b", 4)
            .expect("no rerun")
            .is_none()
    );
}

#[test]
fn lock_allows_one_controller() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("watchdog.sqlite3");
    let first = SingletonLock::acquire(&path).expect("first lock");
    assert!(matches!(
        SingletonLock::acquire(&path),
        Err(WatchdogError::Busy(_))
    ));
    drop(first);
    assert!(SingletonLock::acquire(&path).is_ok());
}

#[test]
fn policy_is_deterministic_and_respects_stop_and_budget() {
    let config = WatchdogConfig {
        database: PathBuf::from("/tmp/watchdog-policy.sqlite3"),
        ..WatchdogConfig::default()
    };
    let policy = SupervisorPolicy::from_config(&config);
    let stopped = ComponentObservation::stopped("gateway", 0);
    let decision = policy.decide(DesiredMode::Stopped, true, &stopped, 0, 0, None);
    assert_eq!(decision.action, ReconcileAction::Noop);
    let start = policy.decide(DesiredMode::Running, true, &stopped, 0, 0, None);
    assert_eq!(start.action, ReconcileAction::Start);
    let blocked = policy.decide(DesiredMode::Running, true, &stopped, 0, 5, None);
    assert_eq!(blocked.resulting_state, ComponentState::Quarantined);
    assert_eq!(
        policy.backoff_delay_ms("gateway", 3),
        policy.backoff_delay_ms("gateway", 3)
    );
}

#[test]
fn real_subprocess_crash_restarts_and_durable_stop_survives_reopen() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut config = config(&temp);
    config.components = vec![shell_component("synthetic", "sleep 0.05")];
    config.validate().expect("config");
    let mut supervisor = Supervisor::initialize(config.clone()).expect("initialize");
    let first = supervisor.reconcile_once(1_000).expect("first reconcile");
    assert_eq!(first.started, vec!["synthetic"]);
    let first_pid = supervisor
        .child_identity("synthetic")
        .expect("identity")
        .pid;
    std::thread::sleep(Duration::from_millis(100));
    let second = supervisor.reconcile_once(5_000).expect("crash reconcile");
    assert_eq!(second.started, vec!["synthetic"]);
    let second_pid = supervisor
        .child_identity("synthetic")
        .expect("replacement")
        .pid;
    assert_ne!(first_pid, second_pid);

    {
        let mut store = Store::open(&config.database, &config).expect("store");
        store
            .set_desired_mode_at(DesiredMode::Stopped, 6_000)
            .expect("durable stop");
    }
    let stopped = supervisor.reconcile_once(6_001).expect("stop reconcile");
    assert_eq!(stopped.desired_mode, DesiredMode::Stopped);
    assert!(supervisor.child_identity("synthetic").is_none());
    drop(supervisor);

    let reopened = Supervisor::open(config).expect("reopen");
    assert_eq!(
        reopened.status().expect("status").desired_mode,
        DesiredMode::Stopped
    );
}
