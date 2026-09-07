use ascension_watchdog::{DesiredMode, Store, WatchdogConfig};
use serde_json::json;

#[test]
fn job_insert_rolls_back_when_its_audit_cannot_commit() {
    let directory = tempfile::tempdir().unwrap();
    let config = WatchdogConfig {
        database: directory.path().join("state.sqlite"),
        ..WatchdogConfig::default()
    };
    let mut store = Store::initialize(&config.database, &config).unwrap();
    let fault = rusqlite::Connection::open(&config.database).unwrap();
    fault.execute_batch("CREATE TRIGGER reject_job_audit BEFORE INSERT ON audit WHEN NEW.action='job_submitted' BEGIN SELECT RAISE(ABORT, 'synthetic audit persistence failure'); END;").unwrap();
    assert!(store.submit_job_at("episode", &json!({}), 1).is_err());
    assert!(store.job_summaries(None, 1).unwrap().jobs.is_empty());
    fault
        .execute_batch("DROP TRIGGER reject_job_audit;")
        .unwrap();
    store.submit_job_at("episode", &json!({}), 2).unwrap();
    assert_eq!(store.job_summaries(None, 1).unwrap().jobs.len(), 1);
}

#[test]
fn summaries_filter_before_limit_and_never_export_private_values() {
    let directory = tempfile::tempdir().unwrap();
    let config = WatchdogConfig {
        database: directory.path().join("state.sqlite"),
        desired_mode: DesiredMode::Running,
        ..WatchdogConfig::default()
    };
    let mut store = Store::initialize(&config.database, &config).unwrap();
    store
        .submit_job_at("episode", &json!({"secret": "private-payload"}), 1)
        .unwrap();
    let claim = store.claim_next_job("private-worker", 2).unwrap().unwrap();
    store
        .complete_job_at(
            &claim.job.id,
            &claim.attempt_id,
            &json!({"secret":"private-result"}),
            3,
        )
        .unwrap();
    for time in 4..7 {
        store.submit_job_at("episode", &json!({}), time).unwrap();
    }
    let page = store
        .job_summaries(Some(ascension_watchdog::JobStatus::Queued), 2)
        .unwrap();
    assert_eq!(page.jobs.len(), 2);
    assert!(page.truncated);
    assert!(
        page.jobs
            .iter()
            .all(|job| job.status == ascension_watchdog::JobStatus::Queued)
    );
    let completed = store
        .job_summaries(Some(ascension_watchdog::JobStatus::Completed), 2)
        .unwrap();
    assert_eq!(completed.jobs.len(), 1);
    assert!(!completed.truncated);
    let attempt = store.attempt_summary(&claim.attempt_id).unwrap().unwrap();
    assert_eq!(attempt.status, "completed");
    assert_eq!(attempt.finished_at_ms, Some(3));
    let output = format!(
        "{}{}",
        serde_json::to_string(&completed).unwrap(),
        serde_json::to_string(&attempt).unwrap()
    );
    assert!(!output.contains("private"));
    assert!(store.job_summaries(None, 0).is_err());
    assert!(store.job_summaries(None, 257).is_err());
}

#[test]
fn production_cli_rejects_direct_job_writes_before_opening_state() {
    let directory = tempfile::tempdir().unwrap();
    let config = WatchdogConfig {
        database: directory.path().join("missing.sqlite"),
        ..WatchdogConfig::default()
    };
    let path = directory.path().join("config.json");
    config.to_file(&path).unwrap();
    for command in ["submit", "claim", "complete", "fail"] {
        let result = ascension_watchdog::cli::execute(vec![
            "job".to_owned(),
            command.to_owned(),
            "--config".to_owned(),
            path.to_string_lossy().into_owned(),
        ]);
        assert!(matches!(
            result,
            Err(ascension_watchdog::WatchdogError::Unauthorized(_))
        ));
    }
    assert!(!config.database.exists());
}
