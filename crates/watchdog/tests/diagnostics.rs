use ascension_watchdog::{Supervisor, WatchdogConfig, cli};
use serde_json::Value;

#[test]
fn diagnostics_is_bounded_and_read_only() -> ascension_watchdog::Result<()> {
    let directory = tempfile::tempdir()?;
    let config_path = directory.path().join("watchdog.json");
    let config = WatchdogConfig {
        database: directory.path().join("watchdog.sqlite3"),
        ..WatchdogConfig::default()
    };
    config.to_file(&config_path)?;
    let supervisor = Supervisor::initialize(config.clone())?;
    let before = supervisor.status()?;
    drop(supervisor);

    let output = cli::execute(vec![
        "diagnostics".to_owned(),
        "--config".to_owned(),
        config_path.to_string_lossy().into_owned(),
    ])?
    .ok_or_else(|| ascension_watchdog::WatchdogError::Conflict("missing diagnostics".to_owned()))?;
    let diagnostics: Value = serde_json::from_str(&output)?;
    assert_eq!(diagnostics["diagnostics_version"], 1);
    assert_eq!(diagnostics["config_valid"], true);
    assert_eq!(diagnostics["initialized"], true);
    assert_eq!(diagnostics["integrity_ok"], true);
    assert_eq!(diagnostics["deployment_id"], before.deployment_id);
    assert_eq!(diagnostics["restart_generation"], before.restart_generation);
    assert_eq!(diagnostics["jobs"]["queued"], before.jobs_queued);
    assert_eq!(diagnostics["operator_receipts_retained"], 0);
    assert!(diagnostics.get("payload").is_none());
    assert!(diagnostics.get("result").is_none());

    let reopened = ascension_watchdog::storage::Store::open_read_only(&config.database, &config)?;
    assert_eq!(reopened.status()?, before);
    Ok(())
}
