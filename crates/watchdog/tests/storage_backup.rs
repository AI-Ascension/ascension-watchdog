use ascension_watchdog::{Store, WatchdogConfig};
use serde_json::json;

#[test]
fn backup_is_complete_and_never_overwrites_an_existing_destination() {
    let directory = tempfile::tempdir().unwrap();
    let config = WatchdogConfig {
        database: directory.path().join("state.sqlite"),
        ..WatchdogConfig::default()
    };
    let mut store = Store::initialize(&config.database, &config).unwrap();
    store
        .submit_job_at("episode", &json!({"private":"result"}), 1)
        .unwrap();
    let backup = directory.path().join("backup.sqlite");
    store.backup_to(&backup).unwrap();
    let snapshot =
        rusqlite::Connection::open_with_flags(&backup, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let count: i64 = snapshot
        .query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
    let integrity: String = snapshot
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    let original = std::fs::read(&backup).unwrap();
    assert!(store.backup_to(&backup).is_err());
    assert_eq!(std::fs::read(&backup).unwrap(), original);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
