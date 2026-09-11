use ascension_watchdog::{WatchdogConfig, storage::Store};

#[test]
fn corrupt_or_exhausted_progress_never_resets_or_partially_commits()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = WatchdogConfig {
        database: directory.path().join("state.sqlite"),
        ..WatchdogConfig::default()
    };
    let mut store = Store::initialize(&config.database, &config)?;
    store.record_reconciliation_progress(100)?;
    let fault = rusqlite::Connection::open(&config.database)?;
    for invalid in ["-1", "0", "corrupt", "9223372036854775807"] {
        fault.execute(
            "UPDATE metadata SET value=? WHERE key='reconciliation_sequence'",
            [invalid],
        )?;
        assert!(store.record_reconciliation_progress(200).is_err());
        let retained: String = fault.query_row(
            "SELECT value FROM metadata WHERE key='reconciliation_sequence'",
            [],
            |row| row.get(0),
        )?;
        let timestamp: String = fault.query_row(
            "SELECT value FROM metadata WHERE key='last_reconciled_at_ms'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(retained, invalid);
        assert_eq!(timestamp, "100");
    }
    fault.execute(
        "DELETE FROM metadata WHERE key='reconciliation_sequence'",
        [],
    )?;
    assert!(store.record_reconciliation_progress(200).is_err());
    Ok(())
}

#[test]
fn second_progress_write_failure_rolls_back_sequence() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = WatchdogConfig {
        database: directory.path().join("state.sqlite"),
        ..WatchdogConfig::default()
    };
    let mut store = Store::initialize(&config.database, &config)?;
    store.record_reconciliation_progress(100)?;
    let fault = rusqlite::Connection::open(&config.database)?;
    fault.execute_batch("CREATE TRIGGER fail_timestamp BEFORE UPDATE ON metadata WHEN NEW.key='last_reconciled_at_ms' BEGIN SELECT RAISE(ABORT, 'synthetic write failure'); END;")?;
    assert!(store.record_reconciliation_progress(200).is_err());
    let sequence: String = fault.query_row(
        "SELECT value FROM metadata WHERE key='reconciliation_sequence'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(sequence, "1");
    Ok(())
}
