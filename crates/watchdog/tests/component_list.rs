use ascension_watchdog::storage::ComponentRecord;
use ascension_watchdog::{ComponentState, Store, Supervisor, WatchdogConfig};

fn record(id: &str, attempts: u32) -> ComponentRecord {
    ComponentRecord {
        id: id.to_owned(),
        state: ComponentState::Stopped,
        launch_nonce: None,
        pid: None,
        executable_digest: None,
        started_at_ms: None,
        restart_attempts: attempts,
        last_restart_at_ms: None,
        last_error: None,
    }
}

#[test]
fn components_lists_durable_records_in_identifier_order() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let config = WatchdogConfig {
        database: directory.path().join("state.sqlite"),
        ..WatchdogConfig::default()
    };
    drop(Supervisor::initialize(config.clone())?);
    let mut store = Store::open(&config.database, &config)?;
    store.upsert_component(&record("zeta", 3), 1)?;
    store.upsert_component(&record("alpha", 1), 1)?;

    let listed = store.components()?;
    let ids = listed
        .iter()
        .map(|record| record.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, ["alpha", "zeta"]);
    assert_eq!(listed[0].restart_attempts, 1);
    assert_eq!(listed[1].restart_attempts, 3);

    let read_only = Store::open_read_only(&config.database, &config)?;
    assert_eq!(read_only.components()?.len(), 2);
    Ok(())
}
