//! Worker-digest independence and historical worker-binding retention.

use super::common::*;

#[test]
fn worker_digest_is_independent_and_historical_binding_never_falls_back() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (mut store, config) = fixture(&temp);
    let approved = binding(&config);
    let watchdog_digest = config.digest().expect("watchdog digest");
    assert_ne!(approved.config_digest, watchdog_digest);
    store
        .configure_worker_binding_at(&approved, 1)
        .expect("worker binding");
    let mut wrong = approved.clone();
    wrong.config_digest = watchdog_digest;
    assert!(store.configure_worker_binding_at(&wrong, 2).is_err());
    drop(store);
    let owner =
        ascension_watchdog::storage::SingletonLock::acquire(&config.database).expect("owner lock");
    let mut reopened = Store::open_for_owner(&config.database, &config, &owner).expect("reopen");
    assert_eq!(
        reopened.configure_worker_binding_at(&approved, 3).unwrap(),
        approved
    );
    assert!(reopened.configure_worker_binding_at(&wrong, 4).is_err());

    // Previously stored values are preserved verbatim, not silently relabeled
    // or upgraded to the newly configured harness digest.
    let legacy_temp = tempfile::tempdir().expect("legacy tempdir");
    let (mut legacy, legacy_config) = fixture(&legacy_temp);
    let mut historical = binding(&legacy_config);
    historical.config_digest = legacy_config.digest().unwrap();
    legacy.configure_worker_binding_at(&historical, 1).unwrap();
    assert!(
        legacy
            .configure_worker_binding_at(&binding(&legacy_config), 2)
            .is_err()
    );
    assert_eq!(
        legacy.configure_worker_binding_at(&historical, 3).unwrap(),
        historical
    );
}
