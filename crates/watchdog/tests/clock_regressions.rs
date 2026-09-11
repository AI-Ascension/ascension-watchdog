use ascension_watchdog::config::{DesiredMode, WatchdogConfig};
use ascension_watchdog::policy::{RestartBudget, SupervisorPolicy};
use ascension_watchdog::storage::Store;
use std::path::PathBuf;

#[test]
fn wall_clock_forward_jump_does_not_clear_persisted_restart_budget() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = WatchdogConfig {
        database: temp.path().join("watchdog.sqlite3"),
        deployment_id: "clock-regression".to_string(),
        desired_mode: DesiredMode::Running,
        allow_synthetic_children: true,
        ..WatchdogConfig::default()
    };
    let mut store = Store::initialize(&config.database, &config).expect("initialize");
    for _ in 0..5 {
        store
            .record_restart_with_elapsed("gateway", 100, 0, 600_000)
            .expect("restart record");
    }
    assert_eq!(
        store
            .restart_count("gateway", u64::MAX, 600_000)
            .expect("count"),
        5
    );
    drop(store);
    let reopened = Store::open(&config.database, &config).expect("reopen");
    assert_eq!(
        reopened
            .restart_count("gateway", 9_000_000_000, 600_000)
            .expect("persisted count"),
        5
    );
}

#[test]
fn only_explicit_monotonic_elapsed_observation_ages_current_epoch() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = WatchdogConfig {
        database: temp.path().join("watchdog.sqlite3"),
        deployment_id: "clock-regression".to_string(),
        desired_mode: DesiredMode::Running,
        allow_synthetic_children: true,
        ..WatchdogConfig::default()
    };
    let mut store = Store::initialize(&config.database, &config).expect("initialize");
    store
        .record_restart_with_elapsed("gateway", 100, 0, 600_000)
        .expect("restart record");
    assert_eq!(
        store
            .restart_count_with_elapsed("gateway", 600_001, 600_000)
            .expect("aged"),
        0
    );
    store
        .record_restart_with_elapsed("gateway", 101, 600_001, 600_000)
        .expect("new record");
    assert_eq!(
        store
            .restart_count_with_elapsed("gateway", 600_001, 600_000)
            .expect("count"),
        1
    );
}

#[test]
fn pure_restart_budget_clamps_backward_observations_and_stays_bounded() {
    let mut budget = RestartBudget::new(5, 600_000);
    for _ in 0..5 {
        budget.record(10);
    }
    assert!(!budget.admits_restart());
    assert_eq!(budget.observe(0), 5);
    assert_eq!(budget.count(), 5);

    let config = WatchdogConfig {
        database: PathBuf::from("/owner-local/clock-policy.sqlite3"),
        ..WatchdogConfig::default()
    };
    let policy = SupervisorPolicy::from_config(&config);
    assert!(policy.in_monotonic_restart_window(100, 100));
    assert!(!policy.in_monotonic_restart_window(600_101, 0));
}
