use ascension_watchdog::storage::LaunchIntentState;
use ascension_watchdog::{DesiredMode, Store, WatchdogConfig};
use serde_json::json;

#[test]
fn nonrunning_intent_blocks_prepare_and_activation_across_reopen() {
    for mode in [
        DesiredMode::Stopped,
        DesiredMode::Paused,
        DesiredMode::Draining,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let config = WatchdogConfig {
            database: directory.path().join("state.sqlite"),
            desired_mode: DesiredMode::Running,
            ..WatchdogConfig::default()
        };
        let mut store = Store::initialize(&config.database, &config).unwrap();
        let intent = store
            .prepare_launch_intent(
                "gateway",
                "nonce",
                "watchdog-generation-1",
                &"a".repeat(64),
                Some("container"),
                1,
            )
            .unwrap();
        store.set_desired_mode_at(mode, 2).unwrap();
        // A stop must not erase evidence of a child created before the stop.
        store
            .record_launch_proof(&intent.id, &json!({"opaque":"retained"}), 3)
            .unwrap();
        drop(store);
        let mut store = Store::open(&config.database, &config).unwrap();
        assert!(store.activate_launch_intent(&intent.id, 4).is_err());
        assert!(
            store
                .prepare_launch_intent(
                    "harness",
                    "second",
                    "watchdog-generation-1",
                    &"a".repeat(64),
                    Some("other"),
                    5,
                )
                .is_err()
        );
        let retained = store.launch_intent(&intent.id).unwrap().unwrap();
        assert_eq!(retained.state, LaunchIntentState::ProofRecorded);
        assert_eq!(
            retained.ownership_proof_json,
            Some(json!({"opaque":"retained"}))
        );
        assert_eq!(store.unsettled_launch_intents().unwrap().len(), 1);
        // The process authority may still acknowledge verified cleanup.
        assert_eq!(
            store.clean_launch_intent(&intent.id, 6).unwrap().state,
            LaunchIntentState::Cleaned
        );
        assert_eq!(store.desired_mode().unwrap(), mode);
    }
}

#[test]
fn failed_admission_leaves_no_intent_and_explicit_resume_permits_it() {
    let directory = tempfile::tempdir().unwrap();
    let config = WatchdogConfig {
        database: directory.path().join("state.sqlite"),
        ..WatchdogConfig::default()
    };
    let mut store = Store::initialize(&config.database, &config).unwrap();
    assert!(
        store
            .prepare_launch_intent(
                "gateway",
                "nonce",
                "watchdog-generation-1",
                &"a".repeat(64),
                Some("container"),
                1,
            )
            .is_err()
    );
    assert!(store.unsettled_launch_intents().unwrap().is_empty());
    store.set_desired_mode_at(DesiredMode::Running, 2).unwrap();
    let intent = store
        .prepare_launch_intent(
            "gateway",
            "nonce",
            "watchdog-generation-1",
            &"a".repeat(64),
            Some("container"),
            3,
        )
        .unwrap();
    store
        .record_launch_proof(&intent.id, &json!({"opaque":"retained"}), 4)
        .unwrap();
    assert_eq!(
        store.activate_launch_intent(&intent.id, 5).unwrap().state,
        LaunchIntentState::Active
    );
}
