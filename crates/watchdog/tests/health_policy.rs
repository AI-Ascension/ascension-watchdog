use ascension_watchdog::{
    ComponentObservation, ComponentState, DesiredMode, ReconcileAction, SupervisorPolicy,
    WatchdogConfig,
};

fn running_observation() -> ComponentObservation {
    ComponentObservation {
        component_id: "gateway".to_owned(),
        state: ComponentState::Running,
        observed_at_ms: 1_000,
        heartbeat_age_ms: Some(0),
        progress_age_ms: Some(0),
        consecutive_misses: 0,
        restart_attempts: 0,
    }
}

#[test]
fn missing_or_stale_heartbeat_cannot_report_running() {
    let policy = SupervisorPolicy::from_config(&WatchdogConfig::default());
    for age in [None, Some(6_001), Some(u64::MAX)] {
        let mut observation = running_observation();
        observation.heartbeat_age_ms = age;
        let result = policy.decide(DesiredMode::Running, true, &observation, 1_000, 0, None);
        assert_eq!(result.action, ReconcileAction::MarkSuspect);
        assert_eq!(result.resulting_state, ComponentState::Suspect);
    }
}

#[test]
fn unchanged_progress_alone_does_not_restart_valid_inference() {
    let policy = SupervisorPolicy::from_config(&WatchdogConfig::default());
    let mut observation = running_observation();
    observation.progress_age_ms = Some(120_000);
    let result = policy.decide(DesiredMode::Running, true, &observation, 1_000, 0, None);
    assert_eq!(result.action, ReconcileAction::Noop);
    assert_eq!(result.resulting_state, ComponentState::Running);
}

#[test]
fn durable_stop_precedes_even_a_fresh_heartbeat() {
    let policy = SupervisorPolicy::from_config(&WatchdogConfig::default());
    let result = policy.decide(
        DesiredMode::Stopped,
        true,
        &running_observation(),
        1_000,
        0,
        None,
    );
    assert_eq!(result.action, ReconcileAction::Stop);
}

#[cfg(target_os = "linux")]
#[test]
fn real_reconciler_retains_suspect_child_without_claiming_progress()
-> Result<(), Box<dyn std::error::Error>> {
    use ascension_watchdog::{ComponentConfig, Store, Supervisor};
    let directory = tempfile::tempdir()?;
    let config = WatchdogConfig {
        database: directory.path().join("state.sqlite"),
        desired_mode: DesiredMode::Running,
        allow_synthetic_children: true,
        components: vec![ComponentConfig {
            id: "synthetic".to_owned(),
            executable: "/bin/sleep".into(),
            args: vec!["30".to_owned()],
            cwd: None,
            environment: std::collections::BTreeMap::new(),
            executable_sha256: None,
            restart: true,
        }],
        ..WatchdogConfig::default()
    };
    let mut supervisor = Supervisor::initialize(config.clone())?;
    assert_eq!(supervisor.reconcile_once(1_000)?.started, ["synthetic"]);
    let pid = supervisor
        .child_identity("synthetic")
        .ok_or("missing exact child")?
        .pid;
    for now in [1_001, 1_002] {
        let report = supervisor.reconcile_once(now)?;
        assert!(report.started.is_empty());
        assert_eq!(report.decisions[0].resulting_state, ComponentState::Suspect);
        assert_eq!(
            supervisor
                .child_identity("synthetic")
                .ok_or("owned child was discarded")?
                .pid,
            pid,
        );
        let record = Store::open_read_only(&config.database, &config)?
            .component("synthetic")?
            .ok_or("missing component")?;
        assert_eq!(record.state, ComponentState::Suspect);
    }
    Ok(())
}
