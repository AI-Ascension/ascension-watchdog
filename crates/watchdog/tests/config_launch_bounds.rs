use ascension_watchdog::config::{ComponentConfig, WatchdogConfig};
use std::collections::BTreeMap;

fn configuration() -> WatchdogConfig {
    WatchdogConfig {
        allow_synthetic_children: true,
        components: vec![ComponentConfig {
            id: "synthetic".to_owned(),
            executable: std::env::current_exe().unwrap(),
            args: Vec::new(),
            cwd: None,
            environment: BTreeMap::new(),
            executable_sha256: None,
            restart: false,
        }],
        ..WatchdogConfig::default()
    }
}

#[test]
fn debug_omits_argument_and_environment_contents() {
    let mut config = configuration();
    config.components[0]
        .args
        .push("private-argument-canary".to_owned());
    config.components[0].environment.insert(
        "PRIVATE_KEY_CANARY".to_owned(),
        "private-value-canary".to_owned(),
    );
    let diagnostic = format!("{config:?}");
    assert!(!diagnostic.contains("private-argument-canary"));
    assert!(!diagnostic.contains("PRIVATE_KEY_CANARY"));
    assert!(!diagnostic.contains("private-value-canary"));
}

#[test]
fn aggregate_launch_data_is_bounded_for_programmatic_configuration() {
    let mut config = configuration();
    assert!(config.validate().is_ok());
    config.components[0].args = vec!["x".repeat(8192); 5];
    assert!(config.validate().is_err());
    config.components[0].args.clear();
    for index in 0..5 {
        config.components[0]
            .environment
            .insert(format!("KEY_{index}"), "x".repeat(8192));
    }
    assert!(config.validate().is_err());
}

#[test]
fn environment_names_reject_unbounded_or_assignment_keys() {
    for key in ["x".repeat(129), "BAD=KEY".to_owned()] {
        let mut config = configuration();
        config.components[0]
            .environment
            .insert(key, "value".to_owned());
        assert!(config.validate().is_err());
    }
}
