use ascension_watchdog::config::{AdminConfig, WatchdogConfig};

fn settings() -> (tempfile::TempDir, AdminConfig) {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = if cfg!(windows) {
        std::path::PathBuf::from(r"\\.\pipe\ascension-watchdog-test")
    } else {
        directory.path().join("admin.sock")
    };
    let admin = AdminConfig {
        endpoint,
        read_token_path: directory.path().join("read.token"),
        admin_token_path: directory.path().join("admin.token"),
        allowed_peer_sid: None,
    };
    (directory, admin)
}

#[test]
fn validation_does_not_open_or_create_credentials_or_endpoint() {
    let (directory, admin) = settings();
    let config = WatchdogConfig {
        admin: Some(admin),
        ..WatchdogConfig::default()
    };
    assert!(config.validate().is_ok());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn rejects_ambiguous_or_traversing_credential_references() {
    let (_directory, mut admin) = settings();
    admin.admin_token_path = admin.read_token_path.clone();
    assert!(admin.validate().is_err());
    admin.admin_token_path = admin.read_token_path.join("..").join("other");
    assert!(admin.validate().is_err());
}

#[test]
fn admin_config_is_closed_and_diagnostic_references_are_redacted() {
    let (_directory, admin) = settings();
    let mut value = serde_json::to_value(&admin).unwrap();
    value["raw_token"] = serde_json::json!("not-permitted");
    assert!(serde_json::from_value::<AdminConfig>(value).is_err());
    let debug = format!("{admin:?}");
    assert!(!debug.contains("read.token"));
    assert!(!debug.contains("admin.token"));
}
