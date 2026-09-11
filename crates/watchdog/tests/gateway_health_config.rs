use ascension_watchdog::config::{ComponentConfig, GatewayHealthConfig, WatchdogConfig};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn local(name: &str) -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\watchdog-health-config-fixture").join(name)
    } else {
        PathBuf::from("/watchdog-health-config-fixture").join(name)
    }
}

fn configured() -> WatchdogConfig {
    let health = GatewayHealthConfig {
        component_id: "gateway".to_owned(),
        address: "127.0.0.1:18701".parse().unwrap(),
        instance_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
        release_digest: "a".repeat(64),
        gateway_config_digest: "b".repeat(64),
        profile_digest: "c".repeat(64),
        runtime_v3_schema_digest: "d".repeat(64),
        timeout_ms: 2_000,
    };
    let deployment_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned();
    let environment = BTreeMap::from([
        ("STS2_GATEWAY_ADDR".to_owned(), health.address.to_string()),
        ("STS2_INSTANCE_ID".to_owned(), health.instance_id.clone()),
        ("STS2_DEPLOYMENT_ID".to_owned(), deployment_id.clone()),
        (
            "STS2_GATEWAY_WATCHDOG_HEALTH_BOOTSTRAP".to_owned(),
            "stdin-v1".to_owned(),
        ),
        (
            "STS2_RUNTIME_PROFILE".to_owned(),
            "watchdog-recovery-v1".to_owned(),
        ),
        (
            "STS2_RECOVERY_RELEASE_DIGEST".to_owned(),
            health.release_digest.clone(),
        ),
        (
            "STS2_RECOVERY_CONFIG_DIGEST".to_owned(),
            health.gateway_config_digest.clone(),
        ),
        (
            "STS2_RECOVERY_PROFILE_DIGEST".to_owned(),
            health.profile_digest.clone(),
        ),
        (
            "STS2_RECOVERY_RUNTIME_V3_SCHEMA_DIGEST".to_owned(),
            health.runtime_v3_schema_digest.clone(),
        ),
        (
            "STS2_RECOVERY_STORE".to_owned(),
            local("gateway.sqlite").to_str().unwrap().to_owned(),
        ),
    ]);
    WatchdogConfig {
        deployment_id,
        database: local("watchdog.sqlite"),
        components: vec![ComponentConfig {
            id: "gateway".to_owned(),
            executable: local("gateway"),
            args: Vec::new(),
            cwd: None,
            environment,
            executable_sha256: Some("e".repeat(64)),
            restart: true,
        }],
        gateway_health: Some(health),
        ..WatchdogConfig::default()
    }
}

#[test]
fn absent_health_preserves_serialized_defaults() {
    let config = WatchdogConfig::default();
    assert!(config.gateway_health.is_none());
    assert!(
        serde_json::to_value(config)
            .unwrap()
            .get("gateway_health")
            .is_none()
    );
}

#[test]
fn approved_health_is_pure_and_binds_a_fresh_launch() {
    let config = configured();
    config.validate().unwrap();
    let digest = config.digest().unwrap();
    let nonce = uuid::Uuid::new_v4();
    let binding = config
        .gateway_health
        .as_ref()
        .unwrap()
        .binding(&config.deployment_id, nonce)
        .unwrap();
    assert_eq!(binding.launch_nonce, nonce);
    assert_eq!(binding.config_digest, "b".repeat(64));
    assert_eq!(config.digest().unwrap(), digest);
    assert!(!config.database.exists());
}

#[test]
fn mismatched_launch_environment_and_static_nonce_are_rejected() {
    for name in [
        "STS2_GATEWAY_ADDR",
        "STS2_RECOVERY_CONFIG_DIGEST",
        "STS2_RUNTIME_PROFILE",
    ] {
        let mut config = configured();
        config.components[0]
            .environment
            .insert(name.to_owned(), "wrong".to_owned());
        assert!(config.validate().is_err());
    }
    for name in [
        "STS2_GATEWAY_WATCHDOG_LAUNCH_NONCE",
        "sts2_gateway_watchdog_launch_nonce",
        "sts2_gateway_addr",
    ] {
        let mut config = configured();
        config.components[0]
            .environment
            .insert(name.to_owned(), "not-authority".to_owned());
        assert!(config.validate().is_err());
    }
}

#[test]
fn endpoint_deadline_and_unconfigured_digest_fail_closed() {
    for address in ["0.0.0.0:18701", "127.0.0.1:0", "192.0.2.1:18701"] {
        let mut config = configured();
        config.gateway_health.as_mut().unwrap().address = address.parse().unwrap();
        assert!(config.validate().is_err());
    }
    for timeout in [0, 2_001] {
        let mut config = configured();
        config.gateway_health.as_mut().unwrap().timeout_ms = timeout;
        assert!(config.validate().is_err());
    }
    let mut config = configured();
    config.gateway_health.as_mut().unwrap().release_digest = "0".repeat(64);
    config.components[0]
        .environment
        .insert("STS2_RECOVERY_RELEASE_DIGEST".to_owned(), "0".repeat(64));
    assert!(config.validate().is_err());
}

#[test]
fn health_config_is_closed_and_cannot_serialize_launch_secrets() {
    let config = configured();
    let mut value = serde_json::to_value(&config).unwrap();
    value["gateway_health"]["key"] = serde_json::json!("forbidden");
    assert!(serde_json::from_value::<WatchdogConfig>(value).is_err());
    let health = config.gateway_health.as_ref().unwrap();
    let encoded = serde_json::to_string(health).unwrap();
    assert!(!encoded.contains("launch_nonce"));
    let duplicate = encoded.replace(
        "\"timeout_ms\":2000",
        "\"timeout_ms\":2000,\"timeout_ms\":2000",
    );
    assert_ne!(encoded, duplicate);
    assert!(serde_json::from_str::<GatewayHealthConfig>(&duplicate).is_err());
}

#[test]
fn health_stores_require_separate_absolute_bounded_paths() {
    for path in [
        configured().database.to_str().unwrap().to_owned(),
        "relative.sqlite".to_owned(),
        local("../gateway.sqlite").to_str().unwrap().to_owned(),
        local("./gateway.sqlite").to_str().unwrap().to_owned(),
        local("gateway\n.sqlite").to_str().unwrap().to_owned(),
        local(&"x".repeat(4097)).to_str().unwrap().to_owned(),
    ] {
        let mut config = configured();
        config.components[0]
            .environment
            .insert("STS2_RECOVERY_STORE".to_owned(), path);
        assert!(config.validate().is_err());
    }
    let mut config = configured();
    config.database = PathBuf::from("relative.sqlite");
    assert!(config.validate().is_err());
}

#[test]
fn gateway_launch_bounds_reserve_the_runtime_nonce() {
    let mut config = configured();
    let component = &mut config.components[0];
    while component.environment.len() < 63 {
        component.environment.insert(
            format!("FIXTURE_{}", component.environment.len()),
            "value".to_owned(),
        );
    }
    config.validate().unwrap();
    config.components[0]
        .environment
        .insert("ONE_TOO_MANY".to_owned(), "value".to_owned());
    assert!(config.validate().is_err());

    let mut config = configured();
    let component = &mut config.components[0];
    component.args = vec!["a".repeat(8 * 1024); 3];
    let used = component.args.iter().map(String::len).sum::<usize>()
        + component
            .environment
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>();
    let dynamic = "STS2_GATEWAY_WATCHDOG_LAUNCH_NONCE".len() + 36;
    component.args.push("a".repeat(32 * 1024 - used - dynamic));
    config.validate().unwrap();
    config.components[0].args.last_mut().unwrap().push('a');
    assert!(config.validate().is_err());
}

#[cfg(unix)]
#[test]
fn health_stores_reject_pseudo_files_and_shared_references() {
    for path in [
        "/dev/null",
        "/proc/self/mem",
        "/sys/state",
        "//server/share/state",
        "/mnt/c/state",
    ] {
        let mut config = configured();
        config.components[0]
            .environment
            .insert("STS2_RECOVERY_STORE".to_owned(), path.to_owned());
        assert!(config.validate().is_err());
        let mut config = configured();
        config.database = PathBuf::from(path);
        assert!(config.validate().is_err());
    }
}

#[cfg(windows)]
#[test]
fn health_stores_reject_windows_aliases() {
    for path in [
        r"C:/WATCHDOG-HEALTH-CONFIG-FIXTURE/WATCHDOG.SQLITE",
        r"C:\watchdog-health-config-fixture\watchdog.sqlite.",
        r"C:\watchdog-health-config-fixture\gateway.sqlite:stream",
        r"C:\watchdog-health-config-fixture\.\gateway.sqlite",
        r"\\server\share\gateway.sqlite",
        r"\\?\C:\watchdog-health-config-fixture\gateway.sqlite",
    ] {
        let mut config = configured();
        config.components[0]
            .environment
            .insert("STS2_RECOVERY_STORE".to_owned(), path.to_owned());
        assert!(config.validate().is_err());
    }
}
