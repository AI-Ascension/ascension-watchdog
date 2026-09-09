// SPDX-License-Identifier: MIT

use ascension_watchdog::config::{AdminConfig, ComponentConfig, WatchdogConfig, WorkerConfig};
use ascension_watchdog::worker_protocol::SCHEMA_DIGEST;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn local(name: &str) -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\watchdog-config-only-fixture").join(name)
    } else {
        PathBuf::from("/watchdog-config-only-fixture").join(name)
    }
}

fn endpoint() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(ascension_watchdog::worker_endpoint::WINDOWS_NAMESPACE)
    } else {
        local("ipc")
    }
}

fn configured() -> WatchdogConfig {
    WatchdogConfig {
        components: vec![ComponentConfig {
            id: "harness".to_owned(),
            executable: local("harness"),
            args: Vec::new(),
            cwd: None,
            environment: BTreeMap::from([(
                "STS2_WORKER_ENDPOINT_NAMESPACE".to_owned(),
                endpoint().to_str().unwrap().to_owned(),
            )]),
            executable_sha256: Some("a".repeat(64)),
            restart: true,
        }],
        worker: Some(WorkerConfig {
            component_id: "harness".to_owned(),
            endpoint_namespace: endpoint(),
            credential_path: local("worker-credential"),
            allowed_peer_sid: None,
            worker_profile_digest: "b".repeat(64),
            release_digest: "c".repeat(64),
            worker_config_digest: "d".repeat(64),
            schema_digest: SCHEMA_DIGEST.to_owned(),
            timeout_ms: 5000,
        }),
        ..WatchdogConfig::default()
    }
}

#[test]
fn legacy_fixed_endpoint_is_rejected_and_resolution_does_not_mutate_config() {
    let config = configured();
    let before = config.digest().unwrap();
    let worker = config.worker.as_ref().unwrap();
    let first = worker
        .endpoint_for_launch("12345678-1234-4234-8234-123456789abc")
        .unwrap();
    let second = worker
        .endpoint_for_launch("22345678-1234-4234-8234-123456789abc")
        .unwrap();
    assert_ne!(first, second);
    assert_eq!(config.digest().unwrap(), before);
    let mut encoded = serde_json::to_value(&config).unwrap();
    let object = encoded.get_mut("worker").unwrap().as_object_mut().unwrap();
    let namespace = object.remove("endpoint_namespace").unwrap();
    object.insert("endpoint".to_owned(), namespace);
    assert!(serde_json::from_value::<WatchdogConfig>(encoded).is_err());
}

#[test]
fn absent_worker_remains_disabled_and_does_not_change_serialized_defaults() {
    let config = WatchdogConfig::default();
    assert!(config.worker.is_none());
    let encoded = serde_json::to_value(&config).unwrap();
    assert!(encoded.get("worker").is_none());
    let decoded: WatchdogConfig = serde_json::from_value(encoded).unwrap();
    assert!(decoded.worker.is_none());
    assert!(decoded.worker_binding().unwrap().is_none());
}

#[test]
fn worker_namespace_requires_exact_launch_environment_without_legacy_aliases() {
    let config = configured();
    config.validate().unwrap();
    let before = config.digest().unwrap();
    for key in [
        "STS2_WORKER_ENDPOINT",
        "sts2_worker_endpoint",
        "sts2_worker_endpoint_namespace",
    ] {
        let mut invalid = config.clone();
        invalid.components[0]
            .environment
            .insert(key.to_owned(), String::new());
        assert!(invalid.validate().is_err());
    }
    let mut invalid = config.clone();
    invalid.components[0].environment.clear();
    assert!(invalid.validate().is_err());
    invalid.components[0].environment.insert(
        "STS2_WORKER_ENDPOINT_NAMESPACE".to_owned(),
        "different-namespace".to_owned(),
    );
    assert!(invalid.validate().is_err());
    assert_eq!(config.digest().unwrap(), before);
}

#[cfg(windows)]
#[test]
fn worker_config_and_transport_share_exact_pipe_namespace() {
    let mut config = configured();
    config.validate().unwrap();
    let name = config
        .worker
        .as_ref()
        .unwrap()
        .endpoint_for_launch("12345678-1234-4234-8234-123456789abc")
        .unwrap();
    ascension_platform_windows::AdminPipeClient::validate_worker_endpoint(name.to_str().unwrap())
        .unwrap();
    for rejected in [
        r"\\.\pipe\ascension-watchdog-worker-fixture",
        r"\\.\pipe\ascension-worker-12345678-1234-3234-8234-123456789abc",
        r"\\.\pipe\ascension-worker-12345678-1234-4234-7234-123456789abc",
        r"\\.\pipe\ascension-worker-12345678-1234-4234-8234-123456789abc\extra",
    ] {
        config.worker.as_mut().unwrap().endpoint_namespace = PathBuf::from(rejected);
        assert!(config.validate().is_err(), "accepted {rejected}");
        assert!(
            ascension_platform_windows::AdminPipeClient::validate_worker_endpoint(rejected)
                .is_err()
        );
    }
}

#[cfg(windows)]
#[test]
fn derived_worker_endpoint_constructs_client_and_rejects_admin_namespace()
-> Result<(), Box<dyn std::error::Error>> {
    use ascension_watchdog::worker_client::{WorkerClientConfig, WorkerPeerIdentity};
    let config = configured();
    let worker = config.worker.as_ref().unwrap();
    let binding = config.worker_binding()?.unwrap();
    let peer = WorkerPeerIdentity::new(local("harness"), "a".repeat(64), 1, "1")?
        .with_windows_account("S-1-5-18".to_owned(), 0)?;
    let directory = tempfile::tempdir()?;
    let credential = directory.path().join("synthetic-credential");
    std::fs::write(&credential, b"synthetic-test-credential")?;
    let status = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            r"
$ErrorActionPreference = 'Stop'
$securityModule = Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1'
Import-Module -Name $securityModule -Force -ErrorAction Stop
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [System.Security.AccessControl.FileSecurity]::new()
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $env:ASCENSION_TEST_CREDENTIAL_PATH -AclObject $acl
            ",
        ])
        .env("ASCENSION_TEST_CREDENTIAL_PATH", &credential)
        .status()?;
    assert!(
        status.success(),
        "protect only the synthetic credential fixture"
    );
    let endpoint = worker.endpoint_for_launch("12345678-1234-4234-8234-123456789abc")?;
    let _client =
        WorkerClientConfig::new(endpoint, credential.clone(), binding.clone(), peer.clone())?;
    assert!(
        WorkerClientConfig::new(
            PathBuf::from(r"\\.\pipe\ascension-watchdog-admin-fixture"),
            credential,
            binding,
            peer
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn worker_binding_uses_harness_digest_and_configured_component_owner() {
    let config = configured();
    let binding = config.worker_binding().unwrap().unwrap();
    assert_eq!(binding.worker_owner_id, "harness");
    assert_eq!(binding.deployment_id, config.deployment_id);
    assert_eq!(binding.config_digest, "d".repeat(64));
    assert_ne!(binding.config_digest, config.digest().unwrap());
    let mut invalid = config;
    invalid.worker.as_mut().unwrap().component_id = "caller-selected".into();
    assert!(invalid.worker_binding().is_err());
}

#[test]
fn worker_validation_is_pure_and_requires_exact_component_and_hash() {
    let config = configured();
    config.validate().unwrap();
    let mut missing = config.clone();
    missing.components.clear();
    assert!(missing.validate().is_err());
    let mut duplicate = config.clone();
    duplicate.components.push(duplicate.components[0].clone());
    assert!(duplicate.validate().is_err());
    let mut unpinned = config.clone();
    unpinned.allow_synthetic_children = true;
    unpinned.components[0].executable_sha256 = None;
    assert!(unpinned.validate().is_err());
    let mut wrong_role = config;
    wrong_role.worker.as_mut().unwrap().component_id = "gateway".into();
    assert!(wrong_role.validate().is_err());
}

#[test]
fn worker_binding_is_closed_and_all_digest_and_deadline_fields_are_checked() {
    let original = serde_json::to_value(configured()).unwrap();
    for (field, value) in [
        ("worker_profile_digest", serde_json::json!("A".repeat(64))),
        ("release_digest", serde_json::json!("short")),
        ("worker_config_digest", serde_json::json!("g".repeat(64))),
        ("schema_digest", serde_json::json!("e".repeat(64))),
        ("timeout_ms", serde_json::json!(0)),
        ("timeout_ms", serde_json::json!(5001)),
    ] {
        let mut value_config = original.clone();
        value_config["worker"][field] = value;
        let config: WatchdogConfig = serde_json::from_value(value_config).unwrap();
        assert!(config.validate().is_err(), "accepted {field}");
    }
    let mut unknown = original;
    unknown["worker"]["worker_boot_id"] = serde_json::json!("configured-stale-boot");
    assert!(serde_json::from_value::<WatchdogConfig>(unknown).is_err());
}

#[test]
fn credential_references_are_absolute_nontraversing_and_debug_redacted() {
    let mut config = configured();
    let debug = format!("{config:?}");
    assert!(!debug.contains("worker-credential"));
    config.worker.as_mut().unwrap().credential_path = PathBuf::from("relative-secret");
    assert!(config.validate().is_err());
    config.worker.as_mut().unwrap().credential_path = local("nested/../secret");
    assert!(config.validate().is_err());
    config.worker.as_mut().unwrap().credential_path = local("bad\nsecret");
    assert!(config.validate().is_err());
}

#[test]
fn worker_credential_cannot_reuse_operator_credentials() {
    let mut config = configured();
    config.admin = Some(AdminConfig {
        endpoint: if cfg!(windows) {
            r"\\.\pipe\ascension-watchdog-admin-fixture".into()
        } else {
            local("admin.sock")
        },
        read_token_path: local("operator-read"),
        admin_token_path: local("operator-write"),
        allowed_peer_sid: None,
    });
    config.validate().unwrap();
    for path in [local("operator-read"), local("operator-write")] {
        config.worker.as_mut().unwrap().credential_path = path;
        assert!(config.validate().is_err());
    }
}

#[test]
fn worker_binding_changes_the_approved_configuration_digest() {
    let config = configured();
    let initial = config.digest().unwrap();
    let mut changed = config;
    changed.worker.as_mut().unwrap().worker_profile_digest = "e".repeat(64);
    assert_ne!(initial, changed.digest().unwrap());
}

#[test]
fn duplicate_worker_fields_and_configured_authority_are_rejected() {
    let worker = serde_json::to_string(configured().worker.as_ref().unwrap()).unwrap();
    let duplicate = worker.replacen('{', "{\"timeout_ms\":1,", 1);
    assert!(serde_json::from_str::<WorkerConfig>(&duplicate).is_err());
    for field in ["watchdog_boot_id", "lease_id", "authority_generation"] {
        let mut worker = serde_json::to_value(configured().worker.unwrap()).unwrap();
        worker[field] = serde_json::json!("stale-authority");
        assert!(serde_json::from_value::<WorkerConfig>(worker).is_err());
    }
}

#[cfg(unix)]
#[test]
fn unix_worker_references_reject_pseudo_files_and_oversized_endpoints() {
    for path in ["/dev/null", "/proc/self/mem", "/sys/kernel/security"] {
        let mut config = configured();
        config.worker.as_mut().unwrap().credential_path = path.into();
        assert!(config.validate().is_err());
    }
    let mut config = configured();
    config.worker.as_mut().unwrap().endpoint_namespace = local(&"x".repeat(101));
    assert!(config.validate().is_err());
    config.worker.as_mut().unwrap().endpoint_namespace = endpoint();
    config.worker.as_mut().unwrap().allowed_peer_sid = Some("S-1-5-18".into());
    assert!(config.validate().is_err());
}

#[cfg(windows)]
#[test]
fn windows_worker_references_reject_aliases_streams_and_remote_paths() {
    let mut config = configured();
    config.admin = Some(AdminConfig {
        endpoint: r"\\.\pipe\ascension-watchdog-admin-fixture".into(),
        read_token_path: local("operator-read"),
        admin_token_path: local("operator-write"),
        allowed_peer_sid: None,
    });
    config.worker.as_mut().unwrap().credential_path = PathBuf::from(
        local("operator-read")
            .to_string_lossy()
            .to_ascii_uppercase(),
    );
    assert!(config.validate().is_err());
    for path in [r"C:\worker\token:stream", r"\\server\share\token"] {
        config.worker.as_mut().unwrap().credential_path = path.into();
        assert!(config.validate().is_err());
    }
}
