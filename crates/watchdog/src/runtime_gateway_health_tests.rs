//! Pure launch/admission tests. No native child, game, or service is launched.

use super::super::{Supervisor, launch_spec_binding_digest, launch_spec_for, runtime_incarnation};
use super::*;
use crate::config::{GatewayHealthConfig, WatchdogConfig};
use crate::platform::gateway_health::GatewayHealthFrameBinding;
use std::collections::BTreeMap;
#[cfg(windows)]
use std::process::Command;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[cfg(windows)]
fn protect_test_directory(path: &std::path::Path) -> TestResult {
    let status = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            r"
$ErrorActionPreference = 'Stop'
$securityModule = Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1'
Import-Module -Name $securityModule -Force -ErrorAction Stop
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [System.Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', $inheritance, 'None', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $env:ASCENSION_TEST_DIRECTORY -AclObject $acl
            ",
        ])
        .env("ASCENSION_TEST_DIRECTORY", path)
        .status()?;
    if !status.success() {
        return Err("PowerShell failed to apply test directory ACL".into());
    }
    Ok(())
}

#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps)]
fn protect_test_directory(_path: &std::path::Path) -> TestResult {
    Ok(())
}

fn configured(root: &std::path::Path) -> WatchdogConfig {
    let health = GatewayHealthConfig {
        component_id: "gateway".to_owned(),
        address: "127.0.0.1:18701".parse().unwrap(),
        instance_id: Uuid::new_v4().to_string(),
        release_digest: "a".repeat(64),
        gateway_config_digest: "b".repeat(64),
        profile_digest: "c".repeat(64),
        runtime_v3_schema_digest: "d".repeat(64),
        timeout_ms: 100,
    };
    let deployment_id = Uuid::new_v4().to_string();
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
            root.join("gateway.sqlite").to_str().unwrap().to_owned(),
        ),
    ]);
    WatchdogConfig {
        deployment_id,
        database: root.join("watchdog.sqlite"),
        desired_mode: DesiredMode::Running,
        components: vec![ComponentConfig {
            id: "gateway".to_owned(),
            executable: root.join("gateway"),
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

fn prepared(
    supervisor: &mut Supervisor,
) -> std::result::Result<
    (LaunchSpec, String, LaunchIntent, GatewayHealthLaunch),
    Box<dyn std::error::Error>,
> {
    supervisor.store.establish_new_generation(1)?;
    let component = supervisor.config.components[0].clone();
    let spec = launch_spec_for(
        &supervisor.config,
        &component,
        Uuid::new_v4().to_string(),
        runtime_incarnation(supervisor.store.status()?.restart_generation)?,
    )?;
    let planned = format!("planned:{}", spec.launch_nonce);
    let digest = launch_spec_binding_digest(&spec, &planned)?;
    let launch = supervisor
        .prepare_gateway_health(&component, &spec)?
        .ok_or("missing health launch")?;
    let intent = supervisor.store.prepare_launch_intent(
        &component.id,
        &spec.launch_nonce,
        &spec.incarnation,
        &digest,
        Some(&planned),
        2,
    )?;
    Ok((spec, planned, intent, launch))
}

#[test]
fn runtime_prepares_fresh_key_without_serializing_it_or_rewriting_config() -> TestResult {
    let directory = tempfile::tempdir()?;
    let config = configured(directory.path());
    let digest = config.digest()?;
    let mut supervisor = Supervisor::initialize(config)?;
    let (spec, _, _, first) = prepared(&mut supervisor)?;
    let component = &supervisor.config.components[0];
    let second = supervisor
        .prepare_gateway_health(component, &spec)?
        .ok_or("missing health launch")?;
    assert_ne!(
        first.bootstrap.frame_sha256(),
        second.bootstrap.frame_sha256()
    );
    assert_eq!(
        first.bootstrap.launch_nonce().to_string(),
        spec.launch_nonce
    );
    assert_eq!(supervisor.config.digest()?, digest);
    assert!(
        !component
            .environment
            .contains_key("STS2_GATEWAY_WATCHDOG_LAUNCH_NONCE")
    );
    assert!(spec.environment.contains(&(
        "STS2_GATEWAY_WATCHDOG_LAUNCH_NONCE".to_owned(),
        spec.launch_nonce.clone()
    )));
    assert!(!supervisor.gateway_allows_fresh_claim());
    assert!(supervisor.children.is_empty());
    Ok(())
}

#[test]
fn helper_admission_requires_independent_binding_and_exact_frame() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut supervisor = Supervisor::initialize(configured(directory.path()))?;
    let (spec, planned, intent, launch) = prepared(&mut supervisor)?;
    let observed = GatewayHealthFrameBinding::from_bootstrap(&launch.bootstrap);
    let authorize = super::super::runtime_gateway_health_admission::authorize_stored;
    assert!(
        authorize(
            &supervisor.config,
            &supervisor.store,
            &spec,
            &planned,
            &observed,
            None
        )
        .is_err()
    );
    let component = supervisor.config.components[0].clone();
    supervisor.bind_prepared_gateway_health(&component, &intent, &launch, 3)?;
    authorize(
        &supervisor.config,
        &supervisor.store,
        &spec,
        &planned,
        &observed,
        Some(&supervisor.worker_boot_id),
    )?;
    let wrong = GatewayHealthBootstrap::new(launch.bootstrap.launch_nonce(), [55; 32])?;
    assert!(
        authorize(
            &supervisor.config,
            &supervisor.store,
            &spec,
            &planned,
            &GatewayHealthFrameBinding::from_bootstrap(&wrong),
            None
        )
        .is_err()
    );
    assert!(
        authorize(
            &supervisor.config,
            &supervisor.store,
            &spec,
            "other-containment",
            &observed,
            None
        )
        .is_err()
    );
    assert!(
        authorize(
            &supervisor.config,
            &supervisor.store,
            &spec,
            &planned,
            &observed,
            Some(&Uuid::new_v4().to_string())
        )
        .is_err()
    );
    let mut changed = spec.clone();
    changed
        .environment
        .retain(|(key, _)| key != "STS2_GATEWAY_WATCHDOG_LAUNCH_NONCE");
    assert!(
        authorize(
            &supervisor.config,
            &supervisor.store,
            &changed,
            &planned,
            &observed,
            None
        )
        .is_err()
    );
    supervisor
        .store
        .set_desired_mode_at(DesiredMode::Paused, 4)?;
    assert!(
        authorize(
            &supervisor.config,
            &supervisor.store,
            &spec,
            &planned,
            &observed,
            None
        )
        .is_err()
    );
    supervisor
        .store
        .set_desired_mode_at(DesiredMode::Stopped, 5)?;
    assert!(
        authorize(
            &supervisor.config,
            &supervisor.store,
            &spec,
            &planned,
            &observed,
            None
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn released_launch_and_replaced_generation_cannot_reuse_health_admission() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut supervisor = Supervisor::initialize(configured(directory.path()))?;
    let (spec, planned, intent, launch) = prepared(&mut supervisor)?;
    let component = supervisor.config.components[0].clone();
    supervisor.bind_prepared_gateway_health(&component, &intent, &launch, 3)?;
    let observed = GatewayHealthFrameBinding::from_bootstrap(&launch.bootstrap);
    let authorize = super::super::runtime_gateway_health_admission::authorize_stored;
    supervisor
        .store
        .record_launch_proof(&intent.id, &serde_json::json!({"test":true}), 4)?;
    assert!(
        authorize(
            &supervisor.config,
            &supervisor.store,
            &spec,
            &planned,
            &observed,
            None
        )
        .is_err()
    );
    supervisor.store.clean_launch_intent(&intent.id, 5)?;
    assert!(
        authorize(
            &supervisor.config,
            &supervisor.store,
            &spec,
            &planned,
            &observed,
            None
        )
        .is_err()
    );
    supervisor.store.establish_new_generation(6)?;
    assert!(
        authorize(
            &supervisor.config,
            &supervisor.store,
            &spec,
            &planned,
            &observed,
            None
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn failed_binding_cleans_unlaunched_intent_and_synthetic_health_is_rejected() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut supervisor = Supervisor::initialize(configured(directory.path()))?;
    let (spec, _, intent, launch) = prepared(&mut supervisor)?;
    let raw = rusqlite::Connection::open(&supervisor.config.database)?;
    raw.execute_batch("CREATE TRIGGER reject_health_bind BEFORE INSERT ON gateway_health_bindings BEGIN SELECT RAISE(ABORT,'injected'); END;")?;
    let component = supervisor.config.components[0].clone();
    assert!(
        supervisor
            .bind_prepared_gateway_health(&component, &intent, &launch, 3)
            .is_err()
    );
    assert!(supervisor.store.unsettled_launch_intents()?.is_empty());
    assert!(supervisor.children.is_empty());
    supervisor.config.allow_synthetic_children = true;
    assert!(
        supervisor
            .prepare_gateway_health(&component, &spec)
            .is_err()
    );
    Ok(())
}

#[test]
fn health_backup_restore_requires_fresh_consistent_identity_and_same_approval() -> TestResult {
    let directory = tempfile::tempdir()?;
    protect_test_directory(directory.path())?;
    let config = configured(directory.path());
    let store = crate::storage::Store::initialize(&config.database, &config)?;
    let backup = directory.path().join("backup.sqlite");
    store.backup_to(&backup)?;
    let mut restored_config = config.clone();
    restored_config.database = directory.path().join("restored.sqlite");
    assert!(
        crate::storage::Store::restore_from(&backup, &restored_config.database, &restored_config)
            .is_err()
    );
    assert!(!restored_config.database.exists());
    restored_config.deployment_id = Uuid::new_v4().to_string();
    // A new top-level identity without the matching approved gateway binding
    // is invalid configuration, not permission to rewrite it implicitly.
    assert!(
        crate::storage::Store::restore_from(&backup, &restored_config.database, &restored_config)
            .is_err()
    );
    restored_config.components[0].environment.insert(
        "STS2_DEPLOYMENT_ID".to_owned(),
        restored_config.deployment_id.clone(),
    );
    let mut wrong = restored_config.clone();
    wrong.gateway_health.as_mut().unwrap().release_digest = "f".repeat(64);
    wrong.components[0]
        .environment
        .insert("STS2_RECOVERY_RELEASE_DIGEST".to_owned(), "f".repeat(64));
    assert!(crate::storage::Store::restore_from(&backup, &wrong.database, &wrong).is_err());
    let mut wrong = restored_config.clone();
    wrong.components[0].environment.insert(
        "STS2_RECOVERY_STORE".to_owned(),
        directory
            .path()
            .join("other-gateway.sqlite")
            .to_str()
            .unwrap()
            .to_owned(),
    );
    assert!(crate::storage::Store::restore_from(&backup, &wrong.database, &wrong).is_err());
    assert!(!restored_config.database.exists());
    let restored =
        crate::storage::Store::restore_from(&backup, &restored_config.database, &restored_config)?;
    assert_eq!(restored.status()?.desired_mode, DesiredMode::Stopped);
    assert_eq!(
        restored.status()?.deployment_id,
        restored_config.deployment_id
    );
    assert!(restored.status()?.restart_generation > store.status()?.restart_generation);
    restored_config.desired_mode = DesiredMode::Stopped;
    drop(restored);
    crate::storage::Store::open_read_only(&restored_config.database, &restored_config)?;
    Ok(())
}

#[test]
fn compatibility_projection_preserves_existing_non_health_fingerprint() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut config = configured(directory.path());
    config.gateway_health = None;
    let _store = crate::storage::Store::initialize(&config.database, &config)?;
    let raw = rusqlite::Connection::open(&config.database)?;
    let actual: String = raw.query_row(
        "SELECT value FROM metadata WHERE key='config_compat_digest'",
        [],
        |row| row.get(0),
    )?;
    let mut legacy_projection = config;
    legacy_projection.deployment_id = "watchdog-compatibility-identity".to_owned();
    legacy_projection.database = std::path::PathBuf::from("/owner-local/watchdog.sqlite3");
    legacy_projection.desired_mode = DesiredMode::Stopped;
    assert_eq!(actual, legacy_projection.digest()?);
    Ok(())
}

#[test]
fn launch_admission_reservation_serializes_stop_and_releases_on_drop() -> TestResult {
    let directory = tempfile::tempdir()?;
    let config = configured(directory.path());
    let store = crate::storage::Store::initialize(&config.database, &config)?;
    let guard =
        crate::storage::Store::open(&config.database, &config)?.reserve_launch_admission()?;
    let other = rusqlite::Connection::open(&config.database)?;
    other.busy_timeout(Duration::ZERO)?;
    assert!(
        matches!(other.execute("UPDATE metadata SET value='stopped' WHERE key='desired_mode'", []),
        Err(rusqlite::Error::SqliteFailure(error, _)) if error.code == rusqlite::ErrorCode::DatabaseBusy)
    );
    assert_eq!(store.desired_mode()?, DesiredMode::Running);
    drop(guard);
    assert_eq!(
        other.execute(
            "UPDATE metadata SET value='stopped' WHERE key='desired_mode'",
            []
        )?,
        1
    );
    assert_eq!(store.desired_mode()?, DesiredMode::Stopped);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn linux_admission_database_descriptors_are_close_on_exec() -> TestResult {
    let directory = tempfile::tempdir()?;
    let config = configured(directory.path());
    let _store = crate::storage::Store::initialize(&config.database, &config)?;
    let _guard =
        crate::storage::Store::open(&config.database, &config)?.reserve_launch_admission()?;
    let paths = [
        config.database.clone(),
        config.database.with_extension("sqlite-wal"),
        config.database.with_extension("sqlite-shm"),
    ];
    let mut checked = 0;
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        if !paths.contains(&target) {
            continue;
        }
        let info = std::fs::read_to_string(
            std::path::Path::new("/proc/self/fdinfo").join(entry.file_name()),
        )?;
        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:\t"))
            .ok_or("descriptor flags missing")?;
        let flags = u64::from_str_radix(flags, 8)?;
        assert_ne!(flags & u64::from(rustix::fs::OFlags::CLOEXEC.bits()), 0);
        checked += 1;
    }
    assert!(
        checked > 0,
        "the actual SQLite database descriptors must be inspected"
    );
    Ok(())
}

#[test]
fn blocked_authority_does_not_deadlock_bootstrap_control_work() -> TestResult {
    // Pure policy fixture, not transport authentication evidence. Production
    // reaches this predicate only after the client's MAC/schema/sequence and
    // retained-native-child checks all succeed.
    let mut body = serde_json::json!({
        "contract":"sts2-gateway-health-v1", "liveness":"live", "process_binding":"launch_nonce",
        "readiness":"blocked", "phase":"blocked", "phase_deadline":null,
        "progress":{"heartbeat_sequence":1,"heartbeat_age_ms":0,"meaningful_progress_age_ms":null,"source":"gateway_worker"},
        "identity":{"deployment_id":Uuid::new_v4().to_string(),"instance_id":Uuid::new_v4().to_string(),"instance_incarnation":Uuid::new_v4().to_string(),
            "boot_id":Uuid::new_v4().to_string(),"authority_generation":1,"launch_nonce":Uuid::new_v4().to_string(),
            "release":{"release_digest":"a".repeat(64),"config_digest":"b".repeat(64),"profile_digest":"c".repeat(64),"runtime_v3_schema_digest":"d".repeat(64)}},
        "lease":{"remaining_ms":null,"expires_at":null}, "queue":{"capacity":16,"depth":0,"age_ms":null},
        "pending_operation_count":null, "downstream_readiness":"not_sampled", "shutdown_requested":false
    });
    let blocked: GatewayHealthStatus = serde_json::from_value(body.clone())?;
    assert!(permits_bootstrap_work(
        &blocked,
        super::super::ComponentState::Running
    ));
    for state in [
        super::super::ComponentState::Quarantined,
        super::super::ComponentState::Stopped,
        super::super::ComponentState::Suspect,
        super::super::ComponentState::Starting,
    ] {
        assert!(!permits_bootstrap_work(&blocked, state));
    }
    body["phase"] = "draining".into();
    body["shutdown_requested"] = true.into();
    let draining: GatewayHealthStatus = serde_json::from_value(body)?;
    assert!(!permits_bootstrap_work(
        &draining,
        super::super::ComponentState::Running
    ));
    Ok(())
}
