use ascension_watchdog::platform::gateway_health::GatewayHealthBootstrap;
use ascension_watchdog::storage::SingletonLock;
use ascension_watchdog::{DesiredMode, Store, WatchdogConfig};
use uuid::Uuid;

#[cfg(windows)]
fn protect_config_for_native_read(
    path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
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
Set-Acl -LiteralPath $env:ASCENSION_TEST_CONFIG_PATH -AclObject $acl
            ",
        ])
        .env("ASCENSION_TEST_CONFIG_PATH", path)
        .status()?;
    if !status.success() {
        return Err("PowerShell failed to protect the config fixture".into());
    }
    Ok(())
}

fn config(directory: &std::path::Path, mode: DesiredMode) -> WatchdogConfig {
    WatchdogConfig {
        database: directory.join("state.sqlite"),
        desired_mode: mode,
        ..WatchdogConfig::default()
    }
}

#[test]
fn offline_cli_migration_requires_stopped_exclusive_owner() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let config = config(directory.path(), DesiredMode::Running);
    let path = directory.path().join("config.json");
    config.to_file(&path)?;
    #[cfg(windows)]
    protect_config_for_native_read(&path)?;
    let mut store = Store::initialize(&config.database, &config)?;
    let raw = rusqlite::Connection::open(&config.database)?;
    raw.execute_batch("DROP TRIGGER gateway_health_binding_immutable; DROP TABLE gateway_health_bindings; DELETE FROM metadata WHERE key='gateway_health_schema';")?;
    let command = || {
        vec![
            "migrate".to_owned(),
            "gateway-health".to_owned(),
            "--config".to_owned(),
            path.to_string_lossy().into_owned(),
        ]
    };
    assert!(ascension_watchdog::cli::execute(command()).is_err());
    store.set_desired_mode_at(DesiredMode::Stopped, 10)?;
    let owner = SingletonLock::acquire(&config.database)?;
    assert!(ascension_watchdog::cli::execute(command()).is_err());
    drop(owner);
    for _ in 0..2 {
        let output =
            ascension_watchdog::cli::execute(command())?.ok_or("missing migration result")?;
        let result: serde_json::Value = serde_json::from_str(&output)?;
        assert_eq!(result["gateway_health_schema"], 1);
        assert_eq!(store.status()?.desired_mode, DesiredMode::Stopped);
    }
    let audits: i64 = raw.query_row(
        "SELECT count(*) FROM audit WHERE action='gateway_health_schema_installed'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(audits, 1);
    let mut invalid = command();
    invalid.push("unexpected".to_owned());
    assert!(ascension_watchdog::cli::execute(invalid).is_err());
    Ok(())
}

#[test]
fn offline_cli_migration_never_falls_back_from_a_malformed_config_option() {
    for suffix in [
        vec![],
        vec!["--config"],
        vec!["--config", ""],
        vec!["--config", "--unexpected"],
        vec!["--config", "first.json", "--config", "second.json"],
    ] {
        let mut command = vec!["migrate".to_owned(), "gateway-health".to_owned()];
        command.extend(suffix.into_iter().map(str::to_owned));
        let error =
            ascension_watchdog::cli::execute(command).expect_err("explicit config required");
        assert!(error.to_string().contains("exactly one --config PATH"));
    }
}

#[test]
fn binding_is_atomic_immutable_and_survives_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = config(directory.path(), DesiredMode::Running);
    let mut store = Store::initialize(&config.database, &config)?;
    let nonce = Uuid::new_v4();
    let boot = Uuid::new_v4();
    let frame = GatewayHealthBootstrap::new(nonce, [42; 32])?;
    let intent = store.prepare_launch_intent(
        "gateway",
        &nonce.to_string(),
        "incarnation",
        &"a".repeat(64),
        None,
        1,
    )?;
    let raw = rusqlite::Connection::open(&config.database)?;
    raw.execute_batch("CREATE TRIGGER reject_health_audit BEFORE INSERT ON audit WHEN NEW.action='gateway_health_bound' BEGIN SELECT RAISE(ABORT,'injected'); END;")?;
    assert!(
        store
            .bind_gateway_health(&intent.id, boot, &frame, 2)
            .is_err()
    );
    assert_eq!(store.gateway_health_binding(&intent.id)?, None);
    raw.execute_batch("DROP TRIGGER reject_health_audit;")?;
    let binding = store.bind_gateway_health(&intent.id, boot, &frame, 3)?;
    assert_eq!(binding.frame_sha256, frame.frame_sha256());
    assert_eq!(
        store.bind_gateway_health(&intent.id, boot, &frame, 4)?,
        binding
    );
    let count: i64 = raw.query_row(
        "SELECT count(*) FROM audit WHERE action='gateway_health_bound'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);
    assert!(
        raw.execute(
            "UPDATE gateway_health_bindings SET frame_sha256=?",
            [&"b".repeat(64)]
        )
        .is_err()
    );
    let replacement = GatewayHealthBootstrap::new(nonce, [43; 32])?;
    assert!(
        store
            .bind_gateway_health(&intent.id, boot, &replacement, 5)
            .is_err()
    );
    assert!(
        store
            .bind_gateway_health(&intent.id, Uuid::new_v4(), &frame, 5)
            .is_err()
    );
    drop(store);
    let mut store = Store::open(&config.database, &config)?;
    assert_eq!(store.gateway_health_binding(&intent.id)?, Some(binding));
    store.set_desired_mode_at(DesiredMode::Stopped, 6)?;
    assert!(
        store
            .bind_gateway_health(&intent.id, boot, &frame, 7)
            .is_err()
    );
    Ok(())
}

#[test]
fn wrong_role_nonce_boot_and_late_binding_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = config(directory.path(), DesiredMode::Running);
    let mut store = Store::initialize(&config.database, &config)?;
    let nonce = Uuid::new_v4();
    let frame = GatewayHealthBootstrap::new(nonce, [1; 32])?;
    let worker = store.prepare_launch_intent(
        "harness",
        &nonce.to_string(),
        "incarnation",
        &"a".repeat(64),
        None,
        1,
    )?;
    assert!(
        store
            .bind_gateway_health(&worker.id, Uuid::new_v4(), &frame, 2)
            .is_err()
    );
    let gateway = store.prepare_launch_intent(
        "gateway",
        &nonce.to_string(),
        "incarnation",
        &"a".repeat(64),
        None,
        3,
    )?;
    assert!(
        store
            .bind_gateway_health(&gateway.id, Uuid::nil(), &frame, 4)
            .is_err()
    );
    let wrong = GatewayHealthBootstrap::new(Uuid::new_v4(), [1; 32])?;
    assert!(
        store
            .bind_gateway_health(&gateway.id, Uuid::new_v4(), &wrong, 4)
            .is_err()
    );
    store.record_launch_proof(&gateway.id, &serde_json::json!({"test":true}), 5)?;
    assert!(
        store
            .bind_gateway_health(&gateway.id, Uuid::new_v4(), &frame, 6)
            .is_err()
    );
    assert_eq!(store.gateway_health_binding(&gateway.id)?, None);
    Ok(())
}

#[test]
fn migration_requires_owner_stop_and_complete_absence() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = config(directory.path(), DesiredMode::Running);
    let mut store = Store::initialize(&config.database, &config)?;
    let owner = SingletonLock::acquire(&config.database)?;
    let wrong = SingletonLock::acquire(directory.path().join("wrong.sqlite"))?;
    let raw = rusqlite::Connection::open(&config.database)?;
    assert!(store.migrate_gateway_health(&wrong).is_err());
    raw.execute_batch("DROP TABLE gateway_health_bindings; DELETE FROM metadata WHERE key='gateway_health_schema';")?;
    assert!(store.gateway_health_binding("missing").is_err());
    assert!(store.migrate_gateway_health(&owner).is_err());
    store.set_desired_mode_at(DesiredMode::Stopped, 1)?;
    store.migrate_gateway_health(&owner)?;
    store.migrate_gateway_health(&owner)?;
    assert_eq!(store.gateway_health_binding("missing")?, None);
    raw.execute_batch("DROP TRIGGER gateway_health_binding_immutable;")?;
    assert!(store.migrate_gateway_health(&owner).is_err());
    assert!(store.gateway_health_binding("missing").is_err());
    raw.execute_batch("CREATE TRIGGER gateway_health_binding_immutable BEFORE UPDATE ON gateway_health_bindings BEGIN SELECT 1; END;")?;
    assert!(store.migrate_gateway_health(&owner).is_err());
    Ok(())
}

#[test]
fn migration_audit_failure_rolls_back_schema_and_marker() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let config = config(directory.path(), DesiredMode::Stopped);
    let mut store = Store::initialize(&config.database, &config)?;
    let owner = SingletonLock::acquire(&config.database)?;
    let raw = rusqlite::Connection::open(&config.database)?;
    raw.execute_batch("DROP TABLE gateway_health_bindings; DELETE FROM metadata WHERE key='gateway_health_schema'; CREATE TRIGGER reject_health_migration BEFORE INSERT ON audit WHEN NEW.action='gateway_health_schema_installed' BEGIN SELECT RAISE(ABORT,'injected'); END;")?;
    assert!(store.migrate_gateway_health(&owner).is_err());
    let tables: i64 = raw.query_row("SELECT count(*) FROM sqlite_master WHERE name IN ('gateway_health_bindings','gateway_health_binding_immutable')", [], |row| row.get(0))?;
    assert_eq!(tables, 0);
    let markers: i64 = raw.query_row(
        "SELECT count(*) FROM metadata WHERE key='gateway_health_schema'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(markers, 0);
    raw.execute_batch("DROP TRIGGER reject_health_migration;")?;
    store.migrate_gateway_health(&owner)?;
    Ok(())
}
