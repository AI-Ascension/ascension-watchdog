use ascension_watchdog::cli;
use ascension_watchdog::config::{DesiredMode, WatchdogConfig};
use ascension_watchdog::storage::Store;
use serde_json::Value;
use std::path::Path;
#[cfg(windows)]
use std::process::Command;
use tempfile::tempdir;

#[cfg(windows)]
fn protect_config(path: &Path) {
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
$acl = [System.Security.AccessControl.FileSecurity]::new()
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $env:ASCENSION_TEST_CONFIG_PATH -AclObject $acl
            ",
        ])
        .env("ASCENSION_TEST_CONFIG_PATH", path)
        .status()
        .expect("apply protected config ACL");
    assert!(
        status.success(),
        "PowerShell failed to apply protected config ACL"
    );
}

#[cfg(not(windows))]
fn protect_config(_path: &Path) {}

#[cfg(windows)]
fn protect_test_directory(path: &Path) {
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
        .status()
        .expect("apply protected test directory ACL");
    assert!(
        status.success(),
        "PowerShell failed to apply test directory ACL"
    );
}

#[cfg(not(windows))]
fn protect_test_directory(_path: &Path) {}

#[test]
fn restore_cli_requires_explicit_rekey_without_creating_destination() {
    let directory = tempdir().expect("temporary directory");
    protect_test_directory(directory.path());
    let config = WatchdogConfig {
        database: directory.path().join("source.sqlite3"),
        deployment_id: "source-deployment".to_owned(),
        allow_synthetic_children: true,
        ..WatchdogConfig::default()
    };
    let backup = directory.path().join("source-backup.sqlite3");
    let destination = directory.path().join("restored.sqlite3");
    let source = Store::initialize(&config.database, &config).expect("initialize source");
    source.backup_to(&backup).expect("backup source");
    drop(source);

    let config_path = directory.path().join("restore.json");
    let restore_config = WatchdogConfig {
        database: destination.clone(),
        deployment_id: "restored-deployment".to_owned(),
        allow_synthetic_children: true,
        ..config
    };
    restore_config
        .to_file(&config_path)
        .expect("restore config");
    protect_config(&config_path);
    let error = cli::execute(vec![
        "restore".to_owned(),
        "--config".to_owned(),
        config_path.to_string_lossy().into_owned(),
        "--backup".to_owned(),
        backup.to_string_lossy().into_owned(),
    ])
    .expect_err("restore without rekey must fail");
    assert!(error.to_string().contains("explicit --rekey"));
    assert!(!destination.exists());
}

#[test]
fn restore_cli_rekeys_and_keeps_restored_work_blocked() {
    let directory = tempdir().expect("temporary directory");
    protect_test_directory(directory.path());
    let source_config = WatchdogConfig {
        database: directory.path().join("source.sqlite3"),
        deployment_id: "source-deployment".to_owned(),
        desired_mode: DesiredMode::Stopped,
        allow_synthetic_children: true,
        ..WatchdogConfig::default()
    };
    let backup = directory.path().join("source-backup.sqlite3");
    let source = Store::initialize(&source_config.database, &source_config).expect("source");
    source.backup_to(&backup).expect("backup");
    drop(source);

    let destination = directory.path().join("restored.sqlite3");
    let config_path = directory.path().join("restore.json");
    let restore_config = WatchdogConfig {
        database: destination.clone(),
        deployment_id: "restored-deployment".to_owned(),
        desired_mode: DesiredMode::Stopped,
        allow_synthetic_children: true,
        ..source_config
    };
    restore_config
        .to_file(&config_path)
        .expect("restore config");
    protect_config(&config_path);
    let output = cli::execute(vec![
        "restore".to_owned(),
        "--config".to_owned(),
        config_path.to_string_lossy().into_owned(),
        "--backup".to_owned(),
        backup.to_string_lossy().into_owned(),
        "--database".to_owned(),
        destination.to_string_lossy().into_owned(),
        "--rekey".to_owned(),
    ])
    .expect("restore")
    .expect("restore output");
    let value: Value = serde_json::from_str(&output).expect("restore JSON");
    assert_eq!(value["restored"], true);
    assert_eq!(value["rekeyed"], true);
    assert_eq!(value["blocked_until_fenced"], true);
    let status = Store::open_read_only(&destination, &restore_config)
        .expect("reopen restored state")
        .status()
        .expect("restored status");
    assert_eq!(status.deployment_id, "restored-deployment");
    assert_eq!(status.desired_mode, DesiredMode::Stopped);
    assert_eq!(status.restart_generation, 2);
}
