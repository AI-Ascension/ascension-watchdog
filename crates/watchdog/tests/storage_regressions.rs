use ascension_watchdog::config::{DesiredMode, WatchdogConfig};
use ascension_watchdog::error::WatchdogError;
use ascension_watchdog::policy::ComponentState;
use ascension_watchdog::storage::{ComponentRecord, LaunchIntentState, SingletonLock, Store};
use serde_json::json;
use std::path::Path;
#[cfg(windows)]
use std::process::Command;
use tempfile::TempDir;

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

fn config(temp: &TempDir, deployment_id: &str) -> WatchdogConfig {
    WatchdogConfig {
        database: temp.path().join("watchdog.sqlite3"),
        deployment_id: deployment_id.to_string(),
        desired_mode: DesiredMode::Running,
        allow_synthetic_children: true,
        ..WatchdogConfig::default()
    }
}

#[test]
fn absent_component_identity_is_not_a_sqlite_decode_failure() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = config(&temp, "absent-component-identity");
    let mut store = Store::initialize(&config.database, &config).expect("initialize");
    assert!(
        store
            .component_identity("gateway")
            .expect("missing row")
            .is_none()
    );
    store
        .upsert_component(
            &ComponentRecord {
                id: "gateway".to_owned(),
                state: ComponentState::Stopped,
                launch_nonce: None,
                pid: None,
                executable_digest: None,
                started_at_ms: None,
                restart_attempts: 0,
                last_restart_at_ms: None,
                last_error: None,
            },
            1,
        )
        .expect("stopped component");
    assert!(
        store
            .component_identity("gateway")
            .expect("null identity")
            .is_none()
    );
    drop(store);
    let store = Store::open(&config.database, &config).expect("reopen");
    assert!(
        store
            .component_identity("gateway")
            .expect("reopened null identity")
            .is_none()
    );
    let raw = rusqlite::Connection::open(&config.database).expect("raw connection");
    raw.execute(
        "UPDATE components SET identity_json='malformed' WHERE id='gateway'",
        [],
    )
    .expect("corrupt fixture");
    assert!(
        store.component_identity("gateway").is_err(),
        "malformed non-null identity must fail closed"
    );
}

#[test]
fn read_only_open_is_noncreating_and_nonmutating() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = config(&temp, "readonly");
    assert!(matches!(
        Store::open_read_only(&config.database, &config),
        Err(WatchdogError::MissingState(_))
    ));
    assert!(!config.database.exists());

    let store = Store::initialize(&config.database, &config).expect("initialize");
    let mut read_only = Store::open_read_only(&config.database, &config).expect("open");
    assert_eq!(
        read_only.status().expect("status").desired_mode,
        DesiredMode::Running
    );
    assert!(matches!(
        read_only.set_desired_mode_at(DesiredMode::Stopped, 10),
        Err(WatchdogError::Sqlite(_))
    ));
    assert_eq!(store.desired_mode().expect("mode"), DesiredMode::Running);
}

#[test]
fn owner_admission_requires_matching_lock_and_avoids_double_lock() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = config(&temp, "owner");
    let owner = SingletonLock::acquire(&config.database).expect("owner lock");
    let store = Store::initialize_for_owner(&config.database, &config, &owner)
        .expect("initialize under owner lock");
    assert!(matches!(
        SingletonLock::acquire(&config.database),
        Err(WatchdogError::Busy(_))
    ));
    drop(store);

    let wrong_path = temp.path().join("other.sqlite3");
    let wrong_owner = SingletonLock::acquire(&wrong_path).expect("other lock");
    assert!(matches!(
        Store::open_for_owner(&config.database, &config, &wrong_owner),
        Err(WatchdogError::Unauthorized(_))
    ));
    drop(wrong_owner);
    owner
        .write_owner_hint("owner-regression")
        .expect("owner hint");
}

#[test]
fn malformed_metadata_is_reported_instead_of_defaulted() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = config(&temp, "metadata");
    let store = Store::initialize(&config.database, &config).expect("initialize");
    drop(store);
    let connection = rusqlite::Connection::open(&config.database).expect("raw connection");
    connection
        .execute(
            "UPDATE metadata SET value='not-an-integer' WHERE key='restart_generation'",
            [],
        )
        .expect("corrupt metadata fixture");
    let opened = Store::open(&config.database, &config).expect("open");
    assert!(matches!(opened.status(), Err(WatchdogError::Conflict(_))));
}

#[test]
fn restore_requires_fresh_identity_and_quarantines_old_work() {
    let temp = tempfile::tempdir().expect("tempdir");
    protect_test_directory(temp.path());
    let source_config = config(&temp, "source-deployment");
    let mut source = Store::initialize(&source_config.database, &source_config).expect("source");
    source
        .submit_job_at("synthetic", &json!({"pending": true}), 10)
        .expect("pending job");
    source
        .upsert_component(
            &ComponentRecord {
                id: "gateway".to_string(),
                state: ComponentState::Running,
                launch_nonce: Some("old-launch".to_string()),
                pid: Some(1234),
                executable_digest: Some("a".repeat(64)),
                started_at_ms: Some(10),
                restart_attempts: 1,
                last_restart_at_ms: Some(10),
                last_error: None,
            },
            10,
        )
        .expect("component");
    let backup = temp.path().join("watchdog.backup.sqlite3");
    source.backup_to(&backup).expect("backup");
    let same_path = temp.path().join("same.sqlite3");
    let mut same_config = source_config.clone();
    same_config.database = same_path.clone();
    assert!(matches!(
        Store::restore_from(&backup, &same_path, &same_config),
        Err(WatchdogError::Conflict(_))
    ));

    let restored_path = temp.path().join("restored.sqlite3");
    let mut restored_config = source_config.clone();
    restored_config.database = restored_path.clone();
    restored_config.deployment_id = "restored-deployment".to_string();
    let restored = Store::restore_from(&backup, &restored_path, &restored_config).expect("restore");
    let status = restored.status().expect("status");
    assert_eq!(status.desired_mode, DesiredMode::Stopped);
    assert_eq!(status.deployment_id, restored_config.deployment_id);
    assert_eq!(status.jobs_quarantined, 1);
    assert_eq!(
        restored
            .component("gateway")
            .expect("component")
            .expect("row")
            .state,
        ComponentState::Quarantined
    );
    assert!(matches!(
        Store::open(&restored_path, &restored_config),
        Err(WatchdogError::Conflict(_))
    ));
}

#[test]
fn launch_intent_requires_proof_and_serializes_recovery_state() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = config(&temp, "launch-intent");
    let mut store = Store::initialize(&config.database, &config).expect("initialize");
    let prepared = store
        .prepare_launch_intent(
            "gateway",
            "launch-1",
            "watchdog-generation-1",
            &"a".repeat(64),
            Some("containment-1"),
            10,
        )
        .expect("prepare");
    assert_eq!(prepared.state, LaunchIntentState::Prepared);
    assert!(store.activate_launch_intent(&prepared.id, 11).is_err());
    let proof = store
        .record_launch_proof(&prepared.id, &json!({"opaque": "proof"}), 12)
        .expect("proof");
    assert_eq!(proof.state, LaunchIntentState::ProofRecorded);
    assert_eq!(
        store
            .activate_launch_intent(&prepared.id, 13)
            .expect("activate")
            .state,
        LaunchIntentState::Active
    );
    assert_eq!(store.unsettled_launch_intents().expect("list").len(), 1);
    assert_eq!(
        store
            .clean_launch_intent(&prepared.id, 14)
            .expect("clean")
            .state,
        LaunchIntentState::Cleaned
    );
    assert!(store.unsettled_launch_intents().expect("list").is_empty());
}
