// SPDX-License-Identifier: MIT

use ascension_watchdog::preflight::DiskRequirements;

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
        return Err("PowerShell failed to protect the oversized config fixture".into());
    }
    Ok(())
}

#[test]
fn staging_and_backups_cannot_consume_the_runtime_reserve() -> Result<(), String> {
    let requirements = DiskRequirements {
        runtime_reserve_bytes: 100,
        staging_bytes: 200,
        backup_bytes: 300,
    };
    assert!(!requirements.evaluate(1000, 599)?.admitted);
    assert!(requirements.evaluate(1000, 600)?.admitted);
    assert_eq!(requirements.evaluate(1000, 600)?.required_bytes, 600);
    assert!(!requirements.evaluate(1000, 0)?.admitted);
    assert!(requirements.evaluate(1000, 1001).is_err());
    assert!(requirements.evaluate(0, 0).is_err());
    Ok(())
}

#[test]
fn invalid_reserve_and_capacity_overflow_fail_closed() {
    for requirements in [
        DiskRequirements {
            runtime_reserve_bytes: 0,
            staging_bytes: 0,
            backup_bytes: 0,
        },
        DiskRequirements {
            runtime_reserve_bytes: u64::MAX,
            staging_bytes: 1,
            backup_bytes: 0,
        },
        DiskRequirements {
            runtime_reserve_bytes: 1,
            staging_bytes: 0,
            backup_bytes: u64::MAX,
        },
    ] {
        assert!(requirements.evaluate(u64::MAX, u64::MAX).is_err());
    }
}

#[test]
fn native_probe_does_not_create_state_or_missing_directories()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let requirements = DiskRequirements {
        runtime_reserve_bytes: 1,
        staging_bytes: 0,
        backup_bytes: 0,
    };
    let inspection = requirements.inspect(root.path())?;
    assert!(inspection.total_bytes > 0);
    assert!(inspection.available_bytes <= inspection.total_bytes);
    assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    let missing = root.path().join("missing");
    assert!(requirements.inspect(&missing).is_err());
    assert!(!missing.exists());
    Ok(())
}

#[test]
fn operational_preflight_has_nonzero_exit_for_insufficient_space()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let invoke = |reserve: &str| {
        std::process::Command::new(env!("CARGO_BIN_EXE_watchdog"))
            .args(["preflight", "--state-directory"])
            .arg(root.path())
            .args(["--reserve-bytes", reserve])
            .output()
    };
    let approved = invoke("1")?;
    assert!(approved.status.success());
    let value: serde_json::Value = serde_json::from_slice(&approved.stdout)?;
    assert_eq!(value["admitted"], true);
    let denied = invoke("18446744073709551615")?;
    assert!(!denied.status.success());
    assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    Ok(())
}

#[test]
fn oversized_configuration_is_rejected_before_parsing() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let config = root.path().join("oversized.json");
    std::fs::write(&config, vec![b' '; 65_537])?;
    #[cfg(windows)]
    protect_config_for_native_read(&config)?;
    let result = ascension_watchdog::WatchdogConfig::from_file(&config);
    #[cfg(windows)]
    let bound_message = "protected payload file exceeds the payload bound";
    #[cfg(not(windows))]
    let bound_message = "65536-byte limit";
    assert!(
        matches!(&result, Err(ascension_watchdog::error::WatchdogError::InvalidInput(message))
            if message.contains(bound_message)),
        "oversized configuration must fail at the protected byte bound: {result:?}"
    );
    // The same protected file at the exact bound reaches JSON parsing. This
    // distinguishes the size rejection above from an unrelated ACL/path error.
    std::fs::write(&config, vec![b' '; 65_536])?;
    assert!(matches!(
        ascension_watchdog::WatchdogConfig::from_file(&config),
        Err(ascension_watchdog::error::WatchdogError::Json(_))
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn native_probe_rejects_linked_state_directory() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let link = root.path().join("linked");
    std::os::unix::fs::symlink(root.path(), &link)?;
    let requirements = DiskRequirements {
        runtime_reserve_bytes: 1,
        staging_bytes: 0,
        backup_bytes: 0,
    };
    assert!(requirements.inspect(&link).is_err());
    Ok(())
}
