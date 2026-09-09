use super::{boot_scoped_start_token, process_start_token};

#[test]
fn only_the_exact_systemd_method_error_means_unit_absence() -> Result<(), Box<dyn std::error::Error>>
{
    let message =
        zbus::Message::signal("/fixture", "tech.complete.Fixture", "Changed")?.build(&())?;
    for (name, expected) in [
        ("org.freedesktop.systemd1.NoSuchUnit", true),
        ("org.freedesktop.systemd1.NoSuchUnitExtra", false),
        ("org.freedesktop.DBus.Error.Failed", false),
    ] {
        let error = zbus::Error::MethodError(
            name.try_into()?,
            Some("diagnostic mentions NoSuchUnit".to_owned()),
            message.clone(),
        );
        assert_eq!(super::unit_is_missing(&error), expected);
    }
    assert!(!super::unit_is_missing(&zbus::Error::Failure(
        "NoSuchUnit".to_owned()
    )));
    Ok(())
}

fn stat(ticks: &str) -> String {
    format!("42 (synthetic ) command) S {} {ticks}", ["0"; 18].join(" "))
}

#[test]
fn durable_birth_binding_includes_boot_identity_and_canonical_start_ticks() {
    let first_boot = "11111111-1111-4111-8111-111111111111";
    let second_boot = "22222222-2222-4222-8222-222222222222";
    let first = boot_scoped_start_token(first_boot, &stat("42")).expect("first identity");
    assert_eq!(first, format!("boot:{first_boot}:42"));
    assert_eq!(
        first,
        boot_scoped_start_token(&format!("{first_boot}\n"), &stat("42")).expect("kernel newline")
    );
    assert_ne!(
        first,
        boot_scoped_start_token(second_boot, &stat("42")).expect("second boot")
    );
    assert_ne!(
        first,
        boot_scoped_start_token(first_boot, &stat("43")).expect("second birth")
    );
    for ticks in ["", "01", "+1", "-1", "x", "18446744073709551616"] {
        assert!(boot_scoped_start_token(first_boot, &stat(ticks)).is_err());
    }
    for boot in [
        "",
        "invalid",
        "00000000-0000-0000-0000-000000000000",
        "11111111111141118111111111111111",
    ] {
        assert!(boot_scoped_start_token(boot, &stat("42")).is_err());
    }
}

#[test]
fn current_process_binding_is_stable_and_boot_scoped() {
    let first = process_start_token(std::process::id()).expect("current kernel identity");
    assert!(first.starts_with("boot:"));
    assert_eq!(
        first,
        process_start_token(std::process::id()).expect("same current process")
    );
}

#[test]
fn service_capabilities_support_cross_uid_inspection_and_exact_signal_only() {
    let service = include_str!("../../../../../deploy/linux/ascension-watchdog-broker.service");
    let capabilities = service
        .lines()
        .find_map(|line| line.strip_prefix("CapabilityBoundingSet="))
        .expect("explicit service capability allowlist");
    assert_eq!(
        capabilities,
        "CAP_CHOWN CAP_DAC_READ_SEARCH CAP_KILL CAP_SYS_PTRACE"
    );
    assert!(service.lines().any(|line| line == "NoNewPrivileges=yes"));
    assert!(service.lines().any(|line| line == "AmbientCapabilities="));
    assert!(
        service
            .lines()
            .any(|line| line == "RestrictAddressFamilies=AF_UNIX")
    );
}

#[test]
fn broker_service_recovery_has_an_explicit_non_destructive_start_limit() {
    let service = include_str!("../../../../../deploy/linux/ascension-watchdog-broker.service");
    let mut section = "";
    let mut settings = std::collections::BTreeMap::new();
    for line in service.lines().map(str::trim) {
        if line.starts_with('[') {
            section = line;
        } else if let Some((key, value)) = line.split_once('=') {
            assert!(settings.insert((section, key), value).is_none());
        }
    }
    for (section, key, value) in [
        ("[Unit]", "StartLimitIntervalSec", "600s"),
        ("[Unit]", "StartLimitBurst", "5"),
        ("[Unit]", "StartLimitAction", "none"),
        ("[Service]", "Restart", "on-failure"),
        ("[Service]", "RestartSec", "2s"),
        ("[Service]", "TimeoutStartSec", "30s"),
        ("[Service]", "TimeoutStopSec", "15s"),
    ] {
        assert_eq!(settings.get(&(section, key)), Some(&value), "{key}");
    }
}
