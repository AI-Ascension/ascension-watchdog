#![cfg(target_os = "linux")]

use ascension_watchdog::platform::{
    AdapterError, ComponentKind, LaunchSpec, LinuxProcessAdapter, Observation, ProcessAdapter,
    SessionSelector, StopOutcome, TrustedLinuxLauncher,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

fn specification(nonce: &str) -> LaunchSpec {
    LaunchSpec {
        deployment_id: "linux-boundary-deployment".to_owned(),
        instance_id: "linux-boundary-instance".to_owned(),
        component: ComponentKind::Synthetic,
        incarnation: "linux-boundary-incarnation".to_owned(),
        launch_nonce: nonce.to_owned(),
        executable: PathBuf::from("/bin/true"),
        executable_sha256: "a".repeat(64),
        arguments: Vec::new(),
        working_directory: None,
        environment: Vec::new(),
        session: SessionSelector::Explicit(0),
        graceful_timeout: Duration::from_millis(100),
        force_timeout: Duration::from_secs(1),
    }
}

fn linux_pid_is_running(pid: u32) -> bool {
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some(close) = stat.rfind(')') else {
        return false;
    };
    stat.get(close + 2..)
        .and_then(|suffix| suffix.chars().next())
        .is_some_and(|state| state != 'Z')
}

#[test]
fn planned_containment_changes_with_launch_nonce() -> Result<(), Box<dyn std::error::Error>> {
    let first = LinuxProcessAdapter::planned_containment_for(&specification("nonce-a"))?;
    let second = LinuxProcessAdapter::planned_containment_for(&specification("nonce-b"))?;
    assert_ne!(first, second);
    assert!(first.as_str().starts_with("cgroup-v2:ascension-"));
    Ok(())
}

#[test]
fn cgroup_root_without_controls_is_explicitly_unavailable() {
    let result = LinuxProcessAdapter::with_cgroup_root(PathBuf::from("/tmp"), BTreeMap::new());
    assert!(matches!(result, Err(AdapterError::Unavailable(_))));
}

#[test]
fn helper_constructor_hashes_a_regular_executable_before_use() {
    let launcher = TrustedLinuxLauncher::new("/bin/true");
    assert!(launcher.is_ok());
}

/// This is intentionally ignored unless an approved Linux service test host
/// supplies a writable delegated cgroup v2 and the real watchdog binary is
/// wired to dispatch the hidden helper entrypoint.  A local build or a
/// cross-target test must not be reported as native containment evidence.
#[test]
#[ignore = "requires an approved writable delegated cgroup and real helper entrypoint"]
fn native_synthetic_descendant_boundary_is_explicitly_gated()
-> Result<(), Box<dyn std::error::Error>> {
    let executable = fs::canonicalize("/bin/sh")?;
    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(fs::read(&executable)?);
        let mut digest = String::with_capacity(64);
        for byte in hasher.finalize() {
            std::fmt::Write::write_fmt(&mut digest, format_args!("{byte:02x}"))
                .map_err(|_| "digest formatting failed")?;
        }
        digest
    };
    let mut allowlist = BTreeMap::new();
    allowlist.insert(ComponentKind::Synthetic, executable.clone());
    let helper = std::env::var_os("CARGO_BIN_EXE_watchdog")
        .or_else(|| std::env::var_os("ASCENSION_WATCHDOG_EXECUTABLE"))
        .ok_or("native test requires CARGO_BIN_EXE_watchdog or ASCENSION_WATCHDOG_EXECUTABLE")?;
    let launcher = TrustedLinuxLauncher::new(PathBuf::from(helper))?;
    let mut adapter = LinuxProcessAdapter::new_with_launcher(allowlist, launcher)?;
    let directory = tempfile::tempdir()?;
    let specification = LaunchSpec {
        deployment_id: "native-boundary-deployment".to_owned(),
        instance_id: "native-boundary-instance".to_owned(),
        component: ComponentKind::Synthetic,
        incarnation: "native-boundary-incarnation".to_owned(),
        launch_nonce: format!("native-boundary-{}", std::process::id()),
        executable,
        executable_sha256: digest,
        arguments: vec![
            "-c".to_owned(),
            "/bin/sleep 30 & child=$!; printf '%s\\n' \"$child\" > descendant.pid; wait".to_owned(),
        ],
        working_directory: Some(directory.path().to_path_buf()),
        environment: Vec::new(),
        session: SessionSelector::Explicit(0),
        graceful_timeout: Duration::from_millis(100),
        force_timeout: Duration::from_secs(2),
    };
    let owned = adapter.launch(&specification)?;
    let descendant_path = directory.path().join("descendant.pid");
    let deadline = Instant::now() + Duration::from_secs(2);
    let descendant = loop {
        if let Ok(value) = fs::read_to_string(&descendant_path)
            && let Ok(pid) = value.trim().parse::<u32>()
            && pid != 0
        {
            break pid;
        }
        if Instant::now() >= deadline {
            let _ = adapter.force_stop(&owned);
            return Err("native target did not publish a descendant PID".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if !linux_pid_is_running(descendant) {
        let _ = adapter.force_stop(&owned);
        return Err("descendant was not running before cgroup cleanup".into());
    }

    let outcome = match adapter.force_stop(&owned) {
        Ok(outcome) => outcome,
        Err(error) => {
            let recovery = adapter.force_cleanup_planned_containment(&owned.identity.containment);
            return Err(
                format!("native force cleanup failed: {error}; recovery: {recovery:?}").into(),
            );
        }
    };
    if !matches!(outcome, StopOutcome::Exited | StopOutcome::AlreadyExited) {
        let recovery = adapter.force_cleanup_planned_containment(&owned.identity.containment);
        return Err(
            format!("native force cleanup timed out: {outcome:?}; recovery: {recovery:?}").into(),
        );
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while linux_pid_is_running(descendant) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if linux_pid_is_running(descendant) {
        let recovery = adapter.force_cleanup_planned_containment(&owned.identity.containment);
        return Err(format!(
            "cgroup force cleanup left the descendant alive; recovery: {recovery:?}"
        )
        .into());
    }
    assert!(matches!(adapter.inspect(&owned)?, Observation::Missing));
    Ok(())
}
