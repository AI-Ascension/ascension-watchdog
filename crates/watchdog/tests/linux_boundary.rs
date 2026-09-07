#![cfg(target_os = "linux")]

use ascension_watchdog::platform::{
    AdapterError, ComponentKind, LaunchSpec, LinuxProcessAdapter, SessionSelector,
    TrustedLinuxLauncher,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

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
fn native_synthetic_descendant_boundary_is_explicitly_gated() {
    let result = LinuxProcessAdapter::new(BTreeMap::new());
    assert!(
        result.is_ok(),
        "native test host lacks delegated cgroup v2: {result:?}"
    );
}
