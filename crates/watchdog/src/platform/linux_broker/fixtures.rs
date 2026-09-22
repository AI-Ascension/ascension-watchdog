//! Shared value fixtures for the linux broker tests.
//!
//! Extracted verbatim from the `tests` coordinator; only visibility was widened
//! from private to the equivalent linux-broker scope so the coordinator, its
//! sibling test modules and their consumers keep building the same policy,
//! request, credential and observation values. No behaviour changed.

use super::*;
use tempfile::tempdir_in;

pub(in crate::platform::linux_broker) fn digest(path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(fs::read(path).expect("fixture executable must be readable"));
    hex_digest(&hasher.finalize())
}

pub(in crate::platform::linux_broker) fn wait_for_peer_executable(pid: u32) -> PathBuf {
    let expected = fs::canonicalize("/usr/bin/sleep").expect("peer fixture executable path");
    let proc_executable = format!("/proc/{pid}/exe");
    for _ in 0..1_000 {
        if let Ok(executable) = fs::read_link(&proc_executable) {
            if executable == expected {
                return executable;
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("peer fixture process did not reach its executable");
}

pub(in crate::platform::linux_broker) fn peer_fixture() -> (PathBuf, String) {
    let mut child = std::process::Command::new("/usr/bin/sleep")
        .arg("30")
        .spawn()
        .expect("peer fixture process");
    let executable = wait_for_peer_executable(child.id());
    let executable_sha256 = digest(&executable);
    let _ = child.kill();
    let _ = child.wait();
    (executable, executable_sha256)
}

pub(in crate::platform::linux_broker) fn policy() -> BrokerPolicy {
    let executable = fs::canonicalize("/usr/bin/true").expect("fixture executable path");
    let (peer_executable, peer_executable_sha256) = peer_fixture();
    let peer_user_id = rustix::process::getuid().as_raw();
    let peer_group_id = rustix::process::getgid().as_raw();
    let distinct_nonzero = |value: u32| {
        let candidate = value.saturating_add(1);
        if candidate != 0 && candidate != value {
            candidate
        } else {
            1
        }
    };
    let launch = LaunchPolicy {
        executable: executable.clone(),
        executable_sha256: digest(&executable),
        arguments: Vec::new(),
        working_directory: PathBuf::from("/"),
        environment: Vec::new(),
        target_uid: distinct_nonzero(peer_user_id),
        target_gid: distinct_nonzero(peer_group_id),
        capabilities: CapabilityPolicy {
            bounding_set: 0,
            ambient_set: 0,
            no_new_privileges: true,
        },
        cgroup: CgroupPolicy {
            tasks_max: 16,
            memory_max_bytes: 64 * 1024 * 1024,
        },
        timeout: Duration::from_secs(2),
    };
    let peer = PeerPolicy {
        uid: peer_user_id,
        gid: peer_group_id,
        executable: peer_executable.clone(),
        executable_sha256: peer_executable_sha256,
    };
    BrokerPolicy::new(peer, BTreeMap::from([(BrokerComponent::Synthetic, launch)]))
        .expect("valid fixture policy")
}

pub(in crate::platform::linux_broker) fn transport_policy() -> BrokerPolicy {
    let base = policy();
    let executable = fs::canonicalize("/proc/self/exe").expect("test executable path");
    let peer = PeerPolicy {
        uid: base.peer.uid,
        gid: base.peer.gid,
        executable_sha256: digest(&executable),
        executable,
    };
    let mut components = base.components.clone();
    for launch in components.values_mut() {
        launch.timeout = MAX_IO_TIMEOUT;
    }
    // This fixture deliberately authenticates the current test process over a
    // socket pair.  Production rejects procfs policy paths; the direct struct
    // construction is test-only and keeps that production validation intact.
    BrokerPolicy { peer, components }
}

pub(in crate::platform::linux_broker) fn credentials(
    policy: &BrokerPolicy,
) -> (PeerCredentials, std::process::Child) {
    let child = std::process::Command::new("/usr/bin/sleep")
        .arg("30")
        .spawn()
        .expect("peer fixture process");
    assert_eq!(wait_for_peer_executable(child.id()), policy.peer.executable);
    (
        PeerCredentials {
            pid: child.id(),
            uid: policy.peer.uid,
            gid: policy.peer.gid,
        },
        child,
    )
}

pub(in crate::platform::linux_broker) fn request(nonce: &str) -> BrokerRequest {
    BrokerRequest {
        component: BrokerComponent::Synthetic,
        instance: "instance".to_owned(),
        incarnation: "incarnation".to_owned(),
        nonce: nonce.to_owned(),
    }
}

pub(in crate::platform::linux_broker) fn observation(
    policy: &LaunchPolicy,
    unit: &str,
) -> UnitObservation {
    UnitObservation {
        unit: unit.to_owned(),
        pid: 42,
        creation_token: "start-token".to_owned(),
        executable: policy.executable.clone(),
        executable_sha256: policy.executable_sha256.clone(),
        uid: policy.target_uid,
        gid: policy.target_gid,
        capability_bounding_set: policy.capabilities.bounding_set,
        ambient_capabilities: policy.capabilities.ambient_set,
        no_new_privileges: true,
        control_group: format!("/system.slice/{unit}"),
    }
}

pub(in crate::platform::linux_broker) fn protected_tempdir() -> tempfile::TempDir {
    // A user manager normally provides XDG_RUNTIME_DIR, but the repository's
    // Linux test lane also runs in minimal containers where /run/user does
    // not exist.  Keep the fixture on an existing private directory so the
    // protected-ancestor checks exercise the same ownership/mode contract
    // without requiring host-level runtime-directory provisioning.
    let runtime_directory = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute() && path.is_dir())
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    tempdir_in(runtime_directory).expect("protected test directory")
}
