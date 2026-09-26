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

/// Canonical path of the small test-only broker peer helper.
///
/// `cargo test --lib` does not build `[[bin]]` targets, so the helper is built
/// on demand into the same target directory the test binary lives in.  The
/// helper is a few megabytes of trivially-linked code, which is what keeps the
/// broker's `authenticate_peer` hash cheap and the request deadline from
/// measuring test-binary size.
pub(in crate::platform::linux_broker) fn helper_executable() -> PathBuf {
    let helper = std::env::current_exe()
        .expect("test executable path")
        .parent()
        .and_then(Path::parent)
        .expect("target directory")
        .join(HELPER_BIN);
    if !helper.is_file() {
        build_helper();
    }
    fs::canonicalize(&helper).unwrap_or(helper)
}

/// Build the helper with `rustc` directly.
///
/// Re-entering `cargo` here would deadlock: the enclosing `cargo test` holds
/// the build-directory lock for the whole run, so a nested `cargo build`
/// against the same target directory would wait forever.  The helper needs no
/// dependency other than `std`, so a direct one-file compile is both correct
/// and fast.
fn build_helper() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("bin")
        .join("broker_peer_fixture.rs");
    let executable = std::env::current_exe()
        .expect("test executable path")
        .parent()
        .and_then(Path::parent)
        .expect("target directory")
        .join(HELPER_BIN);
    let status = std::process::Command::new("rustc")
        .args([
            "--edition",
            "2024",
            "-C",
            "debuginfo=0",
            "-o",
        ])
        .arg(&executable)
        .arg(&source)
        .status()
        .expect("rustc build for the broker peer helper");
    assert!(status.success(), "broker peer helper build failed");
}

const HELPER_BIN: &str = "broker-peer-fixture";

/// A live authenticated peer plus the broker end of its connection.
///
/// The helper connects itself, so `SO_PEERCRED` on the returned socket reports
/// the helper's PID rather than the test process's.  That is what lets the
/// broker hash a small peer executable.
pub(in crate::platform::linux_broker) struct PeerSession {
    pub(in crate::platform::linux_broker) credentials: PeerCredentials,
    socket: Option<UnixStream>,
    child: std::process::Child,
    reply_path: PathBuf,
    _directory: tempfile::TempDir,
}

impl PeerSession {
    /// Spawn the helper and accept the connection it opens.
    ///
    /// `peer.executable` is the helper the caller put in its policy, so the
    /// broker hashes this process rather than the test binary.
    pub(in crate::platform::linux_broker) fn start(peer: &PeerPolicy) -> BrokerResult<Self> {
        Self::spawn(peer, false)
    }

    /// Spawn a helper that closes the connection instead of relaying the
    /// broker's answer, modelling a peer that vanishes mid-request.
    pub(in crate::platform::linux_broker) fn start_dropping_reply(
        peer: &PeerPolicy,
    ) -> BrokerResult<Self> {
        Self::spawn(peer, true)
    }

    fn spawn(peer: &PeerPolicy, drop_reply: bool) -> BrokerResult<Self> {
        // The helper connects by path, so the directory that holds the socket
        // has to outlive `start`; keep it owned by the session.
        let directory = protected_tempdir();
        let path = directory.path().join("broker-peer.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).map_err(io_error)?;
        let reply_path = directory.path().join("broker-reply.bin");
        let mut command = std::process::Command::new(&peer.executable);
        command
            .arg(&path)
            .arg(&reply_path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null());
        if drop_reply {
            command.arg("DROP_REPLY");
        }
        let child = command.spawn().map_err(io_error)?;
        let (socket, _) = listener.accept().map_err(io_error)?;
        let credentials = peer_credentials(&socket)?;
        wait_for_helper_executable(credentials.pid, &peer.executable);
        Ok(Self {
            credentials,
            socket: Some(socket),
            child,
            reply_path,
            _directory: directory,
        })
    }

    /// Take the broker end of the connection.
    ///
    /// Ownership moves out so the test never keeps a second copy open: the
    /// helper only observes end-of-response once every broker-side descriptor
    /// is closed.
    pub(in crate::platform::linux_broker) fn take_socket(&mut self) -> BrokerResult<UnixStream> {
        self.socket
            .take()
            .ok_or_else(|| BrokerError::Io("peer socket was already taken".to_owned()))
    }

    /// Write `request` to the peer helper's stdin.  The helper relays it to
    /// the broker, half-closes, and writes the broker's reply to its stdout.
    pub(in crate::platform::linux_broker) fn exchange(&mut self, request: &[u8]) -> BrokerResult<()> {
        use std::io::Write;
        self.child
            .stdin
            .as_mut()
            .ok_or_else(|| BrokerError::Io("peer helper stdin is closed".to_owned()))?
            .write_all(request)
            .map_err(io_error)?;
        // Close the helper's stdin so it sees end-of-request and the broker
        // answers; dropping the handle closes the pipe.
        self.child
            .stdin
            .take()
            .ok_or_else(|| BrokerError::Io("peer helper stdin is closed".to_owned()))?;
        Ok(())
    }

    /// Wait for the helper to finish, then read the broker's reply it relayed.
    ///
    /// Call this only after the broker call has returned, so the helper has
    /// observed end-of-response and written the whole reply.
    pub(in crate::platform::linux_broker) fn reply(&mut self) -> BrokerResult<Vec<u8>> {
        self.wait_for_exit()?;
        fs::read(&self.reply_path).map_err(io_error)
    }

    /// Wait for the helper to finish relaying.
    ///
    /// A dropping helper never writes a reply file, so this does not read one.
    pub(in crate::platform::linux_broker) fn wait_for_exit(&mut self) -> BrokerResult<()> {
        let status = self.child.wait().map_err(io_error)?;
        if !status.success() {
            return Err(BrokerError::Io(format!(
                "broker peer helper exited with {status}"
            )));
        }
        Ok(())
    }
}

/// Wait until the peer process reports the approved executable.
///
/// The exec race matters: a spawned process is still the pre-exec image when
/// `connect` returns, so reading `/proc/<pid>/exe` immediately can observe a
/// different binary than the one the broker is about to hash.
fn wait_for_helper_executable(pid: u32, expected: &Path) {
    let proc_executable = format!("/proc/{pid}/exe");
    for _ in 0..10_000 {
        if let Ok(executable) = fs::read_link(&proc_executable)
            && executable == expected
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("broker peer helper did not reach its executable");
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
    let executable = helper_executable();
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
    // This fixture authenticates a dedicated small peer process (see
    // `PeerSession`) rather than the test process itself.  Production rejects
    // procfs policy paths and validates the peer executable as a protected
    // root-owned file; the direct struct construction here is test-only and
    // keeps that production validation intact.
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
