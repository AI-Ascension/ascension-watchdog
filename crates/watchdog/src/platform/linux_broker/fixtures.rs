//! Shared value fixtures for the linux broker tests.
//!
//! Extracted verbatim from the `tests` coordinator; only visibility was widened
//! from private to the equivalent linux-broker scope so the coordinator, its
//! sibling test modules and their consumers keep building the same policy,
//! request, credential and observation values. No behaviour changed.

use super::*;
use std::sync::atomic::Ordering;
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
    let helper = helper_path();
    // Rebuild whenever the helper is missing *or* its source is newer than the
    // binary.  An `is_file()` check alone leaves a stale helper in place after
    // the helper source changes, which would silently authenticate the old
    // build for the rest of the run.
    //
    // The decision to rebuild is made *under* the lock and re-checked there, so
    // a test that arrives after the first build finished waits and then finds
    // the helper already current instead of starting a second `rustc` against
    // the same output path.  `cargo test --lib` runs these tests in parallel on
    // a target directory that has no prebuilt helper, so without this every
    // one of them used to build at once (#253).
    ensure_helper_is_current(&helper);
    fs::canonicalize(&helper).unwrap_or(helper)
}

/// Rebuild `helper` from its source unless it is already current, under the
/// process-wide build lock.
///
/// The re-check lives *inside* the lock, so the second and later callers in a
/// parallel `cargo test --lib` run observe the artifact the first one published
/// rather than each starting their own `rustc` against the same path.
fn ensure_helper_is_current(helper: &Path) {
    // A poisoned lock means an earlier build already panicked.  Recovering the
    // guard rather than propagating the poison keeps a single failed rebuild
    // from turning every later test into a confusing "poisoned lock" panic
    // instead of the real build error it is standing on.
    let _build_guard = HELPER_BUILD_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !helper_is_current(helper) {
        build_helper(helper);
    }
}

/// Target-directory path of the helper binary.
fn helper_path() -> PathBuf {
    std::env::current_exe()
        .expect("test executable path")
        .parent()
        .and_then(Path::parent)
        .expect("target directory")
        .join(HELPER_BIN)
}

/// Source path of the helper.
fn helper_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("bin")
        .join("broker_peer_fixture.rs")
}

/// Whether `helper` is present and no older than its source.
fn helper_is_current(helper: &Path) -> bool {
    let Ok(helper_modified) = fs::metadata(helper).and_then(|metadata| metadata.modified()) else {
        return false;
    };
    fs::metadata(helper_source())
        .and_then(|metadata| metadata.modified())
        .is_ok_and(|source_modified| source_modified <= helper_modified)
}

/// Build the helper with `rustc` directly.
///
/// Re-entering `cargo` here would deadlock: the enclosing `cargo test` holds
/// the build-directory lock for the whole run, so a nested `cargo build`
/// against the same target directory would wait forever.  The helper needs no
/// dependency other than `std`, so a direct one-file compile is both correct
/// and fast.
///
/// The compile goes to a process-unique path and is then moved onto the shared
/// one, so a second writer can never have the linker truncating or linking
/// over an artifact another reader is about to hash.  Concurrent `rustc`
/// invocations sharing one `-o` path do not merely race on the file: the
/// linkers collide inside it, and the observed failure is
/// `undefined symbol: main`, which reads like a corrupt source rather than a
/// concurrency fault (issue #253).  The move is atomic within a directory, so
/// the broker only ever hashes a complete helper.
fn build_helper(helper: &Path) {
    let source = helper_source();
    let executable = helper.to_path_buf();
    let staging = executable.with_extension(format!("{}.{}", std::process::id(), "staging"));
    BUILD_IN_PROGRESS.fetch_add(1, Ordering::SeqCst);
    MAX_CONCURRENT_BUILDS.fetch_max(BUILD_IN_PROGRESS.load(Ordering::SeqCst), Ordering::SeqCst);
    let status = std::process::Command::new("rustc")
        .args(["--edition", "2024", "-C", "debuginfo=0", "-o"])
        .arg(&staging)
        .arg(&source)
        .status()
        .expect("rustc build for the broker peer helper");
    BUILD_IN_PROGRESS.fetch_sub(1, Ordering::SeqCst);
    assert!(status.success(), "broker peer helper build failed");
    // Prove the artifact the broker is about to hash is the one just built.
    // Without this the fingerprint is taken on faith, and a silent no-op
    // compile would leave a stale helper authenticating these tests.
    assert!(
        staging.is_file(),
        "broker peer helper build produced no executable"
    );
    // Publish atomically.  A failure to move the artifact into place must not
    // leave the staging file behind to be mistaken for a helper on a later
    // run, and must not be swallowed into a stale-but-present executable.
    if let Err(error) = fs::rename(&staging, &executable) {
        let _ = fs::remove_file(&staging);
        panic!("broker peer helper install failed: {error}");
    }
}

const HELPER_BIN: &str = "broker-peer-fixture";

/// Serialises the on-demand helper build within this test process.
///
/// A `OnceLock` alone would not do: the helper must be rebuilt when its source
/// changes, not once per process, so the guard wraps a *re-checked* build
/// rather than a one-shot initialisation.
static HELPER_BUILD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// How many `rustc` builds are in flight, and the high-water mark.
///
/// These exist for the #253 witness below. They are always compiled — the
/// counters cost a few atomic operations per build, and a build happens at most
/// once per test run — so the witness measures the same `build_helper` the
/// broker tests use rather than a stand-in that could drift from it.
static BUILD_IN_PROGRESS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static MAX_CONCURRENT_BUILDS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Regression witness for the #253 build race.
///
/// The race was not reachable by asserting on the helper's contents: every
/// writer produced a *correct* helper, and the defect was that the writers
/// collided inside the shared output path, so a test could only observe it by
/// entering `build_helper` the way the real failure does — many threads at
/// once, on a helper that is deliberately not yet current.
#[cfg(test)]
mod build_race_tests {
    use super::*;

    /// Concurrent `helper_executable()` calls must not overlap their builds.
    ///
    /// Before the fix every thread that found the helper missing or stale ran
    /// its own `rustc` against the one shared path at the same time; measured
    /// directly, 8 concurrent writers to one `-o` path failed 22 times in 32
    /// attempts, while 8 concurrent writers to distinct paths failed 0 times in
    /// 32. This asserts that the build is serialised by reading the counters
    /// `build_helper` maintains around the real `rustc` call, so it cannot pass
    /// by asserting on something the fix did not change, and it does not depend
    /// on host load — which is exactly what kept the original flake invisible to
    /// CI.
    ///
    /// The helper is removed first, because that is what puts every thread on
    /// the build path: a fresh target directory has no helper, and
    /// `helper_is_current` otherwise short-circuits the second and later
    /// threads before they ever reach the build.
    #[test]
    fn concurrent_helper_calls_do_not_overlap_their_build() {
        const THREADS: usize = 8;
        let helper = helper_path();
        let _ = fs::remove_file(&helper);
        MAX_CONCURRENT_BUILDS.store(0, Ordering::SeqCst);
        let threads: Vec<_> = (0..THREADS)
            .map(|_| {
                std::thread::spawn(move || {
                    // The real call, so the lock under test is the one the
                    // broker tests take.
                    let resolved = helper_executable();
                    assert!(
                        resolved.is_file(),
                        "helper_executable returned a path with no artifact: {}",
                        resolved.display()
                    );
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("helper thread");
        }
        assert!(
            MAX_CONCURRENT_BUILDS.load(Ordering::SeqCst) <= 1,
            "two rustc builds ran at once, so the shared output path is still raced"
        );
        assert!(
            helper.is_file(),
            "the helper was never published: {}",
            helper.display()
        );
    }
}

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
    closed_path: PathBuf,
    release_path: PathBuf,
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
        let closed_path = directory.path().join("broker-closed");
        let release_path = directory.path().join("broker-release");
        let mut command = std::process::Command::new(&peer.executable);
        command
            .arg(&path)
            .arg(&reply_path)
            .arg(&release_path)
            .arg(&closed_path)
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
            closed_path,
            release_path,
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
    pub(in crate::platform::linux_broker) fn exchange(
        &mut self,
        request: &[u8],
    ) -> BrokerResult<()> {
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
    /// observed end-of-response and written the whole reply.  The peer process
    /// stays alive, because the broker re-authenticates on every call and the
    /// test may keep using the same credentials afterwards.
    pub(in crate::platform::linux_broker) fn reply(&mut self) -> BrokerResult<Vec<u8>> {
        self.read_reply()
    }

    /// Read the relayed reply, waiting for the helper to have written it.
    fn read_reply(&self) -> BrokerResult<Vec<u8>> {
        for _ in 0..3_000 {
            if self.reply_path.is_file() {
                return fs::read(&self.reply_path).map_err(io_error);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(BrokerError::Io(
            "broker peer helper never relayed a reply".to_owned(),
        ))
    }

    /// Block until the helper has stopped using the socket.
    ///
    /// A broker write only fails once the peer's end is closed, so a test that
    /// needs the broker to observe a lost response has to wait for this marker
    /// first.  Without it the answer can sit in the kernel buffer and the
    /// broker succeeds, so the test would assert nothing.
    pub(in crate::platform::linux_broker) fn wait_for_close(&self) -> BrokerResult<()> {
        for _ in 0..3_000 {
            if self.closed_path.is_file() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(BrokerError::Io(
            "broker peer helper never closed the connection".to_owned(),
        ))
    }

    /// Release the helper and wait for it to exit.
    ///
    /// The helper lingers until released so the peer process stays alive for
    /// every broker call the test makes; releasing it is what ends the wait.
    pub(in crate::platform::linux_broker) fn wait_for_exit(&mut self) -> BrokerResult<()> {
        fs::write(&self.release_path, b"release").map_err(io_error)?;
        let status = self.child.wait().map_err(io_error)?;
        if !status.success() {
            return Err(BrokerError::Io(format!(
                "broker peer helper exited with {status}"
            )));
        }
        Ok(())
    }
}

impl Drop for PeerSession {
    fn drop(&mut self) {
        // Never leave the helper parked: release it and reap it even when a
        // test fails part way through.
        let _ = fs::write(&self.release_path, b"release");
        let _ = self.child.kill();
        let _ = self.child.wait();
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
