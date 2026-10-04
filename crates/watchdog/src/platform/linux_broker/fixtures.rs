//! Shared value fixtures extracted from the Linux broker test coordinator.

use super::*;
use std::fs::OpenOptions;
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

/// Canonical path of the small test-only peer helper, built on demand because
/// `cargo test --lib` does not build binary targets.
pub(in crate::platform::linux_broker) fn helper_executable() -> PathBuf {
    helper_executable_at(&helper_path())
}

/// Resolve `helper` to a current, canonical executable.
///
/// The #253 witness uses a private output path. Removing the shared helper
/// would replace its inode beneath live peers and stale their executable
/// identity, the #255 regression.
pub(super) fn helper_executable_at(path: &Path) -> PathBuf {
    let helper = path.to_path_buf();
    // Re-check freshness under both locks so concurrent tests cannot rebuild
    // stale/missing output against the same target path (#253).
    ensure_helper_is_current(&helper);
    fs::canonicalize(&helper).unwrap_or(helper)
}

/// Rebuild `helper` from its source unless it is already current, under the
/// process-wide mutex and owner-local process lock.
///
/// The re-check lives inside both locks, so later callers in this process or
/// another process sharing the target directory observe the artifact the first
/// one published rather than starting another `rustc` against shared
/// intermediates.
fn ensure_helper_is_current(helper: &Path) {
    // A poisoned lock means an earlier build already panicked.  Recovering the
    // guard rather than propagating the poison keeps a single failed rebuild
    // from turning every later test into a confusing "poisoned lock" panic
    // instead of the real build error it is standing on.
    let _build_guard = HELPER_BUILD_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let process_lock = open_helper_build_lock(helper);
    if std::env::var_os(HELPER_BUILD_BYPASS_PROCESS_LOCK_ENV).is_none() {
        // `File::lock` associates the lock with this handle, which remains in
        // scope through the re-check/build and drops only when this function
        // returns or unwinds.
        process_lock
            .lock()
            .expect("cross-process helper build lock");
    }
    if !helper_is_current(helper) {
        build_helper(helper);
    }
}

/// Open the owner-local lock file whose kernel-managed advisory lock
/// serializes independent test processes sharing this helper output path.
fn open_helper_build_lock(helper: &Path) -> File {
    let parent = helper.parent().expect("helper output directory");
    fs::create_dir_all(parent).expect("helper output directory");
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(helper_build_lock_path(helper))
        .expect("helper build lock file")
}

pub(super) fn helper_build_lock_path(helper: &Path) -> PathBuf {
    let mut lock_name = helper
        .file_name()
        .expect("helper output filename")
        .to_os_string();
    lock_name.push(".build.lock");
    helper.with_file_name(lock_name)
}

/// Target-directory path of the helper binary.
fn helper_path() -> PathBuf {
    target_directory().join(HELPER_BIN)
}

/// Directory the test binary itself lives in, one level below the target
/// directory that holds on-demand build products.
pub(super) fn target_directory() -> PathBuf {
    std::env::current_exe()
        .expect("test executable path")
        .parent()
        .and_then(Path::parent)
        .expect("target directory")
        .to_path_buf()
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

/// Build the std-only helper directly with `rustc`; a nested Cargo build would
/// wait forever on the target-directory lock held by the enclosing test.
///
/// Each compiler gets a private parent for its `.rcgu.o` intermediates and
/// output. Atomic rename publishes only a complete helper, even if a compiler
/// outlives the process that held the cross-process lock.
fn build_helper(helper: &Path) {
    let source = helper_source();
    let executable = helper.to_path_buf();
    let parent = executable.parent().expect("helper output directory");
    fs::create_dir_all(parent).expect("helper output directory");
    let staging_directory = tempfile::Builder::new()
        .prefix("broker-peer-fixture-build-")
        .tempdir_in(parent)
        .expect("private helper build directory");
    let staging = staging_directory.path().join(HELPER_BIN);
    BUILD_IN_PROGRESS.fetch_add(1, Ordering::SeqCst);
    MAX_CONCURRENT_BUILDS.fetch_max(BUILD_IN_PROGRESS.load(Ordering::SeqCst), Ordering::SeqCst);
    #[cfg(test)]
    pause_helper_build_before_rustc();
    let mut compiler = match std::process::Command::new("rustc")
        .args(["--edition", "2024", "-C", "debuginfo=0", "-o"])
        .arg(&staging)
        .arg(&source)
        .spawn()
    {
        Ok(compiler) => compiler,
        Err(error) => {
            BUILD_IN_PROGRESS.fetch_sub(1, Ordering::SeqCst);
            panic!("rustc build for the broker peer helper: {error}");
        }
    };
    #[cfg(test)]
    pause_rustc_child_for_death_test(&compiler, &staging);
    #[cfg(test)]
    if std::env::var_os(HELPER_BUILD_EXIT_AFTER_RUSTC_CHILD_ENV).is_some() {
        std::process::exit(73);
    }
    let status = compiler.wait();
    BUILD_IN_PROGRESS.fetch_sub(1, Ordering::SeqCst);
    let status = status.expect("rustc build for the broker peer helper");
    if !status.success() {
        let _ = fs::remove_file(&staging);
        panic!("broker peer helper build failed");
    }
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

#[cfg(test)]
const HELPER_BUILD_TEST_GATE_ENV: &str = "ASCENSION_WATCHDOG_HELPER_BUILD_TEST_GATE";
#[cfg(test)]
pub(super) const HELPER_BUILD_BYPASS_PROCESS_LOCK_ENV: &str =
    "ASCENSION_WATCHDOG_HELPER_BYPASS_PROCESS_LOCK";
#[cfg(test)]
pub(super) const HELPER_BUILD_RUSTC_CHILD_MARKER_ENV: &str =
    "ASCENSION_WATCHDOG_HELPER_RUSTC_CHILD_MARKER";
#[cfg(test)]
pub(super) const HELPER_BUILD_EXIT_AFTER_RUSTC_CHILD_ENV: &str =
    "ASCENSION_WATCHDOG_HELPER_EXIT_AFTER_RUSTC_CHILD";

/// Test-only rendezvous that lets the parent witness observe whether
/// independent builders can enter rustc together.
#[cfg(test)]
fn pause_helper_build_before_rustc() {
    let Some(gate_directory) = std::env::var_os(HELPER_BUILD_TEST_GATE_ENV).map(PathBuf::from)
    else {
        return;
    };
    let process_id = std::process::id();
    let ready = gate_directory.join(format!("rustc-ready-{process_id}"));
    fs::write(ready, process_id.to_string()).expect("signal helper builder ready for rustc");
    let release = gate_directory.join("rustc-go");
    let deadline = Instant::now() + Duration::from_mins(1);
    while !release.is_file() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for cross-process rustc test release"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Stop the spawned compiler before its test owner exits, leaving a live
/// compiler child for the crash-recovery witness to resume.
#[cfg(test)]
fn pause_rustc_child_for_death_test(compiler: &std::process::Child, staging: &Path) {
    let Some(marker) = std::env::var_os(HELPER_BUILD_RUSTC_CHILD_MARKER_ENV) else {
        return;
    };
    let process_id = compiler.id();
    let status = std::process::Command::new("kill")
        .args(["-STOP", &process_id.to_string()])
        .status()
        .expect("stop test-owned rustc child");
    if !status.success() {
        let _ = std::process::Command::new("/bin/kill")
            .args(["-KILL", &process_id.to_string()])
            .status();
        panic!("could not stop test-owned rustc child");
    }
    let mut temporary_marker = marker.as_os_str().to_os_string();
    temporary_marker.push(".tmp");
    let temporary_marker = PathBuf::from(temporary_marker);
    if let Err(error) = fs::write(
        &temporary_marker,
        format!("pid={process_id}\nstaging={}\n", staging.display()),
    )
    .and_then(|()| fs::rename(&temporary_marker, marker))
    {
        let _ = std::process::Command::new("/bin/kill")
            .args(["-KILL", &process_id.to_string()])
            .status();
        panic!("record stopped rustc child: {error}");
    }
}

#[cfg(test)]
pub(super) fn read_rustc_marker(path: &Path) -> (u32, PathBuf) {
    let marker = fs::read_to_string(path).expect("rustc marker");
    let process_id = marker
        .lines()
        .find_map(|line| line.strip_prefix("pid="))
        .expect("rustc pid")
        .parse()
        .expect("valid rustc pid");
    let staging = marker
        .lines()
        .find_map(|line| line.strip_prefix("staging="))
        .map(PathBuf::from)
        .expect("rustc staging path");
    (process_id, staging)
}

#[cfg(test)]
pub(super) fn rustc_process_identity(pid: u32) -> Option<(char, u32, u64)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields = stat
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    Some((
        fields.first()?.chars().next()?,
        fields.get(1)?.parse().ok()?,
        fields.get(19)?.parse().ok()?,
    ))
}

#[cfg(test)]
pub(super) fn signal_rustc_child(pid: u32, start_time: u64, signal: &str) {
    assert_eq!(
        rustc_process_identity(pid)
            .expect("test-owned rustc remains alive")
            .2,
        start_time,
        "rustc pid was reused"
    );
    let status = std::process::Command::new("/bin/kill")
        .args([format!("-{signal}"), pid.to_string()])
        .status()
        .expect("signal test-owned rustc child");
    assert!(status.success(), "could not signal test-owned rustc child");
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

/// Regression witness for the #253 build race.
///
/// The race was not reachable by asserting on the helper's contents: every
/// writer produced a *correct* helper, and the defect was that the writers
/// collided inside the shared output path, so a test could only observe it by
/// entering `build_helper` the way the real failure does — many threads at
/// once, on a helper that is deliberately not yet current.
#[cfg(test)]
pub(super) mod build_race_tests {
    use super::*;

    /// Concurrent same-process callers rebuild a private helper only once.
    #[test]
    fn concurrent_helper_calls_do_not_overlap_their_build() {
        drive_concurrent_helper_builds();
    }

    /// Independent test processes that share the target directory must not
    /// enter rustc together, where rustc can collide on shared `.rcgu.o` files.
    #[test]
    fn independent_helper_builder_processes_do_not_collide() {
        const BUILDERS: usize = 8;
        let scratch = tempdir_in(target_directory()).expect("cross-process witness scratch");
        let output_directory = scratch.path().join("output");
        let shared_temporary_directory = scratch.path().join("shared-tmp");
        let gate_directory = scratch.path().join("coordination");
        fs::create_dir_all(&output_directory).expect("helper output directory");
        fs::create_dir_all(&shared_temporary_directory).expect("shared rustc temporary directory");
        fs::create_dir_all(&gate_directory).expect("builder coordination directory");
        let helper = output_directory.join(HELPER_BIN);
        let worker_ready: Vec<_> = (0..BUILDERS)
            .map(|index| gate_directory.join(format!("worker-ready-{index}")))
            .collect();
        let test_executable = std::env::current_exe().expect("test executable path");
        let mut children = Vec::with_capacity(BUILDERS);

        for index in 0..BUILDERS {
            let child = std::process::Command::new(&test_executable)
                .arg("independent_helper_builder_process_worker")
                .arg("--nocapture")
                .env("ASCENSION_WATCHDOG_HELPER_OUTPUT", &helper)
                .env(
                    "ASCENSION_WATCHDOG_HELPER_TEST_GATE_DIRECTORY",
                    &gate_directory,
                )
                .env(HELPER_BUILD_TEST_GATE_ENV, &gate_directory)
                .env("ASCENSION_WATCHDOG_HELPER_TEST_INDEX", index.to_string())
                .env(
                    "ASCENSION_WATCHDOG_HELPER_TEST_RECEIPT",
                    gate_directory.join(format!("built-{index}")),
                )
                // Pin the pre-fix failure shape: all independent rustc processes
                // inherit one temporary directory and output directory.
                .env("TMPDIR", &shared_temporary_directory)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn independent helper builder test process");
            children.push(child);
        }

        let workers_started = wait_for_helper_build_test_files(&worker_ready);
        // Release both barriers even on a timeout so no test child is stranded.
        fs::write(gate_directory.join("workers-go"), b"go")
            .expect("release helper builder test processes");
        let rustc_ready: Vec<_> = children
            .iter()
            .map(|child| gate_directory.join(format!("rustc-ready-{}", child.id())))
            .collect();
        let rustc_started = workers_started
            && wait_for_helper_build_test_count(&rustc_ready, 1, Duration::from_mins(1));
        let overlapping_rustc_builders = rustc_started
            && wait_for_helper_build_test_count(&rustc_ready, 2, Duration::from_secs(1));
        fs::write(gate_directory.join("rustc-go"), b"go").expect("release concurrent rustc builds");

        let outputs = wait_for_helper_builder_children(children);
        assert!(
            workers_started,
            "all independent builder test processes did not reach the start gate"
        );
        assert!(
            rustc_started,
            "no independent builder process reached the rustc gate"
        );
        assert!(
            !overlapping_rustc_builders,
            "multiple independent builder processes entered rustc together"
        );
        for (index, output) in outputs.iter().enumerate() {
            assert!(
                output.status.success(),
                "independent helper builder {index} failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let mut process_ids = std::collections::BTreeSet::new();
        let mut builder_digests = std::collections::BTreeSet::new();
        for index in 0..BUILDERS {
            let summary = fs::read_to_string(gate_directory.join(format!("built-{index}")))
                .expect("independent builder validation receipt");
            let process_id = summary
                .lines()
                .find_map(|line| line.strip_prefix("pid="))
                .expect("builder PID in receipt")
                .parse::<u32>()
                .expect("valid builder PID");
            let helper_digest = summary
                .lines()
                .find_map(|line| line.strip_prefix("sha256="))
                .expect("helper digest in receipt");
            assert!(summary.lines().any(|line| line == "exit=2"));
            assert!(
                summary
                    .lines()
                    .any(|line| line.starts_with("bytes=") && line != "bytes=0")
            );
            assert_eq!(helper_digest.len(), 64);
            process_ids.insert(process_id);
            builder_digests.insert(helper_digest.to_owned());
        }
        assert_eq!(
            process_ids.len(),
            BUILDERS,
            "builders must be separate processes"
        );
        assert!(helper.is_file(), "no helper was atomically published");
        let final_output = std::process::Command::new(&helper)
            .output()
            .expect("execute final published helper");
        assert_eq!(final_output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&final_output.stderr).contains("SOCKET, REPLY_PATH"));
        assert!(
            builder_digests.contains(&digest(&helper)),
            "published helper differs from every independently validated build"
        );
    }

    #[test]
    fn independent_builder_regression_detects_process_lock_bypass() {
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .arg("independent_helper_builder_processes_do_not_collide")
            .arg("--nocapture")
            .env(HELPER_BUILD_BYPASS_PROCESS_LOCK_ENV, "1")
            .output()
            .expect("run process-lock mutation witness");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "bypassed process lock passed the regression"
        );
        assert!(
            stderr.contains("multiple independent builder processes entered rustc together"),
            "mutation failed for another reason: {stderr}"
        );
    }

    /// Child entrypoint for independently launched helper builders.
    #[test]
    fn independent_helper_builder_process_worker() {
        let Some(helper) = std::env::var_os("ASCENSION_WATCHDOG_HELPER_OUTPUT").map(PathBuf::from)
        else {
            return;
        };
        if let Some(gate_directory) =
            std::env::var_os("ASCENSION_WATCHDOG_HELPER_TEST_GATE_DIRECTORY").map(PathBuf::from)
        {
            let index =
                std::env::var("ASCENSION_WATCHDOG_HELPER_TEST_INDEX").expect("builder test index");
            let ready = gate_directory.join(format!("worker-ready-{index}"));
            fs::write(ready, std::process::id().to_string()).expect("signal builder test ready");
            assert!(wait_for_helper_build_test_file(
                &gate_directory.join("workers-go")
            ));
        }

        let resolved = helper_executable_at(&helper);
        let output = std::process::Command::new(&resolved)
            .output()
            .expect("execute independently built helper");
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("SOCKET, REPLY_PATH"));
        let metadata = fs::metadata(&resolved).expect("built helper metadata");
        let summary = format!(
            "pid={}\nexit={}\nbytes={}\nsha256={}\n",
            std::process::id(),
            output.status.code().expect("helper exit status"),
            metadata.len(),
            digest(&resolved)
        );
        if let Some(receipt) = std::env::var_os("ASCENSION_WATCHDOG_HELPER_TEST_RECEIPT") {
            fs::write(receipt, summary).expect("write independent builder validation receipt");
        }
    }

    fn wait_for_helper_build_test_files(paths: &[PathBuf]) -> bool {
        wait_for_helper_build_test_count(paths, paths.len(), Duration::from_mins(1))
    }

    fn wait_for_helper_build_test_count(
        paths: &[PathBuf],
        expected: usize,
        timeout: Duration,
    ) -> bool {
        let deadline = Instant::now() + timeout;
        while paths.iter().filter(|path| path.is_file()).count() < expected {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        true
    }

    pub(in crate::platform::linux_broker::tests) fn wait_for_helper_build_test_file(
        path: &Path,
    ) -> bool {
        wait_for_helper_build_test_count(&[path.to_path_buf()], 1, Duration::from_secs(20))
    }

    fn wait_for_helper_builder_children(
        children: Vec<std::process::Child>,
    ) -> Vec<std::process::Output> {
        wait_for_helper_builder_children_with_timeout(children, Duration::from_mins(2))
    }

    pub(in crate::platform::linux_broker::tests) fn wait_for_helper_builder_children_with_timeout(
        mut children: Vec<std::process::Child>,
        timeout: Duration,
    ) -> Vec<std::process::Output> {
        let deadline = Instant::now() + timeout;
        loop {
            let wait_states = children
                .iter_mut()
                .map(std::process::Child::try_wait)
                .collect::<std::io::Result<Vec<_>>>();
            let all_finished = match wait_states {
                Ok(statuses) => statuses.iter().all(Option::is_some),
                Err(error) => {
                    stop_helper_builder_children(&mut children);
                    panic!("could not observe independent helper builder: {error}");
                }
            };
            if all_finished {
                break;
            }
            if Instant::now() >= deadline {
                stop_helper_builder_children(&mut children);
                panic!("timed out waiting for independent helper builder processes");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        children
            .into_iter()
            .map(|child| {
                child
                    .wait_with_output()
                    .expect("collect independent builder process output")
            })
            .collect()
    }

    fn stop_helper_builder_children(children: &mut [std::process::Child]) {
        for child in children.iter_mut() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
        }
        for child in children.iter_mut() {
            let _ = child.wait();
        }
    }

    /// Drive the real in-process helper builder from eight concurrent callers.
    fn drive_concurrent_helper_builds() {
        const THREADS: usize = 8;
        // A private, empty directory: no helper exists, so every thread must
        // reach `build_helper`, and nothing outside this test is disturbed.
        let scratch = tempfile::tempdir().expect("witness scratch directory");
        let helper = scratch.path().join(HELPER_BIN);
        MAX_CONCURRENT_BUILDS.store(0, Ordering::SeqCst);
        let threads: Vec<_> = (0..THREADS)
            .map(|_| {
                let helper = helper.clone();
                std::thread::spawn(move || {
                    // The real call, so the lock under test is the one the
                    // broker tests take.
                    let resolved = helper_executable_at(&helper);
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

    /// Regression witness that building a private helper leaves a live approved
    /// peer and its executable identity untouched.
    #[test]
    fn a_live_approved_peer_survives_the_build_race_witness() {
        let policy = transport_policy();
        let session = PeerSession::start(&policy.peer).expect("peer session must start");
        let credentials = session.credentials;
        let deadline = Instant::now() + Duration::from_secs(30);

        // The exact build the race witness performs, via the exact function it
        // performs it in.  If that ever unlinks the shared helper again, the
        // assertions below fail on this run rather than on whichever
        // unrelated broker test loses the race for it.
        drive_concurrent_helper_builds();

        // The shared helper must be untouched: present, and still the exact
        // executable the running peer resolves to.
        let shared = helper_executable();
        assert!(shared.is_file(), "the shared helper went missing");
        let resolved = fs::read_link(format!("/proc/{}/exe", credentials.pid))
            .expect("the live peer must still resolve its executable");
        assert_eq!(
            resolved, shared,
            "the shared helper was republished, so the live peer now resolves a \
             different path than the approved one"
        );

        // And the broker must still approve that live peer.
        assert!(
            authenticate_peer(credentials, &policy.peer, deadline).is_ok(),
            "a live approved peer must still authenticate after the race witness"
        );
    }
}
