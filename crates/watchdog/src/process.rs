//! Restricted direct process adapter.
//!
//! Only an exact, preconfigured executable is launched.  Cleanup uses the
//! owned `Child` handle plus a creation fingerprint and canonical executable
//! path; Unix synthetic children additionally get an exact process group for
//! descendant cleanup. A PID or executable name by itself is never sufficient.

use crate::config::ComponentConfig;
use crate::error::{Result, WatchdogError};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fs::File;
use std::io::{BufReader, Read};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use uuid::Uuid;

#[cfg(unix)]
use rustix::process::{
    Pid, Signal, WaitId, WaitIdOptions, kill_process_group, test_kill_process_group, waitid,
};

const MAX_OUTPUT_BYTES: usize = 64 * 1024;
#[cfg(unix)]
const PROCESS_GROUP_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

/// Immutable launch identity.  It is persisted alongside the component state
/// and is intentionally richer than a PID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub launch_nonce: String,
    pub executable: PathBuf,
    pub executable_digest: String,
    pub started_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_fingerprint: Option<String>,
}

/// Failure from the portable child launcher. `CleanupUncertain` means that
/// the launch may have created a process group whose cleanup could not be
/// proven before the bounded deadline; callers must retain/quarantine the
/// corresponding launch intent instead of treating this as an ordinary
/// rejected launch.
#[derive(Debug)]
pub enum ProcessSpawnError {
    Ordinary(WatchdogError),
    CleanupUncertain(WatchdogError),
}

impl ProcessSpawnError {
    /// Convert to the legacy process error used by callers that do not need
    /// cleanup classification.
    #[must_use]
    pub fn into_watchdog_error(self) -> WatchdogError {
        match self {
            Self::Ordinary(error) | Self::CleanupUncertain(error) => error,
        }
    }

    /// True when process creation may have left exact containment unsettled.
    #[must_use]
    pub fn is_cleanup_uncertain(&self) -> bool {
        matches!(self, Self::CleanupUncertain(_))
    }
}

impl std::fmt::Display for ProcessSpawnError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ordinary(error) => write!(formatter, "ordinary process spawn failure: {error}"),
            Self::CleanupUncertain(error) => {
                write!(formatter, "process spawn cleanup is uncertain: {error}")
            }
        }
    }
}

impl std::error::Error for ProcessSpawnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ordinary(error) | Self::CleanupUncertain(error) => Some(error),
        }
    }
}

impl From<WatchdogError> for ProcessSpawnError {
    fn from(error: WatchdogError) -> Self {
        Self::Ordinary(error)
    }
}

impl From<std::io::Error> for ProcessSpawnError {
    fn from(error: std::io::Error) -> Self {
        Self::Ordinary(WatchdogError::Io(error))
    }
}

/// Bounded captured child output.  Output is diagnostic only and never used as
/// a health or settlement witness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OutputSnapshot {
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Clone, Debug, Default)]
struct BoundedOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

/// Owned process and its exact identity.
pub struct OwnedChild {
    child: Child,
    identity: ProcessIdentity,
    #[cfg(unix)]
    process_group: ProcessGroupAuthority,
    output: Arc<Mutex<BoundedOutput>>,
    readers: Vec<JoinHandle<()>>,
}

#[cfg(unix)]
#[derive(Debug)]
struct ProcessGroupAuthority {
    /// The process-group identifier is usable only while the exact direct
    /// child remains unreaped. Once the leader is reaped, the numeric group
    /// identifier is retained as diagnostic state but can never be signalled.
    pgid: Pid,
    leader_reaped: bool,
    #[cfg(test)]
    force_cleanup_failure: bool,
    #[cfg(test)]
    signal_count: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(unix)]
impl ProcessGroupAuthority {
    fn new(pgid: Pid) -> Self {
        Self {
            pgid,
            leader_reaped: false,
            #[cfg(test)]
            force_cleanup_failure: false,
            #[cfg(test)]
            signal_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    fn is_armed(&self) -> bool {
        !self.leader_reaped
    }

    fn disarm_after_reap(&mut self) {
        self.leader_reaped = true;
    }

    /// Signal the exact group only while its direct leader is still an
    /// unreaped child of this process. A PID/PGID is not a reusable authority
    /// after reap, so callers must treat this guard as a hard lifetime rule.
    fn kill(&self) -> Result<()> {
        if !self.is_armed() {
            return Err(WatchdogError::Conflict(
                "owned child process-group authority was already disarmed".to_owned(),
            ));
        }
        #[cfg(test)]
        self.signal_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match signal_process_group(self.pgid) {
            Ok(()) => Ok(()),
            Err(error)
                if error.raw_os_error()
                    == std::io::Error::from(rustix::io::Errno::SRCH).raw_os_error() =>
            {
                Ok(())
            }
            Err(error) => Err(WatchdogError::Io(error)),
        }
    }

    /// Prove, within a bounded interval, that no descendant remains in the
    /// exact group while the leader is still an unreaped zombie.  Linux's
    /// process-group `kill` status alone includes that zombie, so inspect
    /// `/proc` to distinguish the leader from remaining group members.
    fn cleanup_before_reap(&self, leader_pid: u32, deadline: Instant) -> Result<()> {
        #[cfg(test)]
        if self.force_cleanup_failure {
            return Err(WatchdogError::Timeout(
                "injected process-group cleanup proof failure".to_owned(),
            ));
        }
        loop {
            self.kill()?;
            if !group_has_other_members(self.pgid, leader_pid)? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(WatchdogError::Timeout(format!(
                    "owned process group {} did not become empty before leader reap",
                    self.pgid.as_raw_pid()
                )));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// After the direct child is reaped, never signal the numeric PGID again.
    /// A final status proof is read-only; if the group remains present or
    /// becomes ambiguous, return an error so the caller retains/quarantines
    /// the ownership record instead of claiming cleanup succeeded.
    fn wait_gone_after_reap(&self, deadline: Instant) -> Result<()> {
        loop {
            match test_kill_process_group(self.pgid) {
                Ok(()) => {
                    if Instant::now() >= deadline {
                        return Err(WatchdogError::Timeout(format!(
                            "owned process group {} remained after leader reap",
                            self.pgid.as_raw_pid()
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) if error == rustix::io::Errno::SRCH => return Ok(()),
                Err(error) => return Err(WatchdogError::Io(std::io::Error::from(error))),
            }
        }
    }
}

impl std::fmt::Debug for OwnedChild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedChild")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl OwnedChild {
    /// Spawn one approved component directly (without a shell or proxy).
    pub fn spawn(spec: &ComponentConfig, now_ms: u64) -> Result<Self> {
        Self::spawn_with_cleanup_status(spec, now_ms)
            .map_err(ProcessSpawnError::into_watchdog_error)
    }

    /// Spawn one approved component and preserve whether a failed launch left
    /// exact process-group cleanup uncertain. This is the durable-runtime
    /// entrypoint; [`OwnedChild::spawn`] remains the compatibility wrapper for
    /// callers that only need a legacy `WatchdogError`.
    pub fn spawn_with_cleanup_status(
        spec: &ComponentConfig,
        now_ms: u64,
    ) -> std::result::Result<Self, ProcessSpawnError> {
        validate_component(spec)?;
        let executable = std::fs::canonicalize(&spec.executable).map_err(|error| {
            WatchdogError::InvalidInput(format!(
                "component {} executable cannot be resolved: {error}",
                spec.id
            ))
        })?;
        let metadata = std::fs::metadata(&executable)?;
        if !metadata.is_file() {
            return Err(ProcessSpawnError::Ordinary(WatchdogError::InvalidInput(
                format!("component {} executable is not a regular file", spec.id),
            )));
        }
        let executable_digest = hash_file(&executable)?;
        if let Some(expected) = &spec.executable_sha256 {
            if expected != &executable_digest {
                return Err(ProcessSpawnError::Ordinary(WatchdogError::Conflict(
                    format!(
                        "component {} executable digest does not match approved bytes",
                        spec.id
                    ),
                )));
            }
        }
        let cwd = match &spec.cwd {
            Some(path) => {
                let canonical = std::fs::canonicalize(path)?;
                if !canonical.is_dir() {
                    return Err(ProcessSpawnError::Ordinary(WatchdogError::InvalidInput(
                        format!("component {} cwd is not a directory", spec.id),
                    )));
                }
                Some(canonical)
            }
            None => None,
        };
        let mut command = Command::new(&executable);
        command
            .args(&spec.args)
            .env_clear()
            .envs(spec.environment.iter())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        command.process_group(0);
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }
        let mut child = command.spawn().map_err(|error| {
            WatchdogError::Io(std::io::Error::new(
                error.kind(),
                format!("spawn component {}: {error}", spec.id),
            ))
        })?;
        let pid = child.id();
        #[cfg(unix)]
        // `process_group(0)` asks the kernel to create a fresh group whose
        // identifier is this exact child. The authority remains armed while
        // the direct child is unreaped; after final reap it is permanently
        // disarmed so a recycled numeric PGID can never be signalled.
        let mut process_group = ProcessGroupAuthority::new(Pid::from_child(&child));
        let identity = ProcessIdentity {
            pid,
            launch_nonce: Uuid::new_v4().to_string(),
            executable,
            executable_digest,
            started_at_ms: now_ms,
            creation_fingerprint: process_creation_fingerprint(pid),
        };
        // The direct Child handle is authoritative, but checking a still-live
        // process immediately catches a surprising platform adapter result
        // early. A very short-lived child may already have exited; that is a
        // normal observation for the reconciler, not an identity mismatch.
        // Unix must use a non-reaping observation here: reaping before the
        // group is cleaned would make the numeric PGID recyclable.
        let still_running = match observe_child_exit(&mut child) {
            Ok(status) => status.is_none(),
            Err(error) => {
                #[cfg(unix)]
                let cleanup = abort_spawned_child(
                    &mut child,
                    &mut process_group,
                    Instant::now() + PROCESS_GROUP_CLEANUP_TIMEOUT,
                );
                #[cfg(unix)]
                return Err(report_spawn_cleanup(error, cleanup));
                #[cfg(not(unix))]
                {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ProcessSpawnError::Ordinary(error));
                }
            }
        };
        if still_running && let Err(error) = ensure_identity(&identity) {
            // The direct Child handle is still the exact object returned by
            // spawn, and the process group is the exact containment created
            // for that handle.  Cleanup does not fall back to a PID/name
            // lookup.
            #[cfg(unix)]
            let cleanup = abort_spawned_child(
                &mut child,
                &mut process_group,
                Instant::now() + PROCESS_GROUP_CLEANUP_TIMEOUT,
            );
            #[cfg(unix)]
            return Err(report_spawn_cleanup(error, cleanup));
            #[cfg(not(unix))]
            {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ProcessSpawnError::Ordinary(error));
            }
        }
        let output = Arc::new(Mutex::new(BoundedOutput::default()));
        let mut readers = Vec::new();
        if let Some(stdout) = child.stdout.take() {
            readers.push(spawn_reader(stdout, Arc::clone(&output), true));
        }
        if let Some(stderr) = child.stderr.take() {
            readers.push(spawn_reader(stderr, Arc::clone(&output), false));
        }
        Ok(Self {
            child,
            identity,
            #[cfg(unix)]
            process_group,
            output,
            readers,
        })
    }

    /// Return the immutable launch identity.
    #[must_use]
    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    /// Check whether the exact child is still running.
    pub fn is_running(&mut self) -> Result<bool> {
        if observe_child_exit(&mut self.child)?.is_some() {
            return Ok(false);
        }
        ensure_identity(&self.identity)?;
        Ok(true)
    }

    /// Non-blocking wait for the exact child.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        #[cfg(unix)]
        {
            if observe_child_exit(&mut self.child)?.is_none() {
                ensure_identity(&self.identity)?;
                return Ok(None);
            }
            self.reap_after_group_cleanup(Instant::now() + PROCESS_GROUP_CLEANUP_TIMEOUT)
                .map(Some)
        }
        #[cfg(not(unix))]
        {
            let status = self.child.try_wait()?;
            if status.is_none() {
                ensure_identity(&self.identity)?;
            }
            Ok(status)
        }
    }

    /// Wait for an exact child to exit.
    pub fn wait(&mut self) -> Result<ExitStatus> {
        #[cfg(unix)]
        {
            if observe_child_exit(&mut self.child)?.is_none() {
                ensure_identity(&self.identity)?;
                while observe_child_exit(&mut self.child)?.is_none() {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            self.reap_after_group_cleanup(Instant::now() + PROCESS_GROUP_CLEANUP_TIMEOUT)
        }
        #[cfg(not(unix))]
        {
            if self.child.try_wait()?.is_none() {
                ensure_identity(&self.identity)?;
            }
            let status = self.child.wait()?;
            self.join_readers_bounded(Duration::from_millis(250));
            Ok(status)
        }
    }

    /// Stop the exact owned containment, with a bounded cleanup wait. Unix
    /// synthetic children are killed through the process group created at
    /// spawn; the direct `Child` handle remains the identity and reap
    /// authority. Other platforms retain direct-child cleanup semantics until
    /// their native Job/cgroup adapter is selected.
    pub fn terminate(&mut self, timeout: Duration) -> Result<ExitStatus> {
        let deadline = Instant::now() + timeout;
        #[cfg(unix)]
        {
            if observe_child_exit(&mut self.child)?.is_none() {
                ensure_identity(&self.identity)?;
                self.kill_process_group()?;
            }
            while observe_child_exit(&mut self.child)?.is_none() {
                if Instant::now() >= deadline {
                    return Err(WatchdogError::Timeout(format!(
                        "owned child {} did not terminate",
                        self.identity.pid
                    )));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            self.reap_after_group_cleanup(deadline)
        }
        #[cfg(not(unix))]
        {
            if self.child.try_wait()?.is_some() {
                self.join_readers_bounded(Duration::from_millis(250));
                return Ok(self.child.wait()?);
            }
            ensure_identity(&self.identity)?;
            self.child.kill()?;
            loop {
                if let Some(status) = self.child.try_wait()? {
                    self.join_readers_bounded(Duration::from_millis(250));
                    return Ok(status);
                }
                if Instant::now() >= deadline {
                    return Err(WatchdogError::Timeout(format!(
                        "owned child {} did not terminate",
                        self.identity.pid
                    )));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    #[cfg(unix)]
    fn kill_process_group(&mut self) -> Result<()> {
        self.process_group.kill()
    }

    #[cfg(unix)]
    fn reap_after_group_cleanup(&mut self, deadline: Instant) -> Result<ExitStatus> {
        self.process_group
            .cleanup_before_reap(self.identity.pid, deadline)?;
        let status = self.child.wait()?;
        // From this point onward the numeric PGID is never used for a signal.
        // It is retained only so a failed post-reap proof can be diagnosed by
        // the caller rather than silently treated as clean.
        self.process_group.disarm_after_reap();
        self.join_readers_bounded(Duration::from_millis(250));
        self.process_group.wait_gone_after_reap(deadline)?;
        Ok(status)
    }

    /// Snapshot bounded output without using it as a health signal.
    pub fn output(&self) -> OutputSnapshot {
        let output = self
            .output
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        OutputSnapshot {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            stdout_truncated: output.stdout_truncated,
            stderr_truncated: output.stderr_truncated,
        }
    }

    fn join_readers_bounded(&mut self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while !self.readers.iter().all(JoinHandle::is_finished) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let readers = std::mem::take(&mut self.readers);
        for reader in readers {
            if reader.is_finished() {
                let _ = reader.join();
            }
            // An inherited pipe can remain open in a grandchild. Dropping an
            // unfinished JoinHandle detaches it instead of blocking teardown.
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        // This is the original Child object, never a reconstructed PID/name
        // handle. Keep ownership until the child is reaped: on Unix an exited
        // unreaped child retains its PID; Windows retains the process handle.
        // Dropping during a post-spawn persistence failure must not detach it.
        // Unix synthetic children use their exact process-group authority;
        // native cgroup/Job containment remains responsible for production
        // descendants.
        let deadline = Instant::now() + Duration::from_secs(5);
        #[cfg(unix)]
        {
            // Signal while the exact leader is still an unreaped child. The
            // helper may have exited naturally, but waitid/WNOWAIT keeps its
            // PID and PGID reserved until the cleanup proof completes.
            if self.process_group.is_armed() {
                let _ = self.process_group.kill();
                let observed_exit = wait_for_child_exit(&mut self.child, deadline).is_ok();
                let group_proven_empty = observed_exit
                    && self
                        .process_group
                        .cleanup_before_reap(self.identity.pid, deadline)
                        .is_ok();
                if group_proven_empty {
                    // The non-reaping wait above proves this is an exited
                    // child, so this final reap is bounded by the kernel's
                    // already-recorded wait status. On any failed proof path
                    // below, no blocking wait is attempted.
                    if self.child.wait().is_ok() {
                        self.process_group.disarm_after_reap();
                        let _ = self.process_group.wait_gone_after_reap(deadline);
                    }
                } else {
                    // Keep Drop bounded when the leader is still running or
                    // containment proof is unavailable. The group signal and
                    // this exact-child signal are best effort; the caller has
                    // no safe authority to reap or signal by numeric PGID
                    // after this point.
                    let _ = self.child.kill();
                }
            }
        }
        #[cfg(not(unix))]
        {
            match self.child.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) => {
                    let _ = self.child.kill();
                    while Instant::now() < deadline {
                        match self.child.try_wait() {
                            Ok(Some(_)) | Err(_) => break,
                            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                        }
                    }
                }
                Err(_) => {}
            }
        }
        self.join_readers_bounded(Duration::from_millis(50));
    }
}

#[cfg(unix)]
fn observe_child_exit(child: &mut Child) -> Result<Option<()>> {
    let status = waitid(
        WaitId::Pid(Pid::from_child(child)),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    )
    .map_err(|error| WatchdogError::Io(std::io::Error::from(error)))?;
    Ok(status.map(|_| ()))
}

#[cfg(unix)]
fn signal_process_group(pgid: Pid) -> std::io::Result<()> {
    kill_process_group(pgid, Signal::KILL).map_err(std::io::Error::from)
}

#[cfg(not(unix))]
fn observe_child_exit(child: &mut Child) -> Result<Option<ExitStatus>> {
    child.try_wait().map_err(WatchdogError::from)
}

#[cfg(unix)]
fn wait_for_child_exit(child: &mut Child, deadline: Instant) -> Result<()> {
    loop {
        if observe_child_exit(child)?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(WatchdogError::Timeout(
                "owned child did not exit before cleanup deadline".to_owned(),
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(unix)]
fn cleanup_spawned_child(
    child: &mut Child,
    process_group: &mut ProcessGroupAuthority,
    deadline: Instant,
) -> Result<()> {
    process_group.kill()?;
    wait_for_child_exit(child, deadline)?;
    process_group.cleanup_before_reap(child.id(), deadline)?;
    child.wait()?;
    process_group.disarm_after_reap();
    process_group.wait_gone_after_reap(deadline)
}

#[cfg(unix)]
fn abort_spawned_child(
    child: &mut Child,
    process_group: &mut ProcessGroupAuthority,
    deadline: Instant,
) -> Result<()> {
    match cleanup_spawned_child(child, process_group, deadline) {
        Ok(()) => Ok(()),
        Err(cleanup_error) => {
            // Keep the exact group signal before final reap. If the proof
            // failed, this is still safe because the direct leader has not
            // been reaped. Do not block in a fallback wait after the bounded
            // proof deadline: the caller must retain/report this uncertainty.
            if process_group.is_armed() {
                let _ = process_group.kill();
            }
            let _ = child.kill();
            Err(cleanup_error)
        }
    }
}

#[cfg(unix)]
fn report_spawn_cleanup(original: WatchdogError, cleanup: Result<()>) -> ProcessSpawnError {
    match cleanup {
        Ok(()) => ProcessSpawnError::Ordinary(original),
        Err(cleanup_error) => {
            ProcessSpawnError::CleanupUncertain(WatchdogError::Conflict(format!(
                "spawn failed ({original}); exact containment cleanup is uncertain ({cleanup_error})"
            )))
        }
    }
}

#[cfg(unix)]
fn group_has_other_members(pgid: Pid, leader_pid: u32) -> Result<bool> {
    match test_kill_process_group(pgid) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::SRCH => return Ok(false),
        Err(error) => return Err(WatchdogError::Io(std::io::Error::from(error))),
    }

    #[cfg(target_os = "linux")]
    {
        let entries = std::fs::read_dir("/proc")?;
        for entry in entries {
            let entry = entry?;
            let Some(member_pid) = entry
                .file_name()
                .to_str()
                .and_then(|value| value.parse::<u32>().ok())
            else {
                continue;
            };
            if member_pid == leader_pid {
                continue;
            }
            let stat_path = entry.path().join("stat");
            let stat = match std::fs::read_to_string(stat_path) {
                Ok(stat) => stat,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(WatchdogError::Io(error)),
            };
            let Some((_, process_group)) = parse_proc_stat_identity(&stat) else {
                return Err(WatchdogError::Conflict(format!(
                    "cannot prove process-group membership for pid {member_pid}"
                )));
            };
            if process_group == pgid.as_raw_pid() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = leader_pid;
        Err(WatchdogError::Unsupported(
            "exact synthetic process-group membership proof is unavailable on this Unix target"
                .to_owned(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn parse_proc_stat_identity(stat: &str) -> Option<(u32, i32)> {
    let closing_paren = stat.rfind(')')?;
    let mut fields = stat.get(closing_paren + 1..)?.split_whitespace();
    let _state = fields.next()?;
    let _parent = fields.next()?;
    let process_group = fields.next()?.parse::<i32>().ok()?;
    let pid = stat
        .split_once(' ')
        .and_then(|(pid, _)| pid.parse::<u32>().ok())?;
    Some((pid, process_group))
}

/// Verify an exact process identity before observation or termination.
pub fn ensure_identity(identity: &ProcessIdentity) -> Result<()> {
    if identity.pid == 0 || identity.launch_nonce.is_empty() {
        return Err(WatchdogError::IdentityMismatch(
            "identity is incomplete".to_string(),
        ));
    }
    if !identity.executable.is_absolute() || identity.executable.as_os_str().is_empty() {
        return Err(WatchdogError::IdentityMismatch(
            "identity executable path is incomplete".to_string(),
        ));
    }
    if crate::config::validate_digest(&identity.executable_digest).is_err() {
        return Err(WatchdogError::IdentityMismatch(
            "identity executable digest is invalid".to_string(),
        ));
    }
    if let Some(expected) = &identity.creation_fingerprint {
        let Some(actual) = process_creation_fingerprint(identity.pid) else {
            return Err(WatchdogError::IdentityMismatch(format!(
                "pid {} is no longer present",
                identity.pid
            )));
        };
        if &actual != expected {
            return Err(WatchdogError::IdentityMismatch(format!(
                "pid {} creation fingerprint changed",
                identity.pid
            )));
        }
    }
    if let Ok(actual) = std::fs::canonicalize(format!("/proc/{}/exe", identity.pid)) {
        if actual != identity.executable {
            return Err(WatchdogError::IdentityMismatch(format!(
                "pid {} executable changed from {} to {}",
                identity.pid,
                identity.executable.display(),
                actual.display()
            )));
        }
    }
    Ok(())
}

fn validate_component(spec: &ComponentConfig) -> Result<()> {
    if spec.id.is_empty() || spec.id.len() > 128 || spec.id.as_bytes().contains(&0) {
        return Err(WatchdogError::InvalidInput(
            "component id is invalid".to_string(),
        ));
    }
    if !spec.executable.is_absolute() || spec.executable.as_os_str().is_empty() {
        return Err(WatchdogError::InvalidInput(format!(
            "component {} executable must be absolute",
            spec.id
        )));
    }
    let executable_text = spec
        .executable
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if executable_text.starts_with("/mnt/")
        || executable_text.starts_with("//wsl")
        || executable_text.contains("/proc/")
    {
        return Err(WatchdogError::InvalidInput(format!(
            "component {} executable must be owner-local",
            spec.id
        )));
    }
    if spec.args.len() > 64
        || spec
            .args
            .iter()
            .any(|arg| arg.as_bytes().len() > 8 * 1024 || arg.as_bytes().contains(&0))
    {
        return Err(WatchdogError::InvalidInput(format!(
            "component {} arguments are outside bounds",
            spec.id
        )));
    }
    if let Some(cwd) = &spec.cwd {
        if !cwd.is_absolute() {
            return Err(WatchdogError::InvalidInput(format!(
                "component {} cwd must be absolute",
                spec.id
            )));
        }
        let cwd_text = cwd
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        if cwd_text.starts_with("/mnt/") || cwd_text.starts_with("//wsl") {
            return Err(WatchdogError::InvalidInput(format!(
                "component {} cwd must be owner-local",
                spec.id
            )));
        }
    }
    if spec.environment.len() > 64
        || spec.environment.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > 128
                || key.contains('=')
                || key.as_bytes().contains(&0)
                || value.as_bytes().len() > 8 * 1024
                || value.as_bytes().contains(&0)
        })
    {
        return Err(WatchdogError::InvalidInput(format!(
            "component {} environment is outside bounds",
            spec.id
        )));
    }
    let launch_bytes = spec
        .args
        .iter()
        .map(String::len)
        .chain(
            spec.environment
                .iter()
                .map(|(key, value)| key.len().saturating_add(value.len())),
        )
        .fold(0_usize, usize::saturating_add);
    if launch_bytes > 32 * 1024 {
        return Err(WatchdogError::InvalidInput(
            "component launch data exceeds aggregate byte limit".to_owned(),
        ));
    }
    if let Some(digest) = &spec.executable_sha256 {
        crate::config::validate_digest(digest).map_err(|message| {
            WatchdogError::InvalidInput(format!("component {}: {message}", spec.id))
        })?;
    }
    Ok(())
}

fn spawn_reader<R: Read + Send + 'static>(
    mut reader: R,
    output: Arc<Mutex<BoundedOutput>>,
    stdout: bool,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buffer = [0_u8; 4 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if let Ok(mut output) = output.lock() {
                        if stdout {
                            let remaining = MAX_OUTPUT_BYTES.saturating_sub(output.stdout.len());
                            if read > remaining {
                                output.stdout.extend_from_slice(&buffer[..remaining]);
                                output.stdout_truncated = true;
                            } else {
                                output.stdout.extend_from_slice(&buffer[..read]);
                            }
                        } else {
                            let remaining = MAX_OUTPUT_BYTES.saturating_sub(output.stderr.len());
                            if read > remaining {
                                output.stderr.extend_from_slice(&buffer[..remaining]);
                                output.stderr_truncated = true;
                            } else {
                                output.stderr.extend_from_slice(&buffer[..read]);
                            }
                        }
                    }
                }
            }
        }
    })
}

#[cfg(target_os = "linux")]
fn process_creation_fingerprint(pid: u32) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = text.rfind(')')?;
    let fields = text
        .get(close + 2..)?
        .split_whitespace()
        .collect::<Vec<_>>();
    // Fields after the command name start at field 3; starttime is field 22,
    // hence index 19 in this suffix.
    fields.get(19).map(|value| (*value).to_string())
}

#[cfg(not(target_os = "linux"))]
fn process_creation_fingerprint(_pid: u32) -> Option<String> {
    // The native Windows adapter will replace this hook with a process
    // creation-time query.  The Child handle remains the cleanup authority in
    // this portable slice.
    None
}

fn hash_file(path: &Path) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn immediate_component() -> ComponentConfig {
        ComponentConfig {
            id: "process-group-lifetime".to_owned(),
            executable: PathBuf::from("/bin/sh"),
            args: vec!["-c".to_owned(), "exit 0".to_owned()],
            cwd: None,
            environment: BTreeMap::new(),
            executable_sha256: None,
            restart: false,
        }
    }

    #[test]
    fn repeated_cleanup_after_reap_never_reuses_numeric_group_authority() {
        let mut child = OwnedChild::spawn(&immediate_component(), 1_000).expect("spawn");
        let signal_count = Arc::clone(&child.process_group.signal_count);
        child.wait().expect("wait and clean exact group");
        let after_reap = signal_count.load(std::sync::atomic::Ordering::SeqCst);
        assert!(after_reap > 0, "cleanup must signal the original group");

        let repeated = child.terminate(Duration::from_millis(100));
        assert!(
            repeated.is_err(),
            "a reaped child cannot be terminated again"
        );
        drop(child);
        assert_eq!(
            signal_count.load(std::sync::atomic::Ordering::SeqCst),
            after_reap,
            "terminate/Drop must not signal a recycled numeric PGID"
        );
    }

    #[test]
    fn injected_cleanup_proof_failure_returns_without_unbounded_reap() {
        let mut child = OwnedChild::spawn(&immediate_component(), 1_000).expect("spawn");
        child.process_group.force_cleanup_failure = true;
        let started = Instant::now();
        let result = abort_spawned_child(
            &mut child.child,
            &mut child.process_group,
            Instant::now() + Duration::from_secs(1),
        );
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "injected cleanup failure must not block in Child::wait"
        );
        assert!(result.is_err(), "injected cleanup failure must be reported");

        child.process_group.force_cleanup_failure = false;
        cleanup_spawned_child(
            &mut child.child,
            &mut child.process_group,
            Instant::now() + Duration::from_secs(1),
        )
        .expect("clear injected failure and reap through exact authority");
    }
}

#[allow(dead_code)]
fn _path_for_docs(path: &Path) -> &Path {
    path
}
