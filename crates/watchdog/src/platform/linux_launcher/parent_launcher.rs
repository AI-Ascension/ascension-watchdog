//! Trusted parent launcher and pending-launch lifecycle.

use super::CHILD_CLEANUP_POLL;
use super::CHILD_CLEANUP_TIMEOUT;
use super::DELEGATED_CGROUP_ROOT_ARGUMENT;
use super::GATEWAY_HEALTH_PIPE_ARGUMENT;
use super::GO_MAGIC;
use super::HELPER_ARGUMENT;
use super::MAX_FIELD_BYTES;
use super::MAX_TIMEOUT;
use super::O_CLOEXEC;
use super::O_NONBLOCK;
use super::PARENT_BOOTSTRAP_PID_ARGUMENT;
use super::PROTECTED_CONFIG_ARGUMENT;
use super::READY_MAGIC;
use super::WORKER_BOOT_ID_ARGUMENT;
use super::WORKER_FRAME_SHA256_ARGUMENT;
use super::WORKER_PIPE_ARGUMENT;
use super::executable_snapshot::hash_file;
use super::executable_snapshot::open_verified_executable;
use super::framed_protocol::encode_frame;
use super::framed_protocol::put_string_io;
use super::framed_protocol::read_string;
use super::framed_protocol::set_nonblocking;
use super::framed_protocol::write_bounded;
use super::framed_protocol::write_gateway_health_frame;
use super::framed_protocol::write_worker_frame;
use super::protected_bootstrap::LinuxHelperBootstrap;
use super::protected_bootstrap::parent_fd_path;
use crate::platform::contract::AdapterError;
use crate::platform::contract::ComponentKind;
use crate::platform::contract::LaunchSpec;
use crate::platform::gateway_health::GatewayHealthBootstrap;
use crate::worker_bootstrap::WorkerBootstrapLaunch;
use std::env;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Cursor;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::os::fd::RawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::ChildStdin;
use std::process::Command;
use std::process::Stdio;
use std::thread;
use std::time::Duration;
use std::time::Instant;

/// CLOEXEC parent-owned descriptors kept alive until the helper has opened
/// their proc-fd views.  They are never made inheritable by the parent.
pub(super) struct ParentBootstrap {
    pub(super) config: File,
    pub(super) config_fd: RawFd,
    pub(super) root: File,
    pub(super) root_fd: RawFd,
    pub(super) ready: File,
    pub(super) ready_fd: RawFd,
    pub(super) worker_reader: Option<File>,
    pub(super) worker_reader_fd: Option<RawFd>,
    pub(super) worker_writer: Option<File>,
    pub(super) gateway_health_reader: Option<File>,
    pub(super) gateway_health_reader_fd: Option<RawFd>,
    pub(super) gateway_health_writer: Option<File>,
}

impl std::fmt::Debug for ParentBootstrap {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ParentBootstrap")
            .field("config", &self.config)
            .field("config_fd", &self.config_fd)
            .field("root", &self.root)
            .field("root_fd", &self.root_fd)
            .field("ready", &self.ready)
            .field("ready_fd", &self.ready_fd)
            .field("worker_reader", &self.worker_reader)
            .field("worker_reader_fd", &self.worker_reader_fd)
            .field("worker_writer", &self.worker_writer)
            .field("gateway_health_reader", &self.gateway_health_reader)
            .field("gateway_health_reader_fd", &self.gateway_health_reader_fd)
            .field("gateway_health_writer", &self.gateway_health_writer)
            .finish_non_exhaustive()
    }
}

impl ParentBootstrap {
    pub(super) fn wait_for_ready(
        &mut self,
        launch_nonce: &str,
        timeout: Duration,
    ) -> Result<(), AdapterError> {
        let expected_length = READY_MAGIC
            .len()
            .checked_add(2)
            .and_then(|length| length.checked_add(launch_nonce.len()))
            .ok_or_else(|| {
                AdapterError::Invalid("Linux helper readiness frame length overflow".to_owned())
            })?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        loop {
            let metadata = self.ready.metadata().map_err(|error| {
                AdapterError::Unavailable(format!(
                    "Linux helper readiness descriptor cannot be inspected: {error}"
                ))
            })?;
            let expected_bytes = u64::try_from(expected_length).map_err(|_| {
                AdapterError::Invalid("Linux helper readiness size exceeds bounds".to_owned())
            })?;
            if metadata.len() > expected_bytes {
                return Err(AdapterError::IdentityMismatch(
                    "Linux helper readiness acknowledgement contains trailing bytes".to_owned(),
                ));
            }
            if metadata.len() == expected_bytes {
                self.ready.seek(SeekFrom::Start(0)).map_err(|error| {
                    AdapterError::Unavailable(format!(
                        "Linux helper readiness descriptor cannot be rewound: {error}"
                    ))
                })?;
                let mut frame = vec![0_u8; expected_length];
                self.ready.read_exact(&mut frame).map_err(|error| {
                    AdapterError::Unavailable(format!(
                        "Linux helper readiness acknowledgement cannot be read: {error}"
                    ))
                })?;
                let mut cursor = Cursor::new(frame);
                let mut magic = [0_u8; READY_MAGIC.len()];
                cursor.read_exact(&mut magic).map_err(|error| {
                    AdapterError::Unavailable(format!(
                        "Linux helper readiness acknowledgement is truncated: {error}"
                    ))
                })?;
                if magic != *READY_MAGIC {
                    return Err(AdapterError::IdentityMismatch(
                        "Linux helper readiness acknowledgement has the wrong magic".to_owned(),
                    ));
                }
                let acknowledged_nonce = read_string(&mut cursor, MAX_FIELD_BYTES)?;
                if acknowledged_nonce != launch_nonce {
                    return Err(AdapterError::IdentityMismatch(
                        "Linux helper readiness acknowledgement nonce differs".to_owned(),
                    ));
                }
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(AdapterError::Timeout(
                    "Linux helper did not acknowledge protected bootstrap readiness".to_owned(),
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            thread::sleep(CHILD_CLEANUP_POLL.min(remaining));
        }
    }
}

pub(super) struct HelperReadyChannel {
    pub(super) file: File,
}

impl HelperReadyChannel {
    pub(super) fn send(&mut self, launch_nonce: &str) -> Result<(), AdapterError> {
        let mut frame = Vec::with_capacity(READY_MAGIC.len() + 2 + launch_nonce.len());
        frame.extend_from_slice(READY_MAGIC);
        put_string_io(&mut frame, launch_nonce).map_err(|error| {
            AdapterError::Io(format!(
                "Linux helper readiness acknowledgement failed: {error}"
            ))
        })?;
        self.file.write_all(&frame).map_err(|error| {
            AdapterError::Io(format!(
                "Linux helper readiness acknowledgement failed: {error}"
            ))
        })
    }
}

/// How a launched component's standard stream is connected.
///
/// The launcher never reads a component stream in a detached thread.  When a
/// stream is [`OutputMode::Piped`], ownership remains with the returned
/// [`Child`] and the caller is responsible for bounded draining.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputMode {
    Null,
    Inherit,
    Piped,
}

impl OutputMode {
    pub(super) fn into_stdio(self) -> Stdio {
        match self {
            Self::Null => Stdio::null(),
            Self::Inherit => Stdio::inherit(),
            Self::Piped => Stdio::piped(),
        }
    }
}

/// Standard-stream policy for one trusted launch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LauncherStreams {
    pub stdout: OutputMode,
    pub stderr: OutputMode,
}

impl LauncherStreams {
    /// Keep component output disabled, matching the platform adapter default.
    #[must_use]
    pub const fn null() -> Self {
        Self {
            stdout: OutputMode::Null,
            stderr: OutputMode::Null,
        }
    }
}

impl Default for LauncherStreams {
    fn default() -> Self {
        Self::null()
    }
}

/// A helper process that has received its frame but not yet been released.
///
/// Dropping a pending launch kills the exact helper handle.  The cgroup owner
/// must still remove the cgroup or use `cgroup.kill` when a post-release error
/// occurs.
pub(crate) struct PendingLaunch {
    pub(super) child: Option<Child>,
    pub(super) request_frame: Option<Vec<u8>>,
    pub(super) stdin: Option<ChildStdin>,
    pub(super) parent_bootstrap: Option<ParentBootstrap>,
    pub(super) worker_writer: Option<File>,
    pub(super) worker_launch: Option<WorkerBootstrapLaunch>,
    pub(super) gateway_health_writer: Option<File>,
    pub(super) gateway_health_frame:
        Option<zeroize::Zeroizing<[u8; crate::platform::gateway_health::FRAME_BYTES]>>,
    pub(super) launch_nonce: String,
    pub(super) timeout: Duration,
    pub(super) released: bool,
}

impl std::fmt::Debug for PendingLaunch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingLaunch")
            .field("pid", &self.child.as_ref().map(Child::id))
            .field("released", &self.released)
            .finish_non_exhaustive()
    }
}

impl PendingLaunch {
    /// Return the helper PID that must be assigned before release.
    #[must_use]
    pub(crate) fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// Return the helper's nonce-bound launch timeout.
    #[must_use]
    pub(crate) const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Send `GO` after the parent has proved exact cgroup membership.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the helper closed its anonymous pipe or the
    /// nonce-bound control frame could not be written.
    pub(crate) fn release_gate(&mut self) -> Result<(), AdapterError> {
        if self.released {
            return Err(AdapterError::Invalid(
                "Linux helper release was already sent".to_owned(),
            ));
        }
        // Do not perform any helper-control I/O while the child is only owned
        // by this launcher.  The caller must first put the exact child into
        // its durable cgroup and verify membership; otherwise a bounded write
        // failure could leave an uncontained helper behind.  Retain the frame
        // until this point so every post-spawn I/O failure still returns with
        // the exact Child handle in PendingLaunch for cgroup cleanup.
        {
            let Some(stdin) = self.stdin.as_mut() else {
                return Err(AdapterError::Invalid(
                    "Linux helper stdin is unavailable".to_owned(),
                ));
            };
            let Some(request_frame) = self.request_frame.as_ref() else {
                return Err(AdapterError::Invalid(
                    "Linux helper request frame is unavailable".to_owned(),
                ));
            };
            set_nonblocking(&*stdin, "Linux helper stdin")?;
            write_bounded(
                stdin,
                request_frame,
                self.timeout.min(Duration::from_secs(5)),
                "Linux helper request handoff",
            )?;
        }
        self.request_frame.take();
        if let Some(bootstrap) = self.parent_bootstrap.as_mut() {
            let ready_result = bootstrap.wait_for_ready(&self.launch_nonce, self.timeout);
            // READY proves the helper owns its duplicate. Keeping our reader
            // would conceal a rejected/exited helper from the bounded writer.
            bootstrap.worker_reader.take();
            // The health pipe has the same ownership rule as the worker pipe:
            // after READY, only the helper may retain a read end. Otherwise a
            // dead helper could leave the parent's read end open and make a
            // bounded health-frame write appear successful.
            bootstrap.gateway_health_reader.take();
            ready_result?;
        }
        let Some(stdin) = self.stdin.as_mut() else {
            return Err(AdapterError::Invalid(
                "Linux helper stdin is unavailable".to_owned(),
            ));
        };
        let mut go = Vec::with_capacity(GO_MAGIC.len() + 2 + self.launch_nonce.len());
        go.extend_from_slice(GO_MAGIC);
        put_string_io(&mut go, &self.launch_nonce).map_err(|error| {
            AdapterError::Io(format!("Linux helper GO handoff failed: {error}"))
        })?;
        write_bounded(
            stdin,
            &go,
            self.timeout.min(Duration::from_secs(5)),
            "Linux helper GO handoff",
        )?;
        if let Some(worker_launch) = self.worker_launch.as_ref() {
            let Some(worker_writer) = self.worker_writer.as_mut() else {
                return Err(AdapterError::Invalid(
                    "Linux worker bootstrap writer is unavailable".to_owned(),
                ));
            };
            write_worker_frame(
                worker_writer,
                worker_launch.frame(),
                self.timeout.min(Duration::from_secs(5)),
            )?;
            self.worker_writer.take();
        }
        if let Some(gateway_health_frame) = self.gateway_health_frame.as_ref() {
            let Some(gateway_health_writer) = self.gateway_health_writer.as_mut() else {
                return Err(AdapterError::Invalid(
                    "Linux Gateway health bootstrap writer is unavailable".to_owned(),
                ));
            };
            write_gateway_health_frame(
                gateway_health_writer,
                gateway_health_frame.as_ref(),
                self.timeout.min(Duration::from_secs(5)),
            )?;
            self.gateway_health_writer.take();
        }
        self.released = true;
        Ok(())
    }

    /// Consume the barrier and return the exact helper child handle.
    ///
    /// The helper is replaced in place by the target after the gate.  The
    /// returned handle therefore remains authoritative for the target PID.
    ///
    /// # Errors
    ///
    /// Returns an error if the gate was not released or the child handle was
    /// unexpectedly unavailable.
    pub(crate) fn take_child(&mut self) -> Result<Child, AdapterError> {
        if !self.released {
            return Err(AdapterError::Invalid(
                "Linux helper cannot be consumed before GO".to_owned(),
            ));
        }
        self.stdin.take();
        self.worker_writer.take();
        self.gateway_health_writer.take();
        // The helper parsed and opened both parent descriptors before it could
        // read the frame or accept GO, so the parent-side keepalive can close
        // before returning the target handle.  The target never inherited
        // these CLOEXEC parent descriptors in the first place.
        self.parent_bootstrap.take();
        self.child.take().ok_or_else(|| {
            AdapterError::Unavailable("Linux helper child handle was lost".to_owned())
        })
    }

    /// Close every parent-side handoff descriptor before a caller performs
    /// explicit launch-failure cleanup.  Keeping a reader or writer alive can
    /// make a dead helper/cgroup look reachable and can hide a failed pipe
    /// handoff from the cleanup proof.
    pub(crate) fn close_handoff_descriptors(&mut self) {
        self.stdin.take();
        self.worker_writer.take();
        self.gateway_health_writer.take();
        if let Some(bootstrap) = self.parent_bootstrap.as_mut() {
            bootstrap.worker_reader.take();
            bootstrap.worker_writer.take();
            bootstrap.gateway_health_reader.take();
            bootstrap.gateway_health_writer.take();
        }
    }

    /// Borrow the exact helper child for explicit cgroup cleanup while this
    /// pending launch still owns all of its transport descriptors.
    pub(crate) fn child_mut(&mut self) -> Option<&mut Child> {
        self.child.as_mut()
    }
}

impl Drop for PendingLaunch {
    fn drop(&mut self) {
        // The adapter normally calls `close_handoff_descriptors` and performs
        // a fallible cgroup cleanup while it still owns this object.  Drop is
        // only the final best-effort guard for callers that abandon a pending
        // launch without entering that explicit error path.
        self.close_handoff_descriptors();
        if let Some(child) = self.child.as_mut() {
            terminate_child_bounded(child, CHILD_CLEANUP_TIMEOUT);
        }
    }
}

/// Kill and reap a helper without allowing a launch-error path or `Drop` to
/// block forever.  The cgroup owner remains responsible for a later
/// `cgroup.kill` reconciliation when this best-effort reap cannot be proved.
pub(super) fn terminate_child_bounded(child: &mut Child, timeout: Duration) {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    if child.try_wait().ok().flatten().is_some() {
        return;
    }
    let _ = child.kill();
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) if Instant::now() < deadline => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                thread::sleep(CHILD_CLEANUP_POLL.min(remaining));
            }
            Ok(None) => return,
        }
    }
}

/// Trusted current-executable helper launcher.
#[derive(Clone, Debug)]
pub struct TrustedLinuxLauncher {
    pub(super) helper_executable: PathBuf,
    pub(super) helper_executable_sha256: String,
    pub(super) helper_argument: String,
    pub(super) bootstrap: Option<LinuxHelperBootstrap>,
    pub(super) streams: LauncherStreams,
    pub(super) timeout: Duration,
}

impl TrustedLinuxLauncher {
    /// Construct a launcher around a canonical trusted watchdog executable.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::Unavailable`] if the executable cannot be
    /// canonicalized or is not a regular file.
    pub fn new(helper_executable: impl Into<PathBuf>) -> Result<Self, AdapterError> {
        let helper_executable = helper_executable.into();
        let canonical = fs::canonicalize(&helper_executable).map_err(|error| {
            AdapterError::Unavailable(format!("Linux helper executable is unavailable: {error}"))
        })?;
        let helper_executable_sha256 = hash_file(&canonical)?;
        Ok(Self {
            helper_executable: canonical,
            helper_executable_sha256,
            helper_argument: HELPER_ARGUMENT.to_owned(),
            bootstrap: None,
            streams: LauncherStreams::default(),
            timeout: Duration::from_secs(10),
        })
    }

    /// Construct a launcher from the executable containing the watchdog main.
    ///
    /// The root executable must dispatch [`helper_argument`](super::helper_argument) before normal CLI
    /// parsing.  This constructor does not silently fall back to direct target
    /// spawning when that dispatch is absent.
    ///
    /// # Errors
    ///
    /// Returns an explicit platform error when the current executable cannot
    /// be trusted as a regular file.
    pub fn current_executable() -> Result<Self, AdapterError> {
        Self::new(env::current_exe().map_err(|error| {
            AdapterError::Unavailable(format!("current Linux helper is unavailable: {error}"))
        })?)
    }

    /// Set the bounded helper barrier timeout.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::Invalid`] for a zero or overlarge timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, AdapterError> {
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(AdapterError::Invalid(
                "Linux helper timeout is outside bounds".to_owned(),
            ));
        }
        self.timeout = timeout;
        Ok(self)
    }

    /// Set the caller-owned standard-stream policy.
    #[must_use]
    pub fn with_streams(mut self, streams: LauncherStreams) -> Self {
        self.streams = streams;
        self
    }

    /// Bind a protected configuration path to every helper invocation.
    ///
    /// The path is opened and validated immediately; a parent-owned descriptor
    /// is kept alive and referenced by a fixed argument, never accepted from
    /// the launch frame.  The companion cgroup-root binding must be added for
    /// production helper launches.
    pub fn with_protected_config_path(
        mut self,
        path: impl Into<PathBuf>,
    ) -> Result<Self, AdapterError> {
        self.bootstrap = Some(LinuxHelperBootstrap::new(path)?);
        Ok(self)
    }

    /// Bind the exact delegated cgroup root to the already protected config
    /// bootstrap.  Both descriptors are opened by the helper through the
    /// trusted parent's proc-fd view and remain CLOEXEC in the target.
    pub fn with_delegated_cgroup_root(
        mut self,
        path: impl Into<PathBuf>,
    ) -> Result<Self, AdapterError> {
        let bootstrap = self.bootstrap.take().ok_or_else(|| {
            AdapterError::Invalid(
                "delegated cgroup root requires a protected config bootstrap".to_owned(),
            )
        })?;
        self.bootstrap = Some(bootstrap.with_delegated_cgroup_root(path)?);
        Ok(self)
    }

    /// Bind a previously validated helper bootstrap context.
    #[must_use]
    pub fn with_bootstrap(mut self, bootstrap: LinuxHelperBootstrap) -> Self {
        self.bootstrap = Some(bootstrap);
        self
    }

    /// Return the protected context bound to this launcher, if configured.
    #[must_use]
    pub fn bootstrap(&self) -> Option<&LinuxHelperBootstrap> {
        self.bootstrap.as_ref()
    }

    /// Return the canonical helper executable path.
    #[must_use]
    pub fn helper_executable(&self) -> &Path {
        &self.helper_executable
    }

    /// Return the digest bound to the sealed helper snapshot.
    #[must_use]
    pub(crate) fn helper_executable_sha256(&self) -> &str {
        &self.helper_executable_sha256
    }

    /// Spawn only the trusted helper and retain its bounded request frame.
    ///
    /// The caller must assign [`PendingLaunch::pid`] to the exact durable
    /// cgroup, verify membership, and call [`PendingLaunch::release_gate`],
    /// which performs the initial control handoff only after that proof.
    ///
    /// # Errors
    ///
    /// Returns an explicit error for malformed launch data, an oversized
    /// frame, or helper process/pipe failure.
    pub(crate) fn prepare(
        &self,
        specification: &LaunchSpec,
        cgroup_path: &Path,
    ) -> Result<PendingLaunch, AdapterError> {
        self.prepare_inner(specification, cgroup_path, None, None)
    }

    /// Spawn a helper with a dedicated Linux worker bootstrap pipe.
    ///
    /// The worker frame is retained immutably until the parent has sent GO;
    /// its bytes never enter the helper control pipe, command line, or
    /// environment.  The protected helper bootstrap must be configured for
    /// this overload so the helper can bind and validate the pipe descriptor.
    pub(crate) fn prepare_with_worker_bootstrap(
        &self,
        specification: &LaunchSpec,
        cgroup_path: &Path,
        worker: &WorkerBootstrapLaunch,
    ) -> Result<PendingLaunch, AdapterError> {
        if specification.component != ComponentKind::Harness {
            return Err(AdapterError::Unsupported(
                "Linux worker bootstrap is only valid for the Harness role".to_owned(),
            ));
        }
        if worker.bootstrap().launch_nonce.to_string() != specification.launch_nonce
            || worker.bootstrap().component_id != specification.instance_id
        {
            return Err(AdapterError::IdentityMismatch(
                "Linux worker bootstrap differs from the launch identity".to_owned(),
            ));
        }
        if self.bootstrap.is_none() {
            return Err(AdapterError::Invalid(
                "Linux worker bootstrap requires a protected helper bootstrap".to_owned(),
            ));
        }
        self.prepare_inner(specification, cgroup_path, Some(worker), None)
    }

    /// Spawn a Gateway helper with a dedicated one-shot health bootstrap pipe.
    ///
    /// The fixed health frame is never written to the helper control stdin,
    /// command line, environment, or protected configuration.  The helper
    /// validates the frame after the existing nonce-bound GO barrier and
    /// installs only the validated bytes as the target Gateway's stdin.
    pub(crate) fn prepare_with_gateway_health_bootstrap(
        &self,
        specification: &LaunchSpec,
        cgroup_path: &Path,
        gateway_health: &GatewayHealthBootstrap,
    ) -> Result<PendingLaunch, AdapterError> {
        if specification.component != ComponentKind::Gateway {
            return Err(AdapterError::Unsupported(
                "Gateway health bootstrap is only valid for the Gateway role".to_owned(),
            ));
        }
        if self.bootstrap.is_none() {
            return Err(AdapterError::Invalid(
                "Gateway health bootstrap requires a protected helper bootstrap".to_owned(),
            ));
        }
        gateway_health.validate_for_launch(specification)?;
        self.prepare_inner(specification, cgroup_path, None, Some(gateway_health))
    }

    pub(super) fn prepare_inner(
        &self,
        specification: &LaunchSpec,
        cgroup_path: &Path,
        worker: Option<&WorkerBootstrapLaunch>,
        gateway_health: Option<&GatewayHealthBootstrap>,
    ) -> Result<PendingLaunch, AdapterError> {
        if worker.is_some() && gateway_health.is_some() {
            return Err(AdapterError::Invalid(
                "Linux worker and Gateway health bootstraps cannot be combined".to_owned(),
            ));
        }
        specification.validate()?;
        let frame = encode_frame(specification, cgroup_path)?;
        // Open and hash the helper through one file descriptor immediately
        // before spawning.  The child is invoked through `/proc/self/fd/N`,
        // so replacing the canonical path after this point cannot substitute
        // another helper binary between validation and exec.
        let (helper_file, helper_fd_path) =
            open_verified_executable(&self.helper_executable, &self.helper_executable_sha256)?;
        let mut command = Command::new(&helper_fd_path);
        command.arg0(&self.helper_executable);
        command.arg(&self.helper_argument);
        let mut parent_bootstrap = if let Some(bootstrap) = &self.bootstrap {
            let parent = bootstrap.parent_descriptors(worker, gateway_health)?;
            command
                .arg(PARENT_BOOTSTRAP_PID_ARGUMENT)
                .arg(std::process::id().to_string())
                .arg(PROTECTED_CONFIG_ARGUMENT)
                .arg(parent.config_fd.to_string())
                .arg(DELEGATED_CGROUP_ROOT_ARGUMENT)
                .arg(parent.root_fd.to_string())
                .arg(parent.ready_fd.to_string());
            if let Some(worker) = worker {
                let worker_fd = parent.worker_reader_fd.ok_or_else(|| {
                    AdapterError::Unavailable(
                        "Linux worker bootstrap reader was not created".to_owned(),
                    )
                })?;
                command
                    .arg(WORKER_PIPE_ARGUMENT)
                    .arg(worker_fd.to_string())
                    .arg(WORKER_BOOT_ID_ARGUMENT)
                    .arg(worker.bootstrap().watchdog_boot_id.to_string())
                    .arg(WORKER_FRAME_SHA256_ARGUMENT)
                    .arg(worker.frame_sha256());
            }
            if let Some(_gateway_health) = gateway_health {
                let health_fd = parent.gateway_health_reader_fd.ok_or_else(|| {
                    AdapterError::Unavailable(
                        "Linux Gateway health reader was not created".to_owned(),
                    )
                })?;
                command
                    .arg(GATEWAY_HEALTH_PIPE_ARGUMENT)
                    .arg(health_fd.to_string());
            }
            Some(parent)
        } else {
            None
        };
        command
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(self.streams.stdout.into_stdio())
            .stderr(self.streams.stderr.into_stdio());
        let mut child = command
            .spawn()
            .map_err(|error| AdapterError::Io(format!("Linux helper spawn failed: {error}")))?;
        drop(helper_file);
        let stdin = child.stdin.take();
        let worker_writer = parent_bootstrap
            .as_mut()
            .and_then(|parent| parent.worker_writer.take());
        let gateway_health_writer = parent_bootstrap
            .as_mut()
            .and_then(|parent| parent.gateway_health_writer.take());
        Ok(PendingLaunch {
            child: Some(child),
            request_frame: Some(frame),
            stdin,
            parent_bootstrap,
            worker_writer,
            worker_launch: worker.cloned(),
            gateway_health_writer,
            gateway_health_frame: gateway_health.map(GatewayHealthBootstrap::encoded_frame),
            launch_nonce: specification.launch_nonce.clone(),
            timeout: self.timeout,
            released: false,
        })
    }
}

pub(super) fn open_parent_ready_descriptor(
    parent_pid: u32,
    fd: RawFd,
) -> Result<File, AdapterError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(O_NONBLOCK | O_CLOEXEC)
        .open(parent_fd_path(parent_pid, fd))
        .map_err(|error| {
            AdapterError::Unavailable(format!(
                "Linux parent readiness descriptor cannot be opened: {error}"
            ))
        })
}
