//! Race-free Linux launch handoff.
//!
//! A normal `Command::spawn` starts the requested program before a caller can
//! write its PID to a cgroup.  That ordering is not an ownership proof.  This
//! module instead starts the trusted watchdog executable in a barrier mode.
//! The helper accepts one bounded request frame, waits for a nonce-bound `GO`,
//! and only then starts the approved component.  The parent places the helper
//! in the durable cgroup and verifies membership before sending `GO`.
//!
//! The helper calls the safe Unix `CommandExt::exec` operation only after the
//! complete request and cgroup membership have been checked.  `exec` replaces
//! the helper in place, preserving the PID and all inherited stream handles;
//! there is no second target process or post-spawn PID move to authorize.

use super::contract::{AdapterError, ComponentKind, LaunchSpec, SessionSelector};
use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

const FRAME_MAGIC: &[u8; 8] = b"ASC-LNX1";
const FRAME_VERSION: u8 = 1;
const GO_MAGIC: &[u8; 8] = b"ASC-GO01";
const READY_MAGIC: &[u8; 8] = b"ASC-RDY1";
const HELPER_ARGUMENT: &str = "--ascension-linux-launch-helper";
const PARENT_BOOTSTRAP_PID_ARGUMENT: &str = "--ascension-linux-parent-bootstrap-pid";
const PROTECTED_CONFIG_ARGUMENT: &str = "--ascension-linux-protected-config";
const DELEGATED_CGROUP_ROOT_ARGUMENT: &str = "--ascension-linux-delegated-cgroup-root";
const MAX_FRAME_BYTES: usize = 256 * 1024;
const MAX_FIELD_BYTES: usize = 16 * 1024;
const MAX_ARGUMENTS: usize = 64;
const MAX_ENVIRONMENT: usize = 64;
const MAX_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;
const CHILD_CLEANUP_TIMEOUT: Duration = Duration::from_millis(500);
const CHILD_CLEANUP_POLL: Duration = Duration::from_millis(10);
const MIN_INHERITED_FD: RawFd = 3;
const O_DIRECTORY: i32 = 0o200_000;
const O_NONBLOCK: i32 = 0o4_000;
const O_NOFOLLOW: i32 = 0o400_000;
const O_CLOEXEC: i32 = 0o2_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProtectedFileIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    size: u64,
}

/// Immutable bootstrap context supplied separately from the untrusted launch
/// frame.  The real watchdog binds an already-open configuration file and
/// delegated cgroup root before spawning the helper.
#[derive(Clone, Debug)]
pub struct LinuxHelperBootstrap {
    protected_config_path: PathBuf,
    protected_config: Arc<File>,
    protected_config_identity: ProtectedFileIdentity,
    delegated_cgroup_root_path: Option<PathBuf>,
    delegated_cgroup_root: Option<Arc<File>>,
    delegated_cgroup_root_identity: Option<ProtectedFileIdentity>,
}

impl PartialEq for LinuxHelperBootstrap {
    fn eq(&self, other: &Self) -> bool {
        self.protected_config_path == other.protected_config_path
            && self.protected_config_identity == other.protected_config_identity
            && self.delegated_cgroup_root_path == other.delegated_cgroup_root_path
            && self.delegated_cgroup_root_identity == other.delegated_cgroup_root_identity
    }
}

impl Eq for LinuxHelperBootstrap {}

impl LinuxHelperBootstrap {
    /// Validate and canonicalize an owner-protected configuration path.
    ///
    /// The path must already exist as a regular, non-symlink file and must not
    /// be writable by group or other users.  This check is only a bootstrap
    /// guard; the caller still has to bind the resulting descriptor to its
    /// fixed configuration before reading durable launch intent.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, AdapterError> {
        let path = path.into();
        if !path.is_absolute() || path.as_os_str().is_empty() {
            return Err(AdapterError::Invalid(
                "Linux protected config path must be absolute".to_owned(),
            ));
        }
        let (file, canonical, identity) = open_protected_config_path(&path)?;
        if canonical != path {
            return Err(AdapterError::IdentityMismatch(
                "Linux protected config path is not canonical".to_owned(),
            ));
        }
        Ok(Self {
            protected_config_path: canonical,
            protected_config: Arc::new(file),
            protected_config_identity: identity,
            delegated_cgroup_root_path: None,
            delegated_cgroup_root: None,
            delegated_cgroup_root_identity: None,
        })
    }

    fn from_parent_fds(
        parent_pid: u32,
        config_fd: RawFd,
        root_fd: RawFd,
        ready_fd: RawFd,
    ) -> Result<(Self, HelperReadyChannel), AdapterError> {
        let actual_parent_pid =
            rustix::process::getppid().and_then(|pid| u32::try_from(pid.as_raw_pid()).ok());
        if actual_parent_pid != Some(parent_pid) {
            return Err(AdapterError::IdentityMismatch(
                "Linux helper bootstrap parent process is unexpected".to_owned(),
            ));
        }
        if config_fd < MIN_INHERITED_FD
            || root_fd < MIN_INHERITED_FD
            || ready_fd < MIN_INHERITED_FD
            || config_fd == root_fd
            || config_fd == ready_fd
            || root_fd == ready_fd
        {
            return Err(AdapterError::Invalid(
                "Linux helper bootstrap descriptors are invalid".to_owned(),
            ));
        }
        // The trusted parent keeps these descriptors open while the helper
        // starts, but does not make them inheritable.  Opening through the
        // parent's proc-fd view duplicates the exact already-open file
        // descriptions into CLOEXEC handles owned only by this helper.  This
        // avoids a process-wide inheritable-fd window and leaves no raw
        // bootstrap descriptor for the eventual target exec to inherit.
        let ready = open_parent_ready_descriptor(parent_pid, ready_fd)?;
        let ready_metadata = ready.metadata().map_err(|error| {
            AdapterError::Unavailable(format!(
                "Linux helper readiness descriptor metadata failed: {error}"
            ))
        })?;
        if !ready_metadata.is_file() || ready_metadata.len() != 0 {
            return Err(AdapterError::Invalid(
                "Linux helper readiness descriptor is not a fresh regular file".to_owned(),
            ));
        }
        let config = open_parent_descriptor(parent_pid, config_fd, false)?;
        let root = open_parent_descriptor(parent_pid, root_fd, true)?;
        let config_identity = validate_protected_config_handle(&config)?;
        let root_metadata = root.metadata().map_err(|error| {
            AdapterError::Unavailable(format!(
                "Linux delegated cgroup root metadata failed: {error}"
            ))
        })?;
        let root_identity = protected_file_identity(&root_metadata);
        if !root_metadata.is_dir() || root_identity.mode & 0o022 != 0 {
            return Err(AdapterError::Invalid(
                "Linux delegated cgroup root descriptor is unsafe".to_owned(),
            ));
        }
        let config_path = canonical_parent_fd_path(parent_pid, config_fd)?;
        let root_path = canonical_parent_fd_path(parent_pid, root_fd)?;
        for control in ["cgroup.procs", "cgroup.events", "cgroup.kill"] {
            let metadata = fs::symlink_metadata(parent_fd_child(
                parent_pid,
                root_fd,
                std::ffi::OsStr::new(control),
            ))
            .map_err(|error| {
                AdapterError::Unavailable(format!(
                    "Linux delegated cgroup root lacks {control}: {error}"
                ))
            })?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(AdapterError::Invalid(format!(
                    "Linux delegated cgroup root has invalid {control}"
                )));
            }
        }
        Ok((
            Self {
                protected_config_path: config_path,
                protected_config: Arc::new(config),
                protected_config_identity: config_identity,
                delegated_cgroup_root_path: Some(root_path),
                delegated_cgroup_root: Some(Arc::new(root)),
                delegated_cgroup_root_identity: Some(root_identity),
            },
            HelperReadyChannel { file: ready },
        ))
    }

    /// Return the canonical path that was validated for helper bootstrap.
    #[must_use]
    pub fn protected_config_path(&self) -> &Path {
        &self.protected_config_path
    }

    /// Attach the exact delegated cgroup root used by the parent adapter.
    /// The directory is opened before the helper is spawned and retained by
    /// the parent, so a helper cannot substitute a sibling root by changing a
    /// caller-controlled path or by winning a rename race.
    pub fn with_delegated_cgroup_root(
        mut self,
        path: impl Into<PathBuf>,
    ) -> Result<Self, AdapterError> {
        let path = path.into();
        let (directory, canonical, identity) = open_delegated_cgroup_root(&path)?;
        self.delegated_cgroup_root_path = Some(canonical);
        self.delegated_cgroup_root = Some(Arc::new(directory));
        self.delegated_cgroup_root_identity = Some(identity);
        Ok(self)
    }

    /// Return the exact cgroup root path bound to this bootstrap.
    #[must_use]
    pub(crate) fn delegated_cgroup_root_path(&self) -> Option<&Path> {
        self.delegated_cgroup_root_path.as_deref()
    }

    /// Read from the descriptor opened when this bootstrap was validated.
    /// The returned handle is still bound to the original inode.
    pub(crate) fn protected_config_file(&self) -> Result<File, AdapterError> {
        self.protected_config.try_clone().map_err(|error| {
            AdapterError::Unavailable(format!(
                "Linux protected config descriptor cannot be cloned: {error}"
            ))
        })
    }

    fn parent_descriptors(&self) -> Result<ParentBootstrap, AdapterError> {
        let Some(root) = self.delegated_cgroup_root.as_ref() else {
            return Err(AdapterError::Invalid(
                "Linux helper requires an exact delegated cgroup root bootstrap".to_owned(),
            ));
        };
        let config = self.protected_config.try_clone().map_err(|error| {
            AdapterError::Unavailable(format!(
                "Linux protected config descriptor cannot be cloned: {error}"
            ))
        })?;
        let root = root.try_clone().map_err(|error| {
            AdapterError::Unavailable(format!(
                "Linux delegated cgroup root descriptor cannot be cloned: {error}"
            ))
        })?;
        let config_fd = config.as_raw_fd();
        let root_fd = root.as_raw_fd();
        let ready = File::from(
            memfd_create("ascension-linux-helper-ready", MemfdFlags::CLOEXEC).map_err(|error| {
                AdapterError::Unavailable(format!(
                    "Linux helper readiness descriptor cannot be created: {error}"
                ))
            })?,
        );
        let ready_fd = ready.as_raw_fd();
        if config_fd < MIN_INHERITED_FD
            || root_fd < MIN_INHERITED_FD
            || ready_fd < MIN_INHERITED_FD
            || config_fd == root_fd
            || config_fd == ready_fd
            || root_fd == ready_fd
        {
            return Err(AdapterError::Unavailable(
                "Linux helper bootstrap descriptor is reserved for stdio".to_owned(),
            ));
        }
        Ok(ParentBootstrap {
            config,
            config_fd,
            root,
            root_fd,
            ready,
            ready_fd,
        })
    }
}

/// CLOEXEC parent-owned descriptors kept alive until the helper has opened
/// their proc-fd views.  They are never made inheritable by the parent.
struct ParentBootstrap {
    config: File,
    config_fd: RawFd,
    root: File,
    root_fd: RawFd,
    ready: File,
    ready_fd: RawFd,
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
            .finish_non_exhaustive()
    }
}

impl ParentBootstrap {
    fn wait_for_ready(
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

struct HelperReadyChannel {
    file: File,
}

impl HelperReadyChannel {
    fn send(&mut self, launch_nonce: &str) -> Result<(), AdapterError> {
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

fn protected_file_identity(metadata: &std::fs::Metadata) -> ProtectedFileIdentity {
    ProtectedFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
        size: metadata.len(),
    }
}

fn validate_protected_config_handle(file: &File) -> Result<ProtectedFileIdentity, AdapterError> {
    let metadata = file.metadata().map_err(|error| {
        AdapterError::Unavailable(format!("Linux protected config metadata failed: {error}"))
    })?;
    let identity = protected_file_identity(&metadata);
    if !metadata.is_file() {
        return Err(AdapterError::Invalid(
            "Linux protected config must be a regular file".to_owned(),
        ));
    }
    if identity.uid != rustix::process::geteuid().as_raw()
        || identity.mode & 0o077 != 0
        || identity.mode & 0o400 == 0
    {
        return Err(AdapterError::Invalid(
            "Linux protected config must be owner-readable and owner-only".to_owned(),
        ));
    }
    if identity.size > 65_536 {
        return Err(AdapterError::Invalid(
            "Linux protected config exceeds the bounded read size".to_owned(),
        ));
    }
    Ok(identity)
}

fn open_protected_config_path(
    path: &Path,
) -> Result<(File, PathBuf, ProtectedFileIdentity), AdapterError> {
    let file = open_regular_path_without_links(path, "Linux protected config")?;
    let identity = validate_protected_config_handle(&file)?;
    let canonical = fs::canonicalize(path).map_err(|error| {
        AdapterError::Unavailable(format!(
            "Linux protected config cannot be resolved: {error}"
        ))
    })?;
    let opened = canonical_fd_path(file.as_raw_fd())?;
    if opened != canonical {
        return Err(AdapterError::IdentityMismatch(
            "Linux protected config was replaced while it was opened".to_owned(),
        ));
    }
    Ok((file, canonical, identity))
}

fn open_delegated_cgroup_root(
    path: &Path,
) -> Result<(File, PathBuf, ProtectedFileIdentity), AdapterError> {
    let file = open_directory_path_without_links(path, "Linux delegated cgroup root")?;
    let metadata = file.metadata().map_err(|error| {
        AdapterError::Unavailable(format!(
            "Linux delegated cgroup root metadata failed: {error}"
        ))
    })?;
    let identity = protected_file_identity(&metadata);
    if !metadata.is_dir() {
        return Err(AdapterError::Invalid(
            "Linux delegated cgroup root must be a directory".to_owned(),
        ));
    }
    if identity.mode & 0o022 != 0 {
        return Err(AdapterError::Invalid(
            "Linux delegated cgroup root must not be group/other writable".to_owned(),
        ));
    }
    for control in ["cgroup.procs", "cgroup.events", "cgroup.kill"] {
        let control_path = proc_fd_child(file.as_raw_fd(), std::ffi::OsStr::new(control));
        let metadata = fs::symlink_metadata(&control_path).map_err(|error| {
            AdapterError::Unavailable(format!(
                "Linux delegated cgroup root lacks {control}: {error}"
            ))
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(AdapterError::Invalid(format!(
                "Linux delegated cgroup root has invalid {control}"
            )));
        }
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        AdapterError::Unavailable(format!(
            "Linux delegated cgroup root cannot be resolved: {error}"
        ))
    })?;
    if canonical_fd_path(file.as_raw_fd())? != canonical {
        return Err(AdapterError::IdentityMismatch(
            "Linux delegated cgroup root was replaced while it was opened".to_owned(),
        ));
    }
    Ok((file, canonical, identity))
}

fn open_regular_path_without_links(path: &Path, label: &str) -> Result<File, AdapterError> {
    if !path.is_absolute() {
        return Err(AdapterError::Invalid(format!(
            "{label} path must be absolute"
        )));
    }
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK)
        .open("/")
        .map_err(|error| {
            AdapterError::Unavailable(format!("{label} root is unavailable: {error}"))
        })?;
    let components = checked_path_components(path, label)?;
    let Some((last, parents)) = components.split_last() else {
        return Err(AdapterError::Invalid(format!("{label} path is empty")));
    };
    for component in parents {
        directory = OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK)
            .open(proc_fd_child(directory.as_raw_fd(), component))
            .map_err(|error| {
                AdapterError::Unavailable(format!("{label} parent is unavailable: {error}"))
            })?;
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(proc_fd_child(directory.as_raw_fd(), last))
        .map_err(|error| AdapterError::Unavailable(format!("{label} is unavailable: {error}")))
}

fn open_directory_path_without_links(path: &Path, label: &str) -> Result<File, AdapterError> {
    if !path.is_absolute() {
        return Err(AdapterError::Invalid(format!(
            "{label} path must be absolute"
        )));
    }
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK)
        .open("/")
        .map_err(|error| {
            AdapterError::Unavailable(format!("{label} root is unavailable: {error}"))
        })?;
    for component in checked_path_components(path, label)? {
        directory = OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK)
            .open(proc_fd_child(directory.as_raw_fd(), &component))
            .map_err(|error| {
                AdapterError::Unavailable(format!("{label} directory is unavailable: {error}"))
            })?;
    }
    Ok(directory)
}

fn checked_path_components(
    path: &Path,
    label: &str,
) -> Result<Vec<std::ffi::OsString>, AdapterError> {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::RootDir => None,
            std::path::Component::Normal(value) => Some(Ok(value.to_os_string())),
            _ => Some(Err(AdapterError::Invalid(format!(
                "{label} path contains traversal or an unsupported component"
            )))),
        })
        .collect()
}

fn proc_fd_child(fd: RawFd, component: &std::ffi::OsStr) -> PathBuf {
    let mut path = PathBuf::from(format!("/proc/self/fd/{fd}"));
    path.push(component);
    path
}

fn canonical_fd_path(fd: RawFd) -> Result<PathBuf, AdapterError> {
    canonical_descriptor_path(format!("/proc/self/fd/{fd}"))
}

fn canonical_parent_fd_path(parent_pid: u32, fd: RawFd) -> Result<PathBuf, AdapterError> {
    canonical_descriptor_path(parent_fd_path(parent_pid, fd))
}

fn canonical_descriptor_path(path: impl AsRef<Path>) -> Result<PathBuf, AdapterError> {
    fs::canonicalize(path).map_err(|error| {
        AdapterError::Unavailable(format!(
            "Linux bootstrap descriptor target is unavailable: {error}"
        ))
    })
}

fn parent_fd_path(parent_pid: u32, fd: RawFd) -> PathBuf {
    PathBuf::from(format!("/proc/{parent_pid}/fd/{fd}"))
}

fn parent_fd_child(parent_pid: u32, fd: RawFd, component: &std::ffi::OsStr) -> PathBuf {
    let mut path = parent_fd_path(parent_pid, fd);
    path.push(component);
    path
}

fn open_parent_descriptor(
    parent_pid: u32,
    fd: RawFd,
    directory: bool,
) -> Result<File, AdapterError> {
    let mut options = OpenOptions::new();
    options.read(true);
    if directory {
        options.custom_flags(O_DIRECTORY | O_NONBLOCK | O_CLOEXEC);
    } else {
        options.custom_flags(O_NONBLOCK | O_CLOEXEC);
    }
    options
        .open(parent_fd_path(parent_pid, fd))
        .map_err(|error| {
            AdapterError::Unavailable(format!(
                "Linux parent bootstrap descriptor cannot be opened: {error}"
            ))
        })
}

/// Hidden command-line argument recognized by the watchdog's real executable
/// entrypoint.  The normal CLI must dispatch this before parsing user input.
#[must_use]
pub const fn helper_argument() -> &'static str {
    HELPER_ARGUMENT
}

/// Hidden argument carrying the parent-owned separately validated config fd.
#[must_use]
pub const fn protected_config_argument() -> &'static str {
    PROTECTED_CONFIG_ARGUMENT
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
    fn into_stdio(self) -> Stdio {
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

/// The request supplied to the root-owned durable-intent authorizer.
///
/// A caller must authorize the complete specification and exact cgroup path;
/// authorizing only the launch nonce or executable path is insufficient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxHelperRequest {
    pub specification: LaunchSpec,
    pub cgroup_path: PathBuf,
}

/// Authorization returned by the root-owned durable-intent lookup.
///
/// The helper compares the request to this value, canonicalizes the approved
/// role path, and hashes the executable again immediately before launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxHelperAuthorization {
    pub specification: LaunchSpec,
    pub cgroup_path: PathBuf,
    pub allowlisted_executables: BTreeMap<ComponentKind, PathBuf>,
}

impl LinuxHelperAuthorization {
    /// Validate the closed helper authorization surface.
    ///
    /// # Errors
    ///
    /// Returns an explicit error when the durable authorization is malformed,
    /// has no role allowlist entry, or names an untrusted cgroup path.
    pub fn validate(&self) -> Result<(), AdapterError> {
        self.specification.validate()?;
        if !self.cgroup_path.is_absolute() {
            return Err(AdapterError::Invalid(
                "Linux helper cgroup path must be absolute".to_owned(),
            ));
        }
        let Some(approved) = self
            .allowlisted_executables
            .get(&self.specification.component)
        else {
            return Err(AdapterError::Unsupported(
                "Linux helper role is not allowlisted".to_owned(),
            ));
        };
        if !approved.is_absolute() {
            return Err(AdapterError::Invalid(
                "Linux helper allowlist path must be absolute".to_owned(),
            ));
        }
        if self.specification.executable_sha256.len() != 64
            || !self
                .specification
                .executable_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(AdapterError::Invalid(
                "Linux helper executable digest is not SHA-256".to_owned(),
            ));
        }
        Ok(())
    }
}

/// A helper process that has received its frame but not yet been released.
///
/// Dropping a pending launch kills the exact helper handle.  The cgroup owner
/// must still remove the cgroup or use `cgroup.kill` when a post-release error
/// occurs.
pub(crate) struct PendingLaunch {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    parent_bootstrap: Option<ParentBootstrap>,
    launch_nonce: String,
    timeout: Duration,
    released: bool,
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
        if let Some(bootstrap) = self.parent_bootstrap.as_mut() {
            bootstrap.wait_for_ready(&self.launch_nonce, self.timeout)?;
        }
        let Some(stdin) = self.stdin.as_mut() else {
            return Err(AdapterError::Invalid(
                "Linux helper stdin is unavailable".to_owned(),
            ));
        };
        stdin
            .write_all(GO_MAGIC)
            .and_then(|()| put_string_io(stdin, &self.launch_nonce))
            .map_err(|error| {
                AdapterError::Io(format!("Linux helper GO handoff failed: {error}"))
            })?;
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
    pub(crate) fn into_child(mut self) -> Result<Child, AdapterError> {
        if !self.released {
            return Err(AdapterError::Invalid(
                "Linux helper cannot be consumed before GO".to_owned(),
            ));
        }
        self.stdin.take();
        // The helper parsed and opened both parent descriptors before it could
        // read the frame or accept GO, so the parent-side keepalive can close
        // before returning the target handle.  The target never inherited
        // these CLOEXEC parent descriptors in the first place.
        self.parent_bootstrap.take();
        self.child.take().ok_or_else(|| {
            AdapterError::Unavailable("Linux helper child handle was lost".to_owned())
        })
    }
}

impl Drop for PendingLaunch {
    fn drop(&mut self) {
        self.stdin.take();
        if let Some(child) = self.child.as_mut() {
            terminate_child_bounded(child, CHILD_CLEANUP_TIMEOUT);
        }
    }
}

/// Kill and reap a helper without allowing a launch-error path or `Drop` to
/// block forever.  The cgroup owner remains responsible for a later
/// `cgroup.kill` reconciliation when this best-effort reap cannot be proved.
fn terminate_child_bounded(child: &mut Child, timeout: Duration) {
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
    helper_executable: PathBuf,
    helper_executable_sha256: String,
    helper_argument: String,
    bootstrap: Option<LinuxHelperBootstrap>,
    streams: LauncherStreams,
    timeout: Duration,
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
    /// The root executable must dispatch [`helper_argument`] before normal CLI
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

    /// Spawn only the trusted helper and send its bounded request frame.
    ///
    /// The caller must assign [`PendingLaunch::pid`] to the exact durable
    /// cgroup, verify membership, and call [`PendingLaunch::release_gate`].
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
        let parent_bootstrap = if let Some(bootstrap) = &self.bootstrap {
            let parent = bootstrap.parent_descriptors()?;
            command
                .arg(PARENT_BOOTSTRAP_PID_ARGUMENT)
                .arg(std::process::id().to_string())
                .arg(PROTECTED_CONFIG_ARGUMENT)
                .arg(parent.config_fd.to_string())
                .arg(DELEGATED_CGROUP_ROOT_ARGUMENT)
                .arg(parent.root_fd.to_string())
                .arg(parent.ready_fd.to_string());
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
        let Some(mut stdin) = child.stdin.take() else {
            terminate_child_bounded(&mut child, CHILD_CLEANUP_TIMEOUT);
            return Err(AdapterError::Io(
                "Linux helper did not provide anonymous stdin".to_owned(),
            ));
        };
        if let Err(error) = stdin.write_all(&frame) {
            terminate_child_bounded(&mut child, CHILD_CLEANUP_TIMEOUT);
            return Err(AdapterError::Io(format!(
                "Linux helper request handoff failed: {error}"
            )));
        }
        Ok(PendingLaunch {
            child: Some(child),
            stdin: Some(stdin),
            parent_bootstrap,
            launch_nonce: specification.launch_nonce.clone(),
            timeout: self.timeout,
            released: false,
        })
    }
}

/// Return true only for the exact hidden helper invocation.
#[must_use]
pub fn helper_invocation_requested() -> bool {
    let mut arguments = env::args();
    let _ = arguments.next();
    arguments
        .next()
        .is_some_and(|value| value == HELPER_ARGUMENT)
}

fn parse_helper_bootstrap()
-> Result<Option<(LinuxHelperBootstrap, HelperReadyChannel)>, AdapterError> {
    let mut arguments = env::args();
    let _ = arguments.next();
    let Some(argument) = arguments.next() else {
        return Ok(None);
    };
    if argument != HELPER_ARGUMENT {
        return Err(AdapterError::Unsupported(
            "Linux helper entrypoint was not requested".to_owned(),
        ));
    }
    let parent_argument = arguments.next().ok_or_else(|| {
        AdapterError::Invalid(
            "Linux helper parent bootstrap process identifier is missing".to_owned(),
        )
    })?;
    if parent_argument != PARENT_BOOTSTRAP_PID_ARGUMENT {
        return Err(AdapterError::Invalid(
            "Linux helper invocation has an invalid parent bootstrap argument".to_owned(),
        ));
    }
    let parent_pid = arguments
        .next()
        .ok_or_else(|| {
            AdapterError::Invalid(
                "Linux helper parent bootstrap process identifier is missing".to_owned(),
            )
        })?
        .parse::<u32>()
        .map_err(|_| {
            AdapterError::Invalid(
                "Linux helper parent bootstrap process identifier is invalid".to_owned(),
            )
        })?;
    let Some(config_argument) = arguments.next() else {
        return Ok(None);
    };
    if config_argument != PROTECTED_CONFIG_ARGUMENT {
        return Err(AdapterError::Invalid(
            "Linux helper invocation has an invalid bootstrap argument".to_owned(),
        ));
    }
    let config_fd = arguments
        .next()
        .ok_or_else(|| {
            AdapterError::Invalid("Linux helper protected config descriptor is missing".to_owned())
        })?
        .parse::<RawFd>()
        .map_err(|_| {
            AdapterError::Invalid("Linux helper protected config descriptor is invalid".to_owned())
        })?;
    let root_argument = arguments.next().ok_or_else(|| {
        AdapterError::Invalid("Linux helper delegated cgroup root descriptor is missing".to_owned())
    })?;
    if root_argument != DELEGATED_CGROUP_ROOT_ARGUMENT {
        return Err(AdapterError::Invalid(
            "Linux helper invocation has an invalid cgroup root bootstrap argument".to_owned(),
        ));
    }
    let root_fd = arguments
        .next()
        .ok_or_else(|| {
            AdapterError::Invalid(
                "Linux helper delegated cgroup root descriptor is missing".to_owned(),
            )
        })?
        .parse::<RawFd>()
        .map_err(|_| {
            AdapterError::Invalid(
                "Linux helper delegated cgroup root descriptor is invalid".to_owned(),
            )
        })?;
    let ready_fd = arguments
        .next()
        .ok_or_else(|| {
            AdapterError::Invalid("Linux helper readiness descriptor is missing".to_owned())
        })?
        .parse::<RawFd>()
        .map_err(|_| {
            AdapterError::Invalid("Linux helper readiness descriptor is invalid".to_owned())
        })?;
    if arguments.next().is_some() {
        return Err(AdapterError::Invalid(
            "Linux helper invocation has unexpected arguments".to_owned(),
        ));
    }
    LinuxHelperBootstrap::from_parent_fds(parent_pid, config_fd, root_fd, ready_fd).map(Some)
}

/// Run the hidden helper after root code has authorized its frame.
///
/// The authorizer is deliberately called after the frame is decoded and must
/// resolve the launch nonce against durable intent.  It must not authorize a
/// request solely because the executable or role is familiar.
///
/// # Errors
///
/// Returns an explicit error for malformed input, authorization mismatch,
/// cgroup mismatch, GO timeout/nonce mismatch, or target launch failure.
pub fn run_hidden_helper_with_authorizer<F>(authorizer: F) -> Result<i32, AdapterError>
where
    F: FnOnce(&LinuxHelperRequest) -> Result<LinuxHelperAuthorization, AdapterError>,
{
    if !helper_invocation_requested() {
        return Err(AdapterError::Unsupported(
            "Linux helper entrypoint was not requested".to_owned(),
        ));
    }
    if parse_helper_bootstrap()?.is_some() {
        return Err(AdapterError::Invalid(
            "Linux helper protected bootstrap requires the bootstrap authorizer API".to_owned(),
        ));
    }
    run_hidden_helper_core(None, authorizer)
}

/// Run the hidden helper with the separately supplied protected-config
/// context.  The authorizer receives both the decoded frame and this context,
/// allowing it to perform a read-only launch-intent lookup against the exact
/// root-configured store rather than trusting a path from the frame.
pub fn run_hidden_helper_with_bootstrap_authorizer<F>(authorizer: F) -> Result<i32, AdapterError>
where
    F: FnOnce(
        &LinuxHelperRequest,
        &LinuxHelperBootstrap,
    ) -> Result<LinuxHelperAuthorization, AdapterError>,
{
    if !helper_invocation_requested() {
        return Err(AdapterError::Unsupported(
            "Linux helper entrypoint was not requested".to_owned(),
        ));
    }
    let (bootstrap, ready) = parse_helper_bootstrap()?.ok_or_else(|| {
        AdapterError::Invalid(
            "Linux helper requires a separately supplied protected config bootstrap".to_owned(),
        )
    })?;
    run_hidden_helper_core(Some(ready), |request| authorizer(request, &bootstrap))
}

fn run_hidden_helper_core<F>(
    mut ready: Option<HelperReadyChannel>,
    authorizer: F,
) -> Result<i32, AdapterError>
where
    F: FnOnce(&LinuxHelperRequest) -> Result<LinuxHelperAuthorization, AdapterError>,
{
    let (frame_rx, go_rx) = spawn_protocol_reader();
    let started = Instant::now();
    let request = recv_bounded(&frame_rx, remaining_timeout(started, MAX_TIMEOUT))??;
    if let Some(channel) = ready.as_mut() {
        channel.send(&request.specification.launch_nonce)?;
    }
    let authorization = authorize_after_release(&request, &go_rx, started, authorizer)?;
    verify_current_cgroup(&authorization.cgroup_path)?;
    spawn_authorized_target(&authorization).map(|()| 0)
}

fn authorize_after_release<F>(
    request: &LinuxHelperRequest,
    go_rx: &Receiver<Result<String, AdapterError>>,
    started: Instant,
    authorizer: F,
) -> Result<LinuxHelperAuthorization, AdapterError>
where
    F: FnOnce(&LinuxHelperRequest) -> Result<LinuxHelperAuthorization, AdapterError>,
{
    // The request frame can arrive before the parent has assigned this helper
    // to the cgroup. GO is sent only after that assignment and its verification.
    // Checking membership before GO races the parent's legitimate handoff.
    // Query durable authorization after the barrier too: stop may have been
    // committed while this helper was waiting, invalidating earlier approval.
    let go = recv_bounded(go_rx, remaining_timeout(started, MAX_TIMEOUT))??;
    if go != request.specification.launch_nonce {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper GO nonce does not match the authorized launch".to_owned(),
        ));
    }
    let authorization = authorizer(request)?;
    authorize_request(request, &authorization)?;
    Ok(authorization)
}

/// Run the hidden helper if the current process was invoked in helper mode.
///
/// This convenience function is intended for the real watchdog `main`: when
/// it returns `Ok(false)`, normal CLI parsing may continue.  The authorizer
/// remains root-owned so this module cannot invent durable intent.
///
/// # Errors
///
/// Returns the same bounded helper errors as
/// [`run_hidden_helper_with_authorizer`].
pub fn run_hidden_helper_if_requested<F>(authorizer: F) -> Result<Option<i32>, AdapterError>
where
    F: FnOnce(&LinuxHelperRequest) -> Result<LinuxHelperAuthorization, AdapterError>,
{
    if !helper_invocation_requested() {
        return Ok(None);
    }
    run_hidden_helper_with_authorizer(authorizer).map(Some)
}

/// Run the hidden helper with protected bootstrap context when requested.
pub fn run_hidden_helper_if_requested_with_bootstrap_authorizer<F>(
    authorizer: F,
) -> Result<Option<i32>, AdapterError>
where
    F: FnOnce(
        &LinuxHelperRequest,
        &LinuxHelperBootstrap,
    ) -> Result<LinuxHelperAuthorization, AdapterError>,
{
    if !helper_invocation_requested() {
        return Ok(None);
    }
    run_hidden_helper_with_bootstrap_authorizer(authorizer).map(Some)
}

fn spawn_protocol_reader() -> (
    Receiver<Result<LinuxHelperRequest, AdapterError>>,
    Receiver<Result<String, AdapterError>>,
) {
    let (frame_tx, frame_rx) = mpsc::sync_channel(1);
    let (go_tx, go_rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut stdin = io::stdin();
        let result = read_frame(&mut stdin);
        match result {
            Ok(request) => {
                if frame_tx.send(Ok(request)).is_err() {
                    return;
                }
                let go = read_go(&mut stdin);
                let _ = go_tx.send(go);
            }
            Err(error) => {
                let _ = frame_tx.send(Err(error));
            }
        }
    });
    (frame_rx, go_rx)
}

fn recv_bounded<T>(
    receiver: &Receiver<Result<T, AdapterError>>,
    timeout: Duration,
) -> Result<Result<T, AdapterError>, AdapterError> {
    receiver
        .recv_timeout(timeout)
        .map_err(|error| AdapterError::Timeout(format!("Linux helper barrier timed out: {error}")))
}

fn remaining_timeout(started: Instant, limit: Duration) -> Duration {
    limit.checked_sub(started.elapsed()).unwrap_or_default()
}

fn read_frame(reader: &mut impl Read) -> Result<LinuxHelperRequest, AdapterError> {
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .map_err(|error| protocol_io(&error))?;
    let length = u32::from_le_bytes(length);
    let length = usize::try_from(length)
        .map_err(|_| AdapterError::Invalid("Linux helper frame length overflow".to_owned()))?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(AdapterError::Invalid(
            "Linux helper frame exceeds bounds".to_owned(),
        ));
    }
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .map_err(|error| protocol_io(&error))?;
    decode_frame(&payload)
}

fn read_go(reader: &mut impl Read) -> Result<String, AdapterError> {
    let mut magic = [0_u8; GO_MAGIC.len()];
    reader
        .read_exact(&mut magic)
        .map_err(|error| protocol_io(&error))?;
    if &magic != GO_MAGIC {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper received an invalid GO marker".to_owned(),
        ));
    }
    read_string(reader, MAX_FIELD_BYTES)
}

fn encode_frame(specification: &LaunchSpec, cgroup_path: &Path) -> Result<Vec<u8>, AdapterError> {
    if !cgroup_path.is_absolute() {
        return Err(AdapterError::Invalid(
            "Linux helper cgroup path must be absolute".to_owned(),
        ));
    }
    let mut payload = Vec::with_capacity(1024);
    payload.extend_from_slice(FRAME_MAGIC);
    payload.push(FRAME_VERSION);
    payload.push(component_code(specification.component));
    match specification.session {
        SessionSelector::ActiveUser => payload.push(0),
        SessionSelector::Explicit(session) => {
            payload.push(1);
            payload.extend_from_slice(&session.to_le_bytes());
        }
    }
    payload.push(0);
    put_string(&mut payload, &specification.deployment_id)?;
    put_string(&mut payload, &specification.instance_id)?;
    put_string(&mut payload, &specification.incarnation)?;
    put_string(&mut payload, &specification.launch_nonce)?;
    put_path(&mut payload, cgroup_path)?;
    put_path(&mut payload, &specification.executable)?;
    put_string(&mut payload, &specification.executable_sha256)?;
    payload.extend_from_slice(
        &u64::try_from(specification.graceful_timeout.as_millis())
            .map_err(|_| AdapterError::Invalid("Linux graceful timeout overflow".to_owned()))?
            .to_le_bytes(),
    );
    payload.extend_from_slice(
        &u64::try_from(specification.force_timeout.as_millis())
            .map_err(|_| AdapterError::Invalid("Linux force timeout overflow".to_owned()))?
            .to_le_bytes(),
    );
    match specification.working_directory.as_deref() {
        Some(path) => {
            payload.push(1);
            put_path(&mut payload, path)?;
        }
        None => payload.push(0),
    }
    put_count(&mut payload, specification.arguments.len(), MAX_ARGUMENTS)?;
    for argument in &specification.arguments {
        put_string(&mut payload, argument)?;
    }
    put_count(
        &mut payload,
        specification.environment.len(),
        MAX_ENVIRONMENT,
    )?;
    for (name, value) in &specification.environment {
        put_string(&mut payload, name)?;
        put_string(&mut payload, value)?;
    }
    if payload.len() > MAX_FRAME_BYTES {
        return Err(AdapterError::Invalid(
            "Linux helper frame exceeds bounds".to_owned(),
        ));
    }
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(
        &u32::try_from(payload.len())
            .map_err(|_| AdapterError::Invalid("Linux helper frame length overflow".to_owned()))?
            .to_le_bytes(),
    );
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn decode_frame(payload: &[u8]) -> Result<LinuxHelperRequest, AdapterError> {
    let mut cursor = Cursor::new(payload);
    let mut magic = [0_u8; FRAME_MAGIC.len()];
    cursor
        .read_exact(&mut magic)
        .map_err(|error| protocol_io(&error))?;
    if &magic != FRAME_MAGIC {
        return Err(AdapterError::Invalid(
            "Linux helper frame magic is invalid".to_owned(),
        ));
    }
    let version = read_byte(&mut cursor)?;
    if version != FRAME_VERSION {
        return Err(AdapterError::Unsupported(
            "Linux helper frame version is unsupported".to_owned(),
        ));
    }
    let component = component_from_code(read_byte(&mut cursor)?)?;
    let session_code = read_byte(&mut cursor)?;
    let session = match session_code {
        0 => SessionSelector::ActiveUser,
        1 => SessionSelector::Explicit(read_u32(&mut cursor)?),
        _ => {
            return Err(AdapterError::Invalid(
                "Linux helper session selector is invalid".to_owned(),
            ));
        }
    };
    let reserved = read_byte(&mut cursor)?;
    if reserved != 0 {
        return Err(AdapterError::Invalid(
            "Linux helper frame reserved byte is nonzero".to_owned(),
        ));
    }
    let deployment_id = read_string(&mut cursor, MAX_FIELD_BYTES)?;
    let instance_id = read_string(&mut cursor, MAX_FIELD_BYTES)?;
    let incarnation = read_string(&mut cursor, MAX_FIELD_BYTES)?;
    let launch_nonce = read_string(&mut cursor, MAX_FIELD_BYTES)?;
    let cgroup_path = read_path(&mut cursor)?;
    let executable = read_path(&mut cursor)?;
    let executable_sha256 = read_string(&mut cursor, MAX_FIELD_BYTES)?;
    let graceful_timeout = Duration::from_millis(read_u64(&mut cursor)?);
    let force_timeout = Duration::from_millis(read_u64(&mut cursor)?);
    let working_directory = match read_byte(&mut cursor)? {
        0 => None,
        1 => Some(read_path(&mut cursor)?),
        _ => {
            return Err(AdapterError::Invalid(
                "Linux helper working-directory marker is invalid".to_owned(),
            ));
        }
    };
    let argument_count = read_count(&mut cursor, MAX_ARGUMENTS)?;
    let mut arguments = Vec::with_capacity(argument_count);
    for _ in 0..argument_count {
        arguments.push(read_string(&mut cursor, MAX_FIELD_BYTES)?);
    }
    let environment_count = read_count(&mut cursor, MAX_ENVIRONMENT)?;
    let mut environment = Vec::with_capacity(environment_count);
    for _ in 0..environment_count {
        environment.push((
            read_string(&mut cursor, MAX_FIELD_BYTES)?,
            read_string(&mut cursor, MAX_FIELD_BYTES)?,
        ));
    }
    if cursor.position() != u64::try_from(payload.len()).unwrap_or(u64::MAX) {
        return Err(AdapterError::Invalid(
            "Linux helper frame contains trailing bytes".to_owned(),
        ));
    }
    let specification = LaunchSpec {
        deployment_id,
        instance_id,
        component,
        incarnation,
        launch_nonce,
        executable,
        executable_sha256,
        arguments,
        working_directory,
        environment,
        session,
        graceful_timeout,
        force_timeout,
    };
    specification.validate()?;
    Ok(LinuxHelperRequest {
        specification,
        cgroup_path,
    })
}

fn open_parent_ready_descriptor(parent_pid: u32, fd: RawFd) -> Result<File, AdapterError> {
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

fn authorize_request(
    request: &LinuxHelperRequest,
    authorization: &LinuxHelperAuthorization,
) -> Result<(), AdapterError> {
    authorization.validate()?;
    if request.specification != authorization.specification
        || request.cgroup_path != authorization.cgroup_path
    {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper request differs from durable authorization".to_owned(),
        ));
    }
    let approved = fs::canonicalize(
        authorization
            .allowlisted_executables
            .get(&request.specification.component)
            .ok_or_else(|| {
                AdapterError::Unsupported("Linux helper role is not allowlisted".to_owned())
            })?,
    )
    .map_err(|error| {
        AdapterError::Unavailable(format!("Linux helper allowlist unavailable: {error}"))
    })?;
    let requested = fs::canonicalize(&request.specification.executable).map_err(|error| {
        AdapterError::Invalid(format!(
            "Linux helper executable cannot be resolved: {error}"
        ))
    })?;
    if approved != requested {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper executable is outside the role allowlist".to_owned(),
        ));
    }
    let digest = hash_file(&requested)?;
    if digest != request.specification.executable_sha256 {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper executable digest changed".to_owned(),
        ));
    }
    Ok(())
}

fn spawn_authorized_target(authorization: &LinuxHelperAuthorization) -> Result<(), AdapterError> {
    let specification = &authorization.specification;
    if specification.component == ComponentKind::HostBroker {
        return Err(AdapterError::Unsupported(
            "Linux helper does not launch graphical HostBroker sessions".to_owned(),
        ));
    }
    if let SessionSelector::Explicit(session) = specification.session
        && session != 0
    {
        return Err(AdapterError::Unsupported(
            "Linux helper does not select Windows user sessions".to_owned(),
        ));
    }
    let approved = fs::canonicalize(
        authorization
            .allowlisted_executables
            .get(&specification.component)
            .ok_or_else(|| {
                AdapterError::Unsupported("Linux helper role is not allowlisted".to_owned())
            })?,
    )
    .map_err(|error| {
        AdapterError::Unavailable(format!(
            "Linux helper target allowlist is unavailable: {error}"
        ))
    })?;
    let requested = fs::canonicalize(&specification.executable).map_err(|error| {
        AdapterError::Invalid(format!("Linux helper target cannot be resolved: {error}"))
    })?;
    if approved != requested {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper target differs from the authorized role path".to_owned(),
        ));
    }
    let (executable_file, executable_fd_path) =
        open_verified_executable(&approved, &specification.executable_sha256)?;
    let mut command = Command::new(&executable_fd_path);
    command.arg0(&specification.executable);
    command.args(&specification.arguments).env_clear().envs(
        specification
            .environment
            .iter()
            .map(|(name, value)| (name, value)),
    );
    if let Some(path) = specification.working_directory.as_deref() {
        let canonical = fs::canonicalize(path).map_err(|error| {
            AdapterError::Invalid(format!(
                "Linux helper working directory is invalid: {error}"
            ))
        })?;
        command.current_dir(canonical);
    }
    let error = command.exec();
    drop(executable_file);
    Err(AdapterError::Io(format!(
        "Linux target exec failed: {error}"
    )))
}

fn verify_current_cgroup(expected: &Path) -> Result<(), AdapterError> {
    let expected = fs::canonicalize(expected).map_err(|error| {
        AdapterError::Unavailable(format!("Linux helper cgroup cannot be resolved: {error}"))
    })?;
    let current = discover_current_cgroup()?;
    if current != expected {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper is not in the authorized cgroup".to_owned(),
        ));
    }
    let pid = std::process::id();
    let pids = fs::read_to_string(expected.join("cgroup.procs")).map_err(|error| {
        AdapterError::Unavailable(format!(
            "Linux helper cgroup membership is unreadable: {error}"
        ))
    })?;
    if !pids
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .any(|member| member == pid)
    {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper PID is not present in the authorized cgroup".to_owned(),
        ));
    }
    Ok(())
}

fn discover_current_cgroup() -> Result<PathBuf, AdapterError> {
    let mountpoint = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| {
            AdapterError::Unavailable(format!("cgroup mountinfo unavailable: {error}"))
        })?
        .lines()
        .find_map(parse_cgroup2_mountpoint)
        .ok_or_else(|| AdapterError::Unavailable("no cgroup v2 mount is available".to_owned()))?;
    let relative = fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| AdapterError::Unavailable(format!("process cgroup unavailable: {error}")))?
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
        .ok_or_else(|| AdapterError::Unavailable("process has no cgroup v2 path".to_owned()))?;
    let relative = relative.trim_start_matches('/');
    if relative
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(AdapterError::Unavailable(
            "process cgroup path is malformed".to_owned(),
        ));
    }
    let path = if relative.is_empty() {
        mountpoint
    } else {
        mountpoint.join(relative)
    };
    fs::canonicalize(path).map_err(|error| {
        AdapterError::Unavailable(format!("current cgroup cannot be resolved: {error}"))
    })
}

fn parse_cgroup2_mountpoint(line: &str) -> Option<PathBuf> {
    let mut sections = line.split(" - ");
    let pre = sections.next()?;
    let post = sections.next()?;
    if post.split_whitespace().next()? != "cgroup2" {
        return None;
    }
    let fields = pre.split_whitespace().collect::<Vec<_>>();
    fields
        .get(4)
        .map(|field| PathBuf::from(unescape_mountinfo(field)))
}

fn unescape_mountinfo(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\134", "\\")
}

/// Open an approved executable once, copy the verified bytes into a sealed
/// executable memfd, and return its `/proc/self/fd` path.  The source handle
/// is opened nonblocking and all metadata checks are made on that handle, so
/// a FIFO or device cannot make verification hang.  The sealed snapshot makes
/// an in-place source mutation after verification irrelevant to the exec.
fn open_verified_executable(
    path: &Path,
    expected_digest: &str,
) -> Result<(File, PathBuf), AdapterError> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        AdapterError::Invalid(format!("Linux executable cannot be resolved: {error}"))
    })?;
    let mut source = open_nonblocking_read(&canonical)?;
    let metadata = source.metadata().map_err(|error| {
        AdapterError::Unavailable(format!("Linux executable metadata failed: {error}"))
    })?;
    if !metadata.is_file() {
        return Err(AdapterError::Invalid(
            "Linux executable is not a regular file".to_owned(),
        ));
    }
    if metadata.len() > MAX_HASH_BYTES {
        return Err(AdapterError::Invalid(
            "Linux executable exceeds the hash size bound".to_owned(),
        ));
    }
    let snapshot_fd = create_executable_snapshot()?;
    let mut snapshot = File::from(snapshot_fd);
    let digest = hash_and_copy(&mut source, &mut snapshot)?;
    if digest != expected_digest {
        return Err(AdapterError::IdentityMismatch(
            "Linux executable bytes changed before descriptor-bound exec".to_owned(),
        ));
    }
    fcntl_add_seals(
        &snapshot,
        SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL,
    )
    .map_err(|error| {
        AdapterError::Unavailable(format!(
            "Linux executable snapshot cannot be sealed: {error}"
        ))
    })?;
    let fd = snapshot.as_raw_fd();
    if fd < 0 {
        return Err(AdapterError::Io(
            "Linux executable descriptor has an invalid number".to_owned(),
        ));
    }
    let fd_path = PathBuf::from(format!("/proc/self/fd/{fd}"));
    Ok((snapshot, fd_path))
}

fn create_executable_snapshot() -> Result<rustix::fd::OwnedFd, AdapterError> {
    let base_flags = MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING;
    match memfd_create(
        "ascension-verified-executable",
        base_flags | MemfdFlags::EXEC,
    ) {
        Ok(fd) => Ok(fd),
        Err(error) if error == rustix::io::Errno::INVAL => {
            // MFD_EXEC was added in Linux 6.3.  Older kernels either permit
            // executable memfds by default or reject them through a host
            // memfd_noexec policy; retain the latter error below.
            memfd_create("ascension-verified-executable", base_flags).map_err(|fallback| {
                AdapterError::Unavailable(format!(
                    "Linux executable snapshot cannot be created: {fallback}"
                ))
            })
        }
        Err(error) => Err(AdapterError::Unavailable(format!(
            "Linux executable snapshot cannot be created: {error}"
        ))),
    }
}

fn hash_file(path: &Path) -> Result<String, AdapterError> {
    let file = open_nonblocking_read(path)?;
    let metadata = file.metadata().map_err(|error| {
        AdapterError::Unavailable(format!("cannot inspect Linux executable bytes: {error}"))
    })?;
    if !metadata.is_file() {
        return Err(AdapterError::Invalid(
            "Linux executable is not a regular file".to_owned(),
        ));
    }
    if metadata.len() > MAX_HASH_BYTES {
        return Err(AdapterError::Invalid(
            "Linux executable exceeds the hash size bound".to_owned(),
        ));
    }
    hash_reader(file)
}

fn open_nonblocking_read(path: &Path) -> Result<File, AdapterError> {
    let flags = rustix::fs::OFlags::NONBLOCK
        .bits()
        .try_into()
        .map_err(|_| AdapterError::Invalid("Linux nonblocking flag is out of range".to_owned()))?;
    OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|error| {
            AdapterError::Unavailable(format!("cannot open Linux executable bytes: {error}"))
        })
}

fn hash_reader(reader: impl Read) -> Result<String, AdapterError> {
    hash_stream(reader, None)
}

fn hash_and_copy(reader: impl Read, writer: &mut impl Write) -> Result<String, AdapterError> {
    hash_stream(reader, Some(writer))
}

fn hash_stream(
    mut reader: impl Read,
    mut writer: Option<&mut dyn Write>,
) -> Result<String, AdapterError> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total_read = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| AdapterError::Io(format!("cannot hash Linux executable: {error}")))?;
        if read == 0 {
            break;
        }
        total_read = total_read
            .checked_add(u64::try_from(read).map_err(|_| {
                AdapterError::Invalid("Linux executable read size exceeds bounds".to_owned())
            })?)
            .ok_or_else(|| {
                AdapterError::Invalid("Linux executable exceeds the hash size bound".to_owned())
            })?;
        if total_read > MAX_HASH_BYTES {
            return Err(AdapterError::Invalid(
                "Linux executable exceeds the hash size bound".to_owned(),
            ));
        }
        if let Some(writer) = writer.as_deref_mut() {
            writer.write_all(&buffer[..read]).map_err(|error| {
                AdapterError::Io(format!("cannot create Linux executable snapshot: {error}"))
            })?;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn protocol_io(error: &io::Error) -> AdapterError {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        AdapterError::Unavailable("Linux helper pipe closed before the next frame".to_owned())
    } else {
        AdapterError::Io(format!("Linux helper protocol I/O failed: {error}"))
    }
}

fn component_code(component: ComponentKind) -> u8 {
    match component {
        ComponentKind::Gateway => 1,
        ComponentKind::Harness => 2,
        ComponentKind::HostBroker => 3,
        ComponentKind::Synthetic => 4,
    }
}

fn component_from_code(code: u8) -> Result<ComponentKind, AdapterError> {
    match code {
        1 => Ok(ComponentKind::Gateway),
        2 => Ok(ComponentKind::Harness),
        3 => Ok(ComponentKind::HostBroker),
        4 => Ok(ComponentKind::Synthetic),
        _ => Err(AdapterError::Unsupported(
            "Linux helper component role is unsupported".to_owned(),
        )),
    }
}

fn put_count(bytes: &mut Vec<u8>, count: usize, maximum: usize) -> Result<(), AdapterError> {
    if count > maximum {
        return Err(AdapterError::Invalid(
            "Linux helper collection exceeds bounds".to_owned(),
        ));
    }
    bytes.extend_from_slice(
        &u16::try_from(count)
            .map_err(|_| {
                AdapterError::Invalid("Linux helper collection length overflow".to_owned())
            })?
            .to_le_bytes(),
    );
    Ok(())
}

fn read_count(reader: &mut impl Read, maximum: usize) -> Result<usize, AdapterError> {
    let mut bytes = [0_u8; 2];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| protocol_io(&error))?;
    let count = usize::from(u16::from_le_bytes(bytes));
    if count > maximum {
        return Err(AdapterError::Invalid(
            "Linux helper collection exceeds bounds".to_owned(),
        ));
    }
    Ok(count)
}

fn put_path(bytes: &mut Vec<u8>, path: &Path) -> Result<(), AdapterError> {
    let value = path.to_str().ok_or_else(|| {
        AdapterError::Invalid("Linux helper paths must be valid UTF-8".to_owned())
    })?;
    put_string(bytes, value)
}

fn read_path(reader: &mut impl Read) -> Result<PathBuf, AdapterError> {
    Ok(PathBuf::from(read_string(reader, MAX_FIELD_BYTES)?))
}

fn put_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), AdapterError> {
    if value.is_empty() || value.len() > MAX_FIELD_BYTES || value.contains('\0') {
        return Err(AdapterError::Invalid(
            "Linux helper string is outside bounds".to_owned(),
        ));
    }
    bytes.extend_from_slice(
        &u16::try_from(value.len())
            .map_err(|_| AdapterError::Invalid("Linux helper string length overflow".to_owned()))?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_string_io(writer: &mut impl Write, value: &str) -> io::Result<()> {
    let length = u16::try_from(value.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "string is too long"))?;
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(value.as_bytes())
}

fn read_string(reader: &mut impl Read, maximum: usize) -> Result<String, AdapterError> {
    let mut length = [0_u8; 2];
    reader
        .read_exact(&mut length)
        .map_err(|error| protocol_io(&error))?;
    let length = usize::from(u16::from_le_bytes(length));
    if length == 0 || length > maximum {
        return Err(AdapterError::Invalid(
            "Linux helper string is outside bounds".to_owned(),
        ));
    }
    let mut bytes = vec![0_u8; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| protocol_io(&error))?;
    String::from_utf8(bytes)
        .map_err(|_| AdapterError::Invalid("Linux helper string is not UTF-8".to_owned()))
}

fn read_byte(reader: &mut impl Read) -> Result<u8, AdapterError> {
    let mut byte = [0_u8; 1];
    reader
        .read_exact(&mut byte)
        .map_err(|error| protocol_io(&error))?;
    Ok(byte[0])
}

fn read_u64(reader: &mut impl Read) -> Result<u64, AdapterError> {
    let mut bytes = [0_u8; 8];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| protocol_io(&error))?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_u32(reader: &mut impl Read) -> Result<u32, AdapterError> {
    let mut bytes = [0_u8; 4];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| protocol_io(&error))?;
    Ok(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Duration;
    use tempfile::tempdir;

    fn specification() -> LaunchSpec {
        LaunchSpec {
            deployment_id: "deployment".to_owned(),
            instance_id: "instance".to_owned(),
            component: ComponentKind::Synthetic,
            incarnation: "incarnation".to_owned(),
            launch_nonce: "nonce-1".to_owned(),
            executable: PathBuf::from("/bin/true"),
            executable_sha256: "a".repeat(64),
            arguments: vec!["--fixture".to_owned()],
            working_directory: None,
            environment: vec![("PATH".to_owned(), "/usr/bin".to_owned())],
            session: SessionSelector::Explicit(0),
            graceful_timeout: Duration::from_secs(1),
            force_timeout: Duration::from_secs(2),
        }
    }

    #[test]
    fn frame_round_trip_preserves_exact_spec_and_cgroup() -> Result<(), Box<dyn std::error::Error>>
    {
        let specification = specification();
        let path = PathBuf::from("/sys/fs/cgroup/ascension-test");
        let frame = encode_frame(&specification, &path)?;
        let payload_length = u32::from_le_bytes(frame[..4].try_into()?);
        assert_eq!(usize::try_from(payload_length)?, frame.len() - 4);
        let request = decode_frame(&frame[4..])?;
        assert_eq!(request.specification, specification);
        assert_eq!(request.cgroup_path, path);
        Ok(())
    }

    #[test]
    fn wrong_nonce_go_is_rejected_before_target_spawn() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(GO_MAGIC);
        assert!(put_string_io(&mut bytes, "wrong").is_ok());
        let mut cursor = Cursor::new(bytes);
        let result = read_go(&mut cursor);
        assert_eq!(result.as_deref(), Ok("wrong"));
        assert_ne!(result.as_deref(), Ok("nonce-1"));
    }

    #[test]
    fn eof_before_go_is_a_hard_failure() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        assert!(matches!(
            read_go(&mut cursor),
            Err(AdapterError::Unavailable(_))
        ));
    }

    #[test]
    fn unsupported_component_cannot_be_authorized() {
        let mut specification = specification();
        specification.component = ComponentKind::HostBroker;
        let authorization = LinuxHelperAuthorization {
            specification,
            cgroup_path: PathBuf::from("/sys/fs/cgroup/ascension-test"),
            allowlisted_executables: BTreeMap::new(),
        };
        assert!(matches!(
            authorization.validate(),
            Err(AdapterError::Unsupported(_))
        ));
    }

    #[test]
    fn durable_authorization_mismatch_is_rejected_before_hashing() {
        let specification = specification();
        let request = LinuxHelperRequest {
            specification: specification.clone(),
            cgroup_path: PathBuf::from("/sys/fs/cgroup/ascension-test"),
        };
        let mut authorized = specification;
        authorized.launch_nonce = "different-nonce".to_owned();
        let mut allowlist = BTreeMap::new();
        allowlist.insert(ComponentKind::Synthetic, PathBuf::from("/bin/true"));
        let authorization = LinuxHelperAuthorization {
            specification: authorized,
            cgroup_path: request.cgroup_path.clone(),
            allowlisted_executables: allowlist,
        };
        assert!(matches!(
            authorize_request(&request, &authorization),
            Err(AdapterError::IdentityMismatch(_))
        ));
    }

    #[test]
    fn timeout_is_bounded() {
        let result = TrustedLinuxLauncher::new("/bin/true")
            .and_then(|launcher| launcher.with_timeout(Duration::from_secs(16)));
        assert!(result.is_err());
    }

    #[test]
    fn bootstrap_reads_the_opened_config_inode_after_path_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir()?;
        let path = directory.path().join("watchdog.json");
        fs::write(&path, b"trusted-config")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let bootstrap = LinuxHelperBootstrap::new(&path)?;

        fs::rename(&path, directory.path().join("watchdog.json.original"))?;
        fs::write(&path, b"attacker-config")?;

        let mut bytes = String::new();
        bootstrap
            .protected_config_file()?
            .read_to_string(&mut bytes)?;
        assert_eq!(bytes, "trusted-config");
        Ok(())
    }

    #[test]
    fn bootstrap_rejects_group_readable_or_foreign_shape_config()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir()?;
        let path = directory.path().join("watchdog.json");
        fs::write(&path, b"config")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
        assert!(matches!(
            LinuxHelperBootstrap::new(&path),
            Err(AdapterError::Invalid(_))
        ));
        Ok(())
    }

    #[test]
    fn parent_bootstrap_handles_remain_cloexec_and_invisible_to_target()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir()?;
        let config_path = directory.path().join("watchdog.json");
        fs::write(&config_path, b"trusted-config")?;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))?;
        let root_path = directory.path().join("cgroup");
        fs::create_dir(&root_path)?;
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700))?;
        for control in ["cgroup.procs", "cgroup.events", "cgroup.kill"] {
            fs::write(root_path.join(control), b"")?;
        }

        let bootstrap =
            LinuxHelperBootstrap::new(&config_path)?.with_delegated_cgroup_root(&root_path)?;
        let parent = bootstrap.parent_descriptors()?;
        assert!(rustix::io::fcntl_getfd(&parent.config)?.contains(rustix::io::FdFlags::CLOEXEC));
        assert!(rustix::io::fcntl_getfd(&parent.root)?.contains(rustix::io::FdFlags::CLOEXEC));
        assert!(rustix::io::fcntl_getfd(&parent.ready)?.contains(rustix::io::FdFlags::CLOEXEC));

        let status = Command::new("/bin/sh")
            .args([
                "-c",
                "test ! -e /proc/self/fd/$1 && test ! -e /proc/self/fd/$2 && test ! -e /proc/self/fd/$3",
                "fd-check",
                &parent.config_fd.to_string(),
                &parent.root_fd.to_string(),
                &parent.ready_fd.to_string(),
            ])
            .status()?;
        assert!(status.success(), "target observed a parent bootstrap fd");
        Ok(())
    }

    #[test]
    fn parent_bootstrap_drop_closes_keepalive_descriptors() -> Result<(), Box<dyn std::error::Error>>
    {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir()?;
        let config_path = directory.path().join("watchdog.json");
        fs::write(&config_path, b"trusted-config")?;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))?;
        let root_path = directory.path().join("cgroup");
        fs::create_dir(&root_path)?;
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700))?;
        for control in ["cgroup.procs", "cgroup.events", "cgroup.kill"] {
            fs::write(root_path.join(control), b"")?;
        }

        let bootstrap =
            LinuxHelperBootstrap::new(&config_path)?.with_delegated_cgroup_root(&root_path)?;
        let (config_fd, root_fd, ready_fd, config_target, root_target, ready_target) = {
            let parent = bootstrap.parent_descriptors()?;
            assert!(Path::new(&format!("/proc/self/fd/{}", parent.config_fd)).exists());
            assert!(Path::new(&format!("/proc/self/fd/{}", parent.root_fd)).exists());
            assert!(Path::new(&format!("/proc/self/fd/{}", parent.ready_fd)).exists());
            (
                parent.config_fd,
                parent.root_fd,
                parent.ready_fd,
                fs::read_link(format!("/proc/self/fd/{}", parent.config_fd))?,
                fs::read_link(format!("/proc/self/fd/{}", parent.root_fd))?,
                fs::read_link(format!("/proc/self/fd/{}", parent.ready_fd))?,
            )
        };
        assert_ne!(
            fs::read_link(format!("/proc/self/fd/{config_fd}")).ok(),
            Some(config_target)
        );
        assert_ne!(
            fs::read_link(format!("/proc/self/fd/{root_fd}")).ok(),
            Some(root_target)
        );
        assert_ne!(
            fs::read_link(format!("/proc/self/fd/{ready_fd}")).ok(),
            Some(ready_target)
        );
        Ok(())
    }

    #[test]
    fn delayed_helper_ready_ack_keeps_parent_descriptor_alive()
    -> Result<(), Box<dyn std::error::Error>> {
        let ready = File::from(memfd_create("ascension-ready-test", MemfdFlags::CLOEXEC)?);
        let ready_fd = ready.as_raw_fd();
        let mut parent = ParentBootstrap {
            config: File::open("/dev/null")?,
            config_fd: 0,
            root: File::open("/dev/null")?,
            root_fd: 1,
            ready,
            ready_fd,
        };
        let mut delayed_helper = Command::new("/bin/sh")
            .args([
                "-c",
                "sleep 0.05; printf 'ASC-RDY1\\001\\000x' > /proc/$PPID/fd/$1",
                "delayed-helper",
                &ready_fd.to_string(),
            ])
            .spawn()?;
        let started = Instant::now();
        parent.wait_for_ready("x", Duration::from_secs(1))?;
        assert!(started.elapsed() >= Duration::from_millis(30));
        assert!(delayed_helper.wait()?.success());
        Ok(())
    }

    #[test]
    fn readiness_ack_rejects_trailing_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let mut ready = File::from(memfd_create("ascension-ready-extra", MemfdFlags::CLOEXEC)?);
        ready.write_all(b"ASC-RDY1\x01\x00xextra")?;
        let mut parent = ParentBootstrap {
            config: File::open("/dev/null")?,
            config_fd: 0,
            root: File::open("/dev/null")?,
            root_fd: 1,
            ready_fd: ready.as_raw_fd(),
            ready,
        };
        assert!(matches!(
            parent.wait_for_ready("x", Duration::from_millis(10)),
            Err(AdapterError::IdentityMismatch(_))
        ));
        Ok(())
    }

    #[test]
    fn descriptor_bound_exec_is_not_redirected_by_path_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("approved-target");
        fs::copy("/bin/true", &path)?;
        let digest = hash_file(&path)?;
        let (file, fd_path) = open_verified_executable(&path, &digest)?;

        let moved = directory.path().join("approved-target.original");
        fs::rename(&path, &moved)?;
        fs::copy("/bin/false", &path)?;
        let status = Command::new(&fd_path).status()?;

        assert!(
            status.success(),
            "descriptor exec followed the replaced path"
        );
        drop(file);
        Ok(())
    }

    #[test]
    fn sealed_snapshot_is_not_changed_by_in_place_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("approved-target");
        fs::copy("/bin/true", &path)?;
        let digest = hash_file(&path)?;
        let (file, fd_path) = open_verified_executable(&path, &digest)?;

        let replacement = fs::read("/bin/false")?;
        fs::write(&path, replacement)?;
        let status = Command::new(&fd_path).status()?;

        assert!(
            status.success(),
            "sealed snapshot followed in-place mutation"
        );
        drop(file);
        Ok(())
    }

    #[test]
    fn special_file_is_rejected_before_reading() {
        let result = open_verified_executable(Path::new("/dev/null"), &"0".repeat(64));
        assert!(matches!(result, Err(AdapterError::Invalid(_))));
    }

    #[test]
    fn descriptor_bound_exec_rejects_changed_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("approved-target");
        fs::copy("/bin/true", &path)?;
        let result = open_verified_executable(&path, &"0".repeat(64));
        assert!(matches!(result, Err(AdapterError::IdentityMismatch(_))));
        Ok(())
    }

    #[test]
    fn release_barrier_precedes_durable_authorization() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let request = LinuxHelperRequest {
            specification: specification(),
            cgroup_path: PathBuf::from("/sys/fs/cgroup/ascension-test"),
        };
        let stopped = Arc::new(AtomicBool::new(false));
        let producer_stop = Arc::clone(&stopped);
        let (sender, receiver) = mpsc::channel();
        let nonce = request.specification.launch_nonce.clone();
        let producer = thread::spawn(move || {
            // Models durable stop becoming visible before the parent's GO.
            producer_stop.store(true, Ordering::Release);
            sender.send(Ok(nonce)).unwrap();
        });
        let result = authorize_after_release(&request, &receiver, Instant::now(), |_| {
            assert!(stopped.load(Ordering::Acquire));
            Err(AdapterError::Unavailable(
                "durable stop denies launch".to_owned(),
            ))
        });
        producer.join().unwrap();
        assert!(
            matches!(result, Err(AdapterError::Unavailable(message)) if message == "durable stop denies launch")
        );
    }

    #[test]
    fn wrong_release_nonce_never_queries_authority() {
        let request = LinuxHelperRequest {
            specification: specification(),
            cgroup_path: PathBuf::from("/sys/fs/cgroup/ascension-test"),
        };
        let (sender, receiver) = mpsc::channel();
        sender.send(Ok("stale-nonce".to_owned())).unwrap();
        let mut queried = false;
        let result = authorize_after_release(&request, &receiver, Instant::now(), |_| {
            queried = true;
            Err(AdapterError::Unavailable(
                "must not reach authority".to_owned(),
            ))
        });
        assert!(matches!(result, Err(AdapterError::IdentityMismatch(_))));
        assert!(!queried);
    }
}
