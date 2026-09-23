//! Protected helper bootstrap and inherited-descriptor validation.

use super::DELEGATED_CGROUP_ROOT_ARGUMENT;
use super::GATEWAY_HEALTH_PIPE_ARGUMENT;
use super::HELPER_ARGUMENT;
use super::MIN_INHERITED_FD;
use super::O_CLOEXEC;
use super::O_DIRECTORY;
use super::O_NOFOLLOW;
use super::O_NONBLOCK;
use super::PARENT_BOOTSTRAP_PID_ARGUMENT;
use super::PROTECTED_CONFIG_ARGUMENT;
use super::WORKER_BOOT_ID_ARGUMENT;
use super::WORKER_FRAME_SHA256_ARGUMENT;
use super::WORKER_PIPE_ARGUMENT;
use super::framed_protocol::open_parent_gateway_health_descriptor;
use super::framed_protocol::open_parent_worker_descriptor;
use super::framed_protocol::validate_worker_boot_metadata;
use super::parent_launcher::HelperReadyChannel;
use super::parent_launcher::ParentBootstrap;
use super::parent_launcher::open_parent_ready_descriptor;
use crate::platform::contract::AdapterError;
use crate::platform::gateway_health::GatewayHealthBootstrap;
use crate::worker_bootstrap::ExpectedPeer;
use crate::worker_bootstrap::WorkerBootstrapLaunch;
use rustix::fs::MemfdFlags;
use rustix::fs::memfd_create;
use rustix::pipe::PipeFlags;
use rustix::pipe::pipe_with;
use std::env;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProtectedFileIdentity {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) uid: u32,
    pub(super) mode: u32,
    pub(super) size: u64,
}

/// Immutable bootstrap context supplied separately from the untrusted launch
/// frame.  The real watchdog binds an already-open configuration file and
/// delegated cgroup root before spawning the helper.
#[derive(Clone, Debug)]
pub struct LinuxHelperBootstrap {
    pub(super) protected_config_path: PathBuf,
    pub(super) protected_config: Arc<File>,
    pub(super) protected_config_identity: ProtectedFileIdentity,
    pub(super) delegated_cgroup_root_path: Option<PathBuf>,
    pub(super) delegated_cgroup_root: Option<Arc<File>>,
    pub(super) delegated_cgroup_root_identity: Option<ProtectedFileIdentity>,
    pub(super) worker_boot_id: Option<String>,
    pub(super) worker_frame_sha256: Option<String>,
    pub(super) worker_reader: Option<Arc<File>>,
    pub(super) gateway_health_reader: Option<Arc<File>>,
}

impl PartialEq for LinuxHelperBootstrap {
    fn eq(&self, other: &Self) -> bool {
        self.protected_config_path == other.protected_config_path
            && self.protected_config_identity == other.protected_config_identity
            && self.delegated_cgroup_root_path == other.delegated_cgroup_root_path
            && self.delegated_cgroup_root_identity == other.delegated_cgroup_root_identity
            && self.worker_boot_id == other.worker_boot_id
            && self.worker_frame_sha256 == other.worker_frame_sha256
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
            worker_boot_id: None,
            worker_frame_sha256: None,
            worker_reader: None,
            gateway_health_reader: None,
        })
    }

    pub(super) fn from_parent_fds(
        parent_pid: u32,
        config_fd: RawFd,
        root_fd: RawFd,
        ready_fd: RawFd,
        worker_fd: Option<RawFd>,
        worker_boot_id: Option<String>,
        worker_frame_sha256: Option<String>,
        gateway_health_fd: Option<RawFd>,
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
            || worker_fd.is_some_and(|fd| {
                fd < MIN_INHERITED_FD || fd == config_fd || fd == root_fd || fd == ready_fd
            })
            || gateway_health_fd.is_some_and(|fd| {
                fd < MIN_INHERITED_FD
                    || fd == config_fd
                    || fd == root_fd
                    || fd == ready_fd
                    || worker_fd.is_some_and(|worker_fd| fd == worker_fd)
            })
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
        let worker_reader = match worker_fd {
            None if worker_boot_id.is_none() && worker_frame_sha256.is_none() => None,
            Some(fd) if worker_boot_id.is_some() && worker_frame_sha256.is_some() => {
                let boot_id = worker_boot_id.as_deref().ok_or_else(|| {
                    AdapterError::Invalid("Linux worker boot metadata is missing".to_owned())
                })?;
                let frame_sha256 = worker_frame_sha256.as_deref().ok_or_else(|| {
                    AdapterError::Invalid("Linux worker frame metadata is missing".to_owned())
                })?;
                validate_worker_boot_metadata(boot_id, frame_sha256)?;
                Some(Arc::new(open_parent_worker_descriptor(parent_pid, fd)?))
            }
            _ => {
                return Err(AdapterError::Invalid(
                    "Linux worker pipe metadata must be supplied as one complete set".to_owned(),
                ));
            }
        };
        let gateway_health_reader = gateway_health_fd
            .map(|fd| open_parent_gateway_health_descriptor(parent_pid, fd))
            .transpose()?;
        if gateway_health_reader.is_some() && worker_reader.is_some() {
            return Err(AdapterError::Invalid(
                "Linux worker and Gateway health pipes cannot be combined".to_owned(),
            ));
        }
        Ok((
            Self {
                protected_config_path: config_path,
                protected_config: Arc::new(config),
                protected_config_identity: config_identity,
                delegated_cgroup_root_path: Some(root_path),
                delegated_cgroup_root: Some(Arc::new(root)),
                delegated_cgroup_root_identity: Some(root_identity),
                worker_boot_id,
                worker_frame_sha256,
                worker_reader,
                gateway_health_reader: gateway_health_reader.map(Arc::new),
            },
            HelperReadyChannel { file: ready },
        ))
    }

    /// Return the canonical path that was validated for helper bootstrap.
    #[must_use]
    pub fn protected_config_path(&self) -> &Path {
        &self.protected_config_path
    }

    /// Return the worker watchdog boot UUID supplied in the helper metadata,
    /// when this invocation carries a dedicated worker bootstrap pipe.
    #[must_use]
    pub fn worker_boot_id(&self) -> Option<&str> {
        self.worker_boot_id.as_deref()
    }

    /// Return the exact SHA-256 digest of the worker bootstrap frame supplied
    /// in the helper metadata, when present.
    #[must_use]
    pub fn worker_frame_sha256(&self) -> Option<&str> {
        self.worker_frame_sha256.as_deref()
    }

    /// Alias naming the frame represented by [`Self::worker_frame_sha256`].
    #[must_use]
    pub fn worker_bootstrap_frame_sha256(&self) -> Option<&str> {
        self.worker_frame_sha256()
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

    pub(super) fn worker_pipe_file(&self) -> Result<Option<File>, AdapterError> {
        self.worker_reader
            .as_ref()
            .map(|file| {
                file.try_clone().map_err(|error| {
                    AdapterError::Unavailable(format!(
                        "Linux worker pipe descriptor cannot be cloned: {error}"
                    ))
                })
            })
            .transpose()
    }

    pub(super) fn gateway_health_pipe_file(&self) -> Result<Option<File>, AdapterError> {
        self.gateway_health_reader
            .as_ref()
            .map(|file| {
                file.try_clone().map_err(|error| {
                    AdapterError::Unavailable(format!(
                        "Linux Gateway health pipe descriptor cannot be cloned: {error}"
                    ))
                })
            })
            .transpose()
    }

    pub(super) fn parent_descriptors(
        &self,
        worker: Option<&WorkerBootstrapLaunch>,
        gateway_health: Option<&GatewayHealthBootstrap>,
    ) -> Result<ParentBootstrap, AdapterError> {
        if worker.is_some() && gateway_health.is_some() {
            return Err(AdapterError::Invalid(
                "Linux worker and Gateway health pipes cannot be combined".to_owned(),
            ));
        }
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
        let (worker_reader, worker_writer, worker_reader_fd) = if let Some(worker) = worker {
            if !matches!(worker.bootstrap().expected_peer, ExpectedPeer::Linux(_)) {
                return Err(AdapterError::Unsupported(
                    "Linux worker bootstrap requires a Linux expected peer".to_owned(),
                ));
            }
            let (reader, writer) =
                pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).map_err(|error| {
                    AdapterError::Unavailable(format!(
                        "Linux worker bootstrap pipe cannot be created: {error}"
                    ))
                })?;
            let reader = File::from(reader);
            let writer = File::from(writer);
            let reader_fd = reader.as_raw_fd();
            if invalid_parent_pipe_fd(
                reader_fd,
                writer.as_raw_fd(),
                config_fd,
                root_fd,
                ready_fd,
                None,
            ) {
                return Err(AdapterError::Unavailable(
                    "Linux worker bootstrap descriptor is reserved for stdio".to_owned(),
                ));
            }
            (Some(reader), Some(writer), Some(reader_fd))
        } else {
            (None, None, None)
        };
        let (gateway_health_reader, gateway_health_writer, gateway_health_reader_fd) =
            if gateway_health.is_some() {
                let (reader, writer) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)
                    .map_err(|error| {
                        AdapterError::Unavailable(format!(
                            "Linux Gateway health bootstrap pipe cannot be created: {error}"
                        ))
                    })?;
                let reader = File::from(reader);
                let writer = File::from(writer);
                let reader_fd = reader.as_raw_fd();
                if invalid_parent_pipe_fd(
                    reader_fd,
                    writer.as_raw_fd(),
                    config_fd,
                    root_fd,
                    ready_fd,
                    worker_reader_fd,
                ) {
                    return Err(AdapterError::Unavailable(
                        "Linux Gateway health descriptor is reserved for stdio".to_owned(),
                    ));
                }
                (Some(reader), Some(writer), Some(reader_fd))
            } else {
                (None, None, None)
            };
        Ok(ParentBootstrap {
            config,
            config_fd,
            root,
            root_fd,
            ready,
            ready_fd,
            worker_reader,
            worker_reader_fd,
            worker_writer,
            gateway_health_reader,
            gateway_health_reader_fd,
            gateway_health_writer,
        })
    }
}

pub(super) fn invalid_parent_pipe_fd(
    reader_fd: RawFd,
    writer_fd: RawFd,
    config_fd: RawFd,
    root_fd: RawFd,
    ready_fd: RawFd,
    other_reader_fd: Option<RawFd>,
) -> bool {
    reader_fd < MIN_INHERITED_FD
        || writer_fd < MIN_INHERITED_FD
        || reader_fd == writer_fd
        || [config_fd, root_fd, ready_fd]
            .into_iter()
            .any(|fd| fd == reader_fd || fd == writer_fd)
        || other_reader_fd.is_some_and(|fd| fd == reader_fd || fd == writer_fd)
}

pub(super) fn protected_file_identity(metadata: &std::fs::Metadata) -> ProtectedFileIdentity {
    ProtectedFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
        size: metadata.len(),
    }
}

pub(super) fn validate_protected_config_handle(
    file: &File,
) -> Result<ProtectedFileIdentity, AdapterError> {
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

pub(super) fn open_protected_config_path(
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

pub(super) fn open_delegated_cgroup_root(
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

pub(super) fn open_regular_path_without_links(
    path: &Path,
    label: &str,
) -> Result<File, AdapterError> {
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

pub(super) fn open_directory_path_without_links(
    path: &Path,
    label: &str,
) -> Result<File, AdapterError> {
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

pub(super) fn checked_path_components(
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

pub(super) fn proc_fd_child(fd: RawFd, component: &std::ffi::OsStr) -> PathBuf {
    let mut path = PathBuf::from(format!("/proc/self/fd/{fd}"));
    path.push(component);
    path
}

pub(super) fn canonical_fd_path(fd: RawFd) -> Result<PathBuf, AdapterError> {
    canonical_descriptor_path(format!("/proc/self/fd/{fd}"))
}

pub(super) fn canonical_parent_fd_path(
    parent_pid: u32,
    fd: RawFd,
) -> Result<PathBuf, AdapterError> {
    canonical_descriptor_path(parent_fd_path(parent_pid, fd))
}

pub(super) fn canonical_descriptor_path(path: impl AsRef<Path>) -> Result<PathBuf, AdapterError> {
    fs::canonicalize(path).map_err(|error| {
        AdapterError::Unavailable(format!(
            "Linux bootstrap descriptor target is unavailable: {error}"
        ))
    })
}

pub(super) fn parent_fd_path(parent_pid: u32, fd: RawFd) -> PathBuf {
    PathBuf::from(format!("/proc/{parent_pid}/fd/{fd}"))
}

pub(super) fn parent_fd_child(parent_pid: u32, fd: RawFd, component: &std::ffi::OsStr) -> PathBuf {
    let mut path = parent_fd_path(parent_pid, fd);
    path.push(component);
    path
}

pub(super) fn open_parent_descriptor(
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

/// Return true only for the exact hidden helper invocation.
#[must_use]
pub fn helper_invocation_requested() -> bool {
    let mut arguments = env::args();
    let _ = arguments.next();
    arguments
        .next()
        .is_some_and(|value| value == HELPER_ARGUMENT)
}

pub(super) fn parse_helper_bootstrap()
-> Result<Option<(LinuxHelperBootstrap, HelperReadyChannel)>, AdapterError> {
    parse_helper_bootstrap_arguments(env::args())
}

pub(super) fn parse_helper_bootstrap_arguments(
    mut arguments: impl Iterator<Item = String>,
) -> Result<Option<(LinuxHelperBootstrap, HelperReadyChannel)>, AdapterError> {
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
    let (worker_fd, worker_boot_id, worker_frame_sha256, gateway_health_fd) =
        if let Some(worker_argument) = arguments.next() {
            if worker_argument == GATEWAY_HEALTH_PIPE_ARGUMENT {
                let gateway_health_fd = arguments
                    .next()
                    .ok_or_else(|| {
                        AdapterError::Invalid(
                            "Linux Gateway health pipe descriptor is missing".to_owned(),
                        )
                    })?
                    .parse::<RawFd>()
                    .map_err(|_| {
                        AdapterError::Invalid(
                            "Linux Gateway health pipe descriptor is invalid".to_owned(),
                        )
                    })?;
                if arguments.next().is_some() {
                    return Err(AdapterError::Invalid(
                        "Linux helper invocation has unexpected arguments".to_owned(),
                    ));
                }
                (None, None, None, Some(gateway_health_fd))
            } else if worker_argument != WORKER_PIPE_ARGUMENT {
                return Err(AdapterError::Invalid(
                    "Linux helper invocation has an invalid worker pipe argument".to_owned(),
                ));
            } else {
                let worker_fd = arguments
                    .next()
                    .ok_or_else(|| {
                        AdapterError::Invalid("Linux worker pipe descriptor is missing".to_owned())
                    })?
                    .parse::<RawFd>()
                    .map_err(|_| {
                        AdapterError::Invalid("Linux worker pipe descriptor is invalid".to_owned())
                    })?;
                let boot_argument = arguments.next().ok_or_else(|| {
                    AdapterError::Invalid(
                        "Linux worker boot metadata argument is missing".to_owned(),
                    )
                })?;
                if boot_argument != WORKER_BOOT_ID_ARGUMENT {
                    return Err(AdapterError::Invalid(
                        "Linux helper invocation has an invalid worker boot argument".to_owned(),
                    ));
                }
                let worker_boot_id = arguments.next().ok_or_else(|| {
                    AdapterError::Invalid("Linux worker boot metadata is missing".to_owned())
                })?;
                let digest_argument = arguments.next().ok_or_else(|| {
                    AdapterError::Invalid(
                        "Linux worker frame digest argument is missing".to_owned(),
                    )
                })?;
                if digest_argument != WORKER_FRAME_SHA256_ARGUMENT {
                    return Err(AdapterError::Invalid(
                        "Linux helper invocation has an invalid worker frame argument".to_owned(),
                    ));
                }
                let worker_frame_sha256 = arguments.next().ok_or_else(|| {
                    AdapterError::Invalid("Linux worker frame digest is missing".to_owned())
                })?;
                if arguments.next().is_some() {
                    return Err(AdapterError::Invalid(
                        "Linux helper invocation has unexpected arguments".to_owned(),
                    ));
                }
                (
                    Some(worker_fd),
                    Some(worker_boot_id),
                    Some(worker_frame_sha256),
                    None,
                )
            }
        } else {
            (None, None, None, None)
        };
    LinuxHelperBootstrap::from_parent_fds(
        parent_pid,
        config_fd,
        root_fd,
        ready_fd,
        worker_fd,
        worker_boot_id,
        worker_frame_sha256,
        gateway_health_fd,
    )
    .map(Some)
}
