//! Authentication helpers for the owner-local worker handoff transport.
//!
//! The worker credential is deliberately kept out of protocol frames and
//! durable records.  It is presented only in the transport authentication
//! prelude, after the peer process has been checked by the operating system.

use crate::config::validate_digest;
use crate::error::{Result, WatchdogError};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{ErrorKind, Read};
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::path::Component;
use std::path::{Path, PathBuf};
use std::time::Instant;

const MAX_CREDENTIAL_BYTES: usize = 4 * 1024;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_PEER_IMAGE_BYTES: usize = 256 * 1024 * 1024;

/// Immutable identity of the supervised worker process.
///
/// The path and digest are configuration, never request-controlled values.
/// On Linux the connected peer's UID/GID, PID, process start token, image
/// path, and image digest are checked before a protocol frame is sent.  The
/// Windows named-pipe adapter performs the equivalent held-process identity
/// check for the configured image.
#[derive(Clone, Eq, PartialEq)]
pub struct WorkerPeerIdentity {
    pub(crate) executable: PathBuf,
    pub(crate) executable_sha256: String,
    pub(crate) uid: Option<u32>,
    pub(crate) gid: Option<u32>,
    /// PID captured from the supervisor's live process identity.  A PID is
    /// not sufficient by itself; it is always paired with `creation_token`.
    pub(crate) pid: u32,
    /// OS process-start token (Linux `/proc/<pid>/stat` start time or the
    /// Windows creation timestamp rendered as decimal text).
    pub(crate) creation_token: String,
    #[cfg(target_os = "linux")]
    configured_image_identity: LinuxFileIdentity,
}

impl std::fmt::Debug for WorkerPeerIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("WorkerPeerIdentity");
        debug
            .field("executable", &"<protected-reference>")
            .field("executable_sha256", &self.executable_sha256)
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("pid", &self.pid)
            .field("creation_token", &self.creation_token);
        #[cfg(target_os = "linux")]
        {
            debug.field("configured_image_identity", &self.configured_image_identity);
        }
        debug.finish()
    }
}

impl WorkerPeerIdentity {
    /// Construct an image-bound peer identity.
    pub fn new(
        executable: impl Into<PathBuf>,
        executable_sha256: impl Into<String>,
        pid: u32,
        creation_token: impl Into<String>,
    ) -> Result<Self> {
        let identity = Self {
            executable: executable.into(),
            executable_sha256: executable_sha256.into(),
            uid: None,
            gid: None,
            pid,
            creation_token: creation_token.into(),
            #[cfg(target_os = "linux")]
            configured_image_identity: LinuxFileIdentity {
                device: 0,
                inode: 0,
            },
        };
        #[cfg(target_os = "linux")]
        let mut identity = identity.validate()?;
        #[cfg(not(target_os = "linux"))]
        let identity = identity.validate()?;
        #[cfg(target_os = "linux")]
        {
            identity.configured_image_identity = prime_peer_digest(&identity)?;
        }
        Ok(identity)
    }

    /// Construct the peer binding directly from the supervisor's exact live
    /// process identity.  A missing platform creation fingerprint is a hard
    /// error: image-only or PID-only matching could authorize a second
    /// same-binary process and disclose the worker credential to it.
    pub fn from_process_identity(identity: &crate::ProcessIdentity) -> Result<Self> {
        let creation_token = identity.creation_fingerprint.as_deref().ok_or_else(|| {
            WatchdogError::IdentityMismatch(
                "worker peer process identity has no creation fingerprint".to_owned(),
            )
        })?;
        Self::new(
            identity.executable.clone(),
            identity.executable_digest.clone(),
            identity.pid,
            creation_token.to_owned(),
        )
    }

    /// Require an explicit peer UID/GID in addition to the executable proof.
    /// This is useful for a dedicated service account.  The values are
    /// captured in configuration and cannot be supplied by a worker request.
    pub fn with_peer_credentials(mut self, uid: u32, gid: u32) -> Result<Self> {
        self.uid = Some(uid);
        self.gid = Some(gid);
        self.validate()
    }

    /// Configured executable path, exposed for platform adapter wiring only.
    #[must_use]
    pub(crate) fn executable(&self) -> &Path {
        &self.executable
    }

    /// Exact supervised process PID expected at the local endpoint.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Exact supervised process-start token expected at the local endpoint.
    #[must_use]
    pub fn creation_token(&self) -> &str {
        &self.creation_token
    }

    fn validate(self) -> Result<Self> {
        if !self.executable.is_absolute()
            || self.executable.as_os_str().is_empty()
            || self.executable.as_os_str().to_string_lossy().len() > MAX_PATH_BYTES
            || self.executable.as_os_str().to_string_lossy().contains('\0')
        {
            return Err(WatchdogError::InvalidInput(
                "worker peer executable must be an absolute bounded path".to_owned(),
            ));
        }
        validate_digest(&self.executable_sha256).map_err(|message| {
            WatchdogError::InvalidInput(format!(
                "worker peer executable digest is invalid: {message}"
            ))
        })?;
        if self.pid == 0
            || self.creation_token.is_empty()
            || self.creation_token.len() > 128
            || !self
                .creation_token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(WatchdogError::IdentityMismatch(
                "worker peer process identity requires a bounded PID and creation token".to_owned(),
            ));
        }
        Ok(self)
    }
}

pub(crate) fn validate_credential_reference(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || path.as_os_str().to_string_lossy().len() > MAX_PATH_BYTES
        || path.as_os_str().to_string_lossy().contains('\0')
    {
        return Err(WatchdogError::InvalidInput(
            "worker credential path must be an absolute bounded path".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| WatchdogError::Unauthorized("worker credential is unavailable".to_owned()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(WatchdogError::Unauthorized(
            "worker credential is not a protected regular file".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(WatchdogError::Unauthorized(
                "worker credential is not owner-only".to_owned(),
            ));
        }
    }
    #[cfg(windows)]
    ascension_platform_windows::validate_protected_credential_file(path).map_err(|_| {
        WatchdogError::Unauthorized("worker credential is not owner-protected".to_owned())
    })?;
    Ok(())
}

pub(crate) struct ProtectedCredential {
    #[cfg(target_os = "linux")]
    _ancestors: Vec<OwnedFd>,
    #[cfg(target_os = "linux")]
    _file: File,
    bytes: Vec<u8>,
}

impl ProtectedCredential {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub(crate) fn read_credential(path: &Path, deadline: Instant) -> Result<ProtectedCredential> {
    ensure_deadline(deadline, "worker credential read")?;
    // Open and validate the exact object before reading it.  The Unix Linux
    // path walks held, non-following directory descriptors and opens the final
    // descriptor with O_NONBLOCK before validating its type.  Windows uses the
    // platform's held-handle ancestor walk for the same reason.  This function
    // is called only after worker-peer authentication.
    #[cfg(target_os = "linux")]
    let mut file = open_linux_credential(path, deadline)?;
    #[cfg(windows)]
    let bytes = ascension_platform_windows::read_protected_payload_file(path, MAX_CREDENTIAL_BYTES)
        .map_err(|_| WatchdogError::Unauthorized("worker credential is unavailable".to_owned()))?;
    #[cfg(all(unix, not(target_os = "linux")))]
    let bytes = fs::read(path)
        .map_err(|_| WatchdogError::Unauthorized("worker credential is unavailable".to_owned()))?;
    #[cfg(not(any(unix, windows)))]
    let bytes = fs::read(path)
        .map_err(|_| WatchdogError::Unauthorized("worker credential is unavailable".to_owned()))?;

    #[cfg(target_os = "linux")]
    let bytes = read_bounded_credential(&mut file.file, deadline)?;
    ensure_deadline(deadline, "worker credential read")?;
    if bytes.is_empty()
        || bytes.len() > MAX_CREDENTIAL_BYTES
        || bytes.contains(&0)
        || !bytes.is_ascii()
        || bytes.iter().any(u8::is_ascii_whitespace)
    {
        return Err(WatchdogError::Unauthorized(
            "worker credential is empty, oversized, or malformed".to_owned(),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        Ok(ProtectedCredential {
            _ancestors: file.ancestors,
            _file: file.file,
            bytes,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(ProtectedCredential { bytes })
    }
}

#[cfg(target_os = "linux")]
struct OpenCredential {
    ancestors: Vec<OwnedFd>,
    file: File,
}

#[cfg(target_os = "linux")]
fn open_linux_credential(path: &Path, deadline: Instant) -> Result<OpenCredential> {
    use rustix::fs::{Mode, OFlags, fstatfs, open, openat};

    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(value) => components.push(value),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(WatchdogError::InvalidInput(
                    "worker credential path contains traversal".to_owned(),
                ));
            }
        }
    }
    if !path.is_absolute() || components.is_empty() {
        return Err(WatchdogError::InvalidInput(
            "worker credential path must be an absolute local file".to_owned(),
        ));
    }
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let root = open("/", flags | OFlags::DIRECTORY, Mode::empty())
        .map_err(|_| WatchdogError::Unauthorized("worker credential is unavailable".to_owned()))?;
    validate_linux_credential_directory(&root)?;
    ensure_local_protected_filesystem(
        fstatfs(&root)
            .map_err(|_| {
                WatchdogError::Unauthorized(
                    "worker credential filesystem is unavailable".to_owned(),
                )
            })?
            .f_type
            .cast_unsigned(),
    )?;
    let mut ancestors = vec![root];
    for (index, name) in components.iter().enumerate() {
        ensure_deadline(deadline, "worker credential open")?;
        let final_component = index + 1 == components.len();
        let directory = ancestors.last().ok_or_else(|| {
            WatchdogError::Unauthorized("worker credential path is unavailable".to_owned())
        })?;
        let descriptor = openat(
            directory,
            *name,
            if final_component {
                flags
            } else {
                flags | OFlags::DIRECTORY
            },
            Mode::empty(),
        )
        .map_err(|_| WatchdogError::Unauthorized("worker credential is unavailable".to_owned()))?;
        if final_component {
            let file: File = descriptor.into();
            return Ok(OpenCredential {
                ancestors,
                file: validate_linux_credential_file(file, deadline)?,
            });
        }
        validate_linux_credential_directory(&descriptor)?;
        ensure_local_protected_filesystem(
            fstatfs(&descriptor)
                .map_err(|_| {
                    WatchdogError::Unauthorized(
                        "worker credential filesystem is unavailable".to_owned(),
                    )
                })?
                .f_type
                .cast_unsigned(),
        )?;
        ancestors.push(descriptor);
    }
    Err(WatchdogError::Unauthorized(
        "worker credential is unavailable".to_owned(),
    ))
}

#[cfg(target_os = "linux")]
fn validate_linux_credential_directory(directory: &OwnedFd) -> Result<()> {
    use rustix::fs::fstat;

    let metadata = fstat(directory).map_err(|_| {
        WatchdogError::Unauthorized("worker credential directory is unavailable".to_owned())
    })?;
    let mode = metadata.st_mode;
    let directory_type = (mode & 0o170_000) == 0o040_000;
    // A sticky, root-owned system temporary directory is safe as an outer
    // ancestor: unprivileged users cannot rename another user's directory.
    // Every non-sticky ancestor must be free of group/world write access.
    let sticky_root = metadata.st_uid == 0 && mode & 0o1000 != 0;
    if !directory_type || (mode & 0o022 != 0 && !sticky_root) {
        return Err(WatchdogError::Unauthorized(
            "worker credential ancestor is not protected".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_linux_credential_file(file: File, deadline: Instant) -> Result<File> {
    use rustix::fs::{fstat, fstatfs};

    ensure_deadline(deadline, "worker credential validation")?;
    // fstat is intentionally performed on the held descriptor rather than on
    // the requested path.  `File::metadata` is equivalent but fstat makes the
    // descriptor authority explicit in this security-sensitive path.
    let metadata = fstat(&file)
        .map_err(|_| WatchdogError::Unauthorized("worker credential is unavailable".to_owned()))?;
    let mode = metadata.st_mode;
    let regular = (mode & 0o170_000) == 0o100_000;
    if !regular || metadata.st_uid != rustix::process::geteuid().as_raw() || mode & 0o077 != 0 {
        return Err(WatchdogError::Unauthorized(
            "worker credential is not an owner-only regular file".to_owned(),
        ));
    }
    // A synchronous read cannot be cancelled portably once a regular-file
    // filesystem blocks in the kernel.  Fail closed for filesystems outside
    // the explicitly supported local set instead of claiming the transport
    // deadline covers an unbounded remote/pseudo filesystem read.
    let filesystem = fstatfs(&file).map_err(|_| {
        WatchdogError::Unauthorized("worker credential filesystem is unavailable".to_owned())
    })?;
    ensure_local_protected_filesystem(filesystem.f_type.cast_unsigned())?;
    ensure_deadline(deadline, "worker credential validation")?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn ensure_local_protected_filesystem(filesystem_type: u64) -> Result<()> {
    if !matches!(
        filesystem_type,
        0x0000_ef53 // ext2/ext3/ext4
            | 0x0102_1994 // tmpfs
            | 0x794c_7630 // overlayfs
            | 0x5846_5342 // xfs
            | 0x9123_683e // btrfs
            | 0xf2f5_2010 // f2fs
    ) {
        return Err(WatchdogError::Unauthorized(
            "worker credential filesystem is not an approved local protected filesystem".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_bounded_credential(file: &mut File, deadline: Instant) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(64);
    let mut buffer = [0_u8; 256];
    loop {
        ensure_deadline(deadline, "worker credential read")?;
        let count = file.read(&mut buffer).map_err(|error| {
            if error.kind() == ErrorKind::WouldBlock {
                WatchdogError::Timeout("worker credential read timed out".to_owned())
            } else {
                WatchdogError::Unauthorized("worker credential is unavailable".to_owned())
            }
        })?;
        if count == 0 {
            break;
        }
        if bytes.len().saturating_add(count) > MAX_CREDENTIAL_BYTES {
            return Err(WatchdogError::Unauthorized(
                "worker credential is empty, oversized, or malformed".to_owned(),
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}

fn ensure_deadline(deadline: Instant, phase: &str) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(WatchdogError::Timeout(format!("{phase} timed out")));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn authenticate_linux_peer(
    stream: &std::os::unix::net::UnixStream,
    identity: &WorkerPeerIdentity,
    deadline: Instant,
) -> Result<LinuxPeerSession> {
    use rustix::net::sockopt::socket_peercred;
    use rustix::process::{Pid, PidfdFlags, pidfd_open};

    rustix::net::sockopt::set_socket_passcred(stream, true).map_err(|_| {
        WatchdogError::Unauthorized("worker peer message credentials are unavailable".to_owned())
    })?;
    let peer = socket_peercred(stream).map_err(|_| {
        WatchdogError::Unauthorized("worker peer credentials are unavailable".to_owned())
    })?;
    let pid = u32::try_from(peer.pid.as_raw_pid())
        .map_err(|_| WatchdogError::Unauthorized("worker peer PID is out of bounds".to_owned()))?;
    let expected_user_id = identity
        .uid
        .unwrap_or_else(|| rustix::process::geteuid().as_raw());
    let expected_group_id = identity
        .gid
        .unwrap_or_else(|| rustix::process::getegid().as_raw());
    if pid == 0
        || pid != identity.pid
        || peer.uid.as_raw() != expected_user_id
        || peer.gid.as_raw() != expected_group_id
    {
        return Err(WatchdogError::Unauthorized(
            "worker peer credentials or PID are not approved".to_owned(),
        ));
    }
    let process =
        Pid::from_raw(i32::try_from(pid).map_err(|_| {
            WatchdogError::Unauthorized("worker peer PID is out of bounds".to_owned())
        })?)
        .ok_or_else(|| WatchdogError::Unauthorized("worker peer PID is zero".to_owned()))?;
    let pidfd = pidfd_open(process, PidfdFlags::empty()).map_err(|_| {
        WatchdogError::Unauthorized("worker peer process identity is unavailable".to_owned())
    })?;
    ensure_deadline(deadline, "worker peer authentication")?;
    let start_before = process_start_token(pid, deadline)?;
    if start_before != identity.creation_token {
        return Err(WatchdogError::IdentityMismatch(
            "worker peer process creation token is not approved".to_owned(),
        ));
    }
    let proc_executable = PathBuf::from(format!("/proc/{pid}/exe"));
    ensure_deadline(deadline, "worker peer authentication")?;
    let executable = fs::read_link(&proc_executable).map_err(|_| {
        WatchdogError::Unauthorized("worker peer executable is unavailable".to_owned())
    })?;
    let expected = fs::canonicalize(identity.executable()).map_err(|_| {
        WatchdogError::Unauthorized("configured worker executable is unavailable".to_owned())
    })?;
    ensure_deadline(deadline, "worker peer authentication")?;
    if executable != expected {
        return Err(WatchdogError::Unauthorized(
            "worker peer executable is not approved".to_owned(),
        ));
    }
    // Retain the actual image through `/proc/<pid>/exe` and compare its file
    // identity with the configured artifact that was hashed while constructing
    // `WorkerPeerIdentity`.  Rehashing this descriptor here would make the
    // ordinary transport deadline depend on debug-build SHA-256 throughput;
    // the held descriptor plus device/inode comparison prevents a replaced
    // path or a different image object from inheriting that proof.
    let image = File::open(&proc_executable).map_err(|_| {
        WatchdogError::Unauthorized("worker peer executable is unavailable".to_owned())
    })?;
    let image_identity = linux_file_identity(&image)?;
    if image_identity != identity.configured_image_identity {
        return Err(WatchdogError::IdentityMismatch(
            "worker peer executable image identity is not approved".to_owned(),
        ));
    }
    let image_digest = identity.executable_sha256.clone();
    let start_after = process_start_token(pid, deadline)?;
    ensure_deadline(deadline, "worker peer authentication")?;
    let executable_after = fs::read_link(&proc_executable).map_err(|_| {
        WatchdogError::Unauthorized("worker peer executable is unavailable".to_owned())
    })?;
    if start_before != start_after || executable != executable_after {
        return Err(WatchdogError::IdentityMismatch(
            "worker peer process identity changed during authentication".to_owned(),
        ));
    }
    Ok(LinuxPeerSession {
        _pidfd: pidfd,
        _image: image,
        image_identity,
        _image_digest: image_digest,
        expected_path: expected,
        expected_pid: pid,
        expected_uid: peer.uid.as_raw(),
        expected_gid: peer.gid.as_raw(),
        creation_token: identity.creation_token.clone(),
    })
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LinuxFileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxPeerSession {
    // A pidfd pins the authenticated process identity against PID reuse.  It
    // does not prevent exec or fork; those are checked separately below and
    // in the transport's ancillary-message validation.
    _pidfd: OwnedFd,
    // Keep the actual `/proc/<pid>/exe` object alive until the response has
    // been received.  Its inode and digest are the process-image proof.
    _image: File,
    image_identity: LinuxFileIdentity,
    _image_digest: String,
    expected_path: PathBuf,
    expected_pid: u32,
    expected_uid: u32,
    expected_gid: u32,
    creation_token: String,
}

#[cfg(target_os = "linux")]
impl LinuxPeerSession {
    pub(crate) fn verify_current(&self, deadline: Instant) -> Result<()> {
        ensure_deadline(deadline, "worker peer authentication")?;
        let start = process_start_token(self.expected_pid, deadline)?;
        if start != self.creation_token {
            return Err(WatchdogError::IdentityMismatch(
                "worker peer process creation token changed during exchange".to_owned(),
            ));
        }
        let proc_executable = PathBuf::from(format!("/proc/{}/exe", self.expected_pid));
        let path_before = fs::read_link(&proc_executable).map_err(|_| {
            WatchdogError::Unauthorized("worker peer executable is unavailable".to_owned())
        })?;
        if path_before != self.expected_path {
            return Err(WatchdogError::IdentityMismatch(
                "worker peer executable path changed during exchange".to_owned(),
            ));
        }
        let current_image = File::open(&proc_executable).map_err(|_| {
            WatchdogError::Unauthorized("worker peer executable is unavailable".to_owned())
        })?;
        let current_identity = linux_file_identity(&current_image)?;
        let path_after = fs::read_link(&proc_executable).map_err(|_| {
            WatchdogError::Unauthorized("worker peer executable is unavailable".to_owned())
        })?;
        if path_before != path_after || current_identity != self.image_identity {
            return Err(WatchdogError::IdentityMismatch(
                "worker peer process image changed during exchange".to_owned(),
            ));
        }
        ensure_deadline(deadline, "worker peer authentication")?;
        Ok(())
    }

    pub(crate) fn verify_message_credentials(
        &self,
        credentials: &rustix::net::UCred,
    ) -> Result<()> {
        let pid = u32::try_from(credentials.pid.as_raw_pid()).map_err(|_| {
            WatchdogError::Unauthorized("worker peer message PID is out of bounds".to_owned())
        })?;
        if pid != self.expected_pid
            || credentials.uid.as_raw() != self.expected_uid
            || credentials.gid.as_raw() != self.expected_gid
        {
            return Err(WatchdogError::IdentityMismatch(
                "worker peer message credentials changed during exchange".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn linux_file_identity(file: &File) -> Result<LinuxFileIdentity> {
    let metadata = rustix::fs::fstat(file).map_err(|_| {
        WatchdogError::Unauthorized("worker peer executable identity is unavailable".to_owned())
    })?;
    Ok(LinuxFileIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

#[cfg(target_os = "linux")]
fn prime_peer_digest(identity: &WorkerPeerIdentity) -> Result<LinuxFileIdentity> {
    let executable = fs::canonicalize(identity.executable()).map_err(|_| {
        WatchdogError::Unauthorized("configured worker executable is unavailable".to_owned())
    })?;
    let mut file = File::open(&executable).map_err(|_| {
        WatchdogError::Unauthorized("configured worker executable is unavailable".to_owned())
    })?;
    let digest = hash_file_until(&mut file, None)?;
    if digest != identity.executable_sha256 {
        return Err(WatchdogError::Unauthorized(
            "configured worker executable digest is not approved".to_owned(),
        ));
    }
    linux_file_identity(&file)
}

#[cfg(target_os = "linux")]
fn process_start_token(pid: u32, deadline: Instant) -> Result<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|_| {
        WatchdogError::Unauthorized("worker peer process identity is unavailable".to_owned())
    })?;
    ensure_deadline(deadline, "worker peer process authentication")?;
    let close = stat.rfind(')').ok_or_else(|| {
        WatchdogError::Unauthorized("worker peer process identity is malformed".to_owned())
    })?;
    stat.get(close + 2..)
        .and_then(|suffix| suffix.split_whitespace().nth(19))
        .map(str::to_owned)
        .ok_or_else(|| {
            WatchdogError::Unauthorized("worker peer process identity is incomplete".to_owned())
        })
}

pub(crate) fn hash_file_until(file: &mut File, deadline: Option<Instant>) -> Result<String> {
    let mut hasher = Sha256::new();
    // A larger bounded read keeps the per-call IPC deadline meaningful on
    // filesystems where each procfs read crosses a host boundary (for
    // example WSL).  This allocation is short-lived and capped at 1 MiB.
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut total = 0_usize;
    loop {
        if deadline.is_some_and(|limit| Instant::now() >= limit) {
            return Err(WatchdogError::Timeout(
                "worker peer executable digest timed out".to_owned(),
            ));
        }
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                total = total.checked_add(count).ok_or_else(|| {
                    WatchdogError::Unauthorized(
                        "worker peer executable image exceeds the size bound".to_owned(),
                    )
                })?;
                if total > MAX_PEER_IMAGE_BYTES {
                    return Err(WatchdogError::Unauthorized(
                        "worker peer executable image exceeds the size bound".to_owned(),
                    ));
                }
                hasher.update(&buffer[..count]);
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(WatchdogError::Io(error)),
        }
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    fn current_peer_session() -> LinuxPeerSession {
        use rustix::process::{Pid, PidfdFlags, pidfd_open};

        let pid = std::process::id();
        let process = Pid::from_raw(i32::try_from(pid).expect("test PID fits i32"))
            .expect("test PID is nonzero");
        let pidfd = pidfd_open(process, PidfdFlags::empty()).expect("test pidfd");
        let executable = fs::read_link(format!("/proc/{pid}/exe")).expect("test executable");
        let image = File::open(format!("/proc/{pid}/exe")).expect("test image");
        let image_identity = linux_file_identity(&image).expect("test image identity");
        let creation_token = process_start_token(pid, Instant::now() + Duration::from_secs(1))
            .expect("test creation token");
        LinuxPeerSession {
            _pidfd: pidfd,
            _image: image,
            image_identity,
            _image_digest: String::new(),
            expected_path: executable,
            expected_pid: pid,
            expected_uid: rustix::process::geteuid().as_raw(),
            expected_gid: rustix::process::getegid().as_raw(),
            creation_token,
        }
    }

    #[test]
    fn forked_socket_writer_credentials_are_rejected() {
        use rustix::net::UCred;
        use rustix::process::{Gid, Pid, Uid};

        let session = current_peer_session();
        let pid = Pid::from_raw(i32::try_from(session.expected_pid).expect("test PID fits i32"))
            .expect("test PID is nonzero");
        let credentials = UCred {
            pid,
            uid: Uid::from_raw(session.expected_uid),
            gid: Gid::from_raw(session.expected_gid),
        };
        session
            .verify_message_credentials(&credentials)
            .expect("original process credentials");

        let inherited_socket_writer = UCred {
            pid: Pid::from_raw(pid.as_raw_pid().saturating_add(1)).expect("alternate PID"),
            ..credentials
        };
        assert!(matches!(
            session.verify_message_credentials(&inherited_socket_writer),
            Err(WatchdogError::IdentityMismatch(_))
        ));
    }

    #[test]
    fn protected_credential_keeps_authority_after_path_replacement() {
        let directory = tempfile::tempdir().expect("credential directory");
        fs::set_permissions(
            directory.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("credential directory permissions");
        let path = directory.path().join("worker.token");
        fs::write(&path, b"held-secret").expect("credential");
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .expect("credential permissions");
        let protected = read_credential(&path, Instant::now() + Duration::from_secs(1))
            .expect("protected credential");
        fs::remove_file(&path).expect("replace credential path");
        assert_eq!(protected.bytes(), b"held-secret");
    }

    #[test]
    fn image_identity_swap_is_rejected_before_peer_digest_use() {
        let (client, _server) = UnixStream::pair().expect("peer socket");
        let executable = std::env::current_exe().expect("test executable");
        let digest = hash_file_until(
            &mut File::open(&executable).expect("test executable file"),
            None,
        )
        .expect("test executable digest");
        let pid = std::process::id();
        let creation_token = process_start_token(pid, Instant::now() + Duration::from_secs(1))
            .expect("test creation token");
        let mut identity = WorkerPeerIdentity::new(executable, digest, pid, creation_token)
            .expect("peer identity");
        identity.configured_image_identity = LinuxFileIdentity {
            device: identity.configured_image_identity.device.wrapping_add(1),
            inode: identity.configured_image_identity.inode,
        };
        let result =
            authenticate_linux_peer(&client, &identity, Instant::now() + Duration::from_secs(1));
        assert!(matches!(result, Err(WatchdogError::IdentityMismatch(_))));
    }
}
