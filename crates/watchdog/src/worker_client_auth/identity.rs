//! Peer-identity model for the owner-local worker handoff transport.
//!
//! This module owns the immutable [`WorkerPeerIdentity`] value: the configured
//! executable path and digest, the expected OS account and process birth, and
//! the Linux sealed-image proof.  Constructors accept only trusted launch
//! policy or an already-inspected live process identity; no field is ever
//! populated from a worker request.  The small image-identity primitives
//! (`LinuxFileIdentity`, seal verification and digest priming) live here
//! because they are part of that model, while the live-process/OS probing
//! helpers live in the sibling `peer` module.

use crate::config::validate_digest;
use crate::error::{Result, WatchdogError};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::fs::File;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::time::Instant;

use super::MAX_PATH_BYTES;
#[cfg(target_os = "linux")]
use super::ensure_deadline;
#[cfg(target_os = "linux")]
use super::peer::{hash_file_until, linux_file_identity, process_start_token};

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
    #[cfg(windows)]
    pub(crate) windows_account: Option<(String, u32)>,
    #[cfg(target_os = "linux")]
    pub(super) configured_image_identity: LinuxFileIdentity,
    #[cfg(target_os = "linux")]
    pub(super) sealed_image: Option<std::sync::Arc<LinuxSealedImage>>,
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
            debug.field("sealed_image", &self.sealed_image.is_some());
        }
        #[cfg(windows)]
        debug.field("windows_account", &"<protected-policy>");
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
            #[cfg(windows)]
            windows_account: None,
            #[cfg(target_os = "linux")]
            configured_image_identity: LinuxFileIdentity {
                device: 0,
                inode: 0,
            },
            #[cfg(target_os = "linux")]
            sealed_image: None,
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
    /// This public constructor accepts raw OS birth tokens and file-backed
    /// images (including explicit synthetic children). Linux native adapter
    /// identities carry `boot-id:start-ticks` and sealed images; only the
    /// runtime's private owned-native path may translate and authorize those.
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

    /// Only the runtime's freshly inspected native child may select this policy.
    /// Durable records and public file-backed constructors cannot grant it.
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    pub(crate) fn from_owned_linux_process(
        identity: &crate::ProcessIdentity,
        deadline: Instant,
    ) -> Result<Self> {
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let token = identity.creation_fingerprint.as_deref().unwrap_or_default();
        let (recorded_boot, ticks) = token.split_once(':').ok_or_else(|| {
            WatchdogError::IdentityMismatch("native worker birth token is malformed".to_owned())
        })?;
        if recorded_boot != boot.trim()
            || ticks.is_empty()
            || !ticks.bytes().all(|byte| byte.is_ascii_digit())
            || process_start_token(identity.pid, deadline)? != ticks
        {
            return Err(WatchdogError::IdentityMismatch(
                "native worker birth token is not current".to_owned(),
            ));
        }
        let proc_path = PathBuf::from(format!("/proc/{}/exe", identity.pid));
        let path = fs::read_link(&proc_path)?;
        let mut file = File::open(&proc_path)?;
        require_full_image_seals(&file)?;
        let image_identity = linux_file_identity(&file)?;
        let digest = hash_file_until(&mut file, Some(deadline))?;
        if digest != identity.executable_digest
            || fs::read_link(&proc_path)? != path
            || linux_file_identity(&File::open(&proc_path)?)? != image_identity
            || process_start_token(identity.pid, deadline)? != ticks
        {
            return Err(WatchdogError::IdentityMismatch(
                "native worker sealed image is not approved".to_owned(),
            ));
        }
        ensure_deadline(deadline, "native worker image capture")?;
        Self {
            executable: identity.executable.clone(),
            executable_sha256: digest,
            uid: None,
            gid: None,
            pid: identity.pid,
            creation_token: ticks.to_owned(),
            configured_image_identity: image_identity,
            sealed_image: Some(std::sync::Arc::new(LinuxSealedImage {
                file,
                path,
                identity: image_identity,
            })),
        }
        .validate()
    }

    /// Require an explicit peer UID/GID in addition to the executable proof.
    /// This is useful for a dedicated service account.  The values are
    /// captured in configuration and cannot be supplied by a worker request.
    pub fn with_peer_credentials(mut self, uid: u32, gid: u32) -> Result<Self> {
        self.uid = Some(uid);
        self.gid = Some(gid);
        self.validate()
    }

    /// Bind the expected Windows account and session from trusted launch policy.
    /// Never populate these values from the connected peer being authenticated.
    #[cfg(windows)]
    pub fn with_windows_account(mut self, sid: String, session_id: u32) -> Result<Self> {
        let executable = self.executable.to_str().ok_or_else(|| {
            WatchdogError::IdentityMismatch("worker image path is not Unicode".to_owned())
        })?;
        crate::worker_bootstrap::WindowsPeer::new(
            self.pid,
            self.creation_token.clone(),
            executable,
            self.executable_sha256.clone(),
            session_id,
            sid.clone(),
        )
        .map_err(|_| {
            WatchdogError::IdentityMismatch("invalid Windows worker account policy".to_owned())
        })?;
        self.windows_account = Some((sid, session_id));
        Ok(self)
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

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LinuxFileIdentity {
    pub(super) device: u64,
    pub(super) inode: u64,
}

#[cfg(target_os = "linux")]
pub(super) struct LinuxSealedImage {
    pub(super) file: File,
    pub(super) path: PathBuf,
    pub(super) identity: LinuxFileIdentity,
}

#[cfg(target_os = "linux")]
impl PartialEq for LinuxSealedImage {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity && self.path == other.path
    }
}

#[cfg(target_os = "linux")]
impl Eq for LinuxSealedImage {}

#[cfg(target_os = "linux")]
pub(super) fn require_full_image_seals(file: &File) -> Result<()> {
    use rustix::fs::{SealFlags, fcntl_get_seals};
    let seals = fcntl_get_seals(file).map_err(|_| {
        WatchdogError::IdentityMismatch("native worker image is not sealed".to_owned())
    })?;
    if !seals.contains(SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL) {
        return Err(WatchdogError::IdentityMismatch(
            "native worker image is not immutable".to_owned(),
        ));
    }
    Ok(())
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
