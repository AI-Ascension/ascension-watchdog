//! Live worker peer authentication and controller image capture.
//!
//! This module owns the platform peer session: controller image capture, the
//! Linux peer credential/PID/creation-token/executable check, and the retained
//! `LinuxPeerSession` that re-verifies the current process image and message
//! credentials after authentication.  Identity models live in `models`.

#[cfg(target_os = "linux")]
use super::credential::ensure_deadline;
#[cfg(target_os = "linux")]
use super::models::{
    LinuxFileIdentity, WorkerPeerIdentity, hash_file_until, linux_file_identity,
    process_start_token, require_full_image_seals,
};
#[cfg(target_os = "linux")]
use crate::error::{Result, WatchdogError};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::time::Instant;

/// Capture this controller's held image, not a configured or request-supplied PID.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub(crate) fn capture_linux_controller(
    deadline: Instant,
) -> Result<crate::worker_bootstrap::LinuxPeer> {
    use std::os::unix::fs::MetadataExt;
    let pid = std::process::id();
    let creation_token = process_start_token(pid, deadline)?;
    let image_path = Path::new("/proc/self/exe");
    let executable = fs::read_link(image_path)?;
    let mut image = File::open(image_path)?;
    let before = image.metadata()?;
    if !before.is_file() || before.mode() & 0o222 != 0 {
        return Err(WatchdogError::Unauthorized(
            "worker controller image must be immutable".to_owned(),
        ));
    }
    let executable_sha256 = hash_file_until(&mut image, Some(deadline))?;
    let after = image.metadata()?;
    let named = fs::metadata(&executable)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.dev() != named.dev()
        || before.ino() != named.ino()
        || fs::read_link(image_path)? != executable
    {
        return Err(WatchdogError::IdentityMismatch(
            "worker controller image changed during bootstrap capture".to_owned(),
        ));
    }
    ensure_deadline(deadline, "worker controller bootstrap capture")?;
    Ok(crate::worker_bootstrap::LinuxPeer {
        pid,
        creation_token,
        executable: executable
            .to_str()
            .ok_or_else(|| {
                WatchdogError::InvalidInput("worker controller image must be Unicode".to_owned())
            })?
            .to_owned(),
        executable_sha256,
        uid: rustix::process::geteuid().as_raw(),
        gid: rustix::process::getegid().as_raw(),
    })
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
    let expected = if let Some(sealed) = &identity.sealed_image {
        require_full_image_seals(&sealed.file)?;
        sealed.path.clone()
    } else {
        fs::canonicalize(identity.executable()).map_err(|_| {
            WatchdogError::Unauthorized("configured worker executable is unavailable".to_owned())
        })?
    };
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
pub(crate) struct LinuxPeerSession {
    // A pidfd pins the authenticated process identity against PID reuse.  It
    // does not prevent exec or fork; those are checked separately below and
    // in the transport's ancillary-message validation.
    pub(super) _pidfd: OwnedFd,
    // Keep the actual `/proc/<pid>/exe` object alive until the response has
    // been received.  Its inode and digest are the process-image proof.
    pub(super) _image: File,
    pub(super) image_identity: LinuxFileIdentity,
    pub(super) _image_digest: String,
    pub(super) expected_path: PathBuf,
    pub(super) expected_pid: u32,
    pub(super) expected_uid: u32,
    pub(super) expected_gid: u32,
    pub(super) creation_token: String,
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
