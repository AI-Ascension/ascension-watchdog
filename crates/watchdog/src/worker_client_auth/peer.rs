//! Linux peer identity validation for the worker handoff transport.
//!
//! This module authenticates the connected peer against the configured
//! [`WorkerPeerIdentity`] before any protocol frame is sent, retains the
//! authenticated process and image for the duration of the exchange, and owns
//! the bounded image digest and process-start-token helpers the identity and
//! bootstrap capture share.  It never reads credential bytes.

use super::ensure_deadline;
use super::models::{LinuxFileIdentity, WorkerPeerIdentity};
use crate::error::{Result, WatchdogError};
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::time::Instant;

const MAX_PEER_IMAGE_BYTES: usize = 256 * 1024 * 1024;

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

pub(super) fn linux_file_identity(file: &File) -> Result<LinuxFileIdentity> {
    let metadata = rustix::fs::fstat(file).map_err(|_| {
        WatchdogError::Unauthorized("worker peer executable identity is unavailable".to_owned())
    })?;
    Ok(LinuxFileIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

pub(super) fn process_start_token(pid: u32, deadline: Instant) -> Result<String> {
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

pub(super) fn hash_file_until(file: &mut File, deadline: Option<Instant>) -> Result<String> {
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
