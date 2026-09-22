//! Peer authentication and protected-filesystem helpers.
//!
//! Kernel-derived peer credentials, the root-owned executable allowlist and
//! the protected path, bounded-read and executable-hashing helpers that the
//! broker boundary relies on.  The shared error vocabulary and the generic
//! `hex_digest`/`io_error` utilities stay with the coordinator module.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Peer credentials captured from the kernel, not supplied by the request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

pub(crate) fn validate_protected_file(path: &Path, label: &str) -> BrokerResult<()> {
    validate_protected_ancestors(path, label)?;
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_file() || !is_protected_owner(metadata.uid()) || metadata.mode() & 0o022 != 0 {
        return Err(BrokerError::Invalid(format!(
            "{label} must be a root-owned non-writable regular file"
        )));
    }
    Ok(())
}

pub(crate) fn validate_protected_directory(path: &Path, label: &str) -> BrokerResult<()> {
    validate_protected_ancestors(path, label)?;
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_dir() || !is_protected_owner(metadata.uid()) || metadata.mode() & 0o022 != 0 {
        return Err(BrokerError::Invalid(format!(
            "{label} must be a root-owned non-writable directory"
        )));
    }
    Ok(())
}

/// Validate every path component, not just the final object.  A root-owned
/// final file is insufficient when a writable or symlinked ancestor can
/// redirect the lookup.
fn validate_protected_ancestors(path: &Path, label: &str) -> BrokerResult<()> {
    if !path.is_absolute() {
        return Err(BrokerError::Invalid(format!(
            "{label} path must be absolute"
        )));
    }
    let components = path.components().collect::<Vec<_>>();
    if components.iter().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir
                | std::path::Component::ParentDir
                | std::path::Component::Prefix(_)
        )
    }) {
        return Err(BrokerError::Invalid(format!(
            "{label} path contains a non-canonical component"
        )));
    }
    let mut current = PathBuf::from("/");
    for component in components {
        let std::path::Component::Normal(part) = component else {
            continue;
        };
        current.push(part);
        let metadata = fs::symlink_metadata(&current).map_err(io_error)?;
        if !metadata.is_dir() || !is_protected_owner(metadata.uid()) || metadata.mode() & 0o022 != 0
        {
            // The final object is validated separately, but all components
            // before it must be directories with no non-root write access.
            if current != path {
                return Err(BrokerError::Invalid(format!(
                    "{label} path has an unsafe ancestor"
                )));
            }
        }
        if current != path && metadata.file_type().is_symlink() {
            return Err(BrokerError::Invalid(format!(
                "{label} path has a symlinked ancestor"
            )));
        }
    }
    Ok(())
}

pub(crate) fn is_protected_owner(uid: u32) -> bool {
    #[cfg(test)]
    {
        // Tests use a mode-0700 per-user runtime fixture because they cannot
        // create root-owned files.  Release builds retain the root-only rule.
        uid == 0 || uid == rustix::process::getuid().as_raw()
    }
    #[cfg(not(test))]
    {
        uid == 0
    }
}

pub(crate) fn hash_file(path: &Path) -> BrokerResult<String> {
    hash_open_file(File::open(path).map_err(io_error)?)
}

fn hash_open_file(file: File) -> BrokerResult<String> {
    let deadline = Instant::now()
        .checked_add(MAX_TIMEOUT)
        .unwrap_or_else(Instant::now);
    hash_open_file_until(file, deadline)
}

pub(crate) fn hash_open_file_until(file: File, deadline: Instant) -> BrokerResult<String> {
    let mut file = file;
    let metadata = file.metadata().map_err(io_error)?;
    if metadata.len() > MAX_HASH_BYTES {
        return Err(BrokerError::Invalid(
            "executable exceeds hash bound".to_owned(),
        ));
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        remaining(deadline)?;
        let count = file.read(&mut buffer).map_err(io_error)?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if total > MAX_HASH_BYTES {
            return Err(BrokerError::Invalid(
                "executable exceeds hash bound".to_owned(),
            ));
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex_digest(&hasher.finalize()))
}

pub(crate) fn read_bounded_file(path: &Path, maximum: usize, label: &str) -> BrokerResult<Vec<u8>> {
    let file = File::open(path).map_err(io_error)?;
    let metadata = file.metadata().map_err(io_error)?;
    if metadata.len() > maximum as u64 {
        return Err(BrokerError::Invalid(format!("{label} exceeds size bound")));
    }
    let mut bytes = Vec::with_capacity(metadata.len().try_into().unwrap_or(maximum));
    file.take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > maximum {
        return Err(BrokerError::Invalid(format!("{label} exceeds size bound")));
    }
    Ok(bytes)
}

/// Exact kernel credentials obtained from a connected Unix stream.
pub fn peer_credentials(stream: &UnixStream) -> BrokerResult<PeerCredentials> {
    let credentials =
        socket_peercred(stream).map_err(|error| BrokerError::Io(error.to_string()))?;
    Ok(PeerCredentials {
        pid: u32::try_from(credentials.pid.as_raw_pid())
            .map_err(|_| BrokerError::Io("peer PID exceeds broker bounds".to_owned()))?,
        uid: credentials.uid.as_raw(),
        gid: credentials.gid.as_raw(),
    })
}

pub(crate) fn authenticate_peer(
    credentials: PeerCredentials,
    policy: &PeerPolicy,
    deadline: Instant,
) -> BrokerResult<()> {
    remaining(deadline)?;
    if credentials.pid == 0 || credentials.uid != policy.uid || credentials.gid != policy.gid {
        return Err(BrokerError::Unauthorized(
            "peer credentials are not approved".to_owned(),
        ));
    }
    let pid = Pid::from_raw(
        i32::try_from(credentials.pid)
            .map_err(|_| BrokerError::Unauthorized("peer PID is out of bounds".to_owned()))?,
    )
    .ok_or_else(|| BrokerError::Unauthorized("peer PID is zero".to_owned()))?;
    // Pin the process identity while the proc executable descriptor is opened
    // and hashed.  SO_PEERCRED supplies the PID, but a connected socket can
    // outlive that process, so a bare /proc/<pid> path is not sufficient.
    let _pidfd = pidfd_open(pid, PidfdFlags::empty()).map_err(|error| {
        BrokerError::Unauthorized(format!("peer process identity is unavailable: {error}"))
    })?;
    remaining(deadline)?;
    let start_before = process_start_token(credentials.pid)?;
    let proc_executable = PathBuf::from(format!("/proc/{}/exe", credentials.pid));
    let executable = fs::read_link(&proc_executable).map_err(io_error)?;
    if executable != policy.executable {
        return Err(BrokerError::Unauthorized(
            "peer executable path is not approved".to_owned(),
        ));
    }
    let actual = hash_open_file_until(File::open(&proc_executable).map_err(io_error)?, deadline)?;
    remaining(deadline)?;
    let start_after = process_start_token(credentials.pid)?;
    if start_before != start_after {
        return Err(BrokerError::Unauthorized(
            "peer process identity changed during authentication".to_owned(),
        ));
    }
    if actual != policy.executable_sha256 {
        return Err(BrokerError::Unauthorized(
            "peer executable digest is not approved".to_owned(),
        ));
    }
    Ok(())
}
