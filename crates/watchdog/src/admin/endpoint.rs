//! Protected local endpoint ownership and cleanup.

#![cfg_attr(
    not(unix),
    allow(
        dead_code,
        unused_imports,
        reason = "the Unix socket implementation is intentionally disabled on other platforms"
    )
)]

use crate::error::{Result, WatchdogError};
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::path::Component;
use std::path::{Path, PathBuf};

/// Validate a Unix-domain endpoint before a bind attempt.  The parent must be
/// an existing owner-only directory; this function never creates or deletes
/// ancestors.
pub fn validate_endpoint_path(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        validate_unix_path(path)
    }
    #[cfg(windows)]
    {
        let _ = path;
        Err(WatchdogError::Unsupported(
            "native Windows admin transport is owned by the P2 broker".to_string(),
        ))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(WatchdogError::Unsupported(
            "admin transport is unsupported on this platform".to_string(),
        ))
    }
}

#[cfg(unix)]
fn validate_unix_path(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || path.as_os_str().to_string_lossy().len() > 4 * 1024
        || path.as_os_str().to_string_lossy().contains('\0')
    {
        return Err(WatchdogError::InvalidInput(
            "admin socket path must be an absolute bounded path".to_string(),
        ));
    }
    let Some(file_name) = path.file_name() else {
        return Err(WatchdogError::InvalidInput(
            "admin socket path must name a socket".to_string(),
        ));
    };
    if file_name.is_empty() || file_name.len() > 255 {
        return Err(WatchdogError::InvalidInput(
            "admin socket filename is empty or oversized".to_string(),
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| WatchdogError::InvalidInput("admin socket parent is missing".to_string()))?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(WatchdogError::InvalidInput(
            "admin socket parent must be a real directory".to_string(),
        ));
    }
    // The direct parent is the trust boundary for the socket and token
    // references.  Require exactly owner-only access (special bits are okay).
    if parent_metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(WatchdogError::InvalidInput(
            "admin socket parent must have mode 0700".to_string(),
        ));
    }
    let current_uid = fs::metadata(".")?.uid();
    if parent_metadata.uid() != current_uid {
        return Err(WatchdogError::Unauthorized(
            "admin socket parent is not owned by the current user".to_string(),
        ));
    }
    // Check every existing ancestor explicitly.  In particular, reject a
    // symlink/reparse-like path component and a non-sticky world-writable
    // ancestor.  `/tmp` remains usable because it is sticky.
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(Path::new("/")),
            Component::Normal(value) => current.push(value),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(WatchdogError::InvalidInput(
                    "admin socket path contains an unsafe component".to_string(),
                ));
            }
        }
        if current == path {
            break;
        }
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(WatchdogError::InvalidInput(
                "admin socket ancestor is not a real directory".to_string(),
            ));
        }
        // System-owned ancestors such as `/tmp`'s parent are trusted when
        // root-owned; user-controlled ancestors must belong to this user.
        if metadata.uid() != current_uid && metadata.uid() != 0 {
            return Err(WatchdogError::Unauthorized(
                "admin socket ancestor has a different owner".to_string(),
            ));
        }
        let mode = metadata.permissions().mode();
        if mode & 0o002 != 0 && mode & 0o1000 == 0 {
            return Err(WatchdogError::InvalidInput(
                "admin socket ancestor is non-sticky world-writable".to_string(),
            ));
        }
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(WatchdogError::Conflict(
                "admin socket path is a symlink".to_string(),
            ));
        }
    }
    Ok(())
}

/// Exact filesystem identity captured after a successful bind.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EndpointIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl EndpointIdentity {
    fn read(path: &Path) -> Result<Self> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
            return Err(WatchdogError::Conflict(
                "bound admin endpoint is not a Unix socket".to_string(),
            ));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

/// Cleanup guard for one exact bound socket.  A path replaced by an incumbent
/// socket or regular file is left untouched.
#[derive(Debug)]
pub struct EndpointGuard {
    path: PathBuf,
    #[cfg(unix)]
    identity: EndpointIdentity,
}

impl EndpointGuard {
    #[cfg(unix)]
    fn new(path: PathBuf, identity: EndpointIdentity) -> Self {
        Self { path, identity }
    }

    /// Endpoint path, exposed for diagnostics but not included in status.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Remove only the exact socket created by this guard.
    pub fn cleanup(&self) -> Result<()> {
        #[cfg(unix)]
        {
            let Ok(current) = EndpointIdentity::read(&self.path) else {
                return Ok(());
            };
            if current != self.identity {
                return Ok(());
            }
            fs::remove_file(&self.path)?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            Err(WatchdogError::Unsupported(
                "native Windows admin transport is owned by the P2 broker".to_string(),
            ))
        }
    }
}

impl Drop for EndpointGuard {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Bind a protected Unix endpoint.  Existing paths are never unlinked as a
/// stale-socket convenience; the kernel's `EADDRINUSE` remains a `BUSY`
/// condition so an incumbent cannot be displaced.
#[cfg(unix)]
pub(crate) fn bind_endpoint(
    path: &Path,
) -> Result<(std::os::unix::net::UnixListener, EndpointGuard)> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    validate_unix_path(path)?;
    let listener = UnixListener::bind(path).map_err(|error| {
        if matches!(error.kind(), std::io::ErrorKind::AddrInUse) {
            WatchdogError::Busy(path.to_path_buf())
        } else {
            WatchdogError::Io(error)
        }
    })?;
    // UnixListener::bind follows the process umask, but the endpoint policy is
    // explicit and must hold even under a permissive umask.
    if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
        let _ = fs::remove_file(path);
        return Err(error.into());
    }
    let identity = match EndpointIdentity::read(path) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = fs::remove_file(path);
            return Err(error);
        }
    };
    Ok((listener, EndpointGuard::new(path.to_path_buf(), identity)))
}

#[cfg(not(unix))]
pub(crate) fn bind_endpoint(path: &Path) -> Result<((), EndpointGuard)> {
    let _ = path;
    Err(WatchdogError::Unsupported(
        "native Windows admin transport is owned by the P2 broker".to_string(),
    ))
}
