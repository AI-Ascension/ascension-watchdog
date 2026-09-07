//! File-backed capability credentials for the local admin sideband.

use super::protocol::{AdminRequest, AuthenticatedPrincipalClass, Capability};
use crate::error::{Result, WatchdogError};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_TOKEN_BYTES: usize = 4 * 1024;

/// Explicit references to the two OS-protected token files.  Raw token bytes
/// are never represented in configuration, status or audit records.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthReferences {
    read_token_path: PathBuf,
    admin_token_path: PathBuf,
}

impl fmt::Debug for AuthReferences {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthReferences")
            .field("read_token_path", &"<protected-reference>")
            .field("admin_token_path", &"<protected-reference>")
            .finish()
    }
}

impl AuthReferences {
    /// Construct references to two distinct token files.
    pub fn new(
        read_token_path: impl Into<PathBuf>,
        admin_token_path: impl Into<PathBuf>,
    ) -> Result<Self> {
        let references = Self {
            read_token_path: read_token_path.into(),
            admin_token_path: admin_token_path.into(),
        };
        references.validate_paths()?;
        if references.read_token_path == references.admin_token_path {
            return Err(WatchdogError::InvalidInput(
                "read and admin token references must be distinct".to_string(),
            ));
        }
        Ok(references)
    }

    /// Read-only reference to the configured read token path for diagnostics.
    /// The path is not included in status responses by this module.
    #[must_use]
    pub fn read_token_path(&self) -> &Path {
        &self.read_token_path
    }

    /// Read-only reference to the configured admin token path for diagnostics.
    #[must_use]
    pub fn admin_token_path(&self) -> &Path {
        &self.admin_token_path
    }

    /// Load both credentials while checking owner-only file policy.
    pub fn load(&self) -> Result<AuthStore> {
        self.validate_paths()?;
        let read = read_protected_token(&self.read_token_path)?;
        let admin = read_protected_token(&self.admin_token_path)?;
        if constant_time_equal(&read, &admin) {
            return Err(WatchdogError::InvalidInput(
                "read and admin credentials must differ".to_string(),
            ));
        }
        Ok(AuthStore { read, admin })
    }

    fn validate_paths(&self) -> Result<()> {
        validate_token_reference(&self.read_token_path, "read token")?;
        validate_token_reference(&self.admin_token_path, "admin token")
    }
}

/// In-memory credentials retained only by the server/client transport owner.
/// This type intentionally has no `Serialize` implementation.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthStore {
    read: Vec<u8>,
    admin: Vec<u8>,
}

impl fmt::Debug for AuthStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthStore")
            .field("read", &"<redacted>")
            .field("admin", &"<redacted>")
            .finish()
    }
}

impl AuthStore {
    /// Authenticate a request's claimed capability.  An admin credential can
    /// be used for a read command, but a read credential can never satisfy an
    /// admin command or a request claiming `Capability::Admin`.
    #[must_use]
    pub fn authorize(&self, request: &AdminRequest) -> Authz {
        let token = request.token.as_bytes();
        let admin_matches = constant_time_equal(token, &self.admin);
        let read_matches = constant_time_equal(token, &self.read);
        let credential = if admin_matches {
            Some((Capability::Admin, AuthenticatedPrincipalClass::AdminToken))
        } else if read_matches {
            Some((Capability::Read, AuthenticatedPrincipalClass::ReadToken))
        } else {
            None
        };
        let Some(credential) = credential else {
            return Authz::Unauthorized;
        };
        if credential.0.includes(request.capability)
            && request
                .capability
                .includes(request.command.name().required_capability())
        {
            Authz::Allowed(credential.1)
        } else {
            Authz::Forbidden
        }
    }

    /// Return a redacted credential-independent capability fingerprint for
    /// tests and diagnostics.  It is not an authority proof.
    #[must_use]
    pub fn capability_count(&self) -> usize {
        2
    }
}

/// Authentication result used by the transport without free-form errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authz {
    Allowed(AuthenticatedPrincipalClass),
    Unauthorized,
    Forbidden,
}

fn validate_token_reference(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || path.as_os_str().to_string_lossy().len() > 4 * 1024
        || path.as_os_str().to_string_lossy().contains('\0')
    {
        return Err(WatchdogError::InvalidInput(format!(
            "{label} reference must be an absolute bounded path"
        )));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            WatchdogError::MissingState(path.to_path_buf())
        } else {
            WatchdogError::Io(error)
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(WatchdogError::InvalidInput(format!(
            "{label} reference must name a regular non-symlink file"
        )));
    }
    #[cfg(windows)]
    {
        ascension_platform_windows::validate_protected_credential_file(path).map_err(|_| {
            WatchdogError::Unauthorized(format!("{label} file is not owner-protected"))
        })?;
    }
    #[cfg(unix)]
    {
        use super::endpoint::current_uid;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = metadata.permissions().mode();
        if metadata.uid() != current_uid() || mode & 0o077 != 0 {
            return Err(WatchdogError::InvalidInput(format!(
                "{label} file must be owner-only"
            )));
        }
    }
    Ok(())
}

fn read_protected_token(path: &Path) -> Result<Vec<u8>> {
    let bytes = fs::read(path)?;
    if bytes.is_empty() || bytes.len() > MAX_TOKEN_BYTES || bytes.contains(&0) {
        return Err(WatchdogError::InvalidInput(
            "token is empty or exceeds its bound".to_string(),
        ));
    }
    // Newlines and whitespace are almost always an accidental shell/file
    // formatting issue.  Reject them instead of silently trimming credentials.
    if bytes.iter().any(u8::is_ascii_whitespace) || !bytes.is_ascii() {
        return Err(WatchdogError::InvalidInput(
            "token must be bounded printable ASCII without whitespace".to_string(),
        ));
    }
    Ok(bytes)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max = left.len().max(right.len());
    for index in 0..max {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(a ^ b);
    }
    diff == 0
}
