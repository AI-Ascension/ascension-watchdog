//! Authenticated bounded admin client.

use super::endpoint::validate_endpoint_path;
use super::protocol::reject_duplicate_fields;
use super::protocol::{AdminCommand, AdminRequest, AdminResponse, Capability};
use super::{MAX_DEADLINE_MS, MAX_FRAME_BYTES};
use crate::error::{Result, WatchdogError};
use std::fs;
#[cfg(unix)]
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

/// Client endpoint and explicit token reference.
#[derive(Clone)]
pub struct AdminClientConfig {
    endpoint: PathBuf,
    token_path: PathBuf,
    capability: Capability,
    timeout: Duration,
    #[cfg(windows)]
    expected_server_executable: Option<PathBuf>,
}

impl std::fmt::Debug for AdminClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut builder = f.debug_struct("AdminClientConfig");
        builder
            .field("endpoint", &"<protected-endpoint>")
            .field("token_path", &"<protected-reference>")
            .field("capability", &self.capability)
            .field("timeout", &self.timeout);
        #[cfg(windows)]
        builder.field(
            "expected_server_executable",
            &self
                .expected_server_executable
                .as_ref()
                .map(|_| "<configured>"),
        );
        builder.finish()
    }
}

impl AdminClientConfig {
    /// Construct a client with an explicit read or admin credential reference.
    pub fn new(
        endpoint: impl Into<PathBuf>,
        token_path: impl Into<PathBuf>,
        capability: Capability,
    ) -> Result<Self> {
        let config = Self {
            endpoint: endpoint.into(),
            token_path: token_path.into(),
            capability,
            timeout: Duration::from_secs(5),
            #[cfg(windows)]
            expected_server_executable: Some(std::env::current_exe()?),
        };
        config.validate()
    }

    /// Configure a shorter bounded transport deadline.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self> {
        self.timeout = timeout;
        self.validate()
    }

    /// Require the Windows server process image to match this executable.
    /// The native client always checks a held server PID and creation
    /// identity and an exact image allowlist check. By default the server must
    /// use the current executable; this overrides that explicit image identity.
    #[cfg(windows)]
    pub fn with_server_executable(mut self, executable: impl Into<PathBuf>) -> Result<Self> {
        self.expected_server_executable = Some(executable.into());
        self.validate()
    }

    /// Endpoint path used by the client.
    #[must_use]
    pub fn endpoint(&self) -> &std::path::Path {
        &self.endpoint
    }

    /// Claimed capability used in each request.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.capability
    }

    fn validate(self) -> Result<Self> {
        validate_endpoint_path(&self.endpoint)?;
        if !self.token_path.is_absolute() {
            return Err(WatchdogError::InvalidInput(
                "admin token path must be absolute".to_string(),
            ));
        }
        if self.timeout.is_zero() || self.timeout > Duration::from_secs(30) {
            return Err(WatchdogError::InvalidInput(
                "admin client timeout must be between 1ms and 30s".to_string(),
            ));
        }
        #[cfg(windows)]
        if let Some(path) = &self.expected_server_executable
            && (!path.is_absolute() || path.as_os_str().is_empty())
        {
            return Err(WatchdogError::InvalidInput(
                "expected Windows admin server executable must be absolute".to_string(),
            ));
        }
        Ok(self)
    }
}

/// One-shot request client.  A fresh Unix stream is used per exchange; the
/// durable idempotency key makes reconnect/retry safe.
#[derive(Clone, Debug)]
pub struct AdminClient {
    config: AdminClientConfig,
}

impl AdminClient {
    /// Validate the explicit token reference and retain only its path.  The
    /// token is read for each request so a controlled file rotation takes
    /// effect without storing raw credentials in the client object.
    pub fn new(config: AdminClientConfig) -> Result<Self> {
        let config = config.validate()?;
        validate_client_token(&config.token_path)?;
        Ok(Self { config })
    }

    /// Execute a typed request over the local authenticated endpoint.
    pub fn execute(&self, idempotency_key: &str, command: AdminCommand) -> Result<AdminResponse> {
        let token = read_client_token(&self.config.token_path)?;
        let deadline_ms = self
            .config
            .timeout
            .as_millis()
            .try_into()
            .unwrap_or(MAX_DEADLINE_MS)
            .clamp(1, MAX_DEADLINE_MS);
        let request = AdminRequest::new(
            self.config.capability,
            token,
            idempotency_key.to_string(),
            command,
            deadline_ms,
        )
        .map_err(WatchdogError::InvalidInput)?;
        let bytes = serde_json::to_vec(&request)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(WatchdogError::InvalidInput(
                "request exceeds frame bound".to_string(),
            ));
        }
        #[cfg(unix)]
        {
            let mut stream = std::os::unix::net::UnixStream::connect(&self.config.endpoint)?;
            stream.set_read_timeout(Some(self.config.timeout))?;
            stream.set_write_timeout(Some(self.config.timeout))?;
            write_frame(&mut stream, &bytes)?;
            let response_bytes = read_frame(&mut stream)?;
            reject_duplicate_fields(&response_bytes).map_err(WatchdogError::InvalidInput)?;
            let response: AdminResponse = serde_json::from_slice(&response_bytes)?;
            response.validate().map_err(WatchdogError::InvalidInput)?;
            Ok(response)
        }
        #[cfg(windows)]
        {
            let mut pipe = ascension_platform_windows::AdminPipeClient::connect(
                self.config.endpoint.to_string_lossy().into_owned(),
                self.config.expected_server_executable.as_deref(),
                self.config.timeout,
            )
            .map_err(|error| WatchdogError::Unsupported(error.to_string()))?;
            pipe.write_frame(&bytes, self.config.timeout)
                .map_err(|error| WatchdogError::Io(std::io::Error::other(error)))?;
            let response_bytes = pipe
                .read_frame(self.config.timeout)
                .map_err(|error| WatchdogError::Io(std::io::Error::other(error)))?;
            reject_duplicate_fields(&response_bytes).map_err(WatchdogError::InvalidInput)?;
            let response: AdminResponse = serde_json::from_slice(&response_bytes)?;
            response.validate().map_err(WatchdogError::InvalidInput)?;
            Ok(response)
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(WatchdogError::Unsupported(
                "admin transport is unsupported on this platform".to_string(),
            ))
        }
    }

    /// Convenience read command.  It never opens, creates or migrates the
    /// watchdog database; all state comes from the main-loop response.
    pub fn status(&self, idempotency_key: &str) -> Result<AdminResponse> {
        self.execute(
            idempotency_key,
            AdminCommand::Status(super::protocol::EmptyParams::default()),
        )
    }
}

#[cfg(all(test, windows))]
mod windows_config_tests {
    use super::*;

    #[test]
    fn default_server_identity_is_the_current_executable() -> Result<()> {
        let config = AdminClientConfig::new(
            r"\\.\pipe\ascension-watchdog-config-test",
            r"C:\watchdog\read.token",
            Capability::Read,
        )?;
        assert_eq!(
            config.expected_server_executable,
            Some(std::env::current_exe()?)
        );
        Ok(())
    }
}

fn validate_client_token(path: &std::path::Path) -> Result<()> {
    // AuthReferences validates owner-only permissions for both server token
    // files.  Reuse the same path checks by constructing a distinct dummy
    // reference only after confirming the companion file is present is not
    // possible here, so retain the strict local checks directly.
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || path.as_os_str().to_string_lossy().len() > 4 * 1024
        || path.as_os_str().to_string_lossy().contains('\0')
    {
        return Err(WatchdogError::InvalidInput(
            "admin token path must be absolute and non-empty".to_string(),
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(WatchdogError::InvalidInput(
            "admin token path must name a regular file".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        use super::endpoint::current_uid;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != current_uid() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(WatchdogError::Unauthorized(
                "admin token file is not owner-only".to_string(),
            ));
        }
    }
    #[cfg(windows)]
    {
        ascension_platform_windows::validate_protected_credential_file(path).map_err(|_| {
            WatchdogError::Unauthorized("admin token file is not owner-protected".to_string())
        })?;
    }
    Ok(())
}

fn read_client_token(path: &std::path::Path) -> Result<String> {
    let bytes = fs::read(path)?;
    if bytes.is_empty()
        || bytes.len() > 4 * 1024
        || bytes.contains(&0)
        || !bytes.is_ascii()
        || bytes.iter().any(u8::is_ascii_whitespace)
    {
        return Err(WatchdogError::InvalidInput(
            "admin token is empty, non-ASCII, whitespace-containing, or oversized".to_string(),
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| WatchdogError::InvalidInput("admin token is not valid UTF-8".to_string()))
}

#[cfg(unix)]
fn write_frame(stream: &mut std::os::unix::net::UnixStream, bytes: &[u8]) -> std::io::Result<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| std::io::Error::other("frame bound"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()
}

#[cfg(unix)]
fn read_frame(stream: &mut std::os::unix::net::UnixStream) -> Result<Vec<u8>> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(WatchdogError::InvalidInput(
            "response exceeds frame bound".to_string(),
        ));
    }
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
