//! Worker client configuration, binding validation and protected references.
//!
//! The endpoint and credential are owner-local references; credential bytes
//! are never retained here.  `validate_binding` proves the frozen
//! worker-handoff-v1 schema and the identity bounds before any exchange.

use crate::error::{Result, WatchdogError};
use crate::worker_protocol::{MAX_TIMEOUT_MS, SCHEMA_DIGEST};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::auth::{self, WorkerPeerIdentity};

pub(super) const DEFAULT_TIMEOUT_MS: u64 = MAX_TIMEOUT_MS;

/// Immutable client settings for one configured worker component.
///
/// The `binding` must come from the owner-approved worker profile, while the
/// peer identity must come from the configured supervised executable.  No
/// request can replace either value.  Credential bytes are read only when an
/// exchange starts and are not retained by this configuration.
#[derive(Clone)]
pub struct WorkerClientConfig {
    pub(super) endpoint: PathBuf,
    pub(super) credential_path: PathBuf,
    pub(super) binding: crate::storage::WorkerBinding,
    pub(super) peer: WorkerPeerIdentity,
    pub(super) timeout: Duration,
}

impl fmt::Debug for WorkerClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerClientConfig")
            .field("endpoint", &"<protected-endpoint>")
            .field("credential_path", &"<protected-reference>")
            .field("binding", &self.binding)
            .field("peer", &self.peer)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl WorkerClientConfig {
    /// Construct a client configuration with the five-second contract bound.
    pub fn new(
        endpoint: impl Into<PathBuf>,
        credential_path: impl Into<PathBuf>,
        binding: crate::storage::WorkerBinding,
        peer: WorkerPeerIdentity,
    ) -> Result<Self> {
        let config = Self {
            endpoint: endpoint.into(),
            credential_path: credential_path.into(),
            binding,
            peer,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
        };
        config.validate()
    }

    /// Use a shorter per-connection deadline.  A caller cannot extend the
    /// frozen five-second worker transport bound.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self> {
        self.timeout = timeout;
        self.validate()
    }

    /// Protected worker endpoint reference.
    #[must_use]
    pub fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    /// Protected credential reference.  The credential bytes are never
    /// exposed through this API.
    #[must_use]
    pub fn credential_path(&self) -> &Path {
        &self.credential_path
    }

    /// Immutable profile/release/config/schema binding.
    #[must_use]
    pub fn binding(&self) -> &crate::storage::WorkerBinding {
        &self.binding
    }

    /// Configured worker process identity.
    #[must_use]
    pub fn peer(&self) -> &WorkerPeerIdentity {
        &self.peer
    }

    /// Per-exchange deadline.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    pub(super) fn validate(self) -> Result<Self> {
        #[cfg(not(windows))]
        crate::admin::validate_endpoint_path(&self.endpoint)?;
        #[cfg(windows)]
        {
            let endpoint = self.endpoint.to_str().ok_or_else(|| {
                WatchdogError::InvalidInput("worker endpoint must be Unicode".to_owned())
            })?;
            ascension_platform_windows::AdminPipeClient::validate_worker_endpoint(endpoint)
                .map_err(|_| {
                    WatchdogError::InvalidInput("invalid worker pipe endpoint".to_owned())
                })?;
        }
        auth::validate_credential_reference(&self.credential_path)?;
        validate_binding(&self.binding)?;
        if self.timeout.is_zero() || self.timeout > Duration::from_millis(MAX_TIMEOUT_MS) {
            return Err(WatchdogError::InvalidInput(
                "worker client timeout must be between 1ms and 5000ms".to_owned(),
            ));
        }
        Ok(self)
    }
}

fn validate_binding(binding: &crate::storage::WorkerBinding) -> Result<()> {
    if binding.schema_digest != SCHEMA_DIGEST {
        return Err(WatchdogError::Conflict(
            "worker client binding is not the frozen worker-handoff-v1 schema".to_owned(),
        ));
    }
    for (digest, field) in [
        (&binding.worker_profile_digest, "worker profile digest"),
        (&binding.release_digest, "worker release digest"),
        (&binding.config_digest, "worker config digest"),
        (&binding.schema_digest, "worker schema digest"),
    ] {
        crate::config::validate_digest(digest).map_err(|message| {
            WatchdogError::InvalidInput(format!("{field} is invalid: {message}"))
        })?;
    }
    if binding.deployment_id.is_empty()
        || binding.worker_owner_id.is_empty()
        || binding.deployment_id.len() > 128
        || binding.worker_owner_id.len() > 128
        || !binding
            .deployment_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || !binding
            .worker_owner_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(WatchdogError::InvalidInput(
            "worker client binding contains an invalid identity".to_owned(),
        ));
    }
    Ok(())
}
