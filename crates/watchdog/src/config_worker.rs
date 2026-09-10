// SPDX-License-Identifier: MIT

//! Pure configuration validation for the dedicated harness-worker channel.
//! Paths are references, not trusted handles: the client must validate peer,
//! protected storage and live process identity at connection time.

use super::{WatchdogConfig, validate_digest, validate_local_path};
use crate::error::{Result, WatchdogError};
use crate::worker_protocol::{MAX_TIMEOUT_MS, SCHEMA_DIGEST};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerConfig {
    pub component_id: String,
    pub endpoint_namespace: PathBuf,
    pub credential_path: PathBuf,
    #[serde(default)]
    pub allowed_peer_sid: Option<String>,
    pub worker_profile_digest: String,
    pub release_digest: String,
    pub worker_config_digest: String,
    pub schema_digest: String,
    pub timeout_ms: u64,
}

impl std::fmt::Debug for WorkerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WorkerConfig { protected_binding: <redacted> }")
    }
}

impl WatchdogConfig {
    /// Derive the worker's immutable binding from approved configuration only.
    /// The wire config digest belongs to the harness; `digest()` separately
    /// identifies the enclosing watchdog configuration.
    pub fn worker_binding(&self) -> Result<Option<crate::storage::WorkerBinding>> {
        self.validate()?;
        Ok(self
            .worker
            .as_ref()
            .map(|worker| crate::storage::WorkerBinding {
                deployment_id: self.deployment_id.clone(),
                worker_owner_id: worker.component_id.clone(),
                worker_profile_digest: worker.worker_profile_digest.clone(),
                release_digest: worker.release_digest.clone(),
                config_digest: worker.worker_config_digest.clone(),
                schema_digest: worker.schema_digest.clone(),
            }))
    }
}

impl WorkerConfig {
    /// Validation performs no filesystem, IPC, store or process operations.
    pub fn validate(&self, config: &WatchdogConfig) -> Result<()> {
        if self.component_id != "harness" {
            return invalid("worker must bind the harness component role");
        }
        let mut matches = config
            .components
            .iter()
            .filter(|c| c.id == self.component_id);
        let Some(component) = matches.next() else {
            return invalid("worker component is not configured");
        };
        if matches.next().is_some() {
            return invalid("worker component is ambiguous");
        }
        let Some(executable_digest) = &component.executable_sha256 else {
            return invalid("worker component requires an immutable executable digest");
        };
        for digest in [
            executable_digest,
            &self.worker_profile_digest,
            &self.release_digest,
            &self.worker_config_digest,
        ] {
            validate_digest(digest).map_err(WatchdogError::InvalidInput)?;
        }
        if self.schema_digest != SCHEMA_DIGEST {
            return invalid("worker handoff schema digest is incompatible");
        }
        if self.timeout_ms == 0 || self.timeout_ms > MAX_TIMEOUT_MS {
            return invalid("worker timeout must be between 1 and 5000 milliseconds");
        }
        validate_reference(&self.credential_path)?;
        self.validate_endpoint()?;
        let namespace = self.endpoint_namespace.to_str().ok_or_else(|| {
            WatchdogError::InvalidInput("worker namespace must be Unicode".to_owned())
        })?;
        if component.environment.iter().any(|(key, _)| {
            key.eq_ignore_ascii_case("STS2_WORKER_ENDPOINT")
                || (key.eq_ignore_ascii_case("STS2_WORKER_ENDPOINT_NAMESPACE")
                    && key != "STS2_WORKER_ENDPOINT_NAMESPACE")
        }) || component
            .environment
            .get("STS2_WORKER_ENDPOINT_NAMESPACE")
            .map(String::as_str)
            != Some(namespace)
        {
            return invalid("worker launch namespace must exactly match approved worker policy");
        }
        if same_reference(&self.endpoint_namespace, &self.credential_path) {
            return invalid("worker endpoint and credential reference must differ");
        }
        if let Some(admin) = &config.admin {
            let overlaps = [&self.endpoint_namespace, &self.credential_path]
                .iter()
                .any(|worker| {
                    [
                        &admin.endpoint,
                        &admin.read_token_path,
                        &admin.admin_token_path,
                    ]
                    .iter()
                    .any(|operator| same_reference(worker, operator))
                });
            if overlaps {
                return invalid("worker and operator channels must have distinct references");
            }
        }
        Ok(())
    }

    fn validate_endpoint(&self) -> Result<()> {
        self.endpoint_for_launch("12345678-1234-4234-8234-123456789abc")?;
        #[cfg(unix)]
        {
            validate_reference(&self.endpoint_namespace)?;
            if self.allowed_peer_sid.is_some() {
                return invalid("Unix worker endpoint must be bounded and cannot specify a SID");
            }
        }
        #[cfg(windows)]
        {
            if let Some(sid) = &self.allowed_peer_sid {
                if sid.len() > 184
                    || !sid.starts_with("S-1-")
                    || !sid[4..]
                        .split('-')
                        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
                {
                    return invalid("worker peer SID syntax is invalid");
                }
            }
        }
        #[cfg(not(any(unix, windows)))]
        return invalid("worker transport is unsupported on this platform");
        #[cfg(any(unix, windows))]
        Ok(())
    }

    pub fn endpoint_for_launch(&self, nonce: &str) -> Result<PathBuf> {
        let namespace = self.endpoint_namespace.to_str().ok_or_else(|| {
            WatchdogError::InvalidInput("worker namespace must be Unicode".to_owned())
        })?;
        #[cfg(windows)]
        let platform = crate::worker_endpoint::EndpointPlatform::Windows;
        #[cfg(not(windows))]
        let platform = crate::worker_endpoint::EndpointPlatform::Linux;
        crate::worker_endpoint::resolve(platform, namespace, nonce).map(PathBuf::from)
    }
}

fn validate_reference(path: &Path) -> Result<()> {
    validate_local_path(path, "worker reference")?;
    let Some(text) = path.to_str() else {
        return invalid("worker reference must be Unicode");
    };
    if !path.is_absolute()
        || path.file_name().is_none()
        || text.len() > 4096
        || text.chars().any(char::is_control)
        || path
            .components()
            .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
    {
        return invalid("worker reference must be a bounded absolute path without traversal");
    }
    #[cfg(unix)]
    if ["/dev", "/proc", "/sys"]
        .iter()
        .any(|root| path.starts_with(root))
    {
        return invalid("worker reference must not name an operating-system pseudo-file");
    }
    #[cfg(windows)]
    if text.starts_with(r"\\") || text.get(2..).is_some_and(|suffix| suffix.contains(':')) {
        return invalid("worker reference must not use a remote namespace or alternate stream");
    }
    Ok(())
}

fn same_reference(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        left.to_string_lossy()
            .replace('/', "\\")
            .eq_ignore_ascii_case(&right.to_string_lossy().replace('/', "\\"))
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

fn invalid<T>(message: &str) -> Result<T> {
    Err(WatchdogError::InvalidInput(message.to_owned()))
}
