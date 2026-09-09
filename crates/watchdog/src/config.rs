//! Closed, bounded configuration for the watchdog process.

use crate::error::{Result, WatchdogError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[path = "config_file.rs"]
mod config_file;

#[path = "config_worker.rs"]
mod config_worker;
pub use config_worker::WorkerConfig;

const MAX_COMPONENTS: usize = 16;
const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 8 * 1024;
const MAX_ENV_ENTRIES: usize = 64;
const MAX_ENV_VALUE_BYTES: usize = 8 * 1024;
const MAX_LAUNCH_DATA_BYTES: usize = 32 * 1024;

/// The durable operator intent consumed by the reconciler.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DesiredMode {
    /// No supervised process may be started.
    #[default]
    Stopped,
    /// Existing processes may be observed, but no new job or child starts.
    Paused,
    /// The reconciler may start approved components and claim jobs.
    Running,
    /// Drain existing work and then settle in stopped mode.
    Draining,
}

impl DesiredMode {
    /// True when new work is permitted by operator intent.
    #[must_use]
    pub const fn admits_work(self) -> bool {
        matches!(self, Self::Running)
    }

    /// True when children should be removed by the reconciler.
    #[must_use]
    pub const fn stops_children(self) -> bool {
        matches!(self, Self::Stopped)
    }
}

/// An exact executable allowlist entry.  No wildcard or shell expansion is
/// performed by the process adapter.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentConfig {
    /// Stable component identifier used in audit and retry state.
    pub id: String,
    /// Absolute executable path.  A path alone is not an identity: the
    /// launched child also receives a nonce and an OS creation fingerprint.
    pub executable: PathBuf,
    /// Arguments passed directly to the executable.
    #[serde(default)]
    pub args: Vec<String>,
    /// Optional exact working directory.
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    /// Environment is cleared before these explicit values are installed.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    /// If set, the executable bytes must match this SHA-256 before launch.
    #[serde(default)]
    pub executable_sha256: Option<String>,
    /// Whether the reconciler should restart the component after a crash.
    #[serde(default = "default_true")]
    pub restart: bool,
}

impl std::fmt::Debug for ComponentConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ComponentConfig")
            .field("id", &self.id)
            .field("executable", &self.executable)
            .field("argument_count", &self.args.len())
            .field("cwd", &self.cwd)
            .field("environment_entry_count", &self.environment.len())
            .field("executable_sha256", &self.executable_sha256)
            .field("restart", &self.restart)
            .finish()
    }
}

/// References for authenticated local operator control. Validation is pure:
/// credential files are opened only by the transport at service startup.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    pub endpoint: PathBuf,
    pub read_token_path: PathBuf,
    pub admin_token_path: PathBuf,
    #[serde(default)]
    pub allowed_peer_sid: Option<String>,
}

impl std::fmt::Debug for AdminConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AdminConfig { protected_references: <redacted> }")
    }
}

impl AdminConfig {
    /// Validate syntax without creating endpoints, reading secrets, or opening state.
    pub fn validate(&self) -> Result<()> {
        for path in [&self.read_token_path, &self.admin_token_path] {
            validate_local_path(path, "admin credential reference")?;
            if !path.is_absolute()
                || path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
            {
                return Err(WatchdogError::InvalidInput(
                    "admin credential references must be absolute without traversal".to_owned(),
                ));
            }
        }
        if self.read_token_path == self.admin_token_path {
            return Err(WatchdogError::InvalidInput(
                "read and admin credential references must differ".to_owned(),
            ));
        }
        let endpoint = self.endpoint.to_string_lossy();
        if endpoint.len() > 240 || endpoint.contains('\0') || endpoint.is_empty() {
            return Err(WatchdogError::InvalidInput(
                "admin endpoint is outside bounds".to_owned(),
            ));
        }
        #[cfg(unix)]
        {
            validate_local_path(&self.endpoint, "admin endpoint")?;
            if !self.endpoint.is_absolute()
                || endpoint.len() > 100
                || self
                    .endpoint
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
                || self.allowed_peer_sid.is_some()
            {
                return Err(WatchdogError::InvalidInput("Unix admin endpoint must be a bounded absolute socket path without a Windows SID".to_owned()));
            }
        }
        #[cfg(windows)]
        if !endpoint.starts_with(r"\\.\pipe\ascension-watchdog-")
            || endpoint[9..].contains(['/', '\\'])
        {
            return Err(WatchdogError::InvalidInput(
                "admin pipe must use the restricted local namespace".to_owned(),
            ));
        }
        if let Some(sid) = &self.allowed_peer_sid {
            if sid.len() > 184
                || !sid.starts_with("S-1-")
                || !sid[4..]
                    .split('-')
                    .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
            {
                return Err(WatchdogError::InvalidInput(
                    "admin peer SID syntax is invalid".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Top-level watchdog configuration.  Unknown fields are rejected so a typo
/// cannot silently weaken an admission or process policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WatchdogConfig {
    /// Configuration schema revision.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Stable deployment identity for this owner-local store.
    #[serde(default = "default_deployment_id")]
    pub deployment_id: String,
    /// Owner-local SQLite database path.
    #[serde(default = "default_database")]
    pub database: PathBuf,
    /// Initial desired mode used only when the store is initialized.
    #[serde(default)]
    pub desired_mode: DesiredMode,
    /// Polling interval in milliseconds.
    #[serde(default = "default_probe_interval_ms")]
    pub probe_interval_ms: u64,
    /// Consecutive failed probes before a component becomes suspect.
    #[serde(default = "default_suspect_threshold")]
    pub suspect_threshold: u32,
    /// Maximum startup grace period.
    #[serde(default = "default_startup_grace_secs")]
    pub startup_grace_secs: u64,
    /// Lease time-to-live for future authority integrations.
    #[serde(default = "default_lease_ttl_secs")]
    pub lease_ttl_secs: u64,
    /// Lease renewal period.
    #[serde(default = "default_lease_renewal_secs")]
    pub lease_renewal_secs: u64,
    /// Initial deterministic restart backoff.
    #[serde(default = "default_restart_backoff_base_secs")]
    pub restart_backoff_base_secs: u64,
    /// Maximum deterministic restart backoff.
    #[serde(default = "default_restart_backoff_cap_secs")]
    pub restart_backoff_cap_secs: u64,
    /// Maximum restarts in the configured window.
    #[serde(default = "default_restart_budget_count")]
    pub restart_budget_count: u32,
    /// Restart-budget rolling window.
    #[serde(default = "default_restart_budget_window_secs")]
    pub restart_budget_window_secs: u64,
    /// Maximum unresolved gateway operations the watchdog will admit from a
    /// future authenticated gateway status adapter.  The watchdog does not
    /// own or settle the gateway journal.
    #[serde(default = "default_max_unresolved_operations")]
    pub max_unresolved_operations: u32,
    /// Maximum job payload retained by the watchdog store.
    #[serde(default = "default_max_payload_bytes")]
    pub max_payload_bytes: usize,
    /// Maximum jobs retained before admission is backpressured.
    #[serde(default = "default_max_jobs")]
    pub max_jobs: u64,
    /// Explicit provider deadline retained for the future harness adapter.
    #[serde(default = "default_provider_timeout_secs")]
    pub provider_timeout_secs: u64,
    /// Exact approved child definitions.
    #[serde(default)]
    pub components: Vec<ComponentConfig>,
    /// Development-only escape hatch for the synthetic subprocess harness.
    /// Production configurations must leave this false, use only gateway and
    /// harness roles, and pin executable bytes with SHA-256.
    #[serde(default)]
    pub allow_synthetic_children: bool,
    /// Explicit local authenticated control endpoint and protected credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<AdminConfig>,
    /// Explicit immutable harness-worker binding. Absence leaves scheduling disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker: Option<WorkerConfig>,
    /// Normalized absolute source path captured when this configuration was loaded from
    /// disk.  It is deliberately not part of the serialized configuration or
    /// its digest; native launch admission uses it only as a protected,
    /// separately supplied reference for fresh durable authorization (Linux
    /// helper release and Windows worker pre-resume admission).
    #[serde(skip)]
    pub source_path: Option<PathBuf>,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            schema_version: default_schema_version(),
            deployment_id: default_deployment_id(),
            database: default_database(),
            desired_mode: DesiredMode::Stopped,
            probe_interval_ms: default_probe_interval_ms(),
            suspect_threshold: default_suspect_threshold(),
            startup_grace_secs: default_startup_grace_secs(),
            lease_ttl_secs: default_lease_ttl_secs(),
            lease_renewal_secs: default_lease_renewal_secs(),
            restart_backoff_base_secs: default_restart_backoff_base_secs(),
            restart_backoff_cap_secs: default_restart_backoff_cap_secs(),
            restart_budget_count: default_restart_budget_count(),
            restart_budget_window_secs: default_restart_budget_window_secs(),
            max_unresolved_operations: default_max_unresolved_operations(),
            max_payload_bytes: default_max_payload_bytes(),
            max_jobs: default_max_jobs(),
            provider_timeout_secs: default_provider_timeout_secs(),
            components: Vec::new(),
            allow_synthetic_children: false,
            admin: None,
            worker: None,
            source_path: None,
        }
    }
}

impl WatchdogConfig {
    /// Read and validate a JSON configuration without touching the database.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let (bytes, source_path) = config_file::read(path.as_ref())?;
        let mut config: Self = serde_json::from_slice(&bytes)?;
        // Keep the helper bootstrap independent from a caller-controlled
        // relative path and reject missing, indirect, or non-regular sources
        // before a daemon can start.
        // The Linux helper performs a second owner/readability check immediately
        // before it opens this path.
        config.source_path = Some(source_path);
        config.validate()?;
        Ok(config)
    }

    /// Encode a stable, human-readable configuration file.
    pub fn to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        self.validate()?;
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let bytes = serde_json::to_vec_pretty(self)?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    /// Validate closed bounded values and local-storage policy.
    pub fn validate(&self) -> Result<()> {
        if let Some(admin) = &self.admin {
            admin.validate()?;
        }
        if let Some(worker) = &self.worker {
            worker.validate(self)?;
        }
        if self.schema_version != 1 {
            return Err(WatchdogError::InvalidInput(format!(
                "unsupported config schema {}",
                self.schema_version
            )));
        }
        validate_identifier("deployment_id", &self.deployment_id, 128)?;
        validate_local_path(&self.database, "database")?;
        if self.probe_interval_ms == 0 {
            return Err(WatchdogError::InvalidInput(
                "probe_interval_ms must be greater than zero".to_string(),
            ));
        }
        if self.suspect_threshold == 0 {
            return Err(WatchdogError::InvalidInput(
                "suspect_threshold must be greater than zero".to_string(),
            ));
        }
        if self.startup_grace_secs == 0 {
            return Err(WatchdogError::InvalidInput(
                "startup_grace_secs must be greater than zero".to_string(),
            ));
        }
        if self.lease_ttl_secs == 0 || self.lease_renewal_secs == 0 {
            return Err(WatchdogError::InvalidInput(
                "lease TTL and renewal must be greater than zero".to_string(),
            ));
        }
        if self.lease_renewal_secs >= self.lease_ttl_secs {
            return Err(WatchdogError::InvalidInput(
                "lease renewal must be shorter than TTL".to_string(),
            ));
        }
        if self.restart_backoff_base_secs == 0
            || self.restart_backoff_cap_secs == 0
            || self.restart_backoff_base_secs > self.restart_backoff_cap_secs
        {
            return Err(WatchdogError::InvalidInput(
                "restart backoff must be non-zero and base <= cap".to_string(),
            ));
        }
        if self.restart_budget_count == 0 || self.restart_budget_window_secs == 0 {
            return Err(WatchdogError::InvalidInput(
                "restart budget count and window must be non-zero".to_string(),
            ));
        }
        if self.max_unresolved_operations == 0 || self.max_payload_bytes == 0 || self.max_jobs == 0
        {
            return Err(WatchdogError::InvalidInput(
                "resource bounds must be non-zero".to_string(),
            ));
        }
        if self.provider_timeout_secs == 0 {
            return Err(WatchdogError::InvalidInput(
                "provider_timeout_secs must be greater than zero".to_string(),
            ));
        }
        if self.components.len() > MAX_COMPONENTS {
            return Err(WatchdogError::InvalidInput(format!(
                "at most {MAX_COMPONENTS} components are supported"
            )));
        }
        let mut ids = std::collections::BTreeSet::new();
        for component in &self.components {
            validate_identifier("component id", &component.id, 128)?;
            if !ids.insert(&component.id) {
                return Err(WatchdogError::InvalidInput(format!(
                    "duplicate component id {}",
                    component.id
                )));
            }
            if !component.executable.is_absolute() {
                return Err(WatchdogError::InvalidInput(format!(
                    "component {} executable must be absolute",
                    component.id
                )));
            }
            validate_local_path(&component.executable, "component executable")?;
            if component.executable.as_os_str().is_empty() {
                return Err(WatchdogError::InvalidInput(format!(
                    "component {} executable is empty",
                    component.id
                )));
            }
            if component.args.len() > MAX_ARGUMENTS
                || component.args.iter().any(|arg| {
                    arg.as_bytes().len() > MAX_ARGUMENT_BYTES || arg.as_bytes().contains(&0)
                })
            {
                return Err(WatchdogError::InvalidInput(format!(
                    "component {} has an oversized or NUL-containing argument",
                    component.id
                )));
            }
            if let Some(cwd) = &component.cwd {
                if !cwd.is_absolute() {
                    return Err(WatchdogError::InvalidInput(format!(
                        "component {} cwd must be absolute",
                        component.id
                    )));
                }
                validate_local_path(cwd, "component cwd")?;
            }
            if component.environment.len() > MAX_ENV_ENTRIES {
                return Err(WatchdogError::InvalidInput(format!(
                    "component {} has too many environment entries",
                    component.id
                )));
            }
            for (key, value) in &component.environment {
                if key.is_empty()
                    || key.len() > 128
                    || key.contains('=')
                    || key.as_bytes().contains(&0)
                    || value.as_bytes().contains(&0)
                    || value.len() > MAX_ENV_VALUE_BYTES
                {
                    return Err(WatchdogError::InvalidInput(format!(
                        "component {} has an invalid environment entry",
                        component.id
                    )));
                }
            }
            let launch_bytes = component
                .args
                .iter()
                .map(String::len)
                .chain(
                    component
                        .environment
                        .iter()
                        .map(|(key, value)| key.len().saturating_add(value.len())),
                )
                .fold(0_usize, usize::saturating_add);
            if launch_bytes > MAX_LAUNCH_DATA_BYTES {
                return Err(WatchdogError::InvalidInput(
                    "component launch data exceeds aggregate byte limit".to_owned(),
                ));
            }
            if let Some(digest) = &component.executable_sha256 {
                validate_digest(digest).map_err(|message| {
                    WatchdogError::InvalidInput(format!("component {}: {message}", component.id))
                })?;
            }
            if !self.allow_synthetic_children
                && (component.id != "gateway" && component.id != "harness"
                    || component.executable_sha256.is_none())
            {
                return Err(WatchdogError::InvalidInput(
                    "production components must be gateway/harness roles with an approved executable hash"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Return a digest suitable for audit/release records.
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        Ok(hex_digest(&bytes))
    }
}

/// Validate a lowercase SHA-256 string.
pub fn validate_digest(value: &str) -> std::result::Result<(), String> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err("digest must be 64 lowercase hexadecimal characters".to_string());
    }
    Ok(())
}

/// Hash bytes without exposing them in logs or status output.
#[must_use]
pub fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_identifier(name: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.as_bytes().contains(&0)
        || value.chars().any(char::is_control)
    {
        return Err(WatchdogError::InvalidInput(format!(
            "{name} must be non-empty, bounded, and free of control characters"
        )));
    }
    Ok(())
}

fn validate_local_path(path: &Path, name: &str) -> Result<()> {
    if path.as_os_str().is_empty() || path.to_string_lossy().contains('\0') {
        return Err(WatchdogError::InvalidInput(format!(
            "{name} path is empty or contains NUL"
        )));
    }
    let text = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if text.starts_with("/mnt/") || text.starts_with("//wsl") || text.contains("/proc/") {
        return Err(WatchdogError::InvalidInput(format!(
            "{name} must be owner-local, not a shared mount or proc path"
        )));
    }
    Ok(())
}

const fn default_true() -> bool {
    true
}
const fn default_schema_version() -> u32 {
    1
}
fn default_deployment_id() -> String {
    "default".to_string()
}
fn default_database() -> PathBuf {
    PathBuf::from("local/watchdog.sqlite3")
}
const fn default_probe_interval_ms() -> u64 {
    2_000
}
const fn default_suspect_threshold() -> u32 {
    3
}
const fn default_startup_grace_secs() -> u64 {
    90
}
const fn default_lease_ttl_secs() -> u64 {
    30
}
const fn default_lease_renewal_secs() -> u64 {
    10
}
const fn default_restart_backoff_base_secs() -> u64 {
    1
}
const fn default_restart_backoff_cap_secs() -> u64 {
    60
}
const fn default_restart_budget_count() -> u32 {
    5
}
const fn default_restart_budget_window_secs() -> u64 {
    600
}
const fn default_max_unresolved_operations() -> u32 {
    1
}
const fn default_max_payload_bytes() -> usize {
    64 * 1024
}
const fn default_max_jobs() -> u64 {
    1_024
}
const fn default_provider_timeout_secs() -> u64 {
    120
}
