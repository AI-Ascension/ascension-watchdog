//! Pure approved gateway-health configuration; no launch secrets are serialized.

use super::{WatchdogConfig, validate_digest, validate_local_path};
use crate::error::{Result, WatchdogError};
use crate::gateway_health::GatewayHealthBinding;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Component, Path};
use uuid::{Uuid, Variant, Version};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayHealthConfig {
    pub component_id: String,
    pub address: SocketAddr,
    pub instance_id: String,
    pub release_digest: String,
    pub gateway_config_digest: String,
    pub profile_digest: String,
    pub runtime_v3_schema_digest: String,
    pub timeout_ms: u64,
}

impl GatewayHealthConfig {
    /// Compare only approved values. This never reads files, connects, or launches.
    pub fn validate(&self, config: &WatchdogConfig) -> Result<()> {
        if self.component_id != "gateway"
            || !self.address.ip().is_loopback()
            || self.address.port() == 0
            || self.timeout_ms == 0
            || self.timeout_ms > 2_000
            || self.timeout_ms > config.probe_interval_ms
            || !canonical_uuid(&self.instance_id)
            || !canonical_uuid(&config.deployment_id)
        {
            return invalid("gateway health endpoint, identity, or deadline is invalid");
        }
        let mut components = config
            .components
            .iter()
            .filter(|c| c.id == self.component_id);
        let Some(component) = components.next() else {
            return invalid("gateway health requires its configured gateway component");
        };
        if components.next().is_some() {
            return invalid("gateway health component is ambiguous");
        }
        validate_launch_capacity(component)?;
        let Some(executable_digest) = &component.executable_sha256 else {
            return invalid("gateway health requires an approved executable digest");
        };
        for digest in [
            executable_digest,
            &self.release_digest,
            &self.gateway_config_digest,
            &self.profile_digest,
            &self.runtime_v3_schema_digest,
        ] {
            validate_digest(digest).map_err(WatchdogError::InvalidInput)?;
            if digest.bytes().all(|byte| byte == b'0') {
                return invalid("gateway health cannot approve an unconfigured zero digest");
            }
        }
        let address = self.address.to_string();
        let required = [
            ("STS2_GATEWAY_ADDR", address.as_str()),
            ("STS2_INSTANCE_ID", self.instance_id.as_str()),
            ("STS2_DEPLOYMENT_ID", config.deployment_id.as_str()),
            ("STS2_GATEWAY_WATCHDOG_HEALTH_BOOTSTRAP", "stdin-v1"),
            ("STS2_RUNTIME_PROFILE", "watchdog-recovery-v1"),
            ("STS2_RECOVERY_RELEASE_DIGEST", self.release_digest.as_str()),
            (
                "STS2_RECOVERY_CONFIG_DIGEST",
                self.gateway_config_digest.as_str(),
            ),
            ("STS2_RECOVERY_PROFILE_DIGEST", self.profile_digest.as_str()),
            (
                "STS2_RECOVERY_RUNTIME_V3_SCHEMA_DIGEST",
                self.runtime_v3_schema_digest.as_str(),
            ),
        ];
        for (name, expected) in required {
            if component.environment.get(name).map(String::as_str) != Some(expected)
                || component
                    .environment
                    .keys()
                    .any(|key| key.eq_ignore_ascii_case(name) && key != name)
            {
                return invalid(
                    "gateway launch environment differs from its approved health binding",
                );
            }
        }
        if component
            .environment
            .keys()
            .any(|key| key.eq_ignore_ascii_case("STS2_GATEWAY_WATCHDOG_LAUNCH_NONCE"))
        {
            return invalid("gateway launch nonce is runtime-owned, not static configuration");
        }
        let Some(recovery_store) = component.environment.get("STS2_RECOVERY_STORE") else {
            return invalid("gateway health requires an explicit owner-local recovery store");
        };
        validate_store_reference(Path::new(recovery_store))?;
        validate_store_reference(&config.database)?;
        if same_store_reference(Path::new(recovery_store), &config.database)
            || component.environment.keys().any(|key| {
                key.eq_ignore_ascii_case("STS2_RECOVERY_STORE") && key != "STS2_RECOVERY_STORE"
            })
        {
            return invalid("gateway recovery store must be a separate bounded local path");
        }
        Ok(())
    }

    /// Bind approved non-secret identity to one newly generated launch nonce.
    pub fn binding(&self, deployment_id: &str, launch_nonce: Uuid) -> Result<GatewayHealthBinding> {
        if !canonical_uuid(deployment_id)
            || launch_nonce.get_variant() != Variant::RFC4122
            || launch_nonce.get_version() != Some(Version::Random)
        {
            return invalid("gateway health launch identity is invalid");
        }
        Ok(GatewayHealthBinding {
            deployment_id: deployment_id.to_owned(),
            instance_id: self.instance_id.clone(),
            launch_nonce,
            release_digest: self.release_digest.clone(),
            config_digest: self.gateway_config_digest.clone(),
            profile_digest: self.profile_digest.clone(),
            runtime_v3_schema_digest: self.runtime_v3_schema_digest.clone(),
        })
    }
}

fn validate_launch_capacity(component: &super::ComponentConfig) -> Result<()> {
    // The nonce is injected after static config validation. Reserve its entry
    // and bytes now so a valid boundary-size config remains launchable.
    let dynamic_bytes = "STS2_GATEWAY_WATCHDOG_LAUNCH_NONCE".len() + 36;
    let bytes = component
        .args
        .iter()
        .map(String::len)
        .chain(
            component
                .environment
                .iter()
                .map(|(name, value)| name.len().saturating_add(value.len())),
        )
        .try_fold(dynamic_bytes, usize::checked_add);
    if component.environment.len() >= super::MAX_ENV_ENTRIES
        || bytes.is_none_or(|size| size > super::MAX_LAUNCH_DATA_BYTES)
    {
        return invalid("gateway launch data must reserve capacity for its runtime-owned nonce");
    }
    Ok(())
}

// These are lexical configuration checks, not filesystem identity proof.
// Runtime admission must still reject links and verify owner-local handles.
fn validate_store_reference(path: &Path) -> Result<()> {
    validate_local_path(path, "gateway health store reference")?;
    let Some(text) = path.to_str() else {
        return invalid("gateway health store reference must be Unicode");
    };
    if !path.is_absolute()
        || path.file_name().is_none()
        || text.len() > 4096
        || text.chars().any(char::is_control)
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        || text.split('/').any(|part| part == "." || part == "..")
        || text.starts_with("//")
    {
        return invalid("gateway health stores require bounded absolute local file paths");
    }
    #[cfg(unix)]
    if ["/dev", "/proc", "/sys"]
        .iter()
        .any(|root| path.starts_with(root))
    {
        return invalid("gateway health stores must not name operating-system pseudo-files");
    }
    #[cfg(windows)]
    {
        if text.starts_with(r"\\")
            || text.get(2..).is_some_and(|suffix| suffix.contains(':'))
            || text
                .split(['/', '\\'])
                .any(|part| part == "." || part == ".." || part.ends_with(['.', ' ']))
        {
            return invalid(
                "gateway health stores reject remote, device, stream, and dotted aliases",
            );
        }
    }
    Ok(())
}

fn same_store_reference(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        // Components collapse repeated separators while retaining the drive.
        let folded = |path: &Path| {
            path.components()
                .map(|part| part.as_os_str().to_string_lossy().to_ascii_lowercase())
                .collect::<Vec<_>>()
        };
        folded(left) == folded(right)
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uuid| {
        !uuid.is_nil() && uuid.get_variant() == Variant::RFC4122 && uuid.to_string() == value
    })
}

fn invalid<T>(message: &str) -> Result<T> {
    Err(WatchdogError::InvalidInput(message.to_owned()))
}
