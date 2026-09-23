//! Pure systemd scope property/proof parsing and bounded durations.
//!
//! These checks never touch systemd or the host, which keeps the negative
//! coverage independent of the local user manager.

use super::{MAX_RUNTIME, MAX_STOP};
use ascension_watchdog::config::validate_digest;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScopeProperties {
    pub(crate) values: BTreeMap<String, String>,
}

impl ScopeProperties {
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    pub(crate) fn state(&self) -> Option<&str> {
        self.get("ActiveState")
    }

    pub(crate) fn control_group(&self) -> Option<&str> {
        self.get("ControlGroup").filter(|value| !value.is_empty())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ScopeProof {
    pub(crate) schema_version: u32,
    pub(crate) state: String,
    pub(crate) unit: String,
    pub(crate) description: String,
    pub(crate) config_path: String,
    pub(crate) config_digest: String,
    pub(crate) daemon_image: String,
    pub(crate) daemon_sha256: String,
    pub(crate) control_group: Option<String>,
    pub(crate) daemon_pid: Option<u32>,
    pub(crate) worker_pid: Option<u32>,
    pub(crate) expected: BTreeMap<String, String>,
    pub(crate) actual: BTreeMap<String, String>,
    pub(crate) detail: String,
}

/// Parse `systemctl show` output without accepting duplicate or malformed
/// fields.  Keeping this parser pure makes the negative tests independent of
/// the local user manager.
pub(crate) fn parse_properties(output: &str) -> Result<ScopeProperties, String> {
    let mut values = BTreeMap::new();
    for line in output.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("systemd property has no '=': {line:?}"));
        };
        if key.is_empty() || values.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(format!("duplicate or empty systemd property: {key:?}"));
        }
    }
    if values.is_empty() {
        return Err("systemd returned no properties".to_owned());
    }
    Ok(ScopeProperties { values })
}

/// Validate all properties that establish bounded, exclusive ownership.
pub(crate) fn validate_scope_properties(
    properties: &ScopeProperties,
    unit: &str,
    description: &str,
) -> Result<String, String> {
    if properties.get("LoadState") == Some("not-found") {
        return Err("scope disappeared before it became active".to_owned());
    }
    if properties.state() != Some("active") {
        return Err(format!("scope is not active: {:?}", properties.state()));
    }
    let id = properties
        .get("Id")
        .ok_or_else(|| "scope has no Id property".to_owned())?;
    if id != unit {
        return Err(format!("scope Id {id:?} does not match {unit:?}"));
    }
    if properties.get("Description") != Some(description) {
        return Err("scope description does not match the owner proof".to_owned());
    }
    if properties.get("Delegate") != Some("yes") {
        return Err("scope is not delegated".to_owned());
    }
    if properties.get("KillMode") != Some("control-group") {
        return Err("scope KillMode is not control-group".to_owned());
    }
    if properties.get("SendSIGKILL") != Some("yes") {
        return Err("scope SendSIGKILL is not enabled".to_owned());
    }
    if properties.get("CollectMode") != Some("inactive-or-failed") {
        return Err("scope is not collectable after stop".to_owned());
    }
    let runtime = parse_duration_usec(
        properties
            .get("RuntimeMaxUSec")
            .ok_or_else(|| "scope has no RuntimeMaxUSec property".to_owned())?,
    )
    .ok_or_else(|| "scope RuntimeMaxUSec is infinite or malformed".to_owned())?;
    if runtime == 0 || runtime > duration_usec(MAX_RUNTIME) {
        return Err(format!(
            "scope runtime bound is outside 0..={MAX_RUNTIME:?}"
        ));
    }
    let timeout = parse_duration_usec(
        properties
            .get("TimeoutStopUSec")
            .ok_or_else(|| "scope has no TimeoutStopUSec property".to_owned())?,
    )
    .ok_or_else(|| "scope TimeoutStopUSec is malformed".to_owned())?;
    if timeout > duration_usec(MAX_STOP) {
        return Err("scope stop timeout exceeds the bounded cleanup limit".to_owned());
    }
    let control_group = properties
        .control_group()
        .ok_or_else(|| "scope has no live ControlGroup property".to_owned())?;
    if !control_group.starts_with('/') || !control_group.ends_with(&format!("/{unit}")) {
        return Err(format!("unexpected scope ControlGroup {control_group:?}"));
    }
    Ok(control_group.to_owned())
}

pub(crate) fn validate_scope_proof(proof: &ScopeProof) -> Result<(), String> {
    if proof.schema_version != 1 {
        return Err("unsupported scope proof schema".to_owned());
    }
    if proof.state != "planned"
        && proof.state != "active"
        && proof.state != "stopped"
        && proof.state != "uncertain"
    {
        return Err(format!("invalid proof state {:?}", proof.state));
    }
    if Path::new(&proof.unit)
        .extension()
        .and_then(|extension| extension.to_str())
        != Some("scope")
        || proof.unit.contains('/')
        || proof.unit.is_empty()
    {
        return Err("invalid transient scope unit".to_owned());
    }
    if proof.description.is_empty()
        || !Path::new(&proof.config_path).is_absolute()
        || !Path::new(&proof.daemon_image).is_absolute()
        || proof.daemon_sha256.len() != 64
        || !proof
            .daemon_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("scope proof has invalid protected identity".to_owned());
    }
    validate_digest(&proof.config_digest)
        .map_err(|error| format!("scope proof config digest is invalid: {error}"))?;
    for (key, expected) in [
        ("Delegate", "yes"),
        ("KillMode", "control-group"),
        ("SendSIGKILL", "yes"),
        ("RuntimeMaxUSec", "<=120s"),
        ("TimeoutStopUSec", "<=5s"),
        ("CollectMode", "inactive-or-failed"),
    ] {
        if proof.expected.get(key).map(String::as_str) != Some(expected) {
            return Err(format!("scope proof expected {key}={expected}"));
        }
    }
    if proof.state == "active" {
        let control_group = proof
            .control_group
            .as_deref()
            .ok_or_else(|| "active scope proof has no cgroup".to_owned())?;
        if !control_group.starts_with('/') || !control_group.ends_with(&format!("/{}", proof.unit))
        {
            return Err("active scope proof cgroup does not identify its unit".to_owned());
        }
        let properties = ScopeProperties {
            values: proof.actual.clone(),
        };
        let actual_group = validate_scope_properties(&properties, &proof.unit, &proof.description)
            .map_err(|error| format!("active proof properties are invalid: {error}"))?;
        if actual_group != control_group {
            return Err("active proof cgroup differs from its actual properties".to_owned());
        }
    }
    Ok(())
}

/// Validate the identity fields returned by a live unit observation.  A
/// state transition is not evidence that the observed object is still the
/// owner-created unit; Id and Description must remain bound to the proof.
pub(crate) fn validate_observed_scope_identity(
    properties: &ScopeProperties,
    unit: &str,
    description: &str,
) -> Result<(), String> {
    if properties.get("Id") != Some(unit) {
        return Err(format!(
            "observed scope Id {:?} does not match {:?}",
            properties.get("Id"),
            unit
        ));
    }
    if properties.get("Description") != Some(description) {
        return Err(format!(
            "observed scope description {:?} does not match {:?}",
            properties.get("Description"),
            description
        ));
    }
    Ok(())
}

/// Validate the cgroup portion of a stopped observation without touching the
/// host.  Runtime code additionally checks the retained directory inode and
/// `cgroup.events` handle; this pure boundary test prevents a recreated unit
/// or missing admission handle from being treated as a successful stop.
pub(crate) fn validate_stopped_scope_identity(
    properties: &ScopeProperties,
    unit: &str,
    description: &str,
    original_control_group: Option<&str>,
) -> Result<(), String> {
    validate_observed_scope_identity(properties, unit, description)?;
    if !matches!(properties.state(), Some("inactive" | "failed")) {
        return Err(format!("scope is not stopped: {:?}", properties.state()));
    }
    let original = original_control_group
        .ok_or_else(|| "stopped observation has no retained original cgroup".to_owned())?;
    if let Some(current) = properties.control_group()
        && current != original
    {
        return Err(format!(
            "observed cgroup {current:?} does not match retained original {original:?}"
        ));
    }
    Ok(())
}

pub(crate) fn duration_usec(duration: Duration) -> u128 {
    duration.as_micros()
}

pub(crate) fn parse_duration_usec(value: &str) -> Option<u128> {
    let mut total = 0_u128;
    let mut token_count = 0_u8;
    for token in value.split_whitespace() {
        let (number, multiplier) = if let Some(value) = token.strip_suffix("min") {
            (value, 60_000_000_u128)
        } else if let Some(value) = token.strip_suffix("ms") {
            (value, 1_000_u128)
        } else if let Some(value) = token.strip_suffix("us") {
            (value, 1_u128)
        } else if let Some(value) = token.strip_suffix('h') {
            (value, 3_600_000_000_u128)
        } else if let Some(value) = token.strip_suffix('d') {
            (value, 86_400_000_000_u128)
        } else {
            (token.strip_suffix('s')?, 1_000_000_u128)
        };
        let amount = number.parse::<u128>().ok()?.checked_mul(multiplier)?;
        total = total.checked_add(amount)?;
        token_count = token_count.checked_add(1)?;
    }
    (token_count != 0).then_some(total)
}
