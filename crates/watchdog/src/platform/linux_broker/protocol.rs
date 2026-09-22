//! Broker protocol and policy documents.
//!
//! Closed request and lifecycle envelopes, the fixed launch-policy model and
//! the strict JSON document loader.  These schemas are security boundaries:
//! unknown members are rejected by serde, duplicate object members are
//! rejected before typed deserialization, and every capability, resource and
//! identity bound is enforced while the policy is loaded.  The shared
//! protocol constants and the broker error vocabulary stay with the
//! coordinator module.

#[allow(clippy::wildcard_imports)]
use super::*;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The only component selector accepted over the broker socket.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BrokerComponent {
    Gateway,
    Harness,
    HostBroker,
    Synthetic,
}

impl BrokerComponent {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::Harness => "harness",
            Self::HostBroker => "hostbroker",
            Self::Synthetic => "synthetic",
        }
    }
}

/// Closed request schema. Unknown fields are rejected by serde.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerRequest {
    pub component: BrokerComponent,
    pub instance: String,
    pub incarnation: String,
    pub nonce: String,
}

impl BrokerRequest {
    pub(super) fn validate(&self) -> BrokerResult<()> {
        validate_identity("instance", &self.instance)?;
        validate_identity("incarnation", &self.incarnation)?;
        validate_identity("nonce", &self.nonce)
    }
}

/// Versioned lifecycle operations are deliberately separate from the legacy
/// four-field launch request.  The nested request is the only identity a
/// lifecycle operation can name; paths, PIDs and unit names are never
/// accepted from a caller.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BrokerLifecycleOperation {
    Inspect,
    Stop,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BrokerLifecycleState {
    Active,
    Stopped,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerLifecycleRequest {
    pub version: u8,
    pub operation: BrokerLifecycleOperation,
    pub request: BrokerRequest,
}

impl BrokerLifecycleRequest {
    pub(super) fn validate(&self) -> BrokerResult<()> {
        if self.version != BROKER_PROTOCOL_VERSION {
            return Err(BrokerError::Invalid(
                "unsupported broker lifecycle protocol version".to_owned(),
            ));
        }
        self.request.validate()
    }
}

/// accepted connection in addition to the kernel-provided UID/GID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerPolicy {
    pub uid: u32,
    pub gid: u32,
    pub executable: PathBuf,
    pub executable_sha256: String,
}

/// Explicit capability and cgroup constraints sent to systemd.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CapabilityPolicy {
    pub bounding_set: u64,
    pub ambient_set: u64,
    pub no_new_privileges: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CgroupPolicy {
    pub tasks_max: u64,
    pub memory_max_bytes: u64,
}

/// Immutable launch details. There is no conversion from BrokerRequest into
/// this type without a fixed policy lookup.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LaunchPolicy {
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub arguments: Vec<String>,
    pub working_directory: PathBuf,
    pub environment: Vec<(String, String)>,
    pub target_uid: u32,
    pub target_gid: u32,
    pub capabilities: CapabilityPolicy,
    pub cgroup: CgroupPolicy,
    pub timeout: Duration,
}

/// Policy object used by the broker after loading and validating its protected
/// source. Component target UIDs/GIDs must each be distinct from the peer and
/// from every other component; this is checked independently for each ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerPolicy {
    pub(super) peer: PeerPolicy,
    pub(super) components: BTreeMap<BrokerComponent, LaunchPolicy>,
}

impl BrokerPolicy {
    pub fn new(
        peer: PeerPolicy,
        components: BTreeMap<BrokerComponent, LaunchPolicy>,
    ) -> BrokerResult<Self> {
        if components.is_empty() || components.len() > MAX_POLICY_COMPONENTS {
            return Err(BrokerError::Invalid(
                "component policy count is out of bounds".to_owned(),
            ));
        }
        validate_peer(&peer)?;
        let mut target_uid_set = BTreeSet::from([peer.uid]);
        let mut target_gid_set = BTreeSet::from([peer.gid]);
        for policy in components.values() {
            validate_launch_policy(policy)?;
            if !target_uid_set.insert(policy.target_uid) {
                return Err(BrokerError::Invalid(
                    "component target UIDs must be distinct from the peer and each other"
                        .to_owned(),
                ));
            }
            if !target_gid_set.insert(policy.target_gid) {
                return Err(BrokerError::Invalid(
                    "component target GIDs must be distinct from the peer and each other"
                        .to_owned(),
                ));
            }
        }
        Ok(Self { peer, components })
    }

    pub fn component(&self, component: BrokerComponent) -> BrokerResult<&LaunchPolicy> {
        self.components.get(&component).ok_or_else(|| {
            BrokerError::Unauthorized("component is not in the fixed policy".to_owned())
        })
    }

    /// Load a root-owned JSON policy. The parser has no request-controlled
    /// fallback or default component entries.
    pub fn from_file(path: &Path) -> BrokerResult<Self> {
        validate_protected_file(path, "broker policy")?;
        let bytes = read_bounded_file(path, MAX_FRAME_BYTES, "broker policy")?;
        let document: PolicyDocument = parse_json(&bytes, "broker policy JSON")?;
        let peer = PeerPolicy {
            uid: document.peer.uid,
            gid: document.peer.gid,
            executable: document.peer.executable,
            executable_sha256: document.peer.executable_sha256,
        };
        let components = document
            .components
            .into_iter()
            .map(|(component, entry)| {
                Ok((
                    component,
                    LaunchPolicy {
                        executable: entry.executable,
                        executable_sha256: entry.executable_sha256,
                        arguments: entry.arguments,
                        working_directory: entry.working_directory,
                        environment: entry.environment,
                        target_uid: entry.target_uid,
                        target_gid: entry.target_gid,
                        capabilities: CapabilityPolicy {
                            bounding_set: entry.capabilities.bounding_set,
                            ambient_set: entry.capabilities.ambient_set,
                            no_new_privileges: entry.capabilities.no_new_privileges,
                        },
                        cgroup: CgroupPolicy {
                            tasks_max: entry.cgroup.tasks_max,
                            memory_max_bytes: entry.cgroup.memory_max_bytes,
                        },
                        timeout: Duration::from_millis(entry.timeout_ms),
                    },
                ))
            })
            .collect::<BrokerResult<BTreeMap<_, _>>>()?;
        Self::new(peer, components)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    peer: PeerPolicyDocument,
    components: BTreeMap<BrokerComponent, LaunchPolicyDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerPolicyDocument {
    uid: u32,
    gid: u32,
    executable: PathBuf,
    executable_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchPolicyDocument {
    executable: PathBuf,
    executable_sha256: String,
    arguments: Vec<String>,
    working_directory: PathBuf,
    environment: Vec<(String, String)>,
    target_uid: u32,
    target_gid: u32,
    capabilities: CapabilityPolicyDocument,
    cgroup: CgroupPolicyDocument,
    timeout_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityPolicyDocument {
    bounding_set: u64,
    ambient_set: u64,
    no_new_privileges: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CgroupPolicyDocument {
    tasks_max: u64,
    memory_max_bytes: u64,
}

/// serde_json normally keeps the last value for a duplicate object member.
/// The broker's policy, request and receipt schemas are security boundaries,
/// so duplicate members are rejected before typed deserialization.
#[derive(Debug, Serialize)]
pub(crate) enum StrictJsonValue {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Self>),
    Object(serde_json::Map<String, serde_json::Value>),
}

impl StrictJsonValue {
    pub(super) fn into_value(self) -> serde_json::Value {
        match self {
            Self::Null => serde_json::Value::Null,
            Self::Bool(value) => serde_json::Value::Bool(value),
            Self::Number(value) => serde_json::Value::Number(value),
            Self::String(value) => serde_json::Value::String(value),
            Self::Array(values) => {
                serde_json::Value::Array(values.into_iter().map(Self::into_value).collect())
            }
            Self::Object(values) => serde_json::Value::Object(values),
        }
    }
}

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> serde::de::Visitor<'de> for StrictVisitor {
            type Value = StrictJsonValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value with unique object members")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictJsonValue::Null)
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictJsonValue::Bool(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictJsonValue::Number(serde_json::Number::from(value)))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictJsonValue::Number(serde_json::Number::from(value)))
            }

            fn visit_i128<E>(self, value: i128) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_i128(value)
                    .map(StrictJsonValue::Number)
                    .ok_or_else(|| E::custom("JSON integer is out of bounds"))
            }

            fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_u128(value)
                    .map(StrictJsonValue::Number)
                    .ok_or_else(|| E::custom("JSON integer is out of bounds"))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(StrictJsonValue::Number)
                    .ok_or_else(|| E::custom("JSON number is not finite"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictJsonValue::String(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictJsonValue::String(value))
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
                    values.push(value);
                }
                Ok(StrictJsonValue::Array(values))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut keys = BTreeSet::new();
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key.clone()) {
                        return Err(serde::de::Error::custom(
                            "duplicate JSON object member is not allowed",
                        ));
                    }
                    let value = map.next_value::<StrictJsonValue>()?.into_value();
                    values.insert(key, value);
                }
                Ok(StrictJsonValue::Object(values))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

pub(crate) fn parse_json<T: DeserializeOwned>(bytes: &[u8], label: &str) -> BrokerResult<T> {
    let value: StrictJsonValue = serde_json::from_slice(bytes)
        .map_err(|error| BrokerError::Invalid(format!("{label} is invalid: {error}")))?;
    serde_json::from_value(value.into_value())
        .map_err(|error| BrokerError::Invalid(format!("{label} schema is invalid: {error}")))
}

fn validate_peer(peer: &PeerPolicy) -> BrokerResult<()> {
    if peer.uid == 0 || peer.gid == 0 {
        return Err(BrokerError::Invalid(
            "broker peer must be a distinct non-root UID/GID".to_owned(),
        ));
    }
    validate_sha256(&peer.executable_sha256)?;
    validate_protected_file(&peer.executable, "broker peer executable")?;
    let actual = hash_file(&peer.executable)?;
    if actual != peer.executable_sha256 {
        return Err(BrokerError::Invalid(
            "broker peer executable digest does not match policy".to_owned(),
        ));
    }
    Ok(())
}

fn validate_launch_policy(policy: &LaunchPolicy) -> BrokerResult<()> {
    validate_sha256(&policy.executable_sha256)?;
    validate_protected_file(&policy.executable, "launch executable")?;
    if hash_file(&policy.executable)? != policy.executable_sha256 {
        return Err(BrokerError::Invalid(
            "launch executable digest does not match policy".to_owned(),
        ));
    }
    validate_protected_directory(&policy.working_directory, "working directory")?;
    if policy.target_uid == 0 || policy.target_gid == 0 {
        return Err(BrokerError::Invalid(
            "launch target UID/GID must not be root".to_owned(),
        ));
    }
    if policy.arguments.len() > MAX_ARGUMENTS
        || policy
            .arguments
            .iter()
            .any(|argument| argument.len() > MAX_ARGUMENT_BYTES || argument.contains('\0'))
    {
        return Err(BrokerError::Invalid(
            "launch arguments exceed bounds".to_owned(),
        ));
    }
    if policy.environment.len() > MAX_ENVIRONMENT
        || policy.environment.iter().any(|(name, value)| {
            name.is_empty()
                || name.contains(['=', '\0'])
                || value.contains('\0')
                || name.len().saturating_add(value.len()) > MAX_ENVIRONMENT_BYTES
        })
    {
        return Err(BrokerError::Invalid(
            "launch environment exceeds bounds".to_owned(),
        ));
    }
    if policy.timeout.is_zero() || policy.timeout > MAX_TIMEOUT {
        return Err(BrokerError::Invalid(
            "launch timeout is out of bounds".to_owned(),
        ));
    }
    if !policy.capabilities.no_new_privileges
        || policy.capabilities.bounding_set != 0
        || policy.capabilities.ambient_set != 0
    {
        return Err(BrokerError::Invalid(
            "launch capability policy must have zero capability sets and retain no-new-privileges"
                .to_owned(),
        ));
    }
    if policy.cgroup.tasks_max == 0
        || policy.cgroup.tasks_max > MAX_TASKS
        || policy.cgroup.memory_max_bytes == 0
        || policy.cgroup.memory_max_bytes > MAX_MEMORY_BYTES
    {
        return Err(BrokerError::Invalid(
            "launch cgroup limits are out of bounds".to_owned(),
        ));
    }
    Ok(())
}

fn validate_identity(label: &str, value: &str) -> BrokerResult<()> {
    if value.is_empty()
        || value.len() > MAX_IDENTITY_BYTES
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    {
        return Err(BrokerError::Invalid(format!(
            "{label} is not a bounded identifier"
        )));
    }
    Ok(())
}

pub(crate) fn validate_sha256(value: &str) -> BrokerResult<()> {
    if value.len() != 64 || value.bytes().any(|byte| !byte.is_ascii_hexdigit()) {
        return Err(BrokerError::Invalid(
            "SHA-256 digest is not canonical".to_owned(),
        ));
    }
    Ok(())
}
