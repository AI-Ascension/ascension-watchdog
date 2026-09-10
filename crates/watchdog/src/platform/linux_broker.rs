//! Root-owned Linux launch broker.
//!
//! The normal Linux adapter is intentionally retained as a same-UID delegated
//! cgroup adapter.  This module is the stronger, separately deployed boundary:
//! a small root-owned Unix socket authenticates the watchdog peer and accepts
//! only an opaque component/instance/incarnation/nonce request.  All launch
//! details live in a root-owned immutable policy.  The production backend asks
//! PID 1 over the native D-Bus API to create a transient unit, and acknowledges
//! only after checking the exact unit, process start token, credentials,
//! capabilities and cgroup membership.
//!
//! No request field contains an executable path, argument, environment, user,
//! group or cgroup name.  Those are deliberately unrepresentable at the IPC
//! boundary.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{Gid, fchown};
use rustix::io::Errno;
use rustix::net::sockopt::{socket_error, socket_peercred};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with};
use rustix::process::{Pid, PidfdFlags, pidfd_open};

const MAX_FRAME_BYTES: usize = 16 * 1024;
const MAX_IDENTITY_BYTES: usize = 128;
const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 8 * 1024;
const MAX_ENVIRONMENT: usize = 64;
const MAX_ENVIRONMENT_BYTES: usize = 8 * 1024;
const MAX_POLICY_COMPONENTS: usize = 8;
const MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TASKS: u64 = 4096;
const MAX_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_TIMEOUT: Duration = Duration::from_mins(2);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RECEIPTS: usize = 128;
const MAX_ACTIVE_PROCESSES: usize = 64;
const MAX_LEDGER_REQUESTS: usize = MAX_RECEIPTS;
const MAX_LEDGER_TRANSITIONS: usize = MAX_LEDGER_REQUESTS * 4;
// Each admitted request has room for pending, committed, stop-pending and
// stopped records, including a newline per maximum-sized record. Reopen must
// accept every journal which the bounded transition machine can produce.
const MAX_LEDGER_BYTES: usize = MAX_LEDGER_TRANSITIONS * (MAX_FRAME_BYTES + 1);
const BROKER_UNIT_NAME: &str = "ascension-watchdog-broker.service";
pub const BROKER_PROTOCOL_VERSION: u8 = 1;

pub mod bootstrap;
mod bootstrap_transport;
pub use bootstrap_transport::BrokerBootstrapLaunchError;

fn remaining(deadline: Instant) -> BrokerResult<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| BrokerError::Unavailable("broker operation deadline expired".to_owned()))
}

/// Errors returned by the broker boundary.  Error text intentionally does not
/// echo request-controlled paths or arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerError {
    Invalid(String),
    Unauthorized(String),
    Conflict(String),
    Unavailable(String),
    Io(String),
}

impl fmt::Display for BrokerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid broker request: {message}"),
            Self::Unauthorized(message) => {
                write!(formatter, "unauthorized broker request: {message}")
            }
            Self::Conflict(message) => write!(formatter, "broker conflict: {message}"),
            Self::Unavailable(message) => write!(formatter, "broker unavailable: {message}"),
            Self::Io(message) => write!(formatter, "broker I/O error: {message}"),
        }
    }
}

impl std::error::Error for BrokerError {}

pub type BrokerResult<T> = Result<T, BrokerError>;

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
    fn as_str(self) -> &'static str {
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
    fn validate(&self) -> BrokerResult<()> {
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
    fn validate(&self) -> BrokerResult<()> {
        if self.version != BROKER_PROTOCOL_VERSION {
            return Err(BrokerError::Invalid(
                "unsupported broker lifecycle protocol version".to_owned(),
            ));
        }
        self.request.validate()
    }
}

/// Peer credentials captured from the kernel, not supplied by the request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Root-owned peer allowlist. The executable digest is checked on every
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
    peer: PeerPolicy,
    components: BTreeMap<BrokerComponent, LaunchPolicy>,
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
enum StrictJsonValue {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Self>),
    Object(serde_json::Map<String, serde_json::Value>),
}

impl StrictJsonValue {
    fn into_value(self) -> serde_json::Value {
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

fn parse_json<T: DeserializeOwned>(bytes: &[u8], label: &str) -> BrokerResult<T> {
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

fn validate_sha256(value: &str) -> BrokerResult<()> {
    if value.len() != 64 || value.bytes().any(|byte| !byte.is_ascii_hexdigit()) {
        return Err(BrokerError::Invalid(
            "SHA-256 digest is not canonical".to_owned(),
        ));
    }
    Ok(())
}

fn validate_protected_file(path: &Path, label: &str) -> BrokerResult<()> {
    validate_protected_ancestors(path, label)?;
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_file() || !is_protected_owner(metadata.uid()) || metadata.mode() & 0o022 != 0 {
        return Err(BrokerError::Invalid(format!(
            "{label} must be a root-owned non-writable regular file"
        )));
    }
    Ok(())
}

fn validate_protected_directory(path: &Path, label: &str) -> BrokerResult<()> {
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

fn is_protected_owner(uid: u32) -> bool {
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

fn hash_file(path: &Path) -> BrokerResult<String> {
    hash_open_file(File::open(path).map_err(io_error)?)
}

fn hash_open_file(file: File) -> BrokerResult<String> {
    let deadline = Instant::now()
        .checked_add(MAX_TIMEOUT)
        .unwrap_or_else(Instant::now);
    hash_open_file_until(file, deadline)
}

fn hash_open_file_until(file: File, deadline: Instant) -> BrokerResult<String> {
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

fn read_bounded_file(path: &Path, maximum: usize, label: &str) -> BrokerResult<Vec<u8>> {
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

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = std::fmt::Write::write_fmt(&mut output, format_args!("{byte:02x}"));
    }
    output
}

#[allow(clippy::needless_pass_by_value)]
fn io_error(error: io::Error) -> BrokerError {
    BrokerError::Io(error.to_string())
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

fn authenticate_peer(
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

fn unit_name(request: &BrokerRequest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(request.component.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(request.instance.as_bytes());
    hasher.update([0]);
    hasher.update(request.incarnation.as_bytes());
    hasher.update([0]);
    hasher.update(request.nonce.as_bytes());
    format!(
        "ascension-watchdog-{}-{}.service",
        request.component.as_str(),
        &hex_digest(&hasher.finalize())[..24]
    )
}

/// Process postcondition returned by a backend. The broker does not
/// acknowledge a launch without all fields being populated and checked.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UnitObservation {
    pub unit: String,
    pub pid: u32,
    pub creation_token: String,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub uid: u32,
    pub gid: u32,
    pub capability_bounding_set: u64,
    pub ambient_capabilities: u64,
    pub no_new_privileges: bool,
    pub control_group: String,
}

impl UnitObservation {
    fn verify(&self, unit: &str, policy: &LaunchPolicy) -> BrokerResult<()> {
        if self.unit != unit
            || self.pid == 0
            || self.creation_token.is_empty()
            || self.executable != policy.executable
            || self.executable_sha256 != policy.executable_sha256
            || self.uid != policy.target_uid
            || self.gid != policy.target_gid
            || self.capability_bounding_set != policy.capabilities.bounding_set
            || self.ambient_capabilities != policy.capabilities.ambient_set
            || self.no_new_privileges != policy.capabilities.no_new_privileges
            || !self.control_group.ends_with(&format!("/{unit}"))
        {
            return Err(BrokerError::Conflict(
                "systemd unit postcondition does not match fixed policy".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Public receipt returned to the bounded broker client.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchReceipt {
    pub request: BrokerRequest,
    pub unit: String,
    pub pid: u32,
    pub creation_token: String,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub uid: u32,
    pub gid: u32,
    pub capability_bounding_set: u64,
    pub ambient_capabilities: u64,
    pub control_group: String,
    pub duplicate: bool,
}

/// Result of a versioned inspect or stop operation.  The embedded launch
/// receipt is the broker-owned identity proof; the state is the only mutable
/// part of the lifecycle view.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerLifecycleReceipt {
    pub receipt: LaunchReceipt,
    pub state: BrokerLifecycleState,
    pub duplicate: bool,
}

#[cfg(target_os = "linux")]
mod ledger;
#[cfg(target_os = "linux")]
pub use ledger::BrokerLedger;
#[cfg(target_os = "linux")]
pub use ledger::JobBinding;
pub mod descriptor_store;
pub trait SystemdBackend: QueuedJobBackend {
    fn start(
        &mut self,
        unit: &str,
        request: &BrokerRequest,
        policy: &LaunchPolicy,
        bootstrap: Option<&bootstrap::BrokerBootstrapLaunch>,
        deadline: Instant,
    ) -> BrokerResult<UnitObservation>;
    fn inspect(
        &mut self,
        unit: &str,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<Option<UnitObservation>>;
    /// Capture containment only for the freshly started process after policy
    /// verification. This is not an adoption path for a previous owner's unit.
    fn retain_containment(
        &mut self,
        request: &BrokerRequest,
        expected: &UnitObservation,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<()>;
    /// Require an already retained original capability. Never recover a lost
    /// handle by reopening the unit pathname, even for a matching live process.
    fn require_containment(
        &mut self,
        expected: &UnitObservation,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<()>;
    /// Local original-object proof for cleanup, including an unacknowledged
    /// launch whose manager-store transfer was uncertain. This never permits
    /// a launch acknowledgement or replacement-path acquisition.
    fn require_local_containment(
        &mut self,
        expected: &UnitObservation,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<()>;
    /// Prove the original containment is empty, not merely that its unit name
    /// is absent. Missing retained evidence returns false or an error. This
    /// method performs no termination and grants no new launch authority.
    fn verify_retirement(
        &mut self,
        expected: &LaunchReceipt,
        deadline: Instant,
    ) -> BrokerResult<bool>;
    /// Validate historical cleanup authority against the retained original
    /// object and current policy, without acquiring any new capability.
    fn require_retained_containment(
        &mut self,
        receipt: &LaunchReceipt,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<()>;
    /// Clean up the already-owned containment when no live leader observation
    /// exists. Caller must durably record stop intent first. Never resolve a
    /// PID or unit pathname; success still requires a positive empty witness.
    fn stop_retained_containment(
        &mut self,
        receipt: &LaunchReceipt,
        deadline: Instant,
    ) -> BrokerResult<()>;
    /// Drop only the descriptor-store capability for an already durable
    /// terminal receipt. Failure retains terminal state and is retryable;
    /// callers must never invoke this from read-only inspection.
    fn release_retired(&mut self, receipt: &LaunchReceipt, deadline: Instant) -> BrokerResult<()>;
    /// Stop only the unit object bound to this exact live observation. Native
    /// backends must use an immutable containment capability rather than resolving
    /// the caller-supplied unit name again at effect time.
    fn stop(
        &mut self,
        unit: &str,
        expected: &UnitObservation,
        deadline: Instant,
    ) -> BrokerResult<()>;
}

/// Broker state and exact nonce idempotence. The backend owns all privileged
/// effects; this object owns admission and duplicate handling.
pub struct LinuxSystemdBroker<B> {
    policy: BrokerPolicy,
    backend: B,
    ledger: BrokerLedger,
    receipts: BTreeMap<BrokerRequest, LaunchReceipt>,
    active_units: BTreeSet<String>,
}

impl<B: SystemdBackend> LinuxSystemdBroker<B> {
    pub fn new(policy: BrokerPolicy, backend: B) -> Self {
        Self::new_with_ledger(policy, backend, BrokerLedger::memory())
    }

    pub fn new_with_ledger(policy: BrokerPolicy, backend: B, ledger: BrokerLedger) -> Self {
        Self {
            policy,
            backend,
            ledger,
            receipts: BTreeMap::new(),
            active_units: BTreeSet::new(),
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn handle(
        &mut self,
        credentials: PeerCredentials,
        request: BrokerRequest,
    ) -> BrokerResult<LaunchReceipt> {
        let policy_timeout = self.policy.component(request.component)?.timeout;
        let deadline = Instant::now()
            .checked_add(policy_timeout)
            .unwrap_or_else(Instant::now);
        self.handle_at_deadline(credentials, &request, deadline)
    }

    fn handle_at_deadline(
        &mut self,
        credentials: PeerCredentials,
        request: &BrokerRequest,
        request_deadline: Instant,
    ) -> BrokerResult<LaunchReceipt> {
        self.handle_launch_at_deadline(credentials, request, None, request_deadline)
    }

    /// Launch a fixed policy with a separately typed stdin frame. The caller
    /// still owns durable deployment admission; parsing a frame is not proof
    /// of Running intent. The broker journals only its immutable frame binding.
    pub fn handle_with_bootstrap(
        &mut self,
        credentials: PeerCredentials,
        request: &BrokerRequest,
        bootstrap: &bootstrap::BrokerBootstrapLaunch,
    ) -> BrokerResult<LaunchReceipt> {
        let timeout = self.policy.component(request.component)?.timeout;
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        self.handle_launch_at_deadline(credentials, request, Some(bootstrap), deadline)
    }

    fn handle_launch_at_deadline(
        &mut self,
        credentials: PeerCredentials,
        request: &BrokerRequest,
        bootstrap: Option<&bootstrap::BrokerBootstrapLaunch>,
        request_deadline: Instant,
    ) -> BrokerResult<LaunchReceipt> {
        request.validate()?;
        authenticate_peer(credentials, &self.policy.peer, request_deadline)?;
        if let Some(bootstrap) = bootstrap {
            bootstrap.validate_for_request(request)?;
            bootstrap_transport::authenticate_worker_peer(
                bootstrap,
                credentials,
                &self.policy.peer,
                request_deadline,
            )?;
        }
        let policy = self.policy.component(request.component)?;
        // Validate the sole generated environment value before reserving a
        // nonce. Invalid fixed policy must not create an uncertain launch.
        bootstrap_transport::launch_environment(policy, request, bootstrap)?;
        self.ledger.ensure_healthy()?;
        let unit = unit_name(request);
        if !self.active_units.contains(&unit) && self.active_units.len() >= MAX_ACTIVE_PROCESSES {
            return Err(BrokerError::Unavailable(
                "broker active-process capacity is exhausted".to_owned(),
            ));
        }
        let deadline = request_deadline.min(
            Instant::now()
                .checked_add(policy.timeout)
                .unwrap_or(request_deadline),
        );
        let existing = self.ledger.contains(request);
        if !existing {
            // An active deterministic unit without a durable pre-launch
            // reservation belongs to no recoverable operation.  Inspect it
            // before writing anything so this request can never adopt or stop
            // an orphan left by another broker incarnation.
            if self.backend.inspect(&unit, policy, deadline)?.is_some() {
                return Err(BrokerError::Conflict(
                    "active unit has no durable launch reservation".to_owned(),
                ));
            }
        }
        let newly_reserved = match bootstrap {
            Some(bootstrap) => self.ledger.reserve_with_bootstrap(
                request,
                &unit,
                policy,
                Some(bootstrap.binding()),
            )?,
            None => self.ledger.reserve(request, &unit, policy)?,
        };
        if !newly_reserved {
            if let Some(observation) = self.backend.inspect(&unit, policy, deadline)? {
                observation.verify(&unit, policy)?;
                let receipt = receipt_from(request, &observation, true);
                self.backend
                    .require_containment(&observation, policy, deadline)?;
                self.ledger.commit(request, &receipt)?;
                self.active_units.insert(unit.clone());
                self.cache_receipt(request, &receipt);
                return Ok(receipt);
            }
            return Err(BrokerError::Conflict(
                "durable launch record has no active unit; refusing to relaunch old nonce"
                    .to_owned(),
            ));
        }
        // A start error does not prove that PID 1 created no unit.  Keep the
        // durable pending reservation and leave cleanup to a later exact-unit
        // reconciliation instead of stopping an orphan that may have raced
        // this request.
        let started = self
            .backend
            .start(&unit, request, policy, bootstrap, deadline);
        // Native systemd returns a unique job object before the unit reaches
        // its active postcondition. Bind that exact object into the pending
        // journal before acknowledging either success or failure. A backend
        // without a queued-job authority (the in-memory test backend and the
        // delegated adapter) conservatively leaves the reservation unbound.
        if let Some(job) = self.backend.queued_job_binding(&unit).cloned() {
            // Append the durable binding before consuming the backend's local
            // copy. If the journal is poisoned, the exact job remains
            // available to this broker incarnation for later reconciliation.
            self.ledger.bind_job(request, policy, &job)?;
            let consumed = self
                .backend
                .take_queued_job_binding(&unit, Instant::now() + MAX_CLEANUP_TIMEOUT)?;
            if consumed != job {
                return Err(BrokerError::Conflict(
                    "backend queued job changed while binding its durable identity".to_owned(),
                ));
            }
        }
        let observation = started?;
        // A failed postcondition cannot supply cleanup authority. In
        // particular, do not follow its cgroup or executable identity:
        // they may describe a different process. Preserve the pending
        // reservation for later exact, policy-verified reconciliation.
        observation.verify(&unit, policy)?;
        if let Err(error) = self
            .backend
            .retain_containment(request, &observation, policy, deadline)
        {
            let cleanup = self.cleanup_failed_launch(request, &observation);
            return Err(cleanup_error(error, cleanup));
        }
        let receipt = receipt_from(request, &observation, false);
        if let Err(error) = self.ledger.commit(request, &receipt) {
            if self.ledger.is_poisoned() {
                // The pending reservation and the exact unit remain for a
                // fresh broker owner to reconcile.  Stopping after an
                // uncertain ledger append would create a second unknown
                // effect and is therefore forbidden while this ledger is
                // poisoned.
                return Err(error);
            }
            let cleanup = self.cleanup_failed_launch(request, &observation);
            return Err(cleanup_error(error, cleanup));
        }
        self.active_units.insert(unit);
        self.cache_receipt(request, &receipt);
        Ok(receipt)
    }

    /// Inspect the exact unit reserved for a request.  This path is
    /// intentionally read-only with respect to the durable ledger and never
    /// adopts a unit or repairs a record.
    pub fn inspect(
        &mut self,
        credentials: PeerCredentials,
        request: BrokerRequest,
    ) -> BrokerResult<BrokerLifecycleReceipt> {
        self.lifecycle(credentials, BrokerLifecycleOperation::Inspect, request)
    }

    /// Stop only the exact, currently verified unit belonging to a committed
    /// request.  Ownership remains active until both the backend and the
    /// durable terminal transition are proven.
    pub fn stop(
        &mut self,
        credentials: PeerCredentials,
        request: BrokerRequest,
    ) -> BrokerResult<BrokerLifecycleReceipt> {
        self.lifecycle(credentials, BrokerLifecycleOperation::Stop, request)
    }

    // Keep ownership of the parsed envelope at this request boundary.
    #[allow(clippy::needless_pass_by_value)]
    fn lifecycle(
        &mut self,
        credentials: PeerCredentials,
        operation: BrokerLifecycleOperation,
        request: BrokerRequest,
    ) -> BrokerResult<BrokerLifecycleReceipt> {
        let policy_timeout = self.policy.component(request.component)?.timeout;
        let deadline = Instant::now()
            .checked_add(policy_timeout)
            .unwrap_or_else(Instant::now);
        self.lifecycle_at_deadline(credentials, operation, &request, deadline)
    }

    fn lifecycle_at_deadline(
        &mut self,
        credentials: PeerCredentials,
        operation: BrokerLifecycleOperation,
        request: &BrokerRequest,
        request_deadline: Instant,
    ) -> BrokerResult<BrokerLifecycleReceipt> {
        request.validate()?;
        authenticate_peer(credentials, &self.policy.peer, request_deadline)?;
        let policy = self.policy.component(request.component)?;
        self.ledger.ensure_healthy()?;
        let unit = unit_name(request);
        let deadline = request_deadline.min(
            Instant::now()
                .checked_add(policy.timeout)
                .unwrap_or(request_deadline),
        );
        let Some(record) = self.ledger.lifecycle_record(request, &unit, policy)? else {
            return Err(BrokerError::Conflict(
                "lifecycle request has no durable launch reservation".to_owned(),
            ));
        };
        let record_is_stop_pending = matches!(&record, ledger::LifecycleRecord::StopPending(_));
        match record {
            ledger::LifecycleRecord::Pending => {
                if operation == BrokerLifecycleOperation::Stop {
                    if let Some(job) = self.ledger.pending_job_binding(request, policy)? {
                        // A queued-job cancellation is an effect, but neither
                        // a successful CancelJob call nor a raced JobRemoved
                        // event proves whether the transient unit executed.
                        // Keep the pending reservation and force exact unit
                        // reconciliation before any terminal transition.
                        match self.backend.resolve_queued_job(&job, deadline)? {
                            native::QueuedJobResolution::Queued => {
                                let _ = self.backend.cancel_queued_job(&job, deadline)?;
                            }
                            native::QueuedJobResolution::Gone => {}
                        }
                    }
                }
                Err(BrokerError::Conflict(
                    "lifecycle request has an unresolved launch reservation; exact execution remains uncertain"
                        .to_owned(),
                ))
            }
            ledger::LifecycleRecord::Stopped(persisted) => {
                verify_receipt_identity(&persisted, request, &unit, policy)?;
                match self.backend.inspect(&unit, policy, deadline)? {
                    None => {
                        if operation == BrokerLifecycleOperation::Stop {
                            self.backend.release_retired(&persisted, deadline)?;
                        }
                        Ok(BrokerLifecycleReceipt {
                            receipt: persisted,
                            state: BrokerLifecycleState::Stopped,
                            duplicate: matches!(operation, BrokerLifecycleOperation::Stop),
                        })
                    }
                    Some(observation) => {
                        observation.verify(&unit, policy)?;
                        let current = receipt_from(request, &observation, false);
                        if !ledger::same_process_binding(&persisted, &current) {
                            return Err(BrokerError::Conflict(
                                "terminal lifecycle unit identity was replaced".to_owned(),
                            ));
                        }
                        Err(BrokerError::Conflict(
                            "terminal lifecycle unit was reactivated".to_owned(),
                        ))
                    }
                }
            }
            ledger::LifecycleRecord::Committed(persisted)
            | ledger::LifecycleRecord::StopPending(persisted) => {
                let stop_pending = record_is_stop_pending;
                verify_receipt_identity(&persisted, request, &unit, policy)?;
                let Some(observation) = self.backend.inspect(&unit, policy, deadline)? else {
                    if operation == BrokerLifecycleOperation::Stop {
                        // Errors are not a populated witness and must not
                        // authorize fallback cleanup. Only a readable original
                        // which is not empty may enter the retained-object path.
                        if !self.backend.verify_retirement(&persisted, deadline)? {
                            self.backend
                                .require_retained_containment(&persisted, policy, deadline)?;
                            if !stop_pending {
                                self.ledger.begin_stop(request, &persisted)?;
                            }
                            self.backend
                                .stop_retained_containment(&persisted, deadline)?;
                            if !self.backend.verify_retirement(&persisted, deadline)? {
                                return Err(BrokerError::Conflict(
                                    "original orphan containment retirement is unproven".to_owned(),
                                ));
                            }
                        }
                        let mut stopped_receipt = persisted;
                        stopped_receipt.duplicate = false;
                        // Idempotent when the populated path already synced
                        // intent, or when recovering a prior StopPending.
                        self.ledger.begin_stop(request, &stopped_receipt)?;
                        self.ledger.mark_stopped(request, &stopped_receipt)?;
                        self.active_units.remove(&unit);
                        self.backend.release_retired(&stopped_receipt, deadline)?;
                        return Ok(BrokerLifecycleReceipt {
                            receipt: stopped_receipt,
                            state: BrokerLifecycleState::Stopped,
                            duplicate: false,
                        });
                    }
                    return Err(BrokerError::Conflict(
                        if stop_pending {
                            "stop-pending lifecycle unit is inactive; absence is uncommitted"
                        } else {
                            "committed lifecycle unit is inactive or missing; ownership is uncertain"
                        }
                        .to_owned(),
                    ));
                };
                observation.verify(&unit, policy)?;
                let observed = receipt_from(request, &observation, false);
                if !ledger::same_process_binding(&persisted, &observed) {
                    return Err(BrokerError::Conflict(
                        "live lifecycle unit identity differs from its durable receipt".to_owned(),
                    ));
                }
                if operation == BrokerLifecycleOperation::Inspect {
                    if stop_pending {
                        return Err(BrokerError::Conflict(
                            "lifecycle stop is pending; active state is uncertain".to_owned(),
                        ));
                    }
                    return Ok(BrokerLifecycleReceipt {
                        receipt: observed,
                        state: BrokerLifecycleState::Active,
                        duplicate: false,
                    });
                }

                self.backend
                    .require_local_containment(&observation, policy, deadline)?;

                // Persist the intent before the first potentially destructive
                // backend call. This is the recovery authority if the broker
                // dies or the backend times out after its effect.
                if !stop_pending {
                    self.ledger.begin_stop(request, &observed)?;
                }
                if !self.active_units.contains(&unit)
                    && self.active_units.len() >= MAX_ACTIVE_PROCESSES
                {
                    return Err(BrokerError::Unavailable(
                        "broker active-process capacity is exhausted".to_owned(),
                    ));
                }
                self.active_units.insert(unit.clone());
                self.backend.stop(&unit, &observation, deadline)?;
                let confirmation_deadline = request_deadline.min(
                    Instant::now()
                        .checked_add(policy.timeout.min(MAX_CLEANUP_TIMEOUT))
                        .unwrap_or(request_deadline),
                );
                loop {
                    match self.backend.inspect(&unit, policy, confirmation_deadline)? {
                        None => {
                            if !self
                                .backend
                                .verify_retirement(&persisted, confirmation_deadline)?
                            {
                                return Err(BrokerError::Conflict(
                                    "original containment retirement is unproven".to_owned(),
                                ));
                            }
                            let mut stopped_receipt = persisted;
                            stopped_receipt.duplicate = false;
                            self.ledger.mark_stopped(request, &stopped_receipt)?;
                            self.active_units.remove(&unit);
                            self.backend
                                .release_retired(&stopped_receipt, confirmation_deadline)?;
                            return Ok(BrokerLifecycleReceipt {
                                receipt: stopped_receipt,
                                state: BrokerLifecycleState::Stopped,
                                duplicate: false,
                            });
                        }
                        Some(observation) => {
                            observation.verify(&unit, policy)?;
                            let current = receipt_from(request, &observation, false);
                            if !ledger::same_process_binding(&persisted, &current) {
                                return Err(BrokerError::Conflict(
                                    "unit identity changed while exact stop was in flight"
                                        .to_owned(),
                                ));
                            }
                        }
                    }
                    thread::sleep(remaining(confirmation_deadline)?.min(POLL_INTERVAL));
                }
            }
        }
    }

    fn cache_receipt(&mut self, request: &BrokerRequest, receipt: &LaunchReceipt) {
        if self.receipts.len() < MAX_RECEIPTS || self.receipts.contains_key(request) {
            self.receipts.insert(request.clone(), receipt.clone());
        }
    }

    fn cleanup_failed_launch(
        &mut self,
        request: &BrokerRequest,
        expected: &UnitObservation,
    ) -> BrokerResult<()> {
        self.ledger.ensure_healthy()?;
        let deadline = Instant::now()
            .checked_add(MAX_CLEANUP_TIMEOUT)
            .unwrap_or_else(Instant::now);
        let policy = self.policy.component(request.component)?;
        self.backend
            .require_local_containment(expected, policy, deadline)?;
        let receipt = receipt_from(request, expected, false);
        // A failed acknowledgement still needs a durable exact process binding
        // before cleanup. Pending -> StopPending preserves retry authority
        // without manufacturing a successful launch acknowledgement.
        self.ledger
            .begin_failed_launch_cleanup(request, &receipt, policy)?;
        self.backend.stop(&expected.unit, expected, deadline)?;
        if !self.backend.verify_retirement(&receipt, deadline)? {
            return Err(BrokerError::Conflict(
                "failed launch containment is not proven empty".to_owned(),
            ));
        }
        self.ledger.mark_stopped(request, &receipt)?;
        self.active_units.remove(&expected.unit);
        self.backend.release_retired(&receipt, deadline)
    }
}

fn cleanup_error(error: BrokerError, cleanup: BrokerResult<()>) -> BrokerError {
    match cleanup {
        Ok(()) => error,
        Err(cleanup_error) => BrokerError::Conflict(format!(
            "launch failed and exact-unit cleanup was not proven: {error}; cleanup: {cleanup_error}"
        )),
    }
}

fn receipt_from(
    request: &BrokerRequest,
    observation: &UnitObservation,
    duplicate: bool,
) -> LaunchReceipt {
    LaunchReceipt {
        request: request.clone(),
        unit: observation.unit.clone(),
        pid: observation.pid,
        creation_token: observation.creation_token.clone(),
        executable: observation.executable.clone(),
        executable_sha256: observation.executable_sha256.clone(),
        uid: observation.uid,
        gid: observation.gid,
        capability_bounding_set: observation.capability_bounding_set,
        ambient_capabilities: observation.ambient_capabilities,
        control_group: observation.control_group.clone(),
        duplicate,
    }
}

fn verify_receipt_identity(
    receipt: &LaunchReceipt,
    request: &BrokerRequest,
    unit: &str,
    policy: &LaunchPolicy,
) -> BrokerResult<()> {
    if receipt.request != *request
        || receipt.unit != unit
        || receipt.pid == 0
        || receipt.creation_token.is_empty()
        || receipt.executable != policy.executable
        || receipt.executable_sha256 != policy.executable_sha256
        || receipt.uid != policy.target_uid
        || receipt.gid != policy.target_gid
        || receipt.capability_bounding_set != policy.capabilities.bounding_set
        || receipt.ambient_capabilities != policy.capabilities.ambient_set
        || !receipt.control_group.ends_with(&format!("/{unit}"))
    {
        return Err(BrokerError::Conflict(
            "durable lifecycle receipt does not match fixed policy".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct WireResponse<'a> {
    accepted: bool,
    duplicate: bool,
    receipt: Option<&'a LaunchReceipt>,
    error: Option<&'a str>,
}

#[derive(Serialize)]
struct LifecycleWireResponse<'a> {
    version: u8,
    operation: BrokerLifecycleOperation,
    accepted: bool,
    duplicate: bool,
    state: Option<BrokerLifecycleState>,
    receipt: Option<&'a LaunchReceipt>,
    error: Option<&'a str>,
}

/// Serve one request per connection. A production unit runs this listener as
/// root and does not expose it through TCP or an abstract world-writable name.
pub fn serve<B: SystemdBackend>(
    listener: &UnixListener,
    mut broker: LinuxSystemdBroker<B>,
) -> BrokerResult<()> {
    for connection in listener.incoming() {
        let Ok(mut stream) = connection else {
            // A single failed accept is not allowed to terminate the root
            // broker. The service manager owns restart policy for persistent
            // listener failures.
            continue;
        };
        let deadline = Instant::now()
            .checked_add(MAX_IO_TIMEOUT)
            .unwrap_or_else(Instant::now);
        let result = handle_connection(&mut stream, &mut broker, deadline);
        if let Err(error) = &result {
            let error_text = error.to_string();
            let response = serde_json::to_vec(&WireResponse {
                accepted: false,
                duplicate: false,
                receipt: None,
                error: Some(&error_text),
            });
            if let Ok(response) = response {
                let _ = write_deadline(&mut stream, &response, deadline);
            }
        }
    }
    Ok(())
}

fn handle_connection<B: SystemdBackend>(
    stream: &mut UnixStream,
    broker: &mut LinuxSystemdBroker<B>,
    deadline: Instant,
) -> BrokerResult<()> {
    let credentials = peer_credentials(stream)?;
    // Authenticate before accepting any request bytes. This prevents an
    // untrusted peer from holding a root broker connection open while it
    // trickles a body, and the handle path repeats the check after parsing.
    authenticate_peer(credentials, &broker.policy.peer, deadline)?;
    let bytes = bootstrap_transport::read_request(stream, deadline)?;
    if bootstrap_transport::is_bootstrap_request(&bytes) {
        return bootstrap_transport::handle_connection(
            stream,
            broker,
            credentials,
            &bytes,
            deadline,
        );
    }
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(BrokerError::Invalid(
            "broker request exceeds frame bound".to_owned(),
        ));
    }
    let value: StrictJsonValue = match parse_json(&bytes, "broker request JSON") {
        Ok(value) => value,
        Err(error) => {
            if let Ok(raw) = serde_json::from_slice::<serde_json::Value>(&bytes)
                && raw.as_object().is_some_and(|object| {
                    object.contains_key("version") || object.contains_key("operation")
                })
            {
                let operation = raw
                    .get("operation")
                    .and_then(|value| serde_json::from_value(value.clone()).ok())
                    .unwrap_or(BrokerLifecycleOperation::Inspect);
                let error_text = error.to_string();
                return write_lifecycle_error(stream, deadline, operation, &error_text);
            }
            return Err(error);
        }
    };
    let value = value.into_value();
    let is_lifecycle = value
        .as_object()
        .is_some_and(|object| object.contains_key("version") || object.contains_key("operation"));
    if is_lifecycle {
        let operation = value
            .get("operation")
            .and_then(|value| serde_json::from_value(value.clone()).ok())
            .unwrap_or(BrokerLifecycleOperation::Inspect);
        let lifecycle: BrokerLifecycleRequest = match serde_json::from_value(value) {
            Ok(lifecycle) => lifecycle,
            Err(error) => {
                let error_text = format!("broker lifecycle request schema is invalid: {error}");
                return write_lifecycle_error(stream, deadline, operation, &error_text);
            }
        };
        if let Err(error) = lifecycle.validate() {
            let error_text = error.to_string();
            return write_lifecycle_error(stream, deadline, operation, &error_text);
        }
        let result =
            broker.lifecycle_at_deadline(credentials, operation, &lifecycle.request, deadline);
        match result {
            Ok(receipt) => {
                let response = serde_json::to_vec(&LifecycleWireResponse {
                    version: BROKER_PROTOCOL_VERSION,
                    operation,
                    accepted: true,
                    duplicate: receipt.duplicate,
                    state: Some(receipt.state),
                    receipt: Some(&receipt.receipt),
                    error: None,
                })
                .map_err(|error| BrokerError::Io(error.to_string()))?;
                if response.len() > MAX_FRAME_BYTES {
                    return Err(BrokerError::Unavailable(
                        "broker response exceeds frame bound".to_owned(),
                    ));
                }
                return write_deadline(stream, &response, deadline);
            }
            Err(error) => {
                let error_text = error.to_string();
                return write_lifecycle_error(stream, deadline, operation, &error_text);
            }
        }
    }
    let request: BrokerRequest = serde_json::from_value(value).map_err(|error| {
        BrokerError::Invalid(format!("broker request JSON schema is invalid: {error}"))
    })?;
    let receipt = broker.handle_at_deadline(credentials, &request, deadline)?;
    let response = serde_json::to_vec(&WireResponse {
        accepted: true,
        duplicate: receipt.duplicate,
        receipt: Some(&receipt),
        error: None,
    })
    .map_err(|error| BrokerError::Io(error.to_string()))?;
    if response.len() > MAX_FRAME_BYTES {
        return Err(BrokerError::Unavailable(
            "broker response exceeds frame bound".to_owned(),
        ));
    }
    write_deadline(stream, &response, deadline)
}

fn write_lifecycle_error(
    stream: &mut UnixStream,
    deadline: Instant,
    operation: BrokerLifecycleOperation,
    error: &str,
) -> BrokerResult<()> {
    let response = serde_json::to_vec(&LifecycleWireResponse {
        version: BROKER_PROTOCOL_VERSION,
        operation,
        accepted: false,
        duplicate: false,
        state: None,
        receipt: None,
        error: Some(error),
    })
    .map_err(|serialize_error| BrokerError::Io(serialize_error.to_string()))?;
    if response.len() > MAX_FRAME_BYTES {
        return Err(BrokerError::Unavailable(
            "broker response exceeds frame bound".to_owned(),
        ));
    }
    write_deadline(stream, &response, deadline)
}

fn read_frame(stream: &mut UnixStream, deadline: Instant) -> BrokerResult<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(io_error)?;
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(bytes),
            Ok(count) => {
                bytes.extend_from_slice(&buffer[..count]);
                if bytes.len() > MAX_FRAME_BYTES {
                    return Err(BrokerError::Invalid(
                        "broker request exceeds frame bound".to_owned(),
                    ));
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(io_error(error)),
        }
    }
}

fn write_deadline(stream: &mut UnixStream, bytes: &[u8], deadline: Instant) -> BrokerResult<()> {
    let mut written = 0;
    while written < bytes.len() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(io_error)?;
        match stream.write(&bytes[written..]) {
            Ok(0) => {
                return Err(BrokerError::Io(
                    "broker peer closed during response".to_owned(),
                ));
            }
            Ok(count) => written += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(io_error(error)),
        }
    }
    Ok(())
}

/// Build a listener only at a root-owned, non-world-writable directory. An
/// existing path is never unlinked, avoiding replacement of another broker.
pub fn bind_root_owned_socket(path: &Path, peer_gid: u32) -> BrokerResult<UnixListener> {
    if peer_gid == 0 || peer_gid == u32::MAX {
        return Err(BrokerError::Invalid(
            "broker peer group must be a non-root valid GID".to_owned(),
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| BrokerError::Invalid("broker socket has no parent directory".to_owned()))?;
    validate_protected_directory(parent, "broker socket directory")?;
    if fs::symlink_metadata(path).is_ok() {
        return Err(BrokerError::Conflict(
            "broker socket already exists".to_owned(),
        ));
    }
    let listener = UnixListener::bind(path).map_err(io_error)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660)).map_err(io_error)?;
    fchown(&listener, None, Some(Gid::from_raw(peer_gid)))
        .map_err(|error| BrokerError::Io(error.to_string()))?;
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.uid() != 0 || metadata.gid() != peer_gid || metadata.mode() & 0o007 != 0 {
        return Err(BrokerError::Unauthorized(
            "broker socket ownership or mode is unsafe".to_owned(),
        ));
    }
    Ok(listener)
}

/// Bounded client used by an explicitly selected production launch path.
/// Existing direct cgroup callers remain unchanged until the integrator
/// selects this client in deployment configuration.
#[derive(Clone, Debug)]
pub struct BrokerClient {
    socket: PathBuf,
    timeout: Duration,
}

impl BrokerClient {
    pub fn new(socket: impl Into<PathBuf>, timeout: Duration) -> BrokerResult<Self> {
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(BrokerError::Invalid(
                "broker client timeout is out of bounds".to_owned(),
            ));
        }
        let socket = socket.into();
        if !socket.is_absolute() {
            return Err(BrokerError::Invalid(
                "broker socket must be absolute".to_owned(),
            ));
        }
        let parent = socket.parent().ok_or_else(|| {
            BrokerError::Invalid("broker socket has no parent directory".to_owned())
        })?;
        validate_protected_directory(parent, "broker socket directory")?;
        Ok(Self { socket, timeout })
    }

    pub fn launch(&self, request: &BrokerRequest) -> BrokerResult<LaunchReceipt> {
        request.validate()?;
        let metadata = fs::symlink_metadata(&self.socket).map_err(io_error)?;
        if !metadata.file_type().is_socket() || metadata.uid() != 0 || metadata.mode() & 0o007 != 0
        {
            return Err(BrokerError::Unauthorized(
                "broker socket ownership or type is unsafe".to_owned(),
            ));
        }
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .unwrap_or_else(Instant::now);
        let mut stream = connect_with_deadline(&self.socket, deadline)?;
        let peer = peer_credentials(&stream)?;
        if peer.uid != 0 {
            return Err(BrokerError::Unauthorized(
                "broker peer is not root".to_owned(),
            ));
        }
        let bytes =
            serde_json::to_vec(request).map_err(|error| BrokerError::Io(error.to_string()))?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(BrokerError::Invalid(
                "broker request exceeds frame bound".to_owned(),
            ));
        }
        write_deadline(&mut stream, &bytes, deadline)?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(io_error)?;
        let response = read_frame(&mut stream, deadline)?;
        let response: WireResponseOwned = parse_json(&response, "broker response JSON")?;
        if !response.accepted {
            return Err(BrokerError::Conflict(
                response
                    .error
                    .unwrap_or_else(|| "broker rejected request".to_owned()),
            ));
        }
        let duplicate = response.duplicate;
        let receipt = response.receipt().ok_or_else(|| {
            BrokerError::Unavailable("broker accepted without a receipt".to_owned())
        })?;
        if receipt.request != *request
            || receipt.unit != unit_name(request)
            || receipt.pid == 0
            || receipt.creation_token.is_empty()
            || !receipt.executable.is_absolute()
            || validate_sha256(&receipt.executable_sha256).is_err()
            || receipt.duplicate != duplicate
        {
            return Err(BrokerError::Conflict(
                "broker receipt does not correlate to the request".to_owned(),
            ));
        }
        Ok(receipt)
    }

    pub fn inspect(&self, request: &BrokerRequest) -> BrokerResult<BrokerLifecycleReceipt> {
        self.lifecycle_request(BrokerLifecycleOperation::Inspect, request)
    }

    pub fn stop(&self, request: &BrokerRequest) -> BrokerResult<BrokerLifecycleReceipt> {
        self.lifecycle_request(BrokerLifecycleOperation::Stop, request)
    }

    fn lifecycle_request(
        &self,
        operation: BrokerLifecycleOperation,
        request: &BrokerRequest,
    ) -> BrokerResult<BrokerLifecycleReceipt> {
        request.validate()?;
        let metadata = fs::symlink_metadata(&self.socket).map_err(io_error)?;
        if !metadata.file_type().is_socket() || metadata.uid() != 0 || metadata.mode() & 0o007 != 0
        {
            return Err(BrokerError::Unauthorized(
                "broker socket ownership or type is unsafe".to_owned(),
            ));
        }
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .unwrap_or_else(Instant::now);
        let mut stream = connect_with_deadline(&self.socket, deadline)?;
        let peer = peer_credentials(&stream)?;
        if peer.uid != 0 {
            return Err(BrokerError::Unauthorized(
                "broker peer is not root".to_owned(),
            ));
        }
        let envelope = BrokerLifecycleRequest {
            version: BROKER_PROTOCOL_VERSION,
            operation,
            request: request.clone(),
        };
        let bytes =
            serde_json::to_vec(&envelope).map_err(|error| BrokerError::Io(error.to_string()))?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(BrokerError::Invalid(
                "broker request exceeds frame bound".to_owned(),
            ));
        }
        write_deadline(&mut stream, &bytes, deadline)?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(io_error)?;
        let response = read_frame(&mut stream, deadline)?;
        let response: LifecycleWireResponseOwned =
            parse_json(&response, "broker lifecycle response JSON")?;
        if response.version != BROKER_PROTOCOL_VERSION || response.operation != operation {
            return Err(BrokerError::Conflict(
                "broker lifecycle response protocol does not correlate".to_owned(),
            ));
        }
        if !response.accepted {
            return Err(BrokerError::Conflict(
                response
                    .error
                    .unwrap_or_else(|| "broker rejected lifecycle request".to_owned()),
            ));
        }
        let state = response.state.ok_or_else(|| {
            BrokerError::Unavailable("broker accepted without lifecycle state".to_owned())
        })?;
        if operation == BrokerLifecycleOperation::Stop && state != BrokerLifecycleState::Stopped {
            return Err(BrokerError::Conflict(
                "broker stop response did not reach terminal state".to_owned(),
            ));
        }
        let duplicate = response.duplicate;
        let receipt = response.receipt().ok_or_else(|| {
            BrokerError::Unavailable("broker accepted without a lifecycle receipt".to_owned())
        })?;
        if receipt.request != *request
            || receipt.unit != unit_name(request)
            || receipt.pid == 0
            || receipt.creation_token.is_empty()
            || !receipt.executable.is_absolute()
            || validate_sha256(&receipt.executable_sha256).is_err()
        {
            return Err(BrokerError::Conflict(
                "broker lifecycle receipt does not correlate to the request".to_owned(),
            ));
        }
        Ok(BrokerLifecycleReceipt {
            receipt,
            state,
            duplicate,
        })
    }
}

fn connect_with_deadline(path: &Path, deadline: Instant) -> BrokerResult<UnixStream> {
    let descriptor = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|error| BrokerError::Io(error.to_string()))?;
    let address = SocketAddrUnix::new(path).map_err(|error| BrokerError::Io(error.to_string()))?;
    match connect(&descriptor, &address) {
        Ok(()) => {}
        Err(error) if error == Errno::INPROGRESS || error == Errno::WOULDBLOCK => {
            let mut poll_fds = [PollFd::new(&descriptor, PollFlags::OUT)];
            let timeout = remaining(deadline)?;
            let timespec = Timespec {
                tv_sec: timeout.as_secs().try_into().unwrap_or(i64::MAX),
                tv_nsec: timeout.subsec_nanos().into(),
            };
            if poll(&mut poll_fds, Some(&timespec))
                .map_err(|error| BrokerError::Io(error.to_string()))?
                == 0
            {
                return Err(BrokerError::Unavailable(
                    "broker socket connect deadline expired".to_owned(),
                ));
            }
            match socket_error(&descriptor).map_err(|error| BrokerError::Io(error.to_string()))? {
                Ok(()) => {}
                Err(error) => return Err(BrokerError::Io(error.to_string())),
            }
        }
        Err(error) => return Err(BrokerError::Io(error.to_string())),
    }
    let stream: UnixStream = descriptor.into();
    stream.set_nonblocking(false).map_err(io_error)?;
    Ok(stream)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResponseOwned {
    accepted: bool,
    #[allow(dead_code)]
    duplicate: bool,
    receipt: Option<LaunchReceiptOwned>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleWireResponseOwned {
    version: u8,
    operation: BrokerLifecycleOperation,
    accepted: bool,
    duplicate: bool,
    state: Option<BrokerLifecycleState>,
    receipt: Option<LaunchReceiptOwned>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchReceiptOwned {
    request: BrokerRequest,
    unit: String,
    pid: u32,
    creation_token: String,
    executable: PathBuf,
    executable_sha256: String,
    uid: u32,
    gid: u32,
    capability_bounding_set: u64,
    ambient_capabilities: u64,
    control_group: String,
    duplicate: bool,
}

impl LaunchReceiptOwned {
    fn into_receipt(self) -> LaunchReceipt {
        LaunchReceipt {
            request: self.request,
            unit: self.unit,
            pid: self.pid,
            creation_token: self.creation_token,
            executable: self.executable,
            executable_sha256: self.executable_sha256,
            uid: self.uid,
            gid: self.gid,
            capability_bounding_set: self.capability_bounding_set,
            ambient_capabilities: self.ambient_capabilities,
            control_group: self.control_group,
            duplicate: self.duplicate,
        }
    }
}

impl WireResponseOwned {
    fn receipt(self) -> Option<LaunchReceipt> {
        self.receipt.map(LaunchReceiptOwned::into_receipt)
    }
}

impl LifecycleWireResponseOwned {
    fn receipt(self) -> Option<LaunchReceipt> {
        self.receipt.map(LaunchReceiptOwned::into_receipt)
    }
}

#[cfg(target_os = "linux")]
mod native;
#[cfg(target_os = "linux")]
pub(crate) use native::process_start_token;
#[cfg(all(target_os = "linux", test))]
pub(crate) use native::require_no_supplementary_groups;
#[cfg(target_os = "linux")]
pub use native::run_native_broker;
#[cfg(all(target_os = "linux", test))]
pub(crate) use native::verify_process_executable;
#[cfg(target_os = "linux")]
pub use native::{
    JobRemovalOutcome, JobRemovedEvent, QueuedJobBackend, QueuedJobCancellation,
    QueuedJobResolution, decode_job_removed,
};

#[cfg(test)]
mod tests;
