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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use rustix::net::sockopt::socket_peercred;

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
/// source. Component target UIDs/GIDs must be pairwise distinct.
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
        let mut target_pairs = BTreeMap::new();
        for (component, policy) in &components {
            validate_launch_policy(policy)?;
            let pair = (policy.target_uid, policy.target_gid);
            if target_pairs.insert(pair, *component).is_some() {
                return Err(BrokerError::Invalid(
                    "component target UID/GID pairs must be distinct".to_owned(),
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
        let bytes = fs::read(path).map_err(io_error)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(BrokerError::Invalid(
                "broker policy exceeds size bound".to_owned(),
            ));
        }
        let document: PolicyDocument = serde_json::from_slice(&bytes).map_err(|error| {
            BrokerError::Invalid(format!("broker policy JSON is invalid: {error}"))
        })?;
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
        || policy.capabilities.ambient_set & !policy.capabilities.bounding_set != 0
    {
        return Err(BrokerError::Invalid(
            "launch capability policy must retain no-new-privileges and bound ambient capabilities"
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
    if !path.is_absolute() {
        return Err(BrokerError::Invalid(format!(
            "{label} path must be absolute"
        )));
    }
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(BrokerError::Invalid(format!(
            "{label} must be a root-owned non-writable regular file"
        )));
    }
    Ok(())
}

fn validate_protected_directory(path: &Path, label: &str) -> BrokerResult<()> {
    if !path.is_absolute() {
        return Err(BrokerError::Invalid(format!(
            "{label} path must be absolute"
        )));
    }
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(BrokerError::Invalid(format!(
            "{label} must be a root-owned non-writable directory"
        )));
    }
    Ok(())
}

fn hash_file(path: &Path) -> BrokerResult<String> {
    let mut file = File::open(path).map_err(io_error)?;
    let metadata = file.metadata().map_err(io_error)?;
    if metadata.len() > MAX_HASH_BYTES {
        return Err(BrokerError::Invalid(
            "executable exceeds hash bound".to_owned(),
        ));
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(io_error)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex_digest(&hasher.finalize()))
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

fn authenticate_peer(credentials: PeerCredentials, policy: &PeerPolicy) -> BrokerResult<()> {
    if credentials.pid == 0 || credentials.uid != policy.uid || credentials.gid != policy.gid {
        return Err(BrokerError::Unauthorized(
            "peer credentials are not approved".to_owned(),
        ));
    }
    let executable = fs::read_link(format!("/proc/{}/exe", credentials.pid)).map_err(io_error)?;
    if executable != policy.executable {
        return Err(BrokerError::Unauthorized(
            "peer executable path is not approved".to_owned(),
        ));
    }
    let actual = hash_file(&executable)?;
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LaunchReceipt {
    pub request: BrokerRequest,
    pub unit: String,
    pub pid: u32,
    pub creation_token: String,
    pub uid: u32,
    pub gid: u32,
    pub capability_bounding_set: u64,
    pub ambient_capabilities: u64,
    pub control_group: String,
    pub duplicate: bool,
}

pub trait SystemdBackend {
    fn start(
        &mut self,
        unit: &str,
        request: &BrokerRequest,
        policy: &LaunchPolicy,
    ) -> BrokerResult<UnitObservation>;
    fn inspect(
        &mut self,
        unit: &str,
        policy: &LaunchPolicy,
    ) -> BrokerResult<Option<UnitObservation>>;
    fn stop(&mut self, unit: &str) -> BrokerResult<()>;
}

/// Broker state and exact nonce idempotence. The backend owns all privileged
/// effects; this object owns admission and duplicate handling.
pub struct LinuxSystemdBroker<B> {
    policy: BrokerPolicy,
    backend: B,
    receipts: BTreeMap<BrokerRequest, LaunchReceipt>,
}

impl<B: SystemdBackend> LinuxSystemdBroker<B> {
    pub fn new(policy: BrokerPolicy, backend: B) -> Self {
        Self {
            policy,
            backend,
            receipts: BTreeMap::new(),
        }
    }

    pub fn handle(
        &mut self,
        credentials: PeerCredentials,
        request: BrokerRequest,
    ) -> BrokerResult<LaunchReceipt> {
        request.validate()?;
        authenticate_peer(credentials, &self.policy.peer)?;
        let policy = self.policy.component(request.component)?;
        let unit = unit_name(&request);
        if let Some(receipt) = self.receipts.get(&request) {
            let mut duplicate = receipt.clone();
            duplicate.duplicate = true;
            return Ok(duplicate);
        }
        if let Some(observation) = self.backend.inspect(&unit, policy)? {
            observation.verify(&unit, policy)?;
            let receipt = receipt_from(&request, &observation, true);
            self.receipts.insert(request, receipt.clone());
            return Ok(receipt);
        }
        let observation = self.backend.start(&unit, &request, policy)?;
        if let Err(error) = observation.verify(&unit, policy) {
            let _ = self.backend.stop(&unit);
            return Err(error);
        }
        let receipt = receipt_from(&request, &observation, false);
        self.receipts.insert(request, receipt.clone());
        Ok(receipt)
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
        uid: observation.uid,
        gid: observation.gid,
        capability_bounding_set: observation.capability_bounding_set,
        ambient_capabilities: observation.ambient_capabilities,
        control_group: observation.control_group.clone(),
        duplicate,
    }
}

#[derive(Serialize)]
struct WireResponse<'a> {
    accepted: bool,
    duplicate: bool,
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
        let mut stream = connection.map_err(io_error)?;
        let result = handle_connection(&mut stream, &mut broker);
        if let Err(error) = &result {
            let error_text = error.to_string();
            let response = serde_json::to_vec(&WireResponse {
                accepted: false,
                duplicate: false,
                receipt: None,
                error: Some(&error_text),
            })
            .map_err(|serialize_error| BrokerError::Io(serialize_error.to_string()))?;
            stream.write_all(&response).map_err(io_error)?;
        }
    }
    Ok(())
}

fn handle_connection<B: SystemdBackend>(
    stream: &mut UnixStream,
    broker: &mut LinuxSystemdBroker<B>,
) -> BrokerResult<()> {
    let credentials = peer_credentials(stream)?;
    let mut bytes = Vec::new();
    stream
        .take((MAX_FRAME_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(BrokerError::Invalid(
            "broker request exceeds frame bound".to_owned(),
        ));
    }
    let request: BrokerRequest = serde_json::from_slice(&bytes).map_err(|error| {
        BrokerError::Invalid(format!("broker request JSON is invalid: {error}"))
    })?;
    let receipt = broker.handle(credentials, request)?;
    let response = serde_json::to_vec(&WireResponse {
        accepted: true,
        duplicate: receipt.duplicate,
        receipt: Some(&receipt),
        error: None,
    })
    .map_err(|error| BrokerError::Io(error.to_string()))?;
    stream.write_all(&response).map_err(io_error)
}

/// Build a listener only at a root-owned, non-world-writable directory. An
/// existing path is never unlinked, avoiding replacement of another broker.
pub fn bind_root_owned_socket(path: &Path) -> BrokerResult<UnixListener> {
    let parent = path
        .parent()
        .ok_or_else(|| BrokerError::Invalid("broker socket has no parent directory".to_owned()))?;
    validate_protected_directory(parent, "broker socket directory")?;
    if path.exists() {
        return Err(BrokerError::Conflict(
            "broker socket already exists".to_owned(),
        ));
    }
    let listener = UnixListener::bind(path).map_err(io_error)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660)).map_err(io_error)?;
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.uid() != 0 || metadata.mode() & 0o007 != 0 {
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
        Ok(Self { socket, timeout })
    }

    pub fn launch(&self, request: &BrokerRequest) -> BrokerResult<LaunchReceipt> {
        request.validate()?;
        let mut stream = UnixStream::connect(&self.socket).map_err(io_error)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(io_error)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(io_error)?;
        let bytes =
            serde_json::to_vec(request).map_err(|error| BrokerError::Io(error.to_string()))?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(BrokerError::Invalid(
                "broker request exceeds frame bound".to_owned(),
            ));
        }
        stream.write_all(&bytes).map_err(io_error)?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(io_error)?;
        let mut response = Vec::new();
        stream
            .take((MAX_FRAME_BYTES + 1) as u64)
            .read_to_end(&mut response)
            .map_err(io_error)?;
        if response.len() > MAX_FRAME_BYTES {
            return Err(BrokerError::Invalid(
                "broker response exceeds frame bound".to_owned(),
            ));
        }
        let response: WireResponseOwned = serde_json::from_slice(&response).map_err(|error| {
            BrokerError::Invalid(format!("broker response JSON is invalid: {error}"))
        })?;
        if !response.accepted {
            return Err(BrokerError::Conflict(
                response
                    .error
                    .unwrap_or_else(|| "broker rejected request".to_owned()),
            ));
        }
        response
            .receipt()
            .ok_or_else(|| BrokerError::Unavailable("broker accepted without a receipt".to_owned()))
    }
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
struct LaunchReceiptOwned {
    request: BrokerRequest,
    unit: String,
    pid: u32,
    creation_token: String,
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

#[cfg(target_os = "linux")]
struct NativeSystemdBackend {
    connection: zbus::blocking::Connection,
}

#[cfg(target_os = "linux")]
impl NativeSystemdBackend {
    fn connect() -> BrokerResult<Self> {
        let connection = zbus::blocking::Connection::system().map_err(|error| {
            BrokerError::Unavailable(format!("system D-Bus connection failed: {error}"))
        })?;
        Ok(Self { connection })
    }

    fn manager(&self) -> BrokerResult<zbus::blocking::Proxy<'_>> {
        zbus::blocking::Proxy::new(
            &self.connection,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        )
        .map_err(|error| BrokerError::Unavailable(format!("systemd manager proxy failed: {error}")))
    }

    fn unit_proxy<'a>(&'a self, path: &'a str) -> BrokerResult<zbus::blocking::Proxy<'a>> {
        zbus::blocking::Proxy::new(
            &self.connection,
            "org.freedesktop.systemd1",
            path,
            "org.freedesktop.DBus.Properties",
        )
        .map_err(|error| {
            BrokerError::Unavailable(format!("systemd property proxy failed: {error}"))
        })
    }

    fn property<T>(&self, path: &str, interface: &str, property: &str) -> BrokerResult<T>
    where
        T: TryFrom<zbus::zvariant::OwnedValue>,
        T::Error: fmt::Display,
    {
        let proxy = self.unit_proxy(path)?;
        let value: zbus::zvariant::OwnedValue =
            proxy.call("Get", &(interface, property)).map_err(|error| {
                BrokerError::Unavailable(format!("systemd property read failed: {error}"))
            })?;
        T::try_from(value).map_err(|error| {
            BrokerError::Unavailable(format!("systemd property type failed: {error}"))
        })
    }

    fn unit_observation(
        &self,
        unit: &str,
        policy: &LaunchPolicy,
    ) -> BrokerResult<Option<UnitObservation>> {
        let manager = self.manager()?;
        let path: zbus::zvariant::OwnedObjectPath = match manager.call("GetUnit", &unit) {
            Ok(path) => path,
            Err(error) if error.to_string().contains("NoSuchUnit") => return Ok(None),
            Err(error) => {
                return Err(BrokerError::Unavailable(format!(
                    "systemd unit lookup failed: {error}"
                )));
            }
        };
        let path = path.as_str();
        let active: String = self.property(path, "org.freedesktop.systemd1.Unit", "ActiveState")?;
        if active != "active" {
            return Ok(None);
        }
        let pid: u32 = self.property(path, "org.freedesktop.systemd1.Service", "MainPID")?;
        if pid == 0 {
            return Ok(None);
        }
        let control_group: String =
            self.property(path, "org.freedesktop.systemd1.Unit", "ControlGroup")?;
        let process = read_process_postcondition(pid, policy, &control_group)?;
        Ok(Some(UnitObservation {
            unit: unit.to_owned(),
            pid,
            creation_token: process.creation_token,
            uid: process.uid,
            gid: process.gid,
            capability_bounding_set: process.capability_bounding_set,
            ambient_capabilities: process.ambient_capabilities,
            no_new_privileges: process.no_new_privileges,
            control_group,
        }))
    }
}

#[cfg(target_os = "linux")]
impl SystemdBackend for NativeSystemdBackend {
    #[allow(clippy::vec_init_then_push)]
    fn start(
        &mut self,
        unit: &str,
        _request: &BrokerRequest,
        policy: &LaunchPolicy,
    ) -> BrokerResult<UnitObservation> {
        if hash_file(&policy.executable)? != policy.executable_sha256 {
            return Err(BrokerError::Conflict(
                "launch executable changed after policy admission".to_owned(),
            ));
        }
        let manager = self.manager()?;
        let mut argv = Vec::with_capacity(policy.arguments.len() + 1);
        argv.push(policy.executable.to_string_lossy().into_owned());
        argv.extend(policy.arguments.iter().cloned());
        let exec_start = zbus::zvariant::Value::new(vec![(
            policy.executable.to_string_lossy().into_owned(),
            argv,
            false,
        )])
        .try_to_owned()
        .map_err(|error| {
            BrokerError::Invalid(format!("systemd ExecStart value failed: {error}"))
        })?;
        let environment = policy
            .environment
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>();
        let mut properties = Vec::new();
        properties.push(("ExecStart", exec_start));
        properties.push((
            "User",
            zbus::zvariant::Value::new(policy.target_uid.to_string())
                .try_to_owned()
                .map_err(|error| BrokerError::Invalid(error.to_string()))?,
        ));
        properties.push((
            "Group",
            zbus::zvariant::Value::new(policy.target_gid.to_string())
                .try_to_owned()
                .map_err(|error| BrokerError::Invalid(error.to_string()))?,
        ));
        properties.push((
            "SupplementaryGroups",
            zbus::zvariant::Value::new(Vec::<String>::new())
                .try_to_owned()
                .map_err(|error| BrokerError::Invalid(error.to_string()))?,
        ));
        properties.push((
            "WorkingDirectory",
            zbus::zvariant::Value::new(policy.working_directory.to_string_lossy().into_owned())
                .try_to_owned()
                .map_err(|error| BrokerError::Invalid(error.to_string()))?,
        ));
        properties.push((
            "Environment",
            zbus::zvariant::Value::new(environment)
                .try_to_owned()
                .map_err(|error| BrokerError::Invalid(error.to_string()))?,
        ));
        properties.push((
            "CapabilityBoundingSet",
            zbus::zvariant::OwnedValue::from(policy.capabilities.bounding_set),
        ));
        properties.push((
            "AmbientCapabilities",
            zbus::zvariant::OwnedValue::from(policy.capabilities.ambient_set),
        ));
        properties.push((
            "NoNewPrivileges",
            zbus::zvariant::OwnedValue::from(policy.capabilities.no_new_privileges),
        ));
        properties.push(("Delegate", zbus::zvariant::OwnedValue::from(false)));
        properties.push((
            "KillMode",
            zbus::zvariant::Value::new("control-group")
                .try_to_owned()
                .map_err(|error| BrokerError::Invalid(error.to_string()))?,
        ));
        properties.push((
            "StandardOutput",
            zbus::zvariant::Value::new("null")
                .try_to_owned()
                .map_err(|error| BrokerError::Invalid(error.to_string()))?,
        ));
        properties.push((
            "StandardError",
            zbus::zvariant::Value::new("null")
                .try_to_owned()
                .map_err(|error| BrokerError::Invalid(error.to_string()))?,
        ));
        properties.push((
            "TasksMax",
            zbus::zvariant::OwnedValue::from(policy.cgroup.tasks_max),
        ));
        properties.push((
            "MemoryMax",
            zbus::zvariant::OwnedValue::from(policy.cgroup.memory_max_bytes),
        ));
        let timeout_us: u64 = policy.timeout.as_micros().try_into().map_err(|_| {
            BrokerError::Invalid("launch timeout overflows systemd property".to_owned())
        })?;
        properties.push((
            "TimeoutStartUSec",
            zbus::zvariant::OwnedValue::from(timeout_us),
        ));
        properties.push((
            "TimeoutStopUSec",
            zbus::zvariant::OwnedValue::from(timeout_us),
        ));
        let aux: Vec<(String, Vec<(String, zbus::zvariant::OwnedValue)>)> = Vec::new();
        let _: zbus::zvariant::OwnedObjectPath = manager
            .call("StartTransientUnit", &(unit, "fail", properties, aux))
            .map_err(|error| {
                BrokerError::Unavailable(format!("systemd transient unit start failed: {error}"))
            })?;
        let deadline = Instant::now()
            .checked_add(policy.timeout)
            .unwrap_or_else(Instant::now);
        loop {
            if let Some(observation) = self.unit_observation(unit, policy)? {
                return Ok(observation);
            }
            if Instant::now() >= deadline {
                return Err(BrokerError::Unavailable(
                    "systemd transient unit did not become active before deadline".to_owned(),
                ));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn inspect(
        &mut self,
        unit: &str,
        policy: &LaunchPolicy,
    ) -> BrokerResult<Option<UnitObservation>> {
        self.unit_observation(unit, policy)
    }

    fn stop(&mut self, unit: &str) -> BrokerResult<()> {
        let manager = self.manager()?;
        let _: zbus::zvariant::OwnedObjectPath = manager
            .call("StopUnit", &(unit, "replace"))
            .map_err(|error| {
                BrokerError::Unavailable(format!("systemd exact-unit cleanup failed: {error}"))
            })?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
struct ProcessPostcondition {
    creation_token: String,
    uid: u32,
    gid: u32,
    capability_bounding_set: u64,
    ambient_capabilities: u64,
    no_new_privileges: bool,
}

#[cfg(target_os = "linux")]
fn read_process_postcondition(
    pid: u32,
    policy: &LaunchPolicy,
    control_group: &str,
) -> BrokerResult<ProcessPostcondition> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).map_err(io_error)?;
    let uid = parse_status_quad(&status, "Uid")?;
    let gid = parse_status_quad(&status, "Gid")?;
    if uid.iter().any(|value| *value != policy.target_uid)
        || gid.iter().any(|value| *value != policy.target_gid)
    {
        return Err(BrokerError::Conflict(
            "systemd target UID/GID postcheck failed".to_owned(),
        ));
    }
    require_no_supplementary_groups(&status)?;
    let cap_bounding_set = parse_hex_status(&status, "CapBnd")?;
    let ambient_capabilities = parse_hex_status(&status, "CapAmb")?;
    let no_new_privileges = status
        .lines()
        .find_map(|line| line.strip_prefix("NoNewPrivs:"))
        .map(str::trim)
        .is_some_and(|value| value == "1");
    if !no_new_privileges
        || cap_bounding_set != policy.capabilities.bounding_set
        || ambient_capabilities != policy.capabilities.ambient_set
    {
        return Err(BrokerError::Conflict(
            "systemd capability postcheck failed".to_owned(),
        ));
    }
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(io_error)?;
    let actual_cgroup = cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| {
            BrokerError::Conflict("target has no unified cgroup membership".to_owned())
        })?;
    if actual_cgroup != control_group {
        return Err(BrokerError::Conflict(
            "target cgroup does not match exact systemd unit".to_owned(),
        ));
    }
    let creation_token = process_start_token(pid)?;
    Ok(ProcessPostcondition {
        creation_token,
        uid: policy.target_uid,
        gid: policy.target_gid,
        capability_bounding_set: cap_bounding_set,
        ambient_capabilities,
        no_new_privileges,
    })
}

#[cfg(target_os = "linux")]
fn require_no_supplementary_groups(status: &str) -> BrokerResult<()> {
    let groups = status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:"))
        .ok_or_else(|| BrokerError::Conflict("process status lacks Groups".to_owned()))?;
    if !groups.trim().is_empty() {
        return Err(BrokerError::Conflict(
            "systemd supplementary-group postcheck failed".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_status_quad(status: &str, field: &str) -> BrokerResult<[u32; 4]> {
    let values = status
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{field}:")))
        .ok_or_else(|| BrokerError::Conflict(format!("process status lacks {field}")))?
        .split_whitespace()
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| BrokerError::Conflict(format!("process status has invalid {field}")))
        })
        .collect::<BrokerResult<Vec<_>>>()?;
    values
        .try_into()
        .map_err(|_| BrokerError::Conflict(format!("process status has incomplete {field}")))
}

#[cfg(target_os = "linux")]
fn parse_hex_status(status: &str, field: &str) -> BrokerResult<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{field}:")))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .ok_or_else(|| BrokerError::Conflict(format!("process status has invalid {field}")))
}

#[cfg(target_os = "linux")]
fn process_start_token(pid: u32) -> BrokerResult<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).map_err(io_error)?;
    let close = stat.rfind(')').ok_or_else(|| {
        BrokerError::Conflict("process stat has no command terminator".to_owned())
    })?;
    stat.get(close + 2..)
        .and_then(|suffix| suffix.split_whitespace().nth(19))
        .map(str::to_owned)
        .ok_or_else(|| BrokerError::Conflict("process stat has no start token".to_owned()))
}

/// Start the root-owned broker binary after loading the protected policy.
#[cfg(target_os = "linux")]
pub fn run_native_broker(socket: &Path, policy_path: &Path) -> BrokerResult<()> {
    let policy = BrokerPolicy::from_file(policy_path)?;
    let listener = bind_root_owned_socket(socket)?;
    let backend = NativeSystemdBackend::connect()?;
    serve(&listener, LinuxSystemdBroker::new(policy, backend))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeBackend {
        starts: usize,
        units: BTreeMap<String, UnitObservation>,
    }

    impl FakeBackend {
        fn new() -> Self {
            Self {
                starts: 0,
                units: BTreeMap::new(),
            }
        }
    }

    impl SystemdBackend for FakeBackend {
        fn start(
            &mut self,
            unit: &str,
            _request: &BrokerRequest,
            policy: &LaunchPolicy,
        ) -> BrokerResult<UnitObservation> {
            self.starts += 1;
            let observation = UnitObservation {
                unit: unit.to_owned(),
                pid: 42,
                creation_token: "start-token".to_owned(),
                uid: policy.target_uid,
                gid: policy.target_gid,
                capability_bounding_set: policy.capabilities.bounding_set,
                ambient_capabilities: policy.capabilities.ambient_set,
                no_new_privileges: true,
                control_group: format!("/system.slice/{unit}"),
            };
            self.units.insert(unit.to_owned(), observation.clone());
            Ok(observation)
        }

        fn inspect(
            &mut self,
            unit: &str,
            _policy: &LaunchPolicy,
        ) -> BrokerResult<Option<UnitObservation>> {
            Ok(self.units.get(unit).cloned())
        }

        fn stop(&mut self, unit: &str) -> BrokerResult<()> {
            self.units.remove(unit);
            Ok(())
        }
    }

    fn digest(path: &Path) -> String {
        let mut hasher = Sha256::new();
        hasher.update(fs::read(path).expect("fixture executable must be readable"));
        hex_digest(&hasher.finalize())
    }

    fn policy() -> BrokerPolicy {
        let executable = PathBuf::from("/bin/true");
        let peer_executable = fs::canonicalize("/bin/sleep").expect("peer fixture executable path");
        let launch = LaunchPolicy {
            executable: executable.clone(),
            executable_sha256: digest(&executable),
            arguments: Vec::new(),
            working_directory: PathBuf::from("/"),
            environment: Vec::new(),
            target_uid: 1001,
            target_gid: 1001,
            capabilities: CapabilityPolicy {
                bounding_set: 0,
                ambient_set: 0,
                no_new_privileges: true,
            },
            cgroup: CgroupPolicy {
                tasks_max: 16,
                memory_max_bytes: 64 * 1024 * 1024,
            },
            timeout: Duration::from_secs(2),
        };
        let peer = PeerPolicy {
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
            executable: peer_executable.clone(),
            executable_sha256: digest(&peer_executable),
        };
        BrokerPolicy::new(peer, BTreeMap::from([(BrokerComponent::Synthetic, launch)]))
            .expect("valid fixture policy")
    }

    fn credentials(policy: &BrokerPolicy) -> (PeerCredentials, std::process::Child) {
        let child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("peer fixture process");
        (
            PeerCredentials {
                pid: child.id(),
                uid: policy.peer.uid,
                gid: policy.peer.gid,
            },
            child,
        )
    }

    fn request(nonce: &str) -> BrokerRequest {
        BrokerRequest {
            component: BrokerComponent::Synthetic,
            instance: "instance".to_owned(),
            incarnation: "incarnation".to_owned(),
            nonce: nonce.to_owned(),
        }
    }

    #[test]
    fn fixed_policy_has_distinct_target_identity_and_no_capabilities() {
        let policy = policy();
        let launch = policy
            .component(BrokerComponent::Synthetic)
            .expect("policy entry");
        assert_ne!(launch.target_uid, policy.peer.uid);
        assert_eq!(launch.capabilities.bounding_set, 0);
        assert_eq!(launch.capabilities.ambient_set, 0);
    }

    #[test]
    fn duplicate_nonce_does_not_start_a_second_unit() {
        let policy = policy();
        let mut broker = LinuxSystemdBroker::new(policy.clone(), FakeBackend::new());
        let (peer, mut child) = credentials(&policy);
        let first = broker.handle(peer, request("nonce")).expect("first launch");
        let second = broker
            .handle(peer, request("nonce"))
            .expect("duplicate launch");
        let _ = child.kill();
        let _ = child.wait();
        assert!(!first.duplicate);
        assert!(second.duplicate);
        assert_eq!(broker.backend.starts, 1);
    }

    #[test]
    fn unit_name_binds_all_request_identity_fields() {
        assert_ne!(unit_name(&request("a")), unit_name(&request("b")));
        assert!(unit_name(&request("a")).ends_with(".service"));
    }

    #[test]
    fn unknown_request_field_is_rejected() {
        let result = serde_json::from_str::<BrokerRequest>(
            r#"{"component":"synthetic","instance":"i","incarnation":"c","nonce":"n","executable":"/bin/sh"}"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn peer_credentials_are_kernel_bound() {
        let policy = policy();
        let (peer, mut child) = credentials(&policy);
        let error = authenticate_peer(
            PeerCredentials {
                pid: peer.pid,
                uid: policy.peer.uid.saturating_add(1),
                gid: policy.peer.gid,
            },
            &policy.peer,
        )
        .expect_err("forged uid must fail");
        let _ = child.kill();
        let _ = child.wait();
        assert!(matches!(error, BrokerError::Unauthorized(_)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_start_token_is_not_pid_only() {
        let token = process_start_token(std::process::id()).expect("current process stat");
        assert!(!token.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn supplementary_groups_postcheck_requires_an_empty_groups_field() {
        let base = "Uid:\t1001\t1001\t1001\t1001\nGid:\t1001\t1001\t1001\t1001\n";
        require_no_supplementary_groups(&format!("{base}Groups:\t"))
            .expect("empty supplementary groups are approved");
        let error = require_no_supplementary_groups(&format!("{base}Groups:\t1001"))
            .expect_err("supplementary groups must be rejected");
        assert!(matches!(error, BrokerError::Conflict(_)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an approved disposable host with a root-owned broker unit and system D-Bus"]
    fn native_systemd_broker_is_explicitly_gated() {
        assert!(std::env::var_os("ASCENSION_NATIVE_BROKER_TEST").is_some());
    }
}
