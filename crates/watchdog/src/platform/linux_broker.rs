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

mod protocol;
pub use protocol::{
    BrokerComponent, BrokerLifecycleOperation, BrokerLifecycleRequest, BrokerLifecycleState,
    BrokerPolicy, BrokerRequest, CapabilityPolicy, CgroupPolicy, LaunchPolicy, PeerPolicy,
};
pub(crate) use protocol::{StrictJsonValue, parse_json, validate_sha256};

mod peer;
pub use peer::{PeerCredentials, peer_credentials};
pub(crate) use peer::{
    authenticate_peer, hash_file, hash_open_file_until, is_protected_owner, read_bounded_file,
    validate_protected_directory, validate_protected_file,
};

mod broker;
pub(crate) use broker::verify_receipt_identity;
pub use broker::{BrokerLifecycleReceipt, LaunchReceipt, LinuxSystemdBroker, UnitObservation};
pub(crate) use broker::{receipt_from, unit_name};

mod transport;
#[cfg(test)]
pub(crate) use transport::handle_connection;
pub use transport::{bind_root_owned_socket, serve};
pub(crate) use transport::{read_frame, write_deadline};

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
