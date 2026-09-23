//! Bounded broker client and the systemd backend contract.
//!
//! Verbatim move out of `linux_broker.rs`: the [`BrokerClient`] used by an
//! explicitly selected production launch path (with its bounded connect
//! helper and owned wire DTOs), and the [`SystemdBackend`] contract
//! implemented by the native and fake backends.  No behaviour changes; the
//! parent re-exports the public names so existing import paths are preserved.

use serde::Deserialize;
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::net::sockopt::socket_error;
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with};

use super::{
    BROKER_PROTOCOL_VERSION, BrokerError, BrokerLifecycleOperation, BrokerLifecycleReceipt,
    BrokerLifecycleRequest, BrokerLifecycleState, BrokerRequest, BrokerResult, LaunchPolicy,
    LaunchReceipt, MAX_FRAME_BYTES, MAX_TIMEOUT, QueuedJobBackend, UnitObservation, bootstrap,
    io_error, parse_json, peer_credentials, read_frame, remaining, unit_name,
    validate_protected_directory, validate_sha256, write_deadline,
};

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
    pub(super) socket: PathBuf,
    pub(super) timeout: Duration,
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

pub(crate) fn connect_with_deadline(path: &Path, deadline: Instant) -> BrokerResult<UnixStream> {
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
pub(super) struct WireResponseOwned {
    pub(super) accepted: bool,
    #[allow(dead_code)]
    pub(super) duplicate: bool,
    pub(super) receipt: Option<LaunchReceiptOwned>,
    pub(super) error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LifecycleWireResponseOwned {
    pub(super) version: u8,
    pub(super) operation: BrokerLifecycleOperation,
    pub(super) accepted: bool,
    pub(super) duplicate: bool,
    pub(super) state: Option<BrokerLifecycleState>,
    pub(super) receipt: Option<LaunchReceiptOwned>,
    pub(super) error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LaunchReceiptOwned {
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
