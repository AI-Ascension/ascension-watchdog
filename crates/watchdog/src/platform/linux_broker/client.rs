//! Bounded client for the root-owned broker boundary.
//!
//! `BrokerClient` opens the authenticated local connection, validates the
//! protected socket and peer, frames one bounded request, and correlates the
//! launch, lifecycle and owned wire responses. The server-side state machine,
//! the transport primitives and the protocol vocabulary stay with their
//! sibling modules.

#[allow(clippy::wildcard_imports)]
use super::*;

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
struct WireResponseOwned {
    accepted: bool,
    #[allow(dead_code)]
    duplicate: bool,
    receipt: Option<LaunchReceiptOwned>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LifecycleWireResponseOwned {
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
