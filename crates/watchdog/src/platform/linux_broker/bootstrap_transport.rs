//! Versioned binary bootstrap transport over the existing authenticated local
//! connection. Only the bounded header is JSON; stdin bytes never are.

use super::bootstrap::{BootstrapKind, BrokerBootstrapBinding, BrokerBootstrapLaunch};
use super::{
    BrokerClient, BrokerError, BrokerRequest, BrokerResult, LaunchPolicy, LaunchReceipt,
    LinuxSystemdBroker, MAX_FRAME_BYTES, PeerCredentials, PeerPolicy, SystemdBackend,
    connect_with_deadline, io_error, parse_json, peer_credentials, process_start_token, read_frame,
    remaining, unit_name, validate_sha256, write_deadline,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{ErrorKind, Read};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::time::Instant;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ASC-BB02";
const VERSION: u8 = 2;
const PREFIX_BYTES: usize = MAGIC.len() + 8;
const MAX_HEADER_BYTES: usize = 4096;
const MAX_REQUEST_BYTES: usize =
    PREFIX_BYTES + MAX_HEADER_BYTES + crate::worker_bootstrap::MAX_FRAME_BYTES;
const HEALTH_NONCE_ENV: &str = "STS2_GATEWAY_WATCHDOG_LAUNCH_NONCE";

/// Dispatch certainty for this client call, not a claim about any earlier
/// call with the same identity. In particular, a rejected response is not
/// proof that the broker performed no process effect.
#[derive(Debug)]
pub enum BrokerBootstrapLaunchError {
    /// This invocation failed before attempting to write request bytes.
    /// Existing durable uncertainty for this identity must still be retained.
    NotDispatched(BrokerError),
    /// Bytes may have reached the broker. Reconcile the same identity; do not
    /// create a new nonce, silently use v1, or treat a timeout as cancellation.
    Unknown(BrokerError),
}

impl std::fmt::Display for BrokerBootstrapLaunchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotDispatched(error) => write!(
                formatter,
                "this broker bootstrap call was not dispatched: {error}"
            ),
            Self::Unknown(error) => write!(
                formatter,
                "broker bootstrap launch outcome is unknown: {error}"
            ),
        }
    }
}

impl std::error::Error for BrokerBootstrapLaunchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotDispatched(error) | Self::Unknown(error) => Some(error),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    request: BrokerRequest,
    binding: BrokerBootstrapBinding,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Response {
    version: u8,
    accepted: bool,
    duplicate: bool,
    binding: Option<BrokerBootstrapBinding>,
    receipt: Option<LaunchReceipt>,
}

fn invalid(message: &str) -> BrokerError {
    BrokerError::Invalid(message.to_owned())
}

pub(super) fn is_bootstrap_request(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

pub(super) fn read_request(
    stream: &mut UnixStream,
    deadline: Instant,
) -> BrokerResult<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new([0_u8; 4096]);
    loop {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(io_error)?;
        match stream.read(buffer.as_mut()) {
            Ok(0) => return Ok(bytes),
            Ok(count) => {
                if bytes.len() + count > MAX_REQUEST_BYTES {
                    return Err(invalid("broker request exceeds its bounded transport size"));
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => {
                return Err(BrokerError::Unavailable(
                    "broker request read failed".to_owned(),
                ));
            }
        }
    }
}

fn encode_request(
    request: &BrokerRequest,
    bootstrap: &BrokerBootstrapLaunch,
) -> BrokerResult<Zeroizing<Vec<u8>>> {
    bootstrap.validate_for_request(request)?;
    let envelope = Envelope {
        version: VERSION,
        request: request.clone(),
        binding: bootstrap.binding().clone(),
    };
    let header = serde_json::to_vec(&envelope)
        .map_err(|_| invalid("broker bootstrap header encoding failed"))?;
    if header.is_empty() || header.len() > MAX_HEADER_BYTES {
        return Err(invalid("broker bootstrap header exceeds its bound"));
    }
    let frame = bootstrap.frame();
    if frame.is_empty() || frame.len() > crate::worker_bootstrap::MAX_FRAME_BYTES {
        return Err(invalid("broker bootstrap frame exceeds its bound"));
    }
    let header_length = u32::try_from(header.len())
        .map_err(|_| invalid("broker bootstrap header length is invalid"))?;
    let frame_length = u32::try_from(frame.len())
        .map_err(|_| invalid("broker bootstrap frame length is invalid"))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        PREFIX_BYTES + header.len() + frame.len(),
    ));
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&header_length.to_be_bytes());
    bytes.extend_from_slice(&frame_length.to_be_bytes());
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(frame);
    Ok(bytes)
}

fn decode_request(bytes: &[u8]) -> BrokerResult<(BrokerRequest, BrokerBootstrapLaunch)> {
    if bytes.len() < PREFIX_BYTES || bytes.len() > MAX_REQUEST_BYTES || !is_bootstrap_request(bytes)
    {
        return Err(invalid("broker bootstrap transport prefix is invalid"));
    }
    let header_length = u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| invalid("broker bootstrap header length is invalid"))?,
    ) as usize;
    let frame_length = u32::from_be_bytes(
        bytes[12..16]
            .try_into()
            .map_err(|_| invalid("broker bootstrap frame length is invalid"))?,
    ) as usize;
    if header_length == 0
        || header_length > MAX_HEADER_BYTES
        || frame_length == 0
        || frame_length > crate::worker_bootstrap::MAX_FRAME_BYTES
        || bytes.len() != PREFIX_BYTES + header_length + frame_length
    {
        return Err(invalid("broker bootstrap transport length is invalid"));
    }
    let frame_offset = PREFIX_BYTES + header_length;
    let envelope: Envelope =
        parse_json(&bytes[PREFIX_BYTES..frame_offset], "bootstrap envelope")
            .map_err(|_| invalid("broker bootstrap envelope is not a closed valid header"))?;
    if envelope.version != VERSION {
        return Err(invalid("unsupported broker bootstrap protocol version"));
    }
    let bootstrap = BrokerBootstrapLaunch::from_frame(
        &envelope.request,
        envelope.binding,
        &bytes[frame_offset..],
    )?;
    Ok((envelope.request, bootstrap))
}

pub(super) fn authenticate_worker_peer(
    bootstrap: &BrokerBootstrapLaunch,
    credentials: PeerCredentials,
    policy: &PeerPolicy,
    deadline: Instant,
) -> BrokerResult<()> {
    if bootstrap.binding().kind != BootstrapKind::Worker {
        return Ok(());
    }
    let worker = crate::worker_bootstrap::decode_frame(bootstrap.frame())
        .map_err(|_| invalid("worker bootstrap frame is invalid"))?;
    let crate::worker_bootstrap::ExpectedPeer::Linux(peer) = worker.expected_peer else {
        return Err(invalid(
            "broker worker bootstrap requires a Linux controller",
        ));
    };
    remaining(deadline)?;
    // The shared worker frame carries decimal start ticks. The broker's own
    // native receipt uses boot:kernel-boot-id:start-ticks; compare the precise
    // decimal component without pretending the worker frame carries a boot ID.
    let birth = process_start_token(credentials.pid)?;
    let (_, start_ticks) = birth.rsplit_once(':').ok_or_else(|| {
        BrokerError::Unauthorized("broker controller birth identity is invalid".to_owned())
    })?;
    if peer.pid != credentials.pid
        || peer.uid != credentials.uid
        || peer.gid != credentials.gid
        || std::path::Path::new(&peer.executable) != policy.executable
        || peer.executable_sha256 != policy.executable_sha256
        || peer.creation_token != start_ticks
    {
        return Err(BrokerError::Unauthorized(
            "worker bootstrap controller differs from the authenticated peer".to_owned(),
        ));
    }
    remaining(deadline)?;
    Ok(())
}

pub(super) fn launch_environment(
    policy: &LaunchPolicy,
    request: &BrokerRequest,
    bootstrap: Option<&BrokerBootstrapLaunch>,
) -> BrokerResult<Vec<String>> {
    let mut environment = policy
        .environment
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>();
    if let Some(bootstrap) = bootstrap {
        bootstrap.validate_for_request(request)?;
        if bootstrap.binding().kind == BootstrapKind::GatewayHealth {
            if policy.environment.len() >= super::MAX_ENVIRONMENT {
                return Err(invalid(
                    "generated health nonce would exceed the environment bound",
                ));
            }
            if policy
                .environment
                .iter()
                .any(|(name, _)| name == HEALTH_NONCE_ENV)
            {
                return Err(invalid(
                    "fixed broker policy may not override the generated health nonce",
                ));
            }
            // This non-secret name/value is fixed by the Gateway health
            // contract. It is derived from the admitted UUID, not IPC env input.
            environment.push(format!("{HEALTH_NONCE_ENV}={}", request.nonce));
        }
    }
    Ok(environment)
}

pub(super) fn handle_connection<B: SystemdBackend>(
    stream: &mut UnixStream,
    broker: &mut LinuxSystemdBroker<B>,
    credentials: PeerCredentials,
    bytes: &[u8],
    deadline: Instant,
) -> BrokerResult<()> {
    let result = decode_request(bytes).and_then(|(request, bootstrap)| {
        let receipt =
            broker.handle_launch_at_deadline(credentials, &request, Some(&bootstrap), deadline)?;
        Ok((receipt, bootstrap.binding().clone()))
    });
    let response = match result {
        Ok((receipt, binding)) => Response {
            version: VERSION,
            accepted: true,
            duplicate: receipt.duplicate,
            binding: Some(binding),
            receipt: Some(receipt),
        },
        // Never reflect payload parsing errors or frame bytes. Rejection is
        // not a non-execution witness: the ledger may already hold Pending.
        Err(_) => Response {
            version: VERSION,
            accepted: false,
            duplicate: false,
            binding: None,
            receipt: None,
        },
    };
    let encoded = serde_json::to_vec(&response).map_err(|_| {
        BrokerError::Unavailable("broker bootstrap response encoding failed".to_owned())
    })?;
    if encoded.len() > MAX_FRAME_BYTES {
        return Err(invalid("broker bootstrap response exceeds its bound"));
    }
    write_deadline(stream, &encoded, deadline)
}

impl BrokerClient {
    /// Send one typed binary stdin bootstrap. Any failure after dispatch is
    /// potentially executed; retain its identity and reconcile through Inspect.
    /// This method never retries, selects another nonce, or changes to v1.
    pub fn launch_with_bootstrap(
        &self,
        request: &BrokerRequest,
        bootstrap: &BrokerBootstrapLaunch,
    ) -> Result<LaunchReceipt, BrokerBootstrapLaunchError> {
        let (mut stream, bytes, deadline) = (|| -> BrokerResult<_> {
            let bytes = encode_request(request, bootstrap)?;
            let metadata = fs::symlink_metadata(&self.socket).map_err(io_error)?;
            if !metadata.file_type().is_socket()
                || metadata.uid() != 0
                || metadata.mode() & 0o007 != 0
            {
                return Err(BrokerError::Unauthorized(
                    "broker socket ownership or type is unsafe".to_owned(),
                ));
            }
            let deadline = Instant::now()
                .checked_add(self.timeout)
                .unwrap_or_else(Instant::now);
            let stream = connect_with_deadline(&self.socket, deadline)?;
            if peer_credentials(&stream)?.uid != 0 {
                return Err(BrokerError::Unauthorized(
                    "broker peer is not root".to_owned(),
                ));
            }
            Ok((stream, bytes, deadline))
        })()
        .map_err(BrokerBootstrapLaunchError::NotDispatched)?;
        dispatch(&mut stream, &bytes, request, bootstrap.binding(), deadline)
    }
}

fn dispatch(
    stream: &mut UnixStream,
    bytes: &[u8],
    request: &BrokerRequest,
    binding: &BrokerBootstrapBinding,
    deadline: Instant,
) -> Result<LaunchReceipt, BrokerBootstrapLaunchError> {
    // From the first write attempt onward even partial-write errors are
    // conservatively unknown. A well-formed negative reply is also unknown:
    // the server can fail after Pending, StartTransientUnit, or receipt sync.
    (|| {
        write_deadline(stream, bytes, deadline)?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(io_error)?;
        let response = read_frame(stream, deadline)?;
        decode_response(&response, request, binding)
    })()
    .map_err(BrokerBootstrapLaunchError::Unknown)
}

fn decode_response(
    bytes: &[u8],
    request: &BrokerRequest,
    binding: &BrokerBootstrapBinding,
) -> BrokerResult<LaunchReceipt> {
    let response: Response = parse_json(bytes, "broker bootstrap response")
        .map_err(|_| invalid("broker bootstrap response schema is invalid"))?;
    if response.version != VERSION || !response.accepted {
        return Err(BrokerError::Conflict(
            "broker did not confirm the typed bootstrap launch".to_owned(),
        ));
    }
    if response.binding.as_ref() != Some(binding) {
        return Err(BrokerError::Conflict(
            "broker bootstrap response binding differs".to_owned(),
        ));
    }
    let receipt = response.receipt.ok_or_else(|| {
        BrokerError::Unavailable("broker accepted bootstrap without a receipt".to_owned())
    })?;
    if receipt.request != *request
        || receipt.unit != unit_name(request)
        || receipt.pid == 0
        || receipt.creation_token.is_empty()
        || !receipt.executable.is_absolute()
        || validate_sha256(&receipt.executable_sha256).is_err()
        || receipt.duplicate != response.duplicate
    {
        return Err(BrokerError::Conflict(
            "broker bootstrap receipt does not correlate".to_owned(),
        ));
    }
    Ok(receipt)
}

#[cfg(test)]
#[path = "bootstrap_transport_tests.rs"]
mod tests;
