//! Unix socket server and framed transport for the root-owned broker.
//!
//! The single-request-per-connection server, the bounded JSON frame reader and
//! deadline writer, the typed wire responses and the root-owned socket binding.
//! The coordinator keeps the broker state machine, the peer and protected-path
//! helpers, the protocol vocabulary and the bounded client.

#[allow(clippy::wildcard_imports)]
use super::*;

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

pub(crate) fn handle_connection<B: SystemdBackend>(
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

pub(crate) fn read_frame(stream: &mut UnixStream, deadline: Instant) -> BrokerResult<Vec<u8>> {
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

pub(crate) fn write_deadline(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: Instant,
) -> BrokerResult<()> {
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
