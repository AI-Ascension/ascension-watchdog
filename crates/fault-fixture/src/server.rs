//! Server transport for the synthetic fixture.
//!
//! Owns the loopback listener loop, per-connection dispatch, the runtime-v3
//! HTTP routes, response framing helpers and the bounded line reader.
//! Extracted verbatim from `lib.rs` by the wire-protocol/client/server-transport
//! split (issue #73); the crate root re-exports `run_server`.

use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::transport::{self, DeadlineReader, IO_TIMEOUT};
use crate::wire::{Frame, ServerConfig, parse_json_no_duplicates, parse_value_no_duplicates};
use crate::{
    DurableHost, FaultController, FaultPoint, FixtureError, MAX_FRAME_BYTES, MAX_LINE_BYTES,
    ResponseAction, status, validate_runtime_v3_envelope,
};

/// Run the synthetic server until a shutdown request or an injected crash.
///
/// # Errors
///
/// Returns an I/O, persistence, protocol, or bounds error when the listener or
/// durable store cannot be initialized or served.
pub fn run_server(config: &ServerConfig) -> Result<(), FixtureError> {
    let listener = TcpListener::bind(config.bind).map_err(FixtureError::Io)?;
    listener.set_nonblocking(false).map_err(FixtureError::Io)?;
    let address = listener.local_addr().map_err(FixtureError::Io)?;
    let store = Arc::new(Mutex::new(DurableHost::open(&config.database)?));
    println!("LISTEN {address}");
    std::io::stdout().flush().map_err(FixtureError::Io)?;
    let mut faults = FaultController::new(config.fault);
    for incoming in listener.incoming() {
        let stream = incoming.map_err(FixtureError::Io)?;
        let action = match serve_connection(stream, &store, &mut faults) {
            Ok(action) => action,
            Err(FixtureError::Io(error)) if transport::is_peer_error(&error) => continue,
            Err(FixtureError::Io(error)) => return Err(FixtureError::Io(error)),
            Err(FixtureError::Sql(error)) => return Err(FixtureError::Sql(error)),
            Err(_) => continue,
        };
        match action {
            ConnectionAction::Continue => {}
            ConnectionAction::Stop => {
                break;
            }
            ConnectionAction::Crash => {
                // This process exit is the intended forced-crash boundary for
                // the test-only fixture.  The durable DB has already committed
                // the preceding stage.
                std::process::exit(70);
            }
        }
    }
    Ok(())
}

enum ConnectionAction {
    Continue,
    Stop,
    Crash,
}

#[allow(clippy::too_many_lines)]
fn serve_connection(
    mut stream: TcpStream,
    store: &Arc<Mutex<DurableHost>>,
    faults: &mut FaultController,
) -> Result<ConnectionAction, FixtureError> {
    let deadline = Instant::now() + IO_TIMEOUT;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(FixtureError::Io)?;
    let mut first = [0_u8; 1];
    let count = stream.peek(&mut first).map_err(FixtureError::Io)?;
    if count > 0 && matches!(first[0], b'G' | b'P' | b'H') {
        return serve_http_connection(stream, store, faults, deadline);
    }
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(FixtureError::Io)?;
    let mut reader =
        BufReader::new(DeadlineReader::new(&stream, deadline).map_err(FixtureError::Io)?);
    let line = match read_bounded_line(&mut reader) {
        Ok(Some(line)) => line,
        Ok(None) => return Ok(ConnectionAction::Continue),
        Err(FixtureError::Bounds(_)) => {
            write_raw_response(&mut stream, b"{\"error\":\"frame_too_large\"}\n")?;
            return Ok(ConnectionAction::Continue);
        }
        Err(error) => return Err(error),
    };
    let frame = match parse_json_no_duplicates::<Frame>(&line) {
        Ok(frame) => frame,
        Err(error) => {
            if let Ok(value) = parse_value_no_duplicates(&line)
                && value.get("protocol_version").and_then(Value::as_str)
                    == Some("runtime-v3-gameplay")
            {
                let kind = value
                    .get("kind")
                    .and_then(Value::as_str)
                    .ok_or_else(|| FixtureError::Invalid("runtime kind missing".to_owned()))?;
                if let Err(error) = validate_runtime_v3_envelope(kind, &value) {
                    write_raw_response(
                        &mut stream,
                        format!(
                            "{{\"error\":\"{}\",\"detail\":\"{}\"}}\n",
                            error.status(),
                            sanitize(&error.to_string())
                        )
                        .as_bytes(),
                    )?;
                    return Ok(ConnectionAction::Continue);
                }
                let response = {
                    let mut guard = store
                        .lock()
                        .map_err(|_| FixtureError::Invalid("store mutex poisoned".to_owned()))?;
                    match guard.v3_handle_value(&value) {
                        Ok(response) => response,
                        Err(error) => {
                            write_raw_response(
                                &mut stream,
                                format!(
                                    "{{\"error\":\"{}\",\"detail\":\"{}\"}}\n",
                                    error.status(),
                                    sanitize(&error.to_string())
                                )
                                .as_bytes(),
                            )?;
                            return Ok(ConnectionAction::Continue);
                        }
                    }
                };
                let response_kind = response_kind(kind);
                validate_runtime_v3_envelope(&response_kind, &response)?;
                write_raw_response(
                    &mut stream,
                    serde_json::to_string(&response)
                        .map_err(|json_error| FixtureError::Json(json_error.to_string()))?
                        .as_bytes(),
                )?;
                return Ok(ConnectionAction::Continue);
            }
            write_raw_response(
                &mut stream,
                format!(
                    "{{\"error\":\"invalid_json:{}\"}}\n",
                    sanitize(&error.to_string())
                )
                .as_bytes(),
            )?;
            return Ok(ConnectionAction::Continue);
        }
    };
    if let Err(error) = frame.validate() {
        let response = error_frame(&frame, &error);
        if response.validate().is_ok() {
            write_frame(&mut stream, &response)?;
        } else {
            write_raw_response(
                &mut stream,
                format!(
                    "{{\"error\":\"{}\",\"detail\":\"{}\"}}\n",
                    error.status(),
                    sanitize(&error.to_string())
                )
                .as_bytes(),
            )?;
        }
        return Ok(ConnectionAction::Continue);
    }
    let handled = {
        let mut guard = store
            .lock()
            .map_err(|_| FixtureError::Invalid("store mutex poisoned".to_owned()))?;
        guard.handle(&frame, faults)
    };
    let (response, action) = match handled {
        Ok(value) => value,
        Err(error)
            if matches!(
                &error,
                FixtureError::Stale(_)
                    | FixtureError::HostNotReady
                    | FixtureError::Conflict
                    | FixtureError::Forbidden
                    | FixtureError::Bounds(_)
            ) =>
        {
            let response = error_frame(&frame, &error);
            if response.validate().is_ok() {
                write_frame(&mut stream, &response)?;
                return Ok(ConnectionAction::Continue);
            }
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    response.validate()?;
    let action = if action == ResponseAction::Send && frame.kind == "host_tick" {
        faults
            .at(FaultPoint::ResponseLoss)
            .or_else(|| faults.at(FaultPoint::MalformedResponse))
            .unwrap_or(ResponseAction::Send)
    } else {
        action
    };
    match action {
        ResponseAction::Send => write_frame(&mut stream, &response)?,
        ResponseAction::Drop => {}
        ResponseAction::Malformed => write_raw_response(&mut stream, b"{\"malformed\"\n")?,
        ResponseAction::Crash => return Ok(ConnectionAction::Crash),
    }
    if frame.kind == "shutdown" {
        Ok(ConnectionAction::Stop)
    } else {
        Ok(ConnectionAction::Continue)
    }
}

fn serve_http_connection(
    mut stream: TcpStream,
    store: &Arc<Mutex<DurableHost>>,
    _faults: &mut FaultController,
    deadline: Instant,
) -> Result<ConnectionAction, FixtureError> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(FixtureError::Io)?;
    let mut reader =
        BufReader::new(DeadlineReader::new(&stream, deadline).map_err(FixtureError::Io)?);
    let request_line = read_bounded_line(&mut reader)?
        .ok_or_else(|| FixtureError::Invalid("HTTP request line missing".to_owned()))?;
    if request_line.len() > 8192 {
        return Err(FixtureError::Bounds("HTTP request line"));
    }
    let request_line = String::from_utf8(request_line)
        .map_err(|_| FixtureError::Invalid("HTTP request line encoding".to_owned()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| FixtureError::Invalid("HTTP method missing".to_owned()))?;
    let path = parts
        .next()
        .ok_or_else(|| FixtureError::Invalid("HTTP path missing".to_owned()))?;
    if parts.next() != Some("HTTP/1.1") {
        write_http_error(&mut stream, 400, "http_version_required")?;
        return Ok(ConnectionAction::Continue);
    }
    let Some(headers) = read_http_headers(&mut reader, &mut stream, request_line.len())? else {
        return Ok(ConnectionAction::Continue);
    };
    let body_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if body_length > MAX_FRAME_BYTES {
        write_http_error(&mut stream, 413, "runtime_v3_body_oversized")?;
        return Ok(ConnectionAction::Continue);
    }
    let mut body = vec![0_u8; body_length];
    reader.read_exact(&mut body).map_err(FixtureError::Io)?;
    let expected_kind = match (method, path) {
        ("GET", "/api/v3/runtime/state") => "state_request",
        ("GET", "/api/v3/runtime/legal-actions") => "legal_actions_request",
        ("POST", "/api/v3/runtime/action") => "dispatch_action_request",
        ("POST", "/api/v3/runtime/wait") => "wait_request",
        ("GET", "/api/v3/runtime/reobserve") => "reobserve_request",
        ("POST", "/api/v3/runtime/recover") => "recover_request",
        _ => {
            write_http_error(&mut stream, 404, "runtime_v3_route_not_found")?;
            return Ok(ConnectionAction::Continue);
        }
    };
    let value: Value = if let Ok(value) = parse_value_no_duplicates(&body) {
        value
    } else {
        write_http_error(&mut stream, 400, "runtime_v3_request_invalid")?;
        return Ok(ConnectionAction::Continue);
    };
    if !http_headers_match(&value, &headers) {
        write_http_error(&mut stream, 400, "runtime_v3_headers_invalid")?;
        return Ok(ConnectionAction::Continue);
    }
    if let Err(error) = validate_runtime_v3_envelope(expected_kind, &value) {
        write_http_error(&mut stream, 400, error.status())?;
        return Ok(ConnectionAction::Continue);
    }
    let response = {
        let mut guard = store
            .lock()
            .map_err(|_| FixtureError::Invalid("store mutex poisoned".to_owned()))?;
        match guard.v3_handle_value(&value) {
            Ok(response) => response,
            Err(error) => {
                write_http_error(&mut stream, 409, error.status())?;
                return Ok(ConnectionAction::Continue);
            }
        }
    };
    let response_kind = response_kind(expected_kind);
    validate_runtime_v3_envelope(&response_kind, &response)?;
    let response_status = match response["status"].as_str() {
        Some("rejected" | "unknown") => 409,
        _ => 200,
    };
    write_http_json(&mut stream, response_status, &response)?;
    Ok(ConnectionAction::Continue)
}

fn read_http_headers(
    reader: &mut impl Read,
    stream: &mut TcpStream,
    mut header_bytes: usize,
) -> Result<Option<std::collections::BTreeMap<String, String>>, FixtureError> {
    let mut headers = std::collections::BTreeMap::new();
    loop {
        let line = read_bounded_line(reader)?
            .ok_or_else(|| FixtureError::Invalid("HTTP headers truncated".to_owned()))?;
        header_bytes += line.len();
        if header_bytes > 16_384 || headers.len() >= 128 {
            return Err(FixtureError::Bounds("HTTP headers"));
        }
        let line = String::from_utf8(line)
            .map_err(|_| FixtureError::Invalid("HTTP header encoding".to_owned()))?;
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            return Ok(Some(headers));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| FixtureError::Invalid("HTTP header malformed".to_owned()))?;
        let name = name.trim().to_ascii_lowercase();
        if headers.contains_key(&name) {
            write_http_error(stream, 400, "runtime_v3_duplicate_header")?;
            return Ok(None);
        }
        headers.insert(name, value.trim().to_owned());
    }
}

fn http_headers_match(value: &Value, headers: &std::collections::BTreeMap<String, String>) -> bool {
    let authorization = headers
        .get("authorization")
        .is_some_and(|value| value.starts_with("Bearer ") && value.len() > 7);
    authorization
        && [
            ("instance_id", "x-sts2-instance-id"),
            ("session_id", "x-sts2-session-id"),
            ("lease_id", "x-sts2-lease-id"),
            ("correlation_id", "x-sts2-correlation-id"),
        ]
        .iter()
        .all(|(field, header)| value[*field].as_str() == headers.get(*header).map(String::as_str))
        && value["lease_epoch"].as_i64().map(|epoch| epoch.to_string())
            == headers.get("x-sts2-lease-epoch").cloned()
}

fn write_http_error(
    stream: &mut TcpStream,
    status_code: u16,
    code: &str,
) -> Result<(), FixtureError> {
    write_http_json(stream, status_code, &json!({"error_code":code}))
}

fn write_http_json(
    stream: &mut TcpStream,
    status_code: u16,
    value: &Value,
) -> Result<(), FixtureError> {
    let body = serde_json::to_vec(value).map_err(|error| FixtureError::Json(error.to_string()))?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(FixtureError::Bounds("HTTP response"));
    }
    let reason = match status_code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        _ => "Bad Gateway",
    };
    let mut bytes = format!("HTTP/1.1 {status_code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    bytes.extend_from_slice(&body);
    transport::write_bytes(stream, &bytes).map_err(FixtureError::Io)
}

fn write_frame(stream: &mut TcpStream, frame: &Frame) -> Result<(), FixtureError> {
    let bytes = serde_json::to_vec(frame).map_err(|error| FixtureError::Json(error.to_string()))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(FixtureError::Bounds("response frame"));
    }
    write_raw_response(stream, &bytes)
}

pub(crate) fn write_raw_response(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), FixtureError> {
    let mut framed = bytes.to_vec();
    if !bytes.ends_with(b"\n") {
        framed.push(b'\n');
    }
    transport::write_bytes(stream, &framed).map_err(FixtureError::Io)
}

fn error_frame(request: &Frame, error: &FixtureError) -> Frame {
    let result = status(error.status());
    let payload = match request.kind.as_str() {
        "bootstrap_request" => json!({"result":result,"boot":null,"fence":null}),
        "host_fence_request" => json!({"result":result,"fence":null}),
        "lease_acquire_request" | "lease_renew_request" => {
            json!({"result":result,"lease":null})
        }
        "operation_intent_request" | "operation_dispatch_request" => {
            json!({"result":result,"operation":null})
        }
        "operation_lookup_request" => {
            json!({"result":result,"operation":null,"mutation_authorized":false})
        }
        "operation_reconcile_request" => {
            json!({"result":result,"operation":null,"witness":null})
        }
        _ => json!({"result":result}),
    };
    request.response(&response_kind(&request.kind), payload)
}

pub(crate) fn response_kind(request_kind: &str) -> String {
    if request_kind.ends_with("_request") {
        format!("{}response", request_kind.trim_end_matches("request"))
    } else {
        format!("{request_kind}_response")
    }
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        .take(160)
        .collect()
}

pub(crate) fn read_bounded_line<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, FixtureError> {
    let mut line = Vec::with_capacity(MAX_LINE_BYTES.min(4096));
    for _ in 0..MAX_LINE_BYTES {
        let mut byte = [0_u8; 1];
        let count = reader.read(&mut byte).map_err(FixtureError::Io)?;
        if count == 0 {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(line))
            };
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(Some(line));
        }
    }
    Err(FixtureError::Bounds("frame line"))
}
