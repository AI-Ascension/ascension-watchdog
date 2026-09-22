//! Wire, HTTP and JSON-schema support for the runtime-v3 integration tests.
//!
//! Extracted verbatim from `tests/runtime.rs`; only visibility was widened to
//! `pub(super)` so the crate-root test functions keep using the same helpers.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use fault_fixture::{Client, Frame, RUNTIME_V3_SCHEMA_DIGEST};
use jsonschema::Validator;
use serde_json::{Value, json};
use uuid::Uuid;

pub(super) fn send_raw(
    address: SocketAddr,
    value: &Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let bytes = serde_json::to_vec(&value)?;
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(&bytes)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(serde_json::from_str(&line)?)
}

pub(super) fn send_http(
    address: SocketAddr,
    method: &str,
    path: &str,
    value: &Value,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    let body = serde_json::to_vec(value)?;
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let instance_id = value["instance_id"].as_str().ok_or("instance id")?;
    let session_id = value["session_id"].as_str().ok_or("session id")?;
    let lease_id = value["lease_id"].as_str().ok_or("lease id")?;
    let lease_epoch = value["lease_epoch"].as_i64().ok_or("lease epoch")?;
    let correlation_id = value["correlation_id"].as_str().ok_or("correlation id")?;
    let headers = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer fixture\r\nX-STS2-Instance-Id: {}\r\nX-STS2-Session-Id: {}\r\nX-STS2-Lease-Id: {}\r\nX-STS2-Lease-Epoch: {}\r\nX-STS2-Correlation-Id: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        instance_id,
        session_id,
        lease_id,
        lease_epoch,
        correlation_id,
        body.len()
    );
    stream.write_all(headers.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()?;
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("HTTP status missing")?
        .parse()?;
    let mut content_length = 0_usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(length) = line.strip_prefix("Content-Length:") {
            content_length = length.trim().parse()?;
        }
    }
    let mut response_body = vec![0_u8; content_length];
    std::io::Read::read_exact(&mut reader, &mut response_body)?;
    Ok((status, serde_json::from_slice(&response_body)?))
}

pub(super) fn bootstrap(client: &Client) -> Result<Value, Box<dyn std::error::Error>> {
    let boot = client
        .request(&Frame::request(
            "bootstrap_request",
            "bootstrap",
            json!({
                "deployment_id": Uuid::new_v4(),
                "instance_id": Uuid::new_v4(),
                "instance_incarnation": Uuid::new_v4(),
                "release": {
                    "release_digest": "00".repeat(32),
                    "config_digest": "11".repeat(32),
                    "profile_digest": "22".repeat(32),
                    "runtime_v3_schema_digest": RUNTIME_V3_SCHEMA_DIGEST
                },
                "lease_policy": {"ttl_seconds":30,"renewal_interval_seconds":10}
            }),
        ))?
        .payload["boot"]
        .clone();
    let fence = client
        .request(&Frame::request(
            "host_fence_request",
            "host_fence",
            json!({"boot":boot}),
        ))?
        .payload["fence"]
        .clone();
    Ok(client
        .request(&Frame::request(
            "lease_acquire_request",
            "lease_acquire",
            json!({"boot":boot,"fence":fence}),
        ))?
        .payload["lease"]
        .clone())
}

pub(super) fn envelope(
    kind: &str,
    generation: i64,
    state_id: Option<&str>,
    operation_id: Option<&str>,
) -> Value {
    json!({
        "protocol_version":"runtime-v3-gameplay", "schema_digest":RUNTIME_V3_SCHEMA_DIGEST,
        "provenance":{"artifact":"sts2-protocol/runtime-v3-gameplay","source":"schemas/runtime-v3-gameplay.schema.json","generator":"hand-authored"},
        "correlation_id":Uuid::new_v4().to_string(), "instance_id":"instance-1",
        "session_id":"session-1", "lease_id":"lease-1", "lease_epoch":0,
        "generation":generation, "kind":kind, "state_id":state_id,
        "operation_id":operation_id, "observation":null, "legal_actions":null,
        "action":null, "status":null, "transition":null, "error_code":null,
        "wait_for_millis":null, "wait_outcome":null, "recovery":null
    })
}

pub(super) fn assert_schema(validator: &Validator, value: &Value) {
    if let Err(error) = validator.validate(value) {
        panic!("runtime-v3 schema rejected {value}: {error}");
    }
}

pub(super) fn with_lease(mut request: Value, lease: &Value) -> Value {
    for field in ["instance_id", "lease_id", "lease_epoch"] {
        request[field] = lease[field].clone();
    }
    request
}
