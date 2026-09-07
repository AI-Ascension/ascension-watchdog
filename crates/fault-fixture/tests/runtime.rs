//! Runtime-v3 newline-adapter coverage against the frozen Draft 2020-12 schema.

use std::fmt::Write as FmtWrite;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use fault_fixture::{
    Client, Frame, MAX_RUNTIME_OPERATIONS, RUNTIME_V3_SCHEMA_DIGEST, RUNTIME_V3_SCHEMA_JSON,
};
use jsonschema::{Draft, Validator};
use serde_json::{Value, json};
use uuid::Uuid;

struct RunningServer {
    child: Child,
    address: SocketAddr,
    database: PathBuf,
}

impl RunningServer {
    fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let database = std::env::temp_dir().join(format!(
            "watchdog-runtime-fixture-{}.sqlite",
            Uuid::new_v4()
        ));
        Self::start_on_database(database)
    }

    fn start_on_database(database: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let child = Command::new(env!("CARGO_BIN_EXE_fault-fixture-server"))
            .arg("--db")
            .arg(&database)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        // Own cleanup immediately after spawn, including announcement failures
        // and assertion unwinding in the calling test.
        let mut server = Self {
            child,
            address: SocketAddr::from(([127, 0, 0, 1], 0)),
            database,
        };
        let stdout = server
            .child
            .stdout
            .take()
            .ok_or("server stdout unavailable")?;
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        server.address = line
            .strip_prefix("LISTEN ")
            .ok_or("server did not announce its listener")?
            .trim()
            .parse()?;
        Ok(server)
    }

    fn stop(mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.child.try_wait()?.is_none() {
            self.child.kill()?;
        }
        let _ = self.child.wait();
        remove_database(&self.database);
        Ok(())
    }

    fn crash_preserving_database(mut self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        if self.child.try_wait()?.is_none() {
            self.child.kill()?;
        }
        let _ = self.child.wait()?;
        let database = self.database.clone();
        // The replacement process needs the durable files. The child has
        // already been reaped, so forgetting only this test owner avoids its
        // normal cleanup path until the replacement stops.
        std::mem::forget(self);
        Ok(database)
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        // Child::kill targets the still-owned handle, never a discovered PID.
        // Reap before removing this fixture's uniquely named database files.
        let _ = self.child.kill();
        let _ = self.child.wait();
        remove_database(&self.database);
    }
}

#[test]
fn failed_test_scope_reaps_its_owned_server() -> Result<(), Box<dyn std::error::Error>> {
    let server = RunningServer::start()?;
    let address = server.address;
    let database = server.database.clone();
    let outcome = std::panic::catch_unwind(move || {
        let _owned = server;
        panic!("synthetic test failure");
    });
    assert!(outcome.is_err());
    assert!(!database.exists());
    assert!(TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_err());
    Ok(())
}

fn assert_connection_closed(peer: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    peer.set_read_timeout(Some(Duration::from_secs(4)))?;
    match peer.read(&mut [0; 1]) {
        Ok(0) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => Ok(()),
        other => Err(format!("expected bounded peer close, got {other:?}").into()),
    }
}

fn assert_server_healthy(server: &RunningServer) -> Result<(), Box<dyn std::error::Error>> {
    let response = Client::new(server.address).request(&Frame::request(
        "stats",
        "recovery_read",
        json!({}),
    ))?;
    assert_eq!(response.kind, "stats_response");
    Ok(())
}

#[test]
fn silent_peer_cannot_block_or_terminate_the_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let server = RunningServer::start()?;
    let mut peer = TcpStream::connect_timeout(&server.address, Duration::from_secs(1))?;
    let started = Instant::now();
    assert_connection_closed(&mut peer)?;
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_server_healthy(&server)?;
    server.stop()
}

#[test]
fn trickled_http_headers_cannot_extend_the_absolute_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let server = RunningServer::start()?;
    let mut peer = TcpStream::connect_timeout(&server.address, Duration::from_secs(1))?;
    peer.write_all(b"GET /api/v3/runtime/state HTTP/1.1\r\nX-Slow: ")?;
    let mut sender = peer.try_clone()?;
    sender.set_write_timeout(Some(Duration::from_secs(1)))?;
    let trickle = std::thread::spawn(move || {
        for _ in 0..12 {
            if sender.write_all(b"a").is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    });
    let started = Instant::now();
    let result = assert_connection_closed(&mut peer);
    trickle.join().map_err(|_| "trickle thread failed")?;
    result?;
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_server_healthy(&server)?;
    server.stop()
}

#[test]
fn aggregate_http_headers_are_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let server = RunningServer::start()?;
    for count in [64, 130] {
        let mut peer = TcpStream::connect_timeout(&server.address, Duration::from_secs(1))?;
        peer.set_write_timeout(Some(Duration::from_secs(1)))?;
        let value = if count == 64 {
            "a".repeat(300)
        } else {
            "a".to_owned()
        };
        let mut request = "GET /api/v3/runtime/state HTTP/1.1\r\n".to_owned();
        for index in 0..count {
            write!(request, "X-{index}: {value}\r\n")?;
        }
        peer.write_all(request.as_bytes())?;
        assert_connection_closed(&mut peer)?;
        assert_server_healthy(&server)?;
    }
    server.stop()
}

fn remove_database(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    let _ = std::fs::remove_file(path.with_extension("sqlite.lock"));
}

fn send_raw(address: SocketAddr, value: &Value) -> Result<Value, Box<dyn std::error::Error>> {
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

fn send_http(
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

fn bootstrap(client: &Client) -> Result<Value, Box<dyn std::error::Error>> {
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

fn envelope(
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

fn assert_schema(validator: &Validator, value: &Value) {
    if let Err(error) = validator.validate(value) {
        panic!("runtime-v3 schema rejected {value}: {error}");
    }
}

fn with_lease(mut request: Value, lease: &Value) -> Value {
    for field in ["instance_id", "lease_id", "lease_epoch"] {
        request[field] = lease[field].clone();
    }
    request
}

#[test]
fn released_lease_cannot_authorize_a_new_runtime_session() -> Result<(), Box<dyn std::error::Error>>
{
    let server = RunningServer::start()?;
    let lease = bootstrap(&Client::new(server.address))?;
    let state = send_raw(
        server.address,
        &with_lease(envelope("state_request", 0, None, None), &lease),
    )?;
    let mut release = with_lease(envelope("recover_request", 0, None, None), &lease);
    release["recovery"] = json!({"kind":"release_lease","operation_id":null});
    assert_eq!(send_raw(server.address, &release)?["status"], "cancelled");
    let connection = rusqlite::Connection::open(&server.database)?;
    let revoked: i64 = connection.query_row("SELECT revoked FROM lease", [], |row| row.get(0))?;
    assert_eq!(revoked, 1);
    let mut dispatch = with_lease(
        envelope(
            "dispatch_action_request",
            0,
            state["state_id"].as_str(),
            Some("after-release"),
        ),
        &lease,
    );
    dispatch["session_id"] = json!("replacement-session");
    dispatch["action"] = state["legal_actions"][0].clone();
    let rejected = send_raw(server.address, &dispatch)?;
    assert_ne!(rejected["status"], "accepted");
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM runtime_operations WHERE operation_id='after-release'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    drop(connection);
    server.stop()?;
    Ok(())
}

#[test]
fn newline_runtime_queue_guard_and_recovery_are_schema_valid()
-> Result<(), Box<dyn std::error::Error>> {
    let schema: Value = serde_json::from_str(RUNTIME_V3_SCHEMA_JSON)?;
    let validator = jsonschema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .build(&schema)?;
    let server = RunningServer::start()?;

    let lease = bootstrap(&Client::new(server.address))?;
    let envelope = |kind, generation, state_id, operation_id| {
        with_lease(envelope(kind, generation, state_id, operation_id), &lease)
    };
    let state_request = envelope("state_request", 0, None, None);
    let state_response = send_raw(server.address, &state_request)?;
    assert_schema(&validator, &state_response);
    assert_eq!(state_response["kind"], "state_response");
    let state_id = state_response["state_id"]
        .as_str()
        .ok_or("state id")?
        .to_owned();

    let legal_request = envelope("legal_actions_request", 0, Some(&state_id), None);
    let legal_response = send_raw(server.address, &legal_request)?;
    assert_schema(&validator, &legal_response);
    let action = legal_response["legal_actions"][0].clone();

    let operation_id = "operation-1";
    let mut dispatch = envelope(
        "dispatch_action_request",
        0,
        Some(&state_id),
        Some(operation_id),
    );
    dispatch["action"] = action.clone();
    let accepted = send_raw(server.address, &dispatch)?;
    assert_schema(&validator, &accepted);
    assert_eq!(accepted["status"], "accepted");

    let second_id = "operation-2";
    let mut conflicting = envelope(
        "dispatch_action_request",
        0,
        Some(&state_id),
        Some(second_id),
    );
    conflicting["action"] = action;
    let rejected = send_raw(server.address, &conflicting)?;
    assert_schema(&validator, &rejected);
    assert_eq!(rejected["status"], "rejected");
    assert_eq!(rejected["error_code"], "active_operation");

    let mut wait = envelope("wait_request", 0, None, Some(operation_id));
    wait["wait_for_millis"] = json!(1);
    let settled = send_raw(server.address, &wait)?;
    assert_schema(&validator, &settled);
    assert_eq!(settled["status"], "settled");
    assert_eq!(settled["wait_outcome"], "successor");
    assert_eq!(settled["generation"], 1);

    let replay = send_raw(server.address, &wait)?;
    assert_schema(&validator, &replay);
    assert_eq!(replay["status"], "settled");
    assert_eq!(replay["observation"], settled["observation"]);

    let mut recover = envelope("recover_request", 1, None, None);
    recover["recovery"] = json!({"kind":"reobserve","operation_id":null});
    let reobserved = send_raw(server.address, &recover)?;
    assert_schema(&validator, &reobserved);
    assert_eq!(reobserved["status"], "accepted");

    let mut next_dispatch = envelope(
        "dispatch_action_request",
        1,
        Some(&state_id),
        Some("operation-3"),
    );
    next_dispatch["action"] = settled["legal_actions"][0].clone();
    let admitted = send_raw(server.address, &next_dispatch)?;
    assert_schema(&validator, &admitted);
    assert_eq!(admitted["status"], "accepted");

    let mut stop = envelope("recover_request", 1, None, None);
    stop["recovery"] = json!({"kind":"stop_episode","operation_id":null});
    let cancelled = send_raw(server.address, &stop)?;
    assert_schema(&validator, &cancelled);
    assert_eq!(cancelled["status"], "cancelled");

    let mut unknown_wait = envelope("wait_request", 1, None, Some("operation-3"));
    unknown_wait["wait_for_millis"] = json!(1);
    let unknown = send_raw(server.address, &unknown_wait)?;
    assert_schema(&validator, &unknown);
    assert_eq!(unknown["status"], "unknown");
    assert_eq!(unknown["wait_outcome"], "recovery_required");

    server.stop()?;
    Ok(())
}

#[test]
fn runtime_rejects_a_second_session_for_the_same_instance() -> Result<(), Box<dyn std::error::Error>>
{
    let server = RunningServer::start()?;
    let lease = bootstrap(&Client::new(server.address))?;
    let action = json!({
        "action_id":"action-end-turn",
        "action":{"kind":"end_turn"}
    });

    let mut first = with_lease(
        envelope(
            "dispatch_action_request",
            0,
            Some("state-a"),
            Some("operation-a"),
        ),
        &lease,
    );
    first["session_id"] = json!("session-a");
    first["action"] = action.clone();
    let accepted = send_raw(server.address, &first)?;
    assert_eq!(accepted["status"], "accepted");

    // Replaying the same operation through its original session remains
    // idempotent and must not create another journal row.
    let replay = send_raw(server.address, &first)?;
    assert_eq!(replay["status"], "accepted");
    assert_eq!(replay["operation_id"], "operation-a");

    let mut second = with_lease(
        envelope(
            "dispatch_action_request",
            0,
            Some("state-b"),
            Some("operation-b"),
        ),
        &lease,
    );
    second["session_id"] = json!("session-b");
    second["action"] = action;
    let rejected = send_raw(server.address, &second)?;
    assert_eq!(rejected["status"], "rejected");
    assert_eq!(rejected["error_code"], "active_session");
    assert_eq!(rejected["session_id"], "session-b");

    let connection = rusqlite::Connection::open(&server.database)?;
    let rows: (i64, i64, i64) = connection.query_row(
        "SELECT (SELECT COUNT(*) FROM runtime_sessions), (SELECT COUNT(*) FROM runtime_operations), (SELECT COUNT(*) FROM runtime_queue)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(rows, (1, 1, 1));
    drop(connection);

    let mut wait = with_lease(
        envelope("wait_request", 0, None, Some("operation-a")),
        &lease,
    );
    wait["session_id"] = json!("session-a");
    wait["wait_for_millis"] = json!(1);
    let settled = send_raw(server.address, &wait)?;
    assert_eq!(settled["status"], "settled");
    assert_eq!(settled["generation"], 1);
    server.stop()?;
    Ok(())
}

#[test]
fn http_runtime_action_and_wait_use_the_same_durable_queue()
-> Result<(), Box<dyn std::error::Error>> {
    let schema: Value = serde_json::from_str(RUNTIME_V3_SCHEMA_JSON)?;
    let validator = jsonschema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .build(&schema)?;
    let server = RunningServer::start()?;
    let lease = bootstrap(&Client::new(server.address))?;
    let envelope = |kind, generation, state_id, operation_id| {
        with_lease(envelope(kind, generation, state_id, operation_id), &lease)
    };
    let operation_id = "http-operation-1";
    let mut action_request = envelope(
        "dispatch_action_request",
        0,
        Some("state-http"),
        Some(operation_id),
    );
    action_request["action"] = json!({
        "action_id":"action-end-turn",
        "action":{"kind":"end_turn"}
    });
    let (status, accepted) = send_http(
        server.address,
        "POST",
        "/api/v3/runtime/action",
        &action_request,
    )?;
    assert_eq!(status, 200);
    assert_schema(&validator, &accepted);
    assert_eq!(accepted["status"], "accepted");

    let mut wait_request = envelope("wait_request", 0, None, Some(operation_id));
    wait_request["wait_for_millis"] = json!(1);
    let (status, settled) = send_http(
        server.address,
        "POST",
        "/api/v3/runtime/wait",
        &wait_request,
    )?;
    assert_eq!(status, 200);
    assert_schema(&validator, &settled);
    assert_eq!(settled["status"], "settled");
    assert_eq!(settled["generation"], 1);
    server.stop()?;
    Ok(())
}

#[test]
fn http_runtime_cannot_create_its_own_mutation_authority() -> Result<(), Box<dyn std::error::Error>>
{
    let server = RunningServer::start()?;
    let mut request = envelope(
        "dispatch_action_request",
        0,
        Some("unapproved-state"),
        Some("unapproved-operation"),
    );
    request["action"] = json!({
        "action_id":"action-end-turn", "action":{"kind":"end_turn"}
    });
    let (status, _) = send_http(server.address, "POST", "/api/v3/runtime/action", &request)?;
    assert_eq!(status, 409);
    let connection = rusqlite::Connection::open(&server.database)?;
    let rows: (i64, i64) = connection.query_row(
        "SELECT (SELECT COUNT(*) FROM runtime_sessions), (SELECT COUNT(*) FROM runtime_operations)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(rows, (0, 0));
    drop(connection);
    server.stop()?;
    Ok(())
}

#[test]
fn http_runtime_rejects_queued_old_lease_after_authority_rotation()
-> Result<(), Box<dyn std::error::Error>> {
    let server = RunningServer::start()?;
    let client = Client::new(server.address);
    let lease = bootstrap(&client)?;
    let session_id = "runtime-stale-session";
    let mut action_request = envelope(
        "dispatch_action_request",
        0,
        Some("state-stale"),
        Some("stale-operation"),
    );
    action_request["instance_id"] = lease["instance_id"].clone();
    action_request["session_id"] = json!(session_id);
    action_request["lease_id"] = lease["lease_id"].clone();
    action_request["lease_epoch"] = lease["lease_epoch"].clone();
    action_request["action"] = json!({
        "action_id":"action-end-turn",
        "action":{"kind":"end_turn"}
    });
    let (status, accepted) = send_http(
        server.address,
        "POST",
        "/api/v3/runtime/action",
        &action_request,
    )?;
    assert_eq!(status, 200);
    assert_eq!(accepted["status"], "accepted");

    let replacement = bootstrap(&client)?;
    assert_ne!(replacement["lease_id"], lease["lease_id"]);
    let mut wait_request = envelope("wait_request", 0, None, Some("stale-operation"));
    wait_request["instance_id"] = lease["instance_id"].clone();
    wait_request["session_id"] = json!(session_id);
    wait_request["lease_id"] = lease["lease_id"].clone();
    wait_request["lease_epoch"] = lease["lease_epoch"].clone();
    wait_request["wait_for_millis"] = json!(1);
    let (status, settled) = send_http(
        server.address,
        "POST",
        "/api/v3/runtime/wait",
        &wait_request,
    )?;
    assert_eq!(
        status, 409,
        "queued runtime work must not execute after authority rotation: {settled}"
    );
    // The frozen wait contract reports blocked progress as unknown, never as
    // settlement or as proof of non-execution from an HTTP status alone.
    assert_eq!(settled["status"], "unknown");
    assert_eq!(settled["wait_outcome"], "recovery_required");
    assert_eq!(settled["error_code"], "stale_lease");
    let schema: Value = serde_json::from_str(RUNTIME_V3_SCHEMA_JSON)?;
    assert_schema(&jsonschema::validator_for(&schema)?, &settled);
    let connection = rusqlite::Connection::open(&server.database)?;
    let durable: (String, i64) = connection.query_row(
        "SELECT o.status,s.generation FROM runtime_operations o JOIN runtime_sessions s ON o.session_id=s.session_id WHERE o.operation_id='stale-operation'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(durable, ("UNKNOWN".to_owned(), 0));
    drop(connection);
    server.stop()?;
    Ok(())
}

#[test]
fn stale_authority_cannot_quarantine_a_new_authoritys_queued_operation()
-> Result<(), Box<dyn std::error::Error>> {
    let server = RunningServer::start()?;
    let client = Client::new(server.address);
    let old_lease = bootstrap(&client)?;
    let new_lease = bootstrap(&client)?;
    let session_id = "runtime-new-authority-session";
    let operation_id = "runtime-new-authority-operation";

    let mut dispatch = with_lease(
        envelope(
            "dispatch_action_request",
            0,
            Some("state-new-authority"),
            Some(operation_id),
        ),
        &new_lease,
    );
    dispatch["session_id"] = json!(session_id);
    dispatch["action"] = json!({
        "action_id":"action-end-turn",
        "action":{"kind":"end_turn"}
    });
    let accepted = send_raw(server.address, &dispatch)?;
    assert_eq!(accepted["status"], "accepted");

    // The old authority is allowed to report stale progress, but its request
    // must be bound to the operation's complete original identity. It names
    // the new operation id while carrying the old instance/lease authority.
    let mut stale_wait = with_lease(
        envelope("wait_request", 0, None, Some(operation_id)),
        &old_lease,
    );
    stale_wait["session_id"] = json!(session_id);
    stale_wait["wait_for_millis"] = json!(1);
    let stale = send_raw(server.address, &stale_wait)?;
    assert_eq!(stale["status"], "unknown");
    assert_eq!(stale["error_code"], "stale_lease");
    assert_eq!(stale["wait_outcome"], "recovery_required");

    let connection = rusqlite::Connection::open(&server.database)?;
    let queued: (String, i64) = connection.query_row(
        "SELECT o.status,(SELECT COUNT(*) FROM runtime_queue WHERE operation_id=o.operation_id) FROM runtime_operations o WHERE o.operation_id=?1",
        [operation_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(queued, ("ADMITTED".to_owned(), 1));
    drop(connection);

    let mut valid_wait = with_lease(
        envelope("wait_request", 0, None, Some(operation_id)),
        &new_lease,
    );
    valid_wait["session_id"] = json!(session_id);
    valid_wait["wait_for_millis"] = json!(1);
    let settled = send_raw(server.address, &valid_wait)?;
    assert_eq!(settled["status"], "settled");
    assert_eq!(settled["operation_id"], operation_id);

    let connection = rusqlite::Connection::open(&server.database)?;
    let final_state: (String, i64) = connection.query_row(
        "SELECT o.status,(SELECT COUNT(*) FROM runtime_queue WHERE operation_id=o.operation_id) FROM runtime_operations o WHERE o.operation_id=?1",
        [operation_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(final_state, ("SETTLED".to_owned(), 0));
    drop(connection);
    server.stop()?;
    Ok(())
}

#[test]
fn http_runtime_persists_unknown_when_queued_lease_is_revoked()
-> Result<(), Box<dyn std::error::Error>> {
    let server = RunningServer::start()?;
    let client = Client::new(server.address);
    let lease = bootstrap(&client)?;
    let session_id = "runtime-revoked-session";
    let operation_id = "runtime-revoked-operation";
    let mut action_request = with_lease(
        envelope(
            "dispatch_action_request",
            0,
            Some("state-revoked"),
            Some(operation_id),
        ),
        &lease,
    );
    action_request["instance_id"] = lease["instance_id"].clone();
    action_request["session_id"] = json!(session_id);
    action_request["action"] = json!({
        "action_id":"action-end-turn",
        "action":{"kind":"end_turn"}
    });
    let (status, accepted) = send_http(
        server.address,
        "POST",
        "/api/v3/runtime/action",
        &action_request,
    )?;
    assert_eq!(status, 200);
    assert_eq!(accepted["status"], "accepted");

    let revoked = client.request(&Frame::request(
        "lease_revoke_request",
        "lease_revoke",
        json!({"lease":lease,"reason":"operator"}),
    ))?;
    assert_eq!(revoked.payload["result"]["status"], "LEASE_REVOKED");

    let mut wait_request = with_lease(
        envelope("wait_request", 0, None, Some(operation_id)),
        &lease,
    );
    wait_request["instance_id"] = lease["instance_id"].clone();
    wait_request["session_id"] = json!(session_id);
    wait_request["wait_for_millis"] = json!(1);
    let (status, unknown) = send_http(
        server.address,
        "POST",
        "/api/v3/runtime/wait",
        &wait_request,
    )?;
    assert_eq!(status, 409);
    assert_eq!(unknown["status"], "unknown");
    assert_eq!(unknown["error_code"], "stale_lease");
    assert_eq!(unknown["wait_outcome"], "recovery_required");
    let schema: Value = serde_json::from_str(RUNTIME_V3_SCHEMA_JSON)?;
    assert_schema(&jsonschema::validator_for(&schema)?, &unknown);

    let connection = rusqlite::Connection::open(&server.database)?;
    let durable: (String, i64) = connection.query_row(
        "SELECT o.status,(SELECT COUNT(*) FROM runtime_queue WHERE operation_id=o.operation_id) FROM runtime_operations o WHERE o.operation_id=?1",
        [operation_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(durable, ("UNKNOWN".to_owned(), 0));
    drop(connection);
    server.stop()?;
    Ok(())
}

#[test]
fn runtime_operation_history_backpressures_without_eviction()
-> Result<(), Box<dyn std::error::Error>> {
    let schema: Value = serde_json::from_str(RUNTIME_V3_SCHEMA_JSON)?;
    let validator = jsonschema::validator_for(&schema)?;
    let server = RunningServer::start()?;
    let lease = bootstrap(&Client::new(server.address))?;
    let session_id = "runtime-retention-session";
    let state_id = "state-retention";
    let action = json!({
        "action_id":"action-end-turn",
        "action":{"kind":"end_turn"}
    });
    let mut generation = 0_i64;
    let mut last_operation_id = String::new();

    for index in 0..MAX_RUNTIME_OPERATIONS {
        let operation_id = format!("runtime-retained-operation-{index}");
        let mut dispatch = with_lease(
            envelope(
                "dispatch_action_request",
                generation,
                Some(state_id),
                Some(&operation_id),
            ),
            &lease,
        );
        dispatch["session_id"] = json!(session_id);
        dispatch["action"] = action.clone();
        let accepted = send_raw(server.address, &dispatch)?;
        assert_schema(&validator, &accepted);
        assert_eq!(accepted["status"], "accepted");

        let mut wait = with_lease(
            envelope("wait_request", generation, None, Some(&operation_id)),
            &lease,
        );
        wait["session_id"] = json!(session_id);
        wait["wait_for_millis"] = json!(1);
        let settled = send_raw(server.address, &wait)?;
        assert_schema(&validator, &settled);
        assert_eq!(settled["status"], "settled");
        generation = settled["generation"].as_i64().ok_or("settled generation")?;
        last_operation_id = operation_id;
    }

    let connection = rusqlite::Connection::open(&server.database)?;
    let retained: i64 =
        connection.query_row("SELECT COUNT(*) FROM runtime_operations", [], |row| {
            row.get(0)
        })?;
    assert_eq!(retained, i64::try_from(MAX_RUNTIME_OPERATIONS)?);
    drop(connection);

    // Existing settled tombstones remain deduplicable even at capacity.
    let mut replay = with_lease(
        envelope(
            "dispatch_action_request",
            generation - 1,
            Some(state_id),
            Some(&last_operation_id),
        ),
        &lease,
    );
    replay["session_id"] = json!(session_id);
    replay["action"] = action.clone();
    let duplicate = send_raw(server.address, &replay)?;
    assert_schema(&validator, &duplicate);
    assert_eq!(duplicate["status"], "settled");
    assert_eq!(duplicate["operation_id"], last_operation_id);

    let mut overflow = with_lease(
        envelope(
            "dispatch_action_request",
            generation,
            Some(state_id),
            Some("runtime-over-capacity"),
        ),
        &lease,
    );
    overflow["session_id"] = json!(session_id);
    overflow["action"] = action;
    let rejected = send_raw(server.address, &overflow)?;
    assert_schema(&validator, &rejected);
    assert_eq!(rejected["status"], "rejected");
    assert_eq!(rejected["error_code"], "runtime_capacity");

    let connection = rusqlite::Connection::open(&server.database)?;
    let retained_after_rejection: i64 =
        connection.query_row("SELECT COUNT(*) FROM runtime_operations", [], |row| {
            row.get(0)
        })?;
    assert_eq!(
        retained_after_rejection,
        i64::try_from(MAX_RUNTIME_OPERATIONS)?
    );
    drop(connection);
    server.stop()?;
    Ok(())
}

#[test]
fn fresh_authority_recovers_historical_session_without_rewriting_old_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let server = RunningServer::start()?;
    let address = server.address;
    let database = server.database.clone();
    let old_lease = bootstrap(&Client::new(address))?;
    let session_id = "historical-session";
    let operation_id = "historical-operation";

    let mut state_request = with_lease(envelope("state_request", 0, None, None), &old_lease);
    state_request["session_id"] = json!(session_id);
    let state = send_raw(address, &state_request)?;
    let state_id = state["state_id"].as_str().ok_or("state id")?.to_owned();
    let mut dispatch = with_lease(
        envelope(
            "dispatch_action_request",
            0,
            Some(&state_id),
            Some(operation_id),
        ),
        &old_lease,
    );
    dispatch["session_id"] = json!(session_id);
    dispatch["action"] = state["legal_actions"][0].clone();
    assert_eq!(send_raw(address, &dispatch)?["status"], "accepted");
    let mut wait = with_lease(
        envelope("wait_request", 0, None, Some(operation_id)),
        &old_lease,
    );
    wait["session_id"] = json!(session_id);
    wait["wait_for_millis"] = json!(1);
    assert_eq!(send_raw(address, &wait)?["status"], "settled");

    let connection = rusqlite::Connection::open(&database)?;
    let old_identity: (String, String, i64) = connection.query_row(
        "SELECT instance_id,lease_id,lease_epoch FROM runtime_operations WHERE operation_id=?1",
        [operation_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    drop(connection);

    let database = server.crash_preserving_database()?;
    let restarted = RunningServer::start_on_database(database.clone())?;
    let restarted_client = Client::new(restarted.address);

    // A stale lease cannot create a new session or admit a mutation after the
    // restart; the adapter returns an explicit stale-authority error.
    let mut stale_dispatch = with_lease(
        envelope(
            "dispatch_action_request",
            1,
            Some(&state_id),
            Some("stale-attempt"),
        ),
        &old_lease,
    );
    stale_dispatch["session_id"] = json!("new-session-after-restart");
    stale_dispatch["action"] = state["legal_actions"][0].clone();
    let stale_response = send_raw(restarted.address, &stale_dispatch)?;
    assert_eq!(stale_response["error"], "STALE_LEASE");

    let new_lease = bootstrap(&restarted_client)?;
    let mut recover = with_lease(envelope("recover_request", 1, None, None), &new_lease);
    recover["session_id"] = json!(session_id);
    recover["recovery"] = json!({"kind":"reconcile","operation_id":operation_id});
    let recovered = send_raw(restarted.address, &recover)?;
    assert_eq!(recovered["status"], "settled");
    assert_eq!(recovered["operation_id"], operation_id);
    assert_eq!(recovered["lease_id"], new_lease["lease_id"]);

    let connection = rusqlite::Connection::open(&database)?;
    let retained: (String, String, i64, String) = connection.query_row(
        "SELECT o.instance_id,o.lease_id,o.lease_epoch,o.status FROM runtime_operations o WHERE o.operation_id=?1",
        [operation_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(
        retained,
        (
            old_identity.0,
            old_identity.1,
            old_identity.2,
            "SETTLED".to_owned()
        )
    );
    drop(connection);
    restarted.stop()?;
    Ok(())
}
