//! Native Unix admin sideband acceptance tests.
//!
//! These tests intentionally use a synthetic dispatcher.  They prove the
//! transport/queue boundary only; they do not claim a live service, gateway,
//! host, or gameplay effect.

#![cfg(unix)]

use ascension_watchdog::admin::{
    AcceptedView, AdminClient, AdminClientConfig, AdminCommand, AdminDispatchError,
    AdminDispatcher, AdminQueue, AdminRequest, AdminResult, AdminServer, AdminServerConfig,
    AuthReferences, Authz, Capability, CommandName, DispatchContext, EmptyParams, HealthSnapshot,
    MAX_FRAME_BYTES, MainLoopHealth, MainLoopPhase, ReplyStatus,
};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use uuid::Uuid;

struct Fixture {
    temp: TempDir,
    socket: PathBuf,
    read_token: PathBuf,
    admin_token: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
            .expect("protected parent");
        let read_token = temp.path().join("read.token");
        let admin_token = temp.path().join("admin.token");
        std::fs::write(&read_token, "read-test-token").expect("read token");
        std::fs::write(&admin_token, "admin-test-token").expect("admin token");
        for token in [&read_token, &admin_token] {
            std::fs::set_permissions(token, std::fs::Permissions::from_mode(0o600))
                .expect("token mode");
        }
        Self {
            socket: temp.path().join("watchdog.sock"),
            temp,
            read_token,
            admin_token,
        }
    }

    fn server(&self, queue: AdminQueue, health: MainLoopHealth) -> AdminServer {
        let auth = AuthReferences::new(&self.read_token, &self.admin_token).expect("auth refs");
        let config = AdminServerConfig::new(&self.socket, auth)
            .expect("server config")
            .with_max_clients(4)
            .expect("client bound")
            .with_worker_count(2)
            .expect("worker bound")
            .with_io_timeout(Duration::from_secs(2))
            .expect("I/O bound");
        AdminServer::start(config, queue, health).expect("server")
    }

    fn client(&self, capability: Capability, token: &Path) -> AdminClient {
        let config = AdminClientConfig::new(&self.socket, token, capability)
            .expect("client config")
            .with_timeout(Duration::from_secs(2))
            .expect("client timeout");
        AdminClient::new(config).expect("client")
    }
}

#[derive(Clone, Default)]
struct RecordingDispatcher {
    commands: Arc<Mutex<Vec<CommandName>>>,
}

impl RecordingDispatcher {
    fn count(&self) -> usize {
        self.commands.lock().expect("commands lock").len()
    }
}

impl AdminDispatcher for RecordingDispatcher {
    fn dispatch(
        &mut self,
        _context: &DispatchContext,
        command: &AdminCommand,
    ) -> std::result::Result<AdminResult, AdminDispatchError> {
        self.commands
            .lock()
            .expect("commands lock")
            .push(command.name());
        Ok(AdminResult::Accepted(AcceptedView {
            command: command.name(),
            queued: true,
        }))
    }
}

fn healthy() -> MainLoopHealth {
    let health = MainLoopHealth::new();
    health
        .publish(HealthSnapshot {
            phase: MainLoopPhase::Reconciling,
            ready: true,
            heartbeat_seq: 42,
            progress_age_ms: Some(2),
            phase_deadline_at_ms: None,
            queue_depth: 0,
            oldest_queue_age_ms: None,
            pending_operations: 0,
            instance_incarnation: None,
            lease_remaining_ms: None,
        })
        .expect("health");
    health
}

fn wait_for_depth(queue: &AdminQueue, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while queue.depth() != expected {
        assert!(
            Instant::now() < deadline,
            "queue depth did not reach {expected}"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

#[test]
fn accepted_mutation_is_drained_by_main_loop_and_duplicate_is_not_dispatched() {
    let fixture = Fixture::new();
    let queue = AdminQueue::new(4).expect("queue");
    let health = healthy();
    let server = fixture.server(queue.clone(), health.clone());
    let client = fixture.client(Capability::Admin, &fixture.admin_token);
    let dispatcher = RecordingDispatcher::default();
    let mut loop_dispatcher = dispatcher.clone();
    let request_client = client.clone();
    let request = thread::spawn(move || {
        request_client
            .execute("stop-once", AdminCommand::Stop(EmptyParams::default()))
            .expect("stop response")
    });
    wait_for_depth(&queue, 1);
    assert_eq!(queue.drain(&mut loop_dispatcher, &health, now_ms(), 16), 1);
    let response = request.join().expect("request thread");
    assert_eq!(response.status, ReplyStatus::Accepted);
    assert_eq!(response.health.heartbeat_seq, 42);
    assert_eq!(dispatcher.count(), 1);

    let duplicate = client
        .execute("stop-once", AdminCommand::Stop(EmptyParams::default()))
        .expect("duplicate response");
    assert_eq!(duplicate.status, ReplyStatus::Accepted);
    assert_eq!(dispatcher.count(), 1);
    server.shutdown().expect("shutdown");
}

#[test]
fn read_and_unknown_credentials_cannot_administer() {
    let fixture = Fixture::new();
    let queue = AdminQueue::new(4).expect("queue");
    let health = healthy();
    let server = fixture.server(queue.clone(), health);
    let auth = AuthReferences::new(&fixture.read_token, &fixture.admin_token)
        .expect("auth refs")
        .load()
        .expect("credentials");
    let admin_read = AdminRequest::new(
        Capability::Admin,
        "admin-test-token".to_string(),
        "admin-status".to_string(),
        AdminCommand::Status(EmptyParams::default()),
        1_000,
    )
    .expect("admin read request");
    assert!(matches!(auth.authorize(&admin_read), Authz::Allowed(_)));

    let read_client = fixture.client(Capability::Read, &fixture.read_token);
    let forbidden = read_client
        .execute("read-stop", AdminCommand::Stop(EmptyParams::default()))
        .expect("forbidden response");
    assert_eq!(forbidden.status, ReplyStatus::Forbidden);

    let wrong_token = fixture.temp.path().join("wrong.token");
    std::fs::write(&wrong_token, "wrong-test-token").expect("wrong token");
    std::fs::set_permissions(&wrong_token, std::fs::Permissions::from_mode(0o600))
        .expect("wrong token mode");
    let wrong_client = fixture.client(Capability::Admin, &wrong_token);
    let unauthorized = wrong_client
        .execute("wrong-stop", AdminCommand::Stop(EmptyParams::default()))
        .expect("unauthorized response");
    assert_eq!(unauthorized.status, ReplyStatus::Unauthorized);
    assert_eq!(queue.depth(), 0);
    server.shutdown().expect("shutdown");
}

#[test]
fn duplicate_unknown_and_oversized_frames_fail_closed() {
    let fixture = Fixture::new();
    let queue = AdminQueue::new(4).expect("queue");
    let health = healthy();
    let server = fixture.server(queue, health);
    let request_id = Uuid::new_v4();
    let base = format!(
        r#"{{"contract":"watchdog-admin-v1","request_id":"{request_id}","idempotency_key":"raw","capability":"read","token":"read-test-token","deadline_ms":1000,"command":{{"kind":"status","params":{{}}}}}}"#
    );
    let unknown = format!("{},\"unknown\":true}}", &base[..base.len() - 1]);
    let unknown_response = raw_exchange(&fixture.socket, unknown.as_bytes());
    assert_eq!(unknown_response.status, ReplyStatus::Invalid);

    let duplicate = format!(
        r#"{{"contract":"watchdog-admin-v1","request_id":"{request_id}","idempotency_key":"dup","capability":"read","token":"read-test-token","deadline_ms":1000,"deadline_ms":1000,"command":{{"kind":"status","params":{{}}}}}}"#
    );
    let duplicate_response = raw_exchange(&fixture.socket, duplicate.as_bytes());
    assert_eq!(duplicate_response.status, ReplyStatus::Invalid);

    let oversized = vec![0x41; MAX_FRAME_BYTES + 1];
    let oversized_response = raw_exchange_header_only(&fixture.socket, oversized.len());
    assert_eq!(oversized_response.status, ReplyStatus::BoundsExceeded);
    assert!(oversized.len() > MAX_FRAME_BYTES);
    server.shutdown().expect("shutdown");
}

#[test]
fn full_queue_returns_busy_and_never_runs_in_io_thread() {
    let fixture = Fixture::new();
    let queue = AdminQueue::new(1).expect("queue");
    let health = healthy();
    let server = fixture.server(queue.clone(), health.clone());
    let client = fixture.client(Capability::Admin, &fixture.admin_token);
    let first_client = client.clone();
    let first = thread::spawn(move || {
        first_client
            .execute("first", AdminCommand::Pause(EmptyParams::default()))
            .expect("first response")
    });
    wait_for_depth(&queue, 1);
    let second_client = client.clone();
    let second = thread::spawn(move || {
        second_client
            .execute("second", AdminCommand::Resume(EmptyParams::default()))
            .expect("second response")
    });
    let second_response = second.join().expect("second thread");
    assert_eq!(second_response.status, ReplyStatus::Busy);
    let dispatcher = RecordingDispatcher::default();
    let mut loop_dispatcher = dispatcher.clone();
    assert_eq!(queue.drain(&mut loop_dispatcher, &health, now_ms(), 16), 1);
    assert_eq!(
        first.join().expect("first thread").status,
        ReplyStatus::Accepted
    );
    assert_eq!(dispatcher.count(), 1);
    server.shutdown().expect("shutdown");
}

#[test]
fn health_and_drain_bounds_fail_closed() {
    let health = MainLoopHealth::new();
    let invalid = HealthSnapshot {
        queue_depth: 65,
        ..HealthSnapshot::default()
    };
    assert!(health.publish(invalid).is_err());

    let queue = AdminQueue::new(1).expect("queue");
    let dispatcher = RecordingDispatcher::default();
    let mut loop_dispatcher = dispatcher.clone();
    assert_eq!(queue.drain(&mut loop_dispatcher, &health, now_ms(), 0), 0);
    assert_eq!(dispatcher.count(), 0);
}

#[test]
fn dispatch_context_is_authenticated_token_free_and_health_age_is_monotonic() {
    let fixture = Fixture::new();
    let request = AdminRequest::new(
        Capability::Admin,
        "admin-test-token".to_string(),
        "context-key".to_string(),
        AdminCommand::Stop(EmptyParams::default()),
        1_000,
    )
    .expect("request");
    let auth = AuthReferences::new(&fixture.read_token, &fixture.admin_token)
        .expect("auth refs")
        .load()
        .expect("credentials");
    let Authz::Allowed(principal) = auth.authorize(&request) else {
        panic!("admin credential should authenticate");
    };
    let context = request.dispatch_context(principal).expect("context");
    assert_eq!(context.request_id().to_string(), request.request_id);
    assert_eq!(context.idempotency_key(), "context-key");
    assert_eq!(context.capability(), Capability::Admin);
    assert_eq!(context.principal(), principal);
    assert_eq!(context.command_fingerprint(), request.fingerprint());
    assert!(!format!("{context:?}").contains("admin-test-token"));

    let health = MainLoopHealth::new();
    health
        .publish(HealthSnapshot {
            phase: MainLoopPhase::Reconciling,
            ready: true,
            heartbeat_seq: 7,
            progress_age_ms: Some(0),
            ..HealthSnapshot::default()
        })
        .expect("initial health");
    thread::sleep(Duration::from_millis(20));
    let before = health.snapshot();
    assert!(before.progress_age_ms.unwrap_or(0) >= 10);
    health
        .publish(HealthSnapshot {
            phase: MainLoopPhase::Blocked,
            ready: false,
            heartbeat_seq: 7,
            progress_age_ms: None,
            ..HealthSnapshot::default()
        })
        .expect("same heartbeat health");
    thread::sleep(Duration::from_millis(20));
    let after = health.snapshot();
    assert_eq!(after.heartbeat_seq, 7);
    assert!(!after.ready);
    assert!(after.progress_age_ms.unwrap_or(0) >= before.progress_age_ms.unwrap_or(0));
    assert!(
        health
            .publish(HealthSnapshot {
                heartbeat_seq: 6,
                ..HealthSnapshot::default()
            })
            .is_err()
    );
}

#[test]
fn socket_and_parent_modes_are_protected_and_incumbent_is_not_deleted() {
    let fixture = Fixture::new();
    let queue = AdminQueue::new(1).expect("queue");
    let health = healthy();
    let server = fixture.server(queue, health);
    let parent = std::fs::symlink_metadata(fixture.socket.parent().expect("parent"))
        .expect("parent metadata");
    assert_eq!(parent.permissions().mode() & 0o777, 0o700);
    let socket = std::fs::symlink_metadata(&fixture.socket).expect("socket metadata");
    assert_eq!(socket.permissions().mode() & 0o777, 0o600);
    assert!(socket.file_type().is_socket());

    // Replace the path while the original listener remains live.  The guard
    // must compare device/inode and leave this incumbent socket in place.
    std::fs::remove_file(&fixture.socket).expect("unlink test path");
    let incumbent = UnixListener::bind(&fixture.socket).expect("incumbent");
    drop(server);
    assert!(fixture.socket.exists());
    drop(incumbent);
    std::fs::remove_file(&fixture.socket).expect("incumbent cleanup");
}

fn raw_exchange(path: &Path, body: &[u8]) -> ascension_watchdog::admin::AdminResponse {
    let mut stream = UnixStream::connect(path).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let length = u32::try_from(body.len()).expect("test frame length");
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(body))
        .expect("write frame");
    read_response(&mut stream)
}

fn raw_exchange_header_only(
    path: &Path,
    body_len: usize,
) -> ascension_watchdog::admin::AdminResponse {
    let mut stream = UnixStream::connect(path).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let length = u32::try_from(body_len).expect("test frame length");
    stream
        .write_all(&length.to_be_bytes())
        .expect("write oversized header");
    read_response(&mut stream)
}

fn read_response(stream: &mut UnixStream) -> ascension_watchdog::admin::AdminResponse {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).expect("response length");
    let body_len = u32::from_be_bytes(length) as usize;
    assert!(body_len <= MAX_FRAME_BYTES);
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).expect("response body");
    serde_json::from_slice(&body).expect("response JSON")
}
