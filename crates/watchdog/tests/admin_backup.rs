//! Authenticated backup admission, replay and denial tests.
//!
//! These tests exercise the real Unix admin socket and reconciliation owner;
//! they do not launch a game, provider, or workstation service.

#![cfg(unix)]

use ascension_watchdog::admin::{
    AdminClient, AdminClientConfig, AdminCommand, AdminQueue, AdminResult, AdminServer,
    AdminServerConfig, AuthReferences, BackupRequest, Capability, ReplyStatus,
};
use ascension_watchdog::cli;
use ascension_watchdog::service::ServiceLoop;
use ascension_watchdog::{Supervisor, WatchdogConfig};
use rusqlite::Connection;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

struct Fixture {
    temp: TempDir,
    config_path: PathBuf,
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
        for (path, value) in [(&read_token, "read-token"), (&admin_token, "admin-token")] {
            std::fs::write(path, value).expect("token");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("token permissions");
        }
        Self {
            config_path: temp.path().join("config.json"),
            socket: temp.path().join("watchdog.sock"),
            read_token,
            admin_token,
            temp,
        }
    }

    fn config(&self) -> WatchdogConfig {
        WatchdogConfig {
            database: self.temp.path().join("state.sqlite3"),
            admin: Some(ascension_watchdog::config::AdminConfig {
                endpoint: self.socket.clone(),
                read_token_path: self.read_token.clone(),
                admin_token_path: self.admin_token.clone(),
                allowed_peer_sid: None,
            }),
            ..WatchdogConfig::default()
        }
    }

    fn write_config(&self, config: &WatchdogConfig) {
        config.to_file(&self.config_path).expect("config");
    }

    fn server(
        &self,
        queue: AdminQueue,
        health: ascension_watchdog::admin::MainLoopHealth,
    ) -> AdminServer {
        let auth =
            AuthReferences::new(&self.read_token, &self.admin_token).expect("auth references");
        let server_config = AdminServerConfig::new(&self.socket, auth)
            .expect("server config")
            .with_max_clients(4)
            .expect("client bound")
            .with_worker_count(2)
            .expect("worker bound")
            .with_io_timeout(Duration::from_secs(3))
            .expect("timeout");
        AdminServer::start(server_config, queue, health).expect("server")
    }

    fn client(&self, capability: Capability) -> AdminClient {
        let token = match capability {
            Capability::Read => self.read_token.clone(),
            Capability::Admin => self.admin_token.clone(),
        };
        AdminClient::new(
            AdminClientConfig::new(self.socket.clone(), token, capability).expect("client config"),
        )
        .expect("client")
    }
}

fn wait_for_queue<T: Send + 'static>(
    queue: &AdminQueue,
    request: &thread::JoinHandle<ascension_watchdog::Result<T>>,
) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while queue.depth() == 0 && !request.is_finished() {
        assert!(Instant::now() < deadline, "admin request was not queued");
        thread::sleep(Duration::from_millis(2));
    }
}

fn run_cli_backup(
    fixture: &Fixture,
    queue: &AdminQueue,
    service: &mut ServiceLoop,
    key: &str,
    backup_id: &str,
) -> ascension_watchdog::Result<Option<String>> {
    let config_path = fixture.config_path.clone();
    let key = key.to_owned();
    let backup_id = backup_id.to_owned();
    let request = thread::spawn(move || {
        cli::execute(vec![
            "backup".to_owned(),
            "--config".to_owned(),
            config_path.to_string_lossy().into_owned(),
            "--idempotency-key".to_owned(),
            key,
            "--backup-id".to_owned(),
            backup_id,
        ])
    });
    wait_for_queue(queue, &request);
    assert_eq!(
        service.drain_admin(queue, ascension_watchdog::storage::now_unix_ms()),
        1
    );
    request.join().expect("request thread")
}

fn backup_path(fixture: &Fixture, backup_id: &str) -> PathBuf {
    fixture
        .temp
        .path()
        .join("backups")
        .join(format!("{backup_id}.sqlite3"))
}

fn assert_durable(output: Option<String>, backup_id: &str) {
    let output = output.expect("backup output");
    let response: ascension_watchdog::admin::AdminResponse =
        serde_json::from_str(&output).expect("response JSON");
    assert_eq!(response.status, ReplyStatus::Ok);
    assert!(matches!(
        response.result,
        Some(AdminResult::Backup(view)) if view.backup_id == backup_id && view.durable
    ));
}

#[test]
fn authenticated_cli_backup_replays_after_owner_restart_without_recreating_file() {
    let fixture = Fixture::new();
    let config = fixture.config();
    fixture.write_config(&config);
    let mut service = ServiceLoop::new(
        Supervisor::initialize(config.clone()).expect("initialize"),
        Duration::from_millis(10),
    )
    .expect("service");
    let queue = AdminQueue::new(8).expect("queue");
    let server = fixture.server(queue.clone(), service.health());
    assert_durable(
        run_cli_backup(&fixture, &queue, &mut service, "backup-once", "release-a")
            .expect("first backup"),
        "release-a",
    );
    let path = backup_path(&fixture, "release-a");
    let original = std::fs::read(&path).expect("snapshot");
    let client = fixture.client(Capability::Admin);
    let request = thread::spawn(move || {
        client.execute(
            "different-request-same-backup",
            AdminCommand::Backup(BackupRequest {
                backup_id: "release-a".to_owned(),
            }),
        )
    });
    wait_for_queue(&queue, &request);
    service.drain_admin(&queue, ascension_watchdog::storage::now_unix_ms());
    assert_eq!(
        request
            .join()
            .expect("duplicate request")
            .expect("duplicate response")
            .status,
        ReplyStatus::Conflict
    );
    assert_eq!(std::fs::read(&path).expect("unchanged snapshot"), original);
    server.shutdown().expect("server shutdown");
    drop(service);

    let mut service = ServiceLoop::new(
        Supervisor::open(config.clone()).expect("reopen owner"),
        Duration::from_millis(10),
    )
    .expect("reopened service");
    let queue = AdminQueue::new(8).expect("reopened queue");
    let server = fixture.server(queue.clone(), service.health());
    assert_durable(
        run_cli_backup(&fixture, &queue, &mut service, "backup-once", "release-a")
            .expect("replayed backup"),
        "release-a",
    );
    assert_eq!(std::fs::read(&path).expect("replayed snapshot"), original);
    server.shutdown().expect("server shutdown");
}

#[test]
fn read_credentials_and_path_components_cannot_create_backups() {
    let fixture = Fixture::new();
    let config = fixture.config();
    fixture.write_config(&config);
    let mut service = ServiceLoop::new(
        Supervisor::initialize(config).expect("initialize"),
        Duration::from_millis(10),
    )
    .expect("service");
    let queue = AdminQueue::new(8).expect("queue");
    let server = fixture.server(queue.clone(), service.health());
    let read_response = fixture
        .client(Capability::Read)
        .execute(
            "read-backup",
            AdminCommand::Backup(BackupRequest {
                backup_id: "read-denied".to_owned(),
            }),
        )
        .expect("read response");
    assert_eq!(read_response.status, ReplyStatus::Forbidden);
    assert_eq!(queue.depth(), 0);
    let client = fixture.client(Capability::Admin);
    let request = thread::spawn(move || {
        client.execute(
            "path-backup",
            AdminCommand::Backup(BackupRequest {
                backup_id: "../outside".to_owned(),
            }),
        )
    });
    wait_for_queue(&queue, &request);
    service.drain_admin(&queue, ascension_watchdog::storage::now_unix_ms());
    let admin_response = request
        .join()
        .expect("path request")
        .expect("path response");
    assert_eq!(admin_response.status, ReplyStatus::Invalid);
    assert!(!fixture.temp.path().join("outside.sqlite3").exists());
    assert!(!fixture.temp.path().join("backups").exists());
    server.shutdown().expect("server shutdown");
    drop(service);
}

#[test]
fn malformed_existing_destination_keeps_pending_intent_without_overwrite() {
    let fixture = Fixture::new();
    let config = fixture.config();
    fixture.write_config(&config);
    let mut service = ServiceLoop::new(
        Supervisor::initialize(config.clone()).expect("initialize"),
        Duration::from_millis(10),
    )
    .expect("service");
    let namespace = fixture.temp.path().join("backups");
    std::fs::create_dir(&namespace).expect("backup namespace");
    std::fs::set_permissions(&namespace, std::fs::Permissions::from_mode(0o700))
        .expect("namespace permissions");
    let destination = backup_path(&fixture, "malformed");
    std::fs::write(&destination, b"not a sqlite database").expect("malformed destination");
    std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600))
        .expect("destination permissions");
    let original = std::fs::read(&destination).expect("original bytes");
    let queue = AdminQueue::new(8).expect("queue");
    let server = fixture.server(queue.clone(), service.health());
    let client = fixture.client(Capability::Admin);
    let request = thread::spawn(move || {
        client.execute(
            "malformed-destination",
            AdminCommand::Backup(BackupRequest {
                backup_id: "malformed".to_owned(),
            }),
        )
    });
    wait_for_queue(&queue, &request);
    service.drain_admin(&queue, ascension_watchdog::storage::now_unix_ms());
    let response = request.join().expect("request").expect("response");
    assert_eq!(response.status, ReplyStatus::Conflict);
    assert_eq!(
        std::fs::read(&destination).expect("unchanged bytes"),
        original
    );
    let ledger = Connection::open(&config.database).expect("ledger read");
    let response_json: String = ledger
        .query_row(
            "SELECT response_json FROM operator_commands WHERE idempotency_key='malformed-destination'",
            [],
            |row| row.get(0),
        )
        .expect("pending receipt");
    assert!(response_json.contains("\"durable\":false"));
    server.shutdown().expect("server shutdown");
    drop(service);
}

#[test]
fn completion_fault_keeps_intent_and_valid_snapshot_for_safe_replay() {
    let fixture = Fixture::new();
    let config = fixture.config();
    fixture.write_config(&config);
    let supervisor = Supervisor::initialize(config.clone()).expect("initialize");
    let fault = Connection::open(&config.database).expect("fault connection");
    fault
        .execute_batch(
            "CREATE TRIGGER reject_backup_completion BEFORE UPDATE OF response_json ON operator_commands BEGIN SELECT RAISE(ABORT, 'completion fault'); END;",
        )
        .expect("completion fault");
    let mut service = ServiceLoop::new(supervisor, Duration::from_millis(10)).expect("service");
    let queue = AdminQueue::new(8).expect("queue");
    let server = fixture.server(queue.clone(), service.health());
    let client = fixture.client(Capability::Admin);
    let request = thread::spawn(move || {
        client.execute(
            "completion-fault",
            AdminCommand::Backup(BackupRequest {
                backup_id: "faulted".to_owned(),
            }),
        )
    });
    wait_for_queue(&queue, &request);
    service.drain_admin(&queue, ascension_watchdog::storage::now_unix_ms());
    let response = request
        .join()
        .expect("fault request")
        .expect("fault response");
    assert_eq!(response.status, ReplyStatus::PersistenceUnavailable);
    server.shutdown().expect("server shutdown");
    drop(service);
    fault
        .execute_batch("DROP TRIGGER reject_backup_completion")
        .expect("remove fault");
    drop(fault);

    let path = backup_path(&fixture, "faulted");
    let original = std::fs::read(&path).expect("snapshot survived completion fault");
    let mut service = ServiceLoop::new(
        Supervisor::open(config.clone()).expect("reopen owner"),
        Duration::from_millis(10),
    )
    .expect("reopened service");
    let queue = AdminQueue::new(8).expect("reopened queue");
    let server = fixture.server(queue.clone(), service.health());
    assert_durable(
        run_cli_backup(
            &fixture,
            &queue,
            &mut service,
            "completion-fault",
            "faulted",
        )
        .expect("safe replay"),
        "faulted",
    );
    assert_eq!(std::fs::read(&path).expect("snapshot"), original);
    let ledger = Connection::open(&config.database).expect("ledger read");
    let response_json: String = ledger
        .query_row(
            "SELECT response_json FROM operator_commands WHERE idempotency_key='completion-fault'",
            [],
            |row| row.get(0),
        )
        .expect("ledger receipt");
    assert!(response_json.contains("\"durable\":true"));
    server.shutdown().expect("server shutdown");
}
