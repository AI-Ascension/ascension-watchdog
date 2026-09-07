//! Authenticated job admission and durable replay tests.

#![cfg(unix)]

use ascension_watchdog::admin::{
    AdminClient, AdminClientConfig, AdminCommand, AdminQueue, AdminServer, AdminServerConfig,
    AuthReferences, Capability, JobSubmitRequest, MainLoopHealth, ReplyStatus,
};
use ascension_watchdog::config::{AdminConfig, DesiredMode, WatchdogConfig};
use ascension_watchdog::service::ServiceLoop;
use ascension_watchdog::storage::{
    OperatorCapability, OperatorCommand, OperatorCommandContext, OperatorCommandOutcome,
    SingletonLock, Store,
};
use ascension_watchdog::{Supervisor, WatchdogError};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn config(temp: &TempDir) -> WatchdogConfig {
    WatchdogConfig {
        database: temp.path().join("state.sqlite"),
        ..WatchdogConfig::default()
    }
}

fn owner_store(temp: &TempDir) -> (SingletonLock, Store, WatchdogConfig) {
    let config = config(temp);
    let owner = SingletonLock::acquire(&config.database).expect("owner lock");
    let store = Store::initialize_for_owner(&config.database, &config, &owner)
        .expect("initialize owner store");
    (owner, store, config)
}

fn job_context(
    request_id: &str,
    key: &str,
    kind: &str,
    payload: &Value,
    capability: Capability,
) -> OperatorCommandContext {
    let command = AdminCommand::JobSubmit(
        JobSubmitRequest::new(kind.to_owned(), payload.clone()).expect("job request"),
    );
    let request = ascension_watchdog::admin::AdminRequest {
        contract: ascension_watchdog::admin::ContractVersion::V1,
        request_id: request_id.to_owned(),
        idempotency_key: key.to_owned(),
        capability,
        token: "test-token".to_owned(),
        deadline_ms: 1_000,
        command,
    };
    let fingerprint = request.fingerprint();
    OperatorCommandContext::new(
        request.request_id.clone(),
        request.idempotency_key.clone(),
        "operator-a",
        match capability {
            Capability::Read => OperatorCapability::Read,
            Capability::Admin => OperatorCapability::Admin,
        },
        fingerprint,
    )
    .expect("operator context")
}

fn accepted_job_id(outcome: OperatorCommandOutcome) -> String {
    let receipt = match outcome {
        OperatorCommandOutcome::Accepted(receipt) | OperatorCommandOutcome::Replayed(receipt) => {
            receipt
        }
        OperatorCommandOutcome::ReadOnly => panic!("job submission cannot be read-only"),
    };
    receipt
        .response
        .get("value")
        .and_then(Value::as_object)
        .and_then(|value| value.get("job_id"))
        .and_then(Value::as_str)
        .expect("job id")
        .to_owned()
}

#[test]
fn submission_replays_original_job_after_completion_and_stop() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (owner, mut store, _config) = owner_store(&temp);
    let payload = json!({"private": "retained-locally"});
    let context = job_context(
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "job-once",
        "episode",
        &payload,
        Capability::Admin,
    );
    let first = store
        .admit_operator_job_submission(&owner, &context, "episode", &payload, 10)
        .expect("first submission");
    let job_id = accepted_job_id(first);
    assert_eq!(store.desired_mode().expect("mode"), DesiredMode::Stopped);

    store
        .set_desired_mode_at(DesiredMode::Running, 11)
        .expect("run intent");
    let claim = store
        .claim_next_job("worker-a", 12)
        .expect("claim")
        .expect("queued job");
    assert_eq!(claim.job.id, job_id);
    store
        .complete_job_at(&job_id, &claim.attempt_id, &json!({"done": true}), 13)
        .expect("complete");
    store
        .set_desired_mode_at(DesiredMode::Stopped, 14)
        .expect("stop intent");

    let replay = store
        .admit_operator_job_submission(&owner, &context, "episode", &payload, 15)
        .expect("replay");
    assert!(matches!(replay, OperatorCommandOutcome::Replayed(_)));
    assert_eq!(accepted_job_id(replay), job_id);
    assert_eq!(store.job_summaries(None, 10).expect("jobs").jobs.len(), 1);
    assert_eq!(store.operator_command_count().expect("receipts"), 1);
    assert_eq!(
        store.desired_mode().expect("stopped mode"),
        DesiredMode::Stopped
    );
}

#[test]
fn conflicting_payload_and_read_capability_fail_without_a_new_job() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (owner, mut store, _config) = owner_store(&temp);
    let first_payload = json!({"value": 1});
    let first = job_context(
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "same-key",
        "episode",
        &first_payload,
        Capability::Admin,
    );
    store
        .admit_operator_job_submission(&owner, &first, "episode", &first_payload, 10)
        .expect("first submission");

    let changed_payload = json!({"value": 2});
    let changed = job_context(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "same-key",
        "episode",
        &changed_payload,
        Capability::Admin,
    );
    assert!(matches!(
        store.admit_operator_job_submission(&owner, &changed, "episode", &changed_payload, 11),
        Err(WatchdogError::Conflict(_))
    ));

    // Even if a caller presents the old transport fingerprint, storage binds
    // the replay to the durable job's kind and payload digest.
    assert!(matches!(
        store.admit_operator_job_submission(&owner, &first, "episode", &changed_payload, 12,),
        Err(WatchdogError::Conflict(_))
    ));

    let read = job_context(
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        "read-job",
        "episode",
        &first_payload,
        Capability::Read,
    );
    assert!(matches!(
        store.admit_operator_job_submission(&owner, &read, "episode", &first_payload, 13),
        Err(WatchdogError::Unauthorized(_))
    ));
    assert_eq!(store.job_summaries(None, 10).expect("jobs").jobs.len(), 1);
    assert_eq!(store.operator_command_count().expect("receipts"), 1);
}

#[test]
fn job_and_receipt_and_audit_failures_roll_back_together() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (owner, mut store, _config) = owner_store(&temp);
    let payload = json!({"value": 1});
    let context = job_context(
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "audit-fault",
        "episode",
        &payload,
        Capability::Admin,
    );
    let fault = Connection::open(store.path()).expect("fault connection");
    fault
        .execute_batch(
            "CREATE TRIGGER reject_job_submission_audit BEFORE INSERT ON audit WHEN NEW.action='job_submitted' BEGIN SELECT RAISE(ABORT, 'job audit failure'); END;",
        )
        .expect("job audit trigger");
    assert!(
        store
            .admit_operator_job_submission(&owner, &context, "episode", &payload, 10)
            .is_err()
    );
    assert_eq!(store.job_summaries(None, 10).expect("jobs").jobs.len(), 0);
    assert_eq!(store.operator_command_count().expect("receipts"), 0);
    fault
        .execute_batch("DROP TRIGGER reject_job_submission_audit")
        .expect("drop job audit trigger");

    fault
        .execute_batch(
            "CREATE TRIGGER reject_job_submission_receipt BEFORE INSERT ON operator_commands BEGIN SELECT RAISE(ABORT, 'receipt failure'); END;",
        )
        .expect("receipt trigger");
    let receipt_context = job_context(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "receipt-fault",
        "episode",
        &payload,
        Capability::Admin,
    );
    assert!(
        store
            .admit_operator_job_submission(&owner, &receipt_context, "episode", &payload, 11)
            .is_err()
    );
    assert_eq!(store.job_summaries(None, 10).expect("jobs").jobs.len(), 0);
    assert_eq!(store.operator_command_count().expect("receipts"), 0);
}

#[test]
fn old_v1_operator_ledger_migrates_transactionally_and_preserves_receipts() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (owner, mut store, config) = owner_store(&temp);
    let start = OperatorCommandContext::new(
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "old-start",
        "operator-a",
        OperatorCapability::Admin,
        "a".repeat(64),
    )
    .expect("start context");
    let stop = OperatorCommandContext::new(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "old-stop",
        "operator-a",
        OperatorCapability::Admin,
        "b".repeat(64),
    )
    .expect("stop context");
    store
        .admit_operator_command(
            &owner,
            &start,
            OperatorCommand::Start,
            &json!({"kind": "Accepted"}),
            10,
        )
        .expect("start receipt");
    store
        .admit_operator_command(
            &owner,
            &stop,
            OperatorCommand::Stop,
            &json!({"kind": "Accepted"}),
            11,
        )
        .expect("stop receipt");
    drop(store);

    // Convert the v2 table to an actual v1 owner store fixture while keeping
    // every row and explicit sequence number. The production migration then
    // has to rebuild only the constrained ledger table.
    let raw = Connection::open(&config.database).expect("raw connection");
    raw.execute_batch(
        "BEGIN IMMEDIATE;
         DROP INDEX operator_commands_order_idx;
         DROP INDEX operator_commands_principal_idx;
         ALTER TABLE operator_commands RENAME TO operator_commands_saved;
         CREATE TABLE operator_commands (
             sequence INTEGER PRIMARY KEY AUTOINCREMENT,
             request_id TEXT NOT NULL UNIQUE,
             idempotency_key TEXT NOT NULL UNIQUE,
             principal TEXT NOT NULL,
             capability TEXT NOT NULL CHECK(capability IN ('read','admin')),
             command TEXT NOT NULL CHECK(command IN (
                 'status','jobs','attempt','release_inspect','start','pause',
                 'resume','drain','stop','quarantine','retry','reconcile',
                 'backup','restore','release_activate'
             )),
             command_fingerprint TEXT NOT NULL,
             desired_mode TEXT CHECK(desired_mode IS NULL OR desired_mode IN ('stopped','paused','running','draining')),
             response_json TEXT NOT NULL,
             recorded_at_ms INTEGER NOT NULL
         );
         INSERT INTO operator_commands SELECT * FROM operator_commands_saved ORDER BY sequence;
         DROP TABLE operator_commands_saved;
         CREATE INDEX operator_commands_order_idx ON operator_commands(sequence);
         CREATE INDEX operator_commands_principal_idx ON operator_commands(principal, sequence);
         UPDATE metadata SET value='1' WHERE key='operator_ledger_schema_version';
         UPDATE sqlite_sequence SET seq=100 WHERE name='operator_commands';
         COMMIT;",
    )
    .expect("v1 fixture");
    drop(raw);

    let mut reopened = Store::open_for_owner(&config.database, &config, &owner)
        .expect("migrate old operator ledger");
    assert_eq!(reopened.operator_command_count().expect("receipt count"), 2);
    let replay = reopened
        .admit_operator_command(
            &owner,
            &start,
            OperatorCommand::Start,
            &json!({"different": true}),
            12,
        )
        .expect("replay old receipt");
    let OperatorCommandOutcome::Replayed(receipt) = replay else {
        panic!("old receipt was not replayed");
    };
    assert_eq!(receipt.sequence, 1);
    assert_eq!(reopened.operator_command_count().expect("receipt count"), 2);
    let receipts = reopened.list_operator_commands(10).expect("receipts");
    assert_eq!(receipts[1].command, OperatorCommand::Stop);
    assert_eq!(
        reopened.desired_mode().expect("stop remains durable"),
        DesiredMode::Stopped
    );
    // AUTOINCREMENT's durable high-water mark can exceed the retained row
    // maximum (for example after INSERT OR IGNORE). Rebuilding the table must
    // not reuse any previously allocated sequence namespace.
    let payload = json!({"value": 1});
    let next = job_context(
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        "after-migration",
        "episode",
        &payload,
        Capability::Admin,
    );
    let outcome = reopened
        .admit_operator_job_submission(&owner, &next, "episode", &payload, 13)
        .expect("post-migration submission");
    let OperatorCommandOutcome::Accepted(receipt) = outcome else {
        panic!("new submission was not accepted");
    };
    assert_eq!(receipt.sequence, 101);
}

#[test]
fn actual_cli_ipc_submission_replays_once_after_service_reopen() {
    let fixture = Fixture::new();
    let config = fixture.config();
    let config_path = fixture.temp.path().join("config.json");
    config.to_file(&config_path).expect("config");
    let mut service = ServiceLoop::new(
        Supervisor::initialize(config.clone()).expect("initialize"),
        Duration::from_millis(10),
    )
    .expect("service");
    let queue = AdminQueue::new(8).expect("queue");
    let server = fixture.server(queue.clone(), service.health());
    let first = submit_via_cli(&config_path, &queue, &mut service, "cli-job");
    let first_id = response_job_id(&first);
    assert_eq!(first.status, ReplyStatus::Accepted);
    drop(server);
    drop(service);

    let mut reopened_service = ServiceLoop::new(
        Supervisor::open(config.clone()).expect("reopen"),
        Duration::from_millis(10),
    )
    .expect("reopened service");
    let queue = AdminQueue::new(8).expect("reopened queue");
    let server = fixture.server(queue.clone(), reopened_service.health());
    let replay = submit_via_cli(&config_path, &queue, &mut reopened_service, "cli-job");
    assert_eq!(replay.status, ReplyStatus::Accepted);
    assert_eq!(response_job_id(&replay), first_id);
    drop(server);
    drop(reopened_service);
    let store = Store::open_read_only(&config.database, &config).expect("inspect state");
    assert_eq!(store.job_summaries(None, 10).expect("jobs").jobs.len(), 1);
    assert_eq!(store.operator_command_count().expect("receipts"), 1);
}

#[test]
fn read_credential_cannot_submit_through_real_ipc() {
    let fixture = Fixture::new();
    let config = fixture.config();
    let service = ServiceLoop::new(
        Supervisor::initialize(config).expect("initialize"),
        Duration::from_millis(10),
    )
    .expect("service");
    let queue = AdminQueue::new(8).expect("queue");
    let server = fixture.server(queue.clone(), service.health());
    let client = fixture.client(Capability::Read, &fixture.read_token);
    let command = AdminCommand::JobSubmit(
        JobSubmitRequest::new("episode", json!({"private": true})).expect("command"),
    );
    let response = client
        .execute("read-job", command)
        .expect("forbidden response");
    assert_eq!(response.status, ReplyStatus::Forbidden);
    assert_eq!(queue.depth(), 0);
    drop(server);
    drop(service);
}

fn submit_via_cli(
    config_path: &Path,
    queue: &AdminQueue,
    service: &mut ServiceLoop,
    key: &str,
) -> ascension_watchdog::admin::AdminResponse {
    let config_path = config_path.to_owned();
    let key = key.to_owned();
    let request = thread::spawn(move || {
        ascension_watchdog::cli::execute(vec![
            "job".to_owned(),
            "submit".to_owned(),
            "--config".to_owned(),
            config_path.to_string_lossy().into_owned(),
            "--idempotency-key".to_owned(),
            key,
            "--kind".to_owned(),
            "episode".to_owned(),
            "--payload".to_owned(),
            r#"{"value":7,"secret":"not-on-wire"}"#.to_owned(),
        ])
    });
    wait_for_queue(queue, &request);
    service.drain_admin(queue, ascension_watchdog::storage::now_unix_ms());
    let output = request
        .join()
        .expect("CLI thread")
        .expect("CLI result")
        .expect("CLI output");
    serde_json::from_str(&output).expect("admin response")
}

fn response_job_id(response: &ascension_watchdog::admin::AdminResponse) -> String {
    let Some(ascension_watchdog::admin::AdminResult::JobSubmitted(view)) = &response.result else {
        panic!("job submission response result");
    };
    view.job_id.clone()
}

fn wait_for_queue(
    queue: &AdminQueue,
    request: &thread::JoinHandle<Result<Option<String>, WatchdogError>>,
) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while queue.depth() == 0 && !request.is_finished() {
        assert!(Instant::now() < deadline, "submission was not queued");
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(queue.depth(), 1, "submission did not reach service queue");
}

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

    fn config(&self) -> WatchdogConfig {
        WatchdogConfig {
            database: self.temp.path().join("state.sqlite"),
            admin: Some(AdminConfig {
                endpoint: self.socket.clone(),
                read_token_path: self.read_token.clone(),
                admin_token_path: self.admin_token.clone(),
                allowed_peer_sid: None,
            }),
            ..WatchdogConfig::default()
        }
    }

    fn server(&self, queue: AdminQueue, health: MainLoopHealth) -> AdminServer {
        let auth = AuthReferences::new(&self.read_token, &self.admin_token).expect("auth refs");
        let config = AdminServerConfig::new(&self.socket, auth)
            .expect("server config")
            .with_max_clients(4)
            .expect("clients")
            .with_worker_count(2)
            .expect("workers")
            .with_io_timeout(Duration::from_secs(2))
            .expect("I/O timeout");
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
