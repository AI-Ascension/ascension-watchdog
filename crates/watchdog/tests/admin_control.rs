//! Native Unix admin sideband acceptance tests.
//!
//! Transport tests use a synthetic dispatcher; the durable lifecycle test uses
//! the real `ServiceLoop` and `Supervisor` store. Neither claims host/game effects.

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

#[test]
fn real_service_read_credential_inspects_jobs_without_private_payloads() {
    use ascension_watchdog::service::ServiceLoop;
    use ascension_watchdog::{Supervisor, WatchdogConfig};
    let fixture = Fixture::new();
    let config = WatchdogConfig {
        database: fixture.temp.path().join("state.sqlite"),
        ..WatchdogConfig::default()
    };
    let mut supervisor = Supervisor::initialize(config).unwrap();
    let job = supervisor
        .submit_job("episode", &serde_json::json!({"private": "do-not-export"}))
        .unwrap();
    let mut service = ServiceLoop::new(supervisor, Duration::from_millis(10)).unwrap();
    let queue = AdminQueue::new(8).unwrap();
    let _server = fixture.server(queue.clone(), service.health());
    let client = fixture.client(Capability::Read, &fixture.read_token);
    let request = thread::spawn(move || {
        client.execute(
            "inspect-jobs",
            AdminCommand::Jobs(ascension_watchdog::admin::JobsRequest {
                filter: ascension_watchdog::admin::JobFilter::Queued,
                limit: 1,
            }),
        )
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    while queue.depth() == 0 && !request.is_finished() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(1));
    }
    service.drain_admin(&queue, ascension_watchdog::storage::now_unix_ms());
    let response = request.join().unwrap().unwrap();
    assert_eq!(response.status, ReplyStatus::Ok);
    let encoded = serde_json::to_string(&response).unwrap();
    assert!(encoded.contains(&job.id));
    assert!(!encoded.contains("do-not-export"));
    assert!(!encoded.contains("payload"));
}

#[cfg(target_os = "linux")]
#[test]
fn release_inspection_without_explicit_catalog_is_unsupported() {
    use ascension_watchdog::service::ServiceLoop;
    use ascension_watchdog::{Supervisor, WatchdogConfig};

    let fixture = Fixture::new();
    let config = WatchdogConfig {
        database: fixture.temp.path().join("state.sqlite"),
        admin: Some(ascension_watchdog::config::AdminConfig {
            endpoint: fixture.socket.clone(),
            read_token_path: fixture.read_token.clone(),
            admin_token_path: fixture.admin_token.clone(),
            allowed_peer_sid: None,
        }),
        ..WatchdogConfig::default()
    };
    let mut service = ServiceLoop::new(
        Supervisor::initialize(config.clone()).unwrap(),
        Duration::from_millis(10),
    )
    .unwrap();
    let queue = AdminQueue::new(8).unwrap();
    let server = fixture.server(queue.clone(), service.health());
    let client = fixture.client(Capability::Read, &fixture.read_token);
    let request = thread::spawn(move || {
        client
            .execute(
                "inspect-release-without-catalog",
                AdminCommand::ReleaseInspect(ascension_watchdog::admin::ReleaseInspectRequest {
                    release_id: "release-1".to_owned(),
                }),
            )
            .unwrap()
    });
    wait_for_depth(&queue, 1);
    service.drain_admin(&queue, ascension_watchdog::storage::now_unix_ms());
    assert_eq!(request.join().unwrap().status, ReplyStatus::Unsupported);
    drop(service);
    drop(server);
    let inspected =
        ascension_watchdog::storage::Store::open_read_only(&config.database, &config).unwrap();
    assert_eq!(inspected.operator_command_count().unwrap(), 0);
}

#[cfg(target_os = "linux")]
#[test]
#[allow(clippy::too_many_lines)]
fn real_service_read_credential_inspects_configured_release_without_store_writes() {
    use ascension_watchdog::Supervisor;
    use ascension_watchdog::config::{
        ComponentConfig, ReleaseCatalogConfig, WatchdogConfig, hex_digest,
    };
    use ascension_watchdog::release::{
        Artifact, ArtifactRole, Compatibility, ReleaseManifest, Revision, StoreCompatibility,
    };
    use ascension_watchdog::release_staged::ProtectedReleaseCatalog;
    use ascension_watchdog::service::ServiceLoop;
    use ascension_watchdog::storage::Store;
    use std::collections::BTreeMap;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fixture = Fixture::new();
    let catalog_root = fixture.temp.path().join("releases");
    let release_root = catalog_root.join("release-1");
    std::fs::create_dir(&catalog_root).unwrap();
    std::fs::create_dir(&release_root).unwrap();
    let artifact_bytes = b"admin release role bytes";
    let artifact_digest = hex_digest(artifact_bytes);
    let owner_uid = u64::from(std::fs::metadata(&catalog_root).unwrap().uid());
    let component = |id: &str| ComponentConfig {
        id: id.to_owned(),
        executable: release_root.join(id),
        args: Vec::new(),
        cwd: None,
        environment: BTreeMap::new(),
        executable_sha256: Some(artifact_digest.clone()),
        restart: true,
    };
    let config = WatchdogConfig {
        database: fixture.temp.path().join("state.sqlite"),
        allow_synthetic_children: true,
        admin: Some(ascension_watchdog::config::AdminConfig {
            endpoint: fixture.socket.clone(),
            read_token_path: fixture.read_token.clone(),
            admin_token_path: fixture.admin_token.clone(),
            allowed_peer_sid: None,
        }),
        release_catalog: Some(ReleaseCatalogConfig {
            root: catalog_root.clone(),
            owner_uid,
        }),
        components: vec![component("gateway"), component("harness")],
        ..WatchdogConfig::default()
    };
    let config_path = fixture.temp.path().join("watchdog.json");
    config.to_file(&config_path).unwrap();
    let compatibility = Compatibility {
        game_build: "admin-test-build".to_owned(),
        runtime_profile: "runtime-v3-gameplay".to_owned(),
        runtime_profile_sha256: "a".repeat(64),
        recovery_profile: "watchdog-recovery-v1".to_owned(),
        recovery_profile_sha256: "b".repeat(64),
        configuration_sha256: config.digest().unwrap(),
        provider_adapter: "admin-test-provider".to_owned(),
        provider_adapter_sha256: "c".repeat(64),
        stores: ["watchdog", "gateway", "harness"]
            .into_iter()
            .map(|owner| StoreCompatibility {
                owner: owner.to_owned(),
                minimum_schema: 1,
                maximum_schema: 1,
            })
            .collect(),
    };
    let manifest = ReleaseManifest {
        schema_version: 1,
        release_id: "release-1".to_owned(),
        revisions: [
            "ascension-watchdog",
            "sts2-gateway",
            "sts2-harness",
            "sts2-mcp-server",
            "sts2-game-mod",
            "sts2-protocol",
        ]
        .into_iter()
        .map(|repository| Revision {
            repository: repository.to_owned(),
            commit: "a".repeat(40),
        })
        .collect(),
        artifacts: [
            (ArtifactRole::Watchdog, "watchdog"),
            (ArtifactRole::Gateway, "gateway"),
            (ArtifactRole::Harness, "harness"),
            (ArtifactRole::Mcp, "mcp"),
            (ArtifactRole::Mod, "mod"),
            (ArtifactRole::HostBroker, "broker"),
        ]
        .into_iter()
        .map(|(role, path)| Artifact {
            role,
            path: path.into(),
            sha256: artifact_digest.clone(),
            bytes: artifact_bytes.len() as u64,
        })
        .collect(),
        compatibility,
    };
    for artifact in &manifest.artifacts {
        std::fs::write(release_root.join(&artifact.path), artifact_bytes).unwrap();
    }
    std::fs::write(
        release_root.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(&catalog_root, std::fs::Permissions::from_mode(0o555)).unwrap();
    std::fs::set_permissions(&release_root, std::fs::Permissions::from_mode(0o555)).unwrap();
    for artifact in &manifest.artifacts {
        std::fs::set_permissions(
            release_root.join(&artifact.path),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
    }
    std::fs::set_permissions(
        release_root.join("manifest.json"),
        std::fs::Permissions::from_mode(0o444),
    )
    .unwrap();

    let expected_manifest_digest =
        hex_digest(&std::fs::read(release_root.join("manifest.json")).unwrap());
    let protected = ProtectedReleaseCatalog::new_with_owner_policy(
        &catalog_root,
        ascension_watchdog::release_staged::CatalogOwnerPolicy::approved_unix_uid(owner_uid),
    )
    .unwrap();
    let local_inspection = protected.inspect("release-1", &config).unwrap();
    assert_eq!(local_inspection.manifest_digest, expected_manifest_digest);
    assert!(local_inspection.compatible);

    let mut service = ServiceLoop::new(
        Supervisor::initialize(config.clone()).unwrap(),
        Duration::from_millis(10),
    )
    .unwrap();
    let queue = AdminQueue::new(8).unwrap();
    let server = fixture.server(queue.clone(), service.health());
    let config_path_for_request = config_path.clone();
    let request = thread::spawn(move || {
        ascension_watchdog::cli::execute(vec![
            "release".to_owned(),
            "inspect".to_owned(),
            "--config".to_owned(),
            config_path_for_request.to_string_lossy().into_owned(),
            "--release-id".to_owned(),
            "release-1".to_owned(),
        ])
    });
    wait_for_depth(&queue, 1);
    service.drain_admin(&queue, ascension_watchdog::storage::now_unix_ms());
    let encoded = request.join().unwrap().unwrap().unwrap();
    let response: ascension_watchdog::admin::AdminResponse =
        serde_json::from_str(&encoded).unwrap();
    assert_eq!(response.status, ReplyStatus::Ok);
    let Some(AdminResult::ReleaseInspection(result)) = response.result else {
        panic!("release inspection result missing");
    };
    assert_eq!(result.release_id, "release-1");
    assert_eq!(result.release_digest, expected_manifest_digest);
    assert!(result.compatible);
    assert!(!result.active);
    drop(service);
    drop(server);
    let inspected = Store::open_read_only(&config.database, &config).unwrap();
    assert_eq!(inspected.operator_command_count().unwrap(), 0);
    drop(inspected);

    // A changed artifact remains non-authoritative and the authenticated
    // operation fails closed without adding a durable operator receipt.
    let tampered = release_root.join("gateway");
    std::fs::set_permissions(&tampered, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(&tampered, b"tampered admin release bytes").unwrap();
    std::fs::set_permissions(&tampered, std::fs::Permissions::from_mode(0o444)).unwrap();
    let mut service = ServiceLoop::new(
        Supervisor::open(config.clone()).unwrap(),
        Duration::from_millis(10),
    )
    .unwrap();
    let queue = AdminQueue::new(8).unwrap();
    let server = fixture.server(queue.clone(), service.health());
    let client = fixture.client(Capability::Read, &fixture.read_token);
    let request = thread::spawn(move || {
        client
            .execute(
                "inspect-release-tampered",
                AdminCommand::ReleaseInspect(ascension_watchdog::admin::ReleaseInspectRequest {
                    release_id: "release-1".to_owned(),
                }),
            )
            .unwrap()
    });
    wait_for_depth(&queue, 1);
    service.drain_admin(&queue, ascension_watchdog::storage::now_unix_ms());
    assert_eq!(request.join().unwrap().status, ReplyStatus::Conflict);
    drop(service);
    drop(server);
    let inspected = Store::open_read_only(&config.database, &config).unwrap();
    assert_eq!(inspected.operator_command_count().unwrap(), 0);
}

#[test]
fn real_service_dispatch_persists_stop_and_old_start_cannot_revive_it() {
    use ascension_watchdog::service::ServiceLoop;
    use ascension_watchdog::{DesiredMode, Supervisor, WatchdogConfig};
    let fixture = Fixture::new();
    let config = WatchdogConfig {
        database: fixture.temp.path().join("state.sqlite"),
        admin: Some(ascension_watchdog::config::AdminConfig {
            endpoint: fixture.socket.clone(),
            read_token_path: fixture.read_token.clone(),
            admin_token_path: fixture.admin_token.clone(),
            allowed_peer_sid: None,
        }),
        ..WatchdogConfig::default()
    };
    let config_path = fixture.temp.path().join("config.json");
    config.to_file(&config_path).unwrap();
    let mut service = ServiceLoop::new(
        Supervisor::initialize(config.clone()).unwrap(),
        Duration::from_millis(10),
    )
    .unwrap();
    let queue = AdminQueue::new(8).unwrap();
    let server = fixture.server(queue.clone(), service.health());
    let client = fixture.client(Capability::Admin, &fixture.admin_token);
    for (key, command, expected) in [
        (
            "start-original",
            AdminCommand::Start(EmptyParams {}),
            DesiredMode::Running,
        ),
        (
            "stop-original",
            AdminCommand::Stop(EmptyParams {}),
            DesiredMode::Stopped,
        ),
    ] {
        let config_path = config_path.clone();
        let name = if matches!(command, AdminCommand::Start(_)) {
            "start"
        } else {
            "stop"
        };
        let request = thread::spawn(move || {
            ascension_watchdog::cli::execute(vec![
                name.to_owned(),
                "--config".to_owned(),
                config_path.to_string_lossy().into_owned(),
                "--idempotency-key".to_owned(),
                key.to_owned(),
            ])
        });
        let deadline = Instant::now() + Duration::from_secs(3);
        while queue.depth() == 0 && !request.is_finished() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        service.drain_admin(&queue, ascension_watchdog::storage::now_unix_ms());
        let response: ascension_watchdog::admin::AdminResponse =
            serde_json::from_str(&request.join().unwrap().unwrap().unwrap()).unwrap();
        assert_eq!(response.status, ReplyStatus::Accepted);
        assert_eq!(service.reconcile(1_000).unwrap().desired_mode, expected);
    }
    drop(server);
    drop(service);
    let mut service =
        ServiceLoop::new(Supervisor::open(config).unwrap(), Duration::from_millis(10)).unwrap();
    let queue = AdminQueue::new(8).unwrap();
    let _server = fixture.server(queue.clone(), service.health());
    let request = thread::spawn(move || {
        client.execute("start-original", AdminCommand::Start(EmptyParams {}))
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    while queue.depth() == 0 && !request.is_finished() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(1));
    }
    service.drain_admin(&queue, ascension_watchdog::storage::now_unix_ms());
    assert_eq!(
        request.join().unwrap().unwrap().status,
        ReplyStatus::Accepted
    );
    assert_eq!(
        service.reconcile(1_010).unwrap().desired_mode,
        DesiredMode::Stopped
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn real_service_quarantine_is_admin_only_atomic_and_replayable_after_restart() {
    use ascension_watchdog::service::ServiceLoop;
    use ascension_watchdog::storage::{JobStatus, Store};
    use ascension_watchdog::{DesiredMode, Supervisor, WatchdogConfig};
    let fixture = Fixture::new();
    let config = WatchdogConfig {
        database: fixture.temp.path().join("state.sqlite"),
        desired_mode: DesiredMode::Running,
        admin: Some(ascension_watchdog::config::AdminConfig {
            endpoint: fixture.socket.clone(),
            read_token_path: fixture.read_token.clone(),
            admin_token_path: fixture.admin_token.clone(),
            allowed_peer_sid: None,
        }),
        ..WatchdogConfig::default()
    };
    let mut supervisor = Supervisor::initialize(config.clone()).unwrap();
    let job = supervisor
        .submit_job("episode", &serde_json::json!({"private": "stay-local"}))
        .unwrap();
    // This fixture exercises quarantine authorization, not wall-clock
    // scheduling. Use the persisted admission time so a host clock correction
    // cannot turn its queued job into a not-yet-due job between calls.
    let admitted_at = job.created_at_ms;
    supervisor.reconcile_once(admitted_at).unwrap();
    assert_eq!(
        supervisor.status().unwrap().desired_mode,
        DesiredMode::Running
    );
    assert!(
        supervisor
            .claim_job("worker-a", admitted_at.saturating_sub(1))
            .unwrap()
            .is_none()
    );
    let claim = supervisor
        .claim_job("worker-a", admitted_at)
        .unwrap()
        .expect("the queued job is due at its persisted admission time");
    let attempt_id = claim.attempt_id.clone();
    let mut service = ServiceLoop::new(supervisor, Duration::from_millis(10)).unwrap();
    let queue = AdminQueue::new(8).unwrap();
    let server = fixture.server(queue.clone(), service.health());
    let read_client = fixture.client(Capability::Read, &fixture.read_token);
    let forbidden = read_client
        .execute(
            "read-cannot-quarantine",
            AdminCommand::Quarantine(ascension_watchdog::admin::QuarantineRequest {
                attempt_id: attempt_id.clone(),
                reason: "read token must not mutate".to_owned(),
            }),
        )
        .unwrap();
    assert_eq!(forbidden.status, ReplyStatus::Forbidden);
    assert_eq!(queue.depth(), 0);

    let command = AdminCommand::Quarantine(ascension_watchdog::admin::QuarantineRequest {
        attempt_id: attempt_id.clone(),
        reason: "operator observed an uncertain boundary".to_owned(),
    });
    let admin_client = fixture.client(Capability::Admin, &fixture.admin_token);
    let request = thread::spawn(move || {
        admin_client
            .execute("quarantine-once", command)
            .expect("quarantine response")
    });
    wait_for_depth(&queue, 1);
    service.drain_admin(&queue, ascension_watchdog::storage::now_unix_ms());
    let accepted = request.join().unwrap();
    assert_eq!(accepted.status, ReplyStatus::Accepted);
    drop(server);
    drop(service);
    let inspected = Store::open_read_only(&config.database, &config).unwrap();
    assert_eq!(
        inspected.get_job(&job.id).unwrap().unwrap().status,
        JobStatus::Quarantined
    );
    assert_eq!(
        inspected
            .attempt_summary(&attempt_id)
            .unwrap()
            .unwrap()
            .status,
        "unknown"
    );
    assert_eq!(inspected.operator_command_count().unwrap(), 1);
    drop(inspected);

    let mut restarted = ServiceLoop::new(
        Supervisor::open(config.clone()).unwrap(),
        Duration::from_millis(10),
    )
    .unwrap();
    let queue = AdminQueue::new(8).unwrap();
    let server = fixture.server(queue.clone(), restarted.health());
    let replay_client = fixture.client(Capability::Admin, &fixture.admin_token);
    let replay_command = AdminCommand::Quarantine(ascension_watchdog::admin::QuarantineRequest {
        attempt_id,
        reason: "operator observed an uncertain boundary".to_owned(),
    });
    let request = thread::spawn(move || {
        replay_client
            .execute("quarantine-once", replay_command)
            .expect("replay response")
    });
    wait_for_depth(&queue, 1);
    restarted.drain_admin(&queue, ascension_watchdog::storage::now_unix_ms());
    assert_eq!(request.join().unwrap().status, ReplyStatus::Accepted);
    drop(server);
    drop(restarted);
    let inspected = Store::open_read_only(&config.database, &config).unwrap();
    assert_eq!(inspected.operator_command_count().unwrap(), 1);
    assert_eq!(
        inspected.get_job(&job.id).unwrap().unwrap().status,
        JobStatus::Quarantined
    );
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
