#![cfg(unix)]

use ascension_watchdog::ProcessIdentity;
use ascension_watchdog::config::{DesiredMode, WatchdogConfig, hex_digest};
use ascension_watchdog::storage::{
    Store, WORKER_HANDOFF_SCHEMA_DIGEST, WorkerBinding, WorkerClaimWitness, WorkerControlMode,
    WorkerControlWitness, WorkerHandoffState,
};
use ascension_watchdog::worker_client::{WorkerClient, WorkerClientConfig, WorkerPeerIdentity};
use ascension_watchdog::worker_protocol::{
    AcknowledgeResponse, AcknowledgeStatus, Direction, DispatchResponse, DispatchStatus, Frame,
    Header, ProbeResponse, TerminalReceipt, TerminalStatus, decode_frame, encode_frame,
};
use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread;
use tempfile::TempDir;

const AUTH_MAGIC: &[u8] = b"ascension-worker-auth-v1\0";
const WATCHDOG_BOOT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const WORKER_BOOT: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const DEPLOYMENT: &str = "watchdog-deployment-1";
const OWNER: &str = "harness";
const PROFILE_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const RELEASE_DIGEST: &str = "2222222222222222222222222222222222222222222222222222222222222222";

struct Fixture {
    temp: TempDir,
    endpoint: PathBuf,
    credential: PathBuf,
    client: WorkerClient,
    binding: WorkerBinding,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("fixture directory");
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
            .expect("fixture directory permissions");
        let endpoint = temp.path().join("worker.sock");
        let credential = temp.path().join("worker.token");
        fs::write(&credential, b"fixture-worker-secret").expect("credential");
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600))
            .expect("credential permissions");
        let executable = std::env::current_exe().expect("test executable");
        let executable_digest = hex_digest(&fs::read(&executable).expect("test executable bytes"));
        let pid = std::process::id();
        let creation_token = process_start_token(pid);
        let peer = WorkerPeerIdentity::new(executable, executable_digest, pid, creation_token)
            .expect("peer");
        let binding = WorkerBinding {
            deployment_id: DEPLOYMENT.to_owned(),
            worker_owner_id: OWNER.to_owned(),
            worker_profile_digest: PROFILE_DIGEST.to_owned(),
            release_digest: RELEASE_DIGEST.to_owned(),
            config_digest: "3333333333333333333333333333333333333333333333333333333333333333"
                .to_owned(),
            schema_digest: WORKER_HANDOFF_SCHEMA_DIGEST.to_owned(),
        };
        let config =
            WorkerClientConfig::new(endpoint.clone(), credential.clone(), binding.clone(), peer)
                .expect("client config");
        let client = WorkerClient::new(config, WATCHDOG_BOOT).expect("client");
        Self {
            temp,
            endpoint,
            credential,
            client,
            binding,
        }
    }

    fn bind(&self) -> UnixListener {
        let listener = UnixListener::bind(&self.endpoint).expect("worker endpoint");
        fs::set_permissions(&self.endpoint, fs::Permissions::from_mode(0o600))
            .expect("worker endpoint permissions");
        listener
    }
}

#[cfg(target_os = "linux")]
fn process_start_token(pid: u32) -> String {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).expect("process stat");
    let close = stat.rfind(')').expect("process stat command name");
    stat[close + 2..]
        .split_whitespace()
        .nth(19)
        .expect("process start token")
        .to_owned()
}

#[cfg(not(target_os = "linux"))]
fn process_start_token(_pid: u32) -> String {
    "test-process-start".to_owned()
}

fn read_frame(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "frame length"))?;
    if length == 0 || length > 65_536 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame bound",
        ));
    }
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body)?;
    Ok(body)
}

fn write_frame(stream: &mut UnixStream, body: &[u8]) -> std::io::Result<()> {
    let length = u32::try_from(body.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "frame length"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(body)
}

fn authenticated_request(listener: &UnixListener) -> (UnixStream, Frame) {
    let (mut stream, _) = listener.accept().expect("worker connection");
    let auth = read_frame(&mut stream).expect("worker auth frame");
    assert!(auth.starts_with(AUTH_MAGIC));
    assert_eq!(&auth[AUTH_MAGIC.len()..], b"fixture-worker-secret");
    let request = decode_frame(&read_frame(&mut stream).expect("worker request"))
        .expect("worker protocol request");
    (stream, request)
}

fn response_header(request: &Header, worker_boot_id: Option<&str>) -> Header {
    Header {
        contract: request.contract.clone(),
        schema_digest: request.schema_digest.clone(),
        direction: Direction::Response,
        command: request.command,
        scope: request.scope,
        request_id: request.request_id.clone(),
        timeout_ms: request.timeout_ms,
        watchdog_boot_id: request.watchdog_boot_id.clone(),
        worker_boot_id: worker_boot_id.map(str::to_owned),
    }
}

fn send_response(stream: &mut UnixStream, response: &Frame) {
    write_frame(
        stream,
        &encode_frame(response).expect("worker response encoding"),
    )
    .expect("worker response");
}

#[test]
fn probe_uses_real_authenticated_local_ipc_and_checks_binding() {
    let fixture = Fixture::new();
    let listener = fixture.bind();
    let binding = fixture.binding.clone();
    let server = thread::spawn(move || {
        let (mut stream, request) = authenticated_request(&listener);
        let Frame::ProbeRequest(request) = request else {
            panic!("probe request expected");
        };
        let response = Frame::ProbeResponse(ProbeResponse {
            header: response_header(&request.header, Some(WORKER_BOOT)),
            deployment_id: binding.deployment_id,
            worker_owner_id: binding.worker_owner_id,
            worker_profile_digest: binding.worker_profile_digest,
            release_digest: binding.release_digest,
            config_digest: binding.config_digest,
            ready: true,
            admitting: false,
        });
        send_response(&mut stream, &response);
    });
    let response = fixture.client.probe().expect("probe");
    assert!(response.ready);
    assert_eq!(response.header.worker_boot_id.as_deref(), Some(WORKER_BOOT));
    server.join().expect("probe server");
}

#[test]
fn response_correlation_mismatch_is_rejected_before_any_store_effect() {
    let fixture = Fixture::new();
    let listener = fixture.bind();
    let binding = fixture.binding.clone();
    let server = thread::spawn(move || {
        let (mut stream, request) = authenticated_request(&listener);
        let Frame::ProbeRequest(request) = request else {
            panic!("probe request expected");
        };
        let mut header = response_header(&request.header, Some(WORKER_BOOT));
        header.request_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc".to_owned();
        let response = Frame::ProbeResponse(ProbeResponse {
            header,
            deployment_id: binding.deployment_id,
            worker_owner_id: binding.worker_owner_id,
            worker_profile_digest: binding.worker_profile_digest,
            release_digest: binding.release_digest,
            config_digest: binding.config_digest,
            ready: true,
            admitting: false,
        });
        send_response(&mut stream, &response);
    });
    let error = fixture.client.probe().expect_err("mismatched response");
    assert!(matches!(
        error,
        ascension_watchdog::WatchdogError::IdentityMismatch(_)
    ));
    server.join().expect("probe server");
}

fn store_fixture(fixture: &Fixture) -> (Store, WatchdogConfig, WorkerControlWitness) {
    let config = WatchdogConfig {
        database: fixture.temp.path().join("state.sqlite"),
        deployment_id: DEPLOYMENT.to_owned(),
        desired_mode: DesiredMode::Running,
        ..WatchdogConfig::default()
    };
    let mut store = Store::initialize(&config.database, &config).expect("store");
    let binding = WorkerBinding {
        deployment_id: DEPLOYMENT.to_owned(),
        worker_owner_id: OWNER.to_owned(),
        worker_profile_digest: PROFILE_DIGEST.to_owned(),
        release_digest: RELEASE_DIGEST.to_owned(),
        config_digest: config.digest().expect("config digest"),
        schema_digest: WORKER_HANDOFF_SCHEMA_DIGEST.to_owned(),
    };
    store
        .configure_worker_binding_at(&binding, 1)
        .expect("worker binding");
    let control = WorkerControlWitness {
        deployment_id: DEPLOYMENT.to_owned(),
        worker_owner_id: OWNER.to_owned(),
        worker_profile_digest: PROFILE_DIGEST.to_owned(),
        watchdog_boot_id: WATCHDOG_BOOT.to_owned(),
        worker_boot_id: WORKER_BOOT.to_owned(),
        mode: WorkerControlMode::Running,
        mode_sequence: 1,
    };
    store
        .set_worker_control_at(&control, 2)
        .expect("worker control");
    store
        .submit_job_at(
            "runtime_v3_episode",
            &Value::Object(serde_json::Map::new()),
            3,
        )
        .expect("worker job");
    (store, config, control)
}

#[test]
fn claim_and_dispatch_marks_before_send_and_admits_real_worker() {
    let fixture = Fixture::new();
    let (mut store, _config, control) = store_fixture(&fixture);
    let listener = fixture.bind();
    let server = thread::spawn(move || {
        let (mut stream, request) = authenticated_request(&listener);
        let Frame::DispatchRequest(request) = request else {
            panic!("dispatch request expected");
        };
        let response = Frame::DispatchResponse(DispatchResponse {
            header: response_header(&request.header, Some(WORKER_BOOT)),
            tuple: request.tuple,
            status: DispatchStatus::Accepted,
            terminal: None,
        });
        send_response(&mut stream, &response);
    });
    let witness = WorkerClaimWitness {
        deployment_id: DEPLOYMENT.to_owned(),
        worker_owner_id: OWNER.to_owned(),
        worker_profile_digest: PROFILE_DIGEST.to_owned(),
        release_digest: RELEASE_DIGEST.to_owned(),
        config_digest: store.status().expect("store status").config_digest,
        schema_digest: WORKER_HANDOFF_SCHEMA_DIGEST.to_owned(),
        watchdog_boot_id: control.watchdog_boot_id.clone(),
        worker_boot_id: control.worker_boot_id.clone(),
        mode_sequence: control.mode_sequence,
    };
    let result = fixture
        .client
        .claim_and_dispatch(&mut store, &witness, 3)
        .expect("dispatch orchestration")
        .expect("claimed handoff");
    assert_eq!(result.status, DispatchStatus::Accepted);
    assert!(!result.acknowledged);
    assert_eq!(result.handoff.state, WorkerHandoffState::Admitted);
    server.join().expect("dispatch server");
}

#[test]
fn uncertain_dispatch_is_retained_and_never_resent() {
    let fixture = Fixture::new();
    let (mut store, _config, control) = store_fixture(&fixture);
    let listener = fixture.bind();
    let server = thread::spawn(move || {
        let (_stream, request) = authenticated_request(&listener);
        assert!(matches!(request, Frame::DispatchRequest(_)));
        // Drop the connected stream after the request.  The client has no
        // response identity to trust and must leave the durable reservation.
    });
    let witness = WorkerClaimWitness {
        deployment_id: DEPLOYMENT.to_owned(),
        worker_owner_id: OWNER.to_owned(),
        worker_profile_digest: PROFILE_DIGEST.to_owned(),
        release_digest: RELEASE_DIGEST.to_owned(),
        config_digest: store.status().expect("store status").config_digest,
        schema_digest: WORKER_HANDOFF_SCHEMA_DIGEST.to_owned(),
        watchdog_boot_id: control.watchdog_boot_id.clone(),
        worker_boot_id: control.worker_boot_id.clone(),
        mode_sequence: control.mode_sequence,
    };
    assert!(
        fixture
            .client
            .claim_and_dispatch(&mut store, &witness, 3)
            .is_err()
    );
    server.join().expect("uncertain server");
    assert!(
        fixture
            .client
            .claim_and_dispatch(&mut store, &witness, 4)
            .expect("held reservation")
            .is_none()
    );
}

#[test]
fn terminal_dispatch_commits_before_ack_and_retains_one_completed_result() {
    let fixture = Fixture::new();
    let (mut store, _config, control) = store_fixture(&fixture);
    let listener = fixture.bind();
    let server = thread::spawn(move || {
        let (mut stream, request) = authenticated_request(&listener);
        let Frame::DispatchRequest(request) = request else {
            panic!("dispatch request expected");
        };
        let terminal = TerminalReceipt {
            handoff_id: request.tuple.handoff_id.clone(),
            deployment_id: request.tuple.deployment_id.clone(),
            job_id: request.tuple.job_id.clone(),
            attempt_id: request.tuple.attempt_id.clone(),
            attempt_number: request.tuple.attempt_number,
            worker_owner_id: request.tuple.worker_owner_id.clone(),
            worker_profile_digest: request.tuple.worker_profile_digest.clone(),
            run_id: request.tuple.run_id.clone(),
            episode_id: request.tuple.episode_id.clone(),
            trajectory_id: request.tuple.trajectory_id.clone(),
            payload_digest: request.tuple.payload_digest.clone(),
            status: TerminalStatus::Completed,
            checkpoint_sequence: 1,
            terminal_ref: "terminal/one".to_owned(),
            result_digest: "9999999999999999999999999999999999999999999999999999999999999999"
                .to_owned(),
        };
        let response = Frame::DispatchResponse(DispatchResponse {
            header: response_header(&request.header, Some(WORKER_BOOT)),
            tuple: request.tuple.clone(),
            status: DispatchStatus::Terminal,
            terminal: Some(terminal),
        });
        send_response(&mut stream, &response);
        let (mut stream, request) = authenticated_request(&listener);
        let Frame::AcknowledgeRequest(request) = request else {
            panic!("acknowledgment request expected");
        };
        send_response(
            &mut stream,
            &Frame::AcknowledgeResponse(AcknowledgeResponse {
                header: response_header(&request.header, Some(WORKER_BOOT)),
                tuple: request.tuple,
                status: AcknowledgeStatus::Acknowledged,
            }),
        );
    });
    let witness = WorkerClaimWitness {
        deployment_id: DEPLOYMENT.to_owned(),
        worker_owner_id: OWNER.to_owned(),
        worker_profile_digest: PROFILE_DIGEST.to_owned(),
        release_digest: RELEASE_DIGEST.to_owned(),
        config_digest: store.status().expect("store status").config_digest,
        schema_digest: WORKER_HANDOFF_SCHEMA_DIGEST.to_owned(),
        watchdog_boot_id: control.watchdog_boot_id.clone(),
        worker_boot_id: control.worker_boot_id.clone(),
        mode_sequence: control.mode_sequence,
    };
    let result = fixture
        .client
        .claim_and_dispatch(&mut store, &witness, 3)
        .expect("terminal orchestration")
        .expect("terminal handoff");
    assert_eq!(result.status, DispatchStatus::Terminal);
    assert!(result.acknowledged);
    assert_eq!(result.handoff.state, WorkerHandoffState::Acknowledged);
    assert_eq!(
        result.handoff.job.status,
        ascension_watchdog::JobStatus::Completed
    );
    assert!(
        fixture
            .client
            .claim_and_dispatch(&mut store, &witness, 4)
            .expect("completed rerun guard")
            .is_none()
    );
    server.join().expect("terminal server");
}

#[test]
fn config_debug_never_contains_credential_bytes() {
    let fixture = Fixture::new();
    let debug = format!("{:?}", fixture.client);
    assert!(!debug.contains("fixture-worker-secret"));
    assert!(!debug.contains(&fixture.credential.to_string_lossy().to_string()));
}

#[test]
fn mismatched_exact_process_is_rejected_before_credential_disclosure() {
    let fixture = Fixture::new();
    let listener = fixture.bind();
    let executable = std::env::current_exe().expect("test executable");
    let executable_digest = hex_digest(&fs::read(&executable).expect("test executable bytes"));
    let wrong_pid = std::process::id().saturating_add(1);
    let peer = WorkerPeerIdentity::new(
        executable,
        executable_digest,
        wrong_pid,
        process_start_token(std::process::id()),
    )
    .expect("mismatched peer identity");
    let config = WorkerClientConfig::new(
        fixture.endpoint.clone(),
        fixture.credential.clone(),
        fixture.binding.clone(),
        peer,
    )
    .expect("mismatched config");
    let client = WorkerClient::new(config, WATCHDOG_BOOT).expect("mismatched client");
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("worker connection");
        stream
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .expect("read timeout");
        let mut stream = stream;
        let mut byte = [0_u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => {}
            Ok(_) => panic!("credential must not be sent"),
            Err(error) => assert!(matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            )),
        }
    });
    let error = client.probe().expect_err("mismatched peer");
    assert!(matches!(
        error,
        ascension_watchdog::WatchdogError::Unauthorized(_)
            | ascension_watchdog::WatchdogError::IdentityMismatch(_)
    ));
    server.join().expect("peer server");
}

#[test]
fn process_identity_without_creation_fingerprint_is_rejected() {
    let executable = std::env::current_exe().expect("test executable");
    let identity = ProcessIdentity {
        pid: std::process::id(),
        launch_nonce: "launch-nonce".to_owned(),
        executable: executable.clone(),
        executable_digest: hex_digest(&fs::read(&executable).expect("test executable bytes")),
        started_at_ms: 1,
        creation_fingerprint: None,
    };
    let error = WorkerPeerIdentity::from_process_identity(&identity)
        .expect_err("missing creation fingerprint");
    assert!(matches!(
        error,
        ascension_watchdog::WatchdogError::IdentityMismatch(_)
    ));
}
