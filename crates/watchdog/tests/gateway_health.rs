//! Real loopback transport tests, not native-child or live-host evidence.

use ascension_watchdog::gateway_health::{GatewayHealthBinding, GatewayHealthClient, HealthError};
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::json;
use sha2::Sha256;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use uuid::Uuid;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const NONCE: &str = "00112233-4455-4677-8899-aabbccddeeff";
const KEY: [u8; 32] = [0x55; 32];

fn binding() -> Result<GatewayHealthBinding, uuid::Error> {
    Ok(GatewayHealthBinding {
        deployment_id: "deployment-a".to_owned(),
        instance_id: "instance-a".to_owned(),
        launch_nonce: Uuid::parse_str(NONCE)?,
        release_digest: "a".repeat(64),
        config_digest: "b".repeat(64),
        profile_digest: "c".repeat(64),
        runtime_v3_schema_digest: "d".repeat(64),
    })
}

fn body(sequence: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "contract":"sts2-gateway-health-v1", "liveness":"live", "process_binding":"launch_nonce",
        "readiness":"blocked", "phase":"blocked", "phase_deadline":null,
        "progress":{"heartbeat_sequence":sequence,"heartbeat_age_ms":0,"meaningful_progress_age_ms":null,"source":"gateway_worker"},
        "identity":{"deployment_id":"deployment-a","instance_id":"instance-a","instance_incarnation":NONCE,
            "boot_id":NONCE,"authority_generation":1,"launch_nonce":NONCE,
            "release":{"release_digest":"a".repeat(64),"config_digest":"b".repeat(64),"profile_digest":"c".repeat(64),"runtime_v3_schema_digest":"d".repeat(64)}},
        "lease":{"remaining_ms":null,"expires_at":null}, "queue":{"capacity":16,"depth":0,"age_ms":null},
        "pending_operation_count":null, "downstream_readiness":"not_sampled", "shutdown_requested":false
    })).expect("fixed JSON fixture")
}

struct Server {
    address: SocketAddr,
    cancel: Arc<AtomicBool>,
    join: Option<JoinHandle<Result<(), String>>>,
}

impl Server {
    fn start<F>(count: usize, mut reply: F) -> Result<Self, std::io::Error>
    where
        F: FnMut(&str, usize, &mut TcpStream) -> Result<(), String> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let join = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(4);
            for index in 0..count {
                let mut stream = loop {
                    if worker_cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
                        return Err("test server admission deadline".to_owned());
                    }
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => return Err(error.to_string()),
                    }
                };
                let request = request(&mut stream, deadline)?;
                stream
                    .set_write_timeout(Some(Duration::from_millis(250)))
                    .map_err(|error| error.to_string())?;
                reply(&request, index, &mut stream)?;
            }
            Ok(())
        });
        Ok(Self {
            address,
            cancel,
            join: Some(join),
        })
    }

    fn finish(mut self) -> TestResult {
        let join = self.join.take().ok_or("missing server join")?;
        join.join()
            .map_err(|_| "server thread panicked")?
            .map_err(Into::into)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn request(stream: &mut TcpStream, deadline: Instant) -> Result<String, String> {
    let mut bytes = Vec::new();
    while bytes.len() < 4096 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("test request deadline".to_owned());
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|error| error.to_string())?;
        let mut byte = [0];
        match stream.read(&mut byte).map_err(|error| error.to_string())? {
            0 => return Err("truncated test request".to_owned()),
            _ => bytes.push(byte[0]),
        }
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes).map_err(|error| error.to_string());
        }
    }
    Err("test request exceeded bound".to_owned())
}

fn response(request: &str, sequence: u64, body: &[u8]) -> Result<Vec<u8>, String> {
    if !request.starts_with("GET /health/status/v1 HTTP/1.1\r\n")
        || request.to_ascii_lowercase().contains("authorization:")
    {
        return Err("wrong route or reusable credential transmission".to_owned());
    }
    let header = |name: &str| -> Result<&str, String> {
        let values: Vec<_> = request
            .split("\r\n")
            .filter_map(|line| line.split_once(':'))
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim())
            .collect();
        match values.as_slice() {
            [value] => Ok(*value),
            _ => Err("missing or duplicate test header".to_owned()),
        }
    };
    if header("X-STS2-Health-Sequence")? != sequence.to_string() {
        return Err("request sequence reused".to_owned());
    }
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header("X-STS2-Health-Challenge")?)
        .map_err(|error| error.to_string())?;
    if challenge.len() != 32 {
        return Err("invalid test challenge".to_owned());
    }
    let mac = |domain: &[u8]| -> Result<Hmac<Sha256>, String> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).map_err(|_| "test key".to_owned())?;
        mac.update(domain);
        mac.update(&[0]);
        for field in [
            b"GET".as_slice(),
            b"/health/status/v1".as_slice(),
            challenge.as_slice(),
        ] {
            mac.update(
                &u32::try_from(field.len())
                    .map_err(|_| "test length".to_owned())?
                    .to_be_bytes(),
            );
            mac.update(field);
        }
        Ok(mac)
    };
    let mut request_mac = mac(b"sts2-gateway-health-request-v1")?;
    request_mac.update(
        Uuid::parse_str(NONCE)
            .map_err(|error| error.to_string())?
            .as_bytes(),
    );
    request_mac.update(&sequence.to_be_bytes());
    let tag = |mac: Hmac<Sha256>| -> String {
        mac.finalize()
            .into_bytes()
            .iter()
            .flat_map(|byte| {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                [
                    char::from(HEX[usize::from(byte >> 4)]),
                    char::from(HEX[usize::from(byte & 15)]),
                ]
            })
            .collect()
    };
    if tag(request_mac) != header("X-STS2-Health-Request")? {
        return Err("invalid request MAC".to_owned());
    }
    let mut response_mac = mac(b"sts2-gateway-health-attestation-v1")?;
    response_mac.update(&200_u16.to_be_bytes());
    response_mac.update(
        &u32::try_from(body.len())
            .map_err(|_| "test body length".to_owned())?
            .to_be_bytes(),
    );
    response_mac.update(body);
    let mut response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nX-STS2-Health-Attestation: {}\r\n\r\n", body.len(), tag(response_mac)).into_bytes();
    response.extend_from_slice(body);
    Ok(response)
}

#[test]
fn real_socket_roundtrip_authenticates_without_transmitting_a_bearer() -> TestResult {
    let server = Server::start(1, |request, _, stream| {
        stream
            .write_all(&response(request, 1, &body(1))?)
            .map_err(|error| error.to_string())
    })?;
    let mut client =
        GatewayHealthClient::new(server.address, KEY, binding()?, Duration::from_secs(1))?;
    let mut checks = 0;
    let status = client.probe(|| {
        checks += 1;
        Ok(())
    })?;
    assert_eq!(checks, 2);
    assert_eq!(status.readiness(), "blocked");
    assert_eq!(status.heartbeat_age_ms(), Some(0));
    assert_eq!(status.pending_operation_count(), None);
    assert_eq!(status.lease_remaining_ms(), None);
    server.finish()
}

#[test]
fn fresh_request_mac_cannot_make_a_stalled_heartbeat_advance() -> TestResult {
    let server = Server::start(2, |request, index, stream| {
        stream
            .write_all(&response(
                request,
                u64::try_from(index).map_err(|error| error.to_string())? + 1,
                &body(1),
            )?)
            .map_err(|error| error.to_string())
    })?;
    let mut client =
        GatewayHealthClient::new(server.address, KEY, binding()?, Duration::from_secs(1))?;
    client.probe(|| Ok(()))?;
    assert!(matches!(
        client.probe(|| Ok(())),
        Err(HealthError::Sequence)
    ));
    server.finish()
}

#[test]
fn signed_wrong_release_and_unsigned_payloads_do_not_become_health() -> TestResult {
    let server = Server::start(1, |request, _, stream| {
        let mut value: serde_json::Value =
            serde_json::from_slice(&body(1)).map_err(|error| error.to_string())?;
        value["identity"]["release"]["config_digest"] = json!("e".repeat(64));
        let body = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
        stream
            .write_all(&response(request, 1, &body)?)
            .map_err(|error| error.to_string())
    })?;
    let mut client =
        GatewayHealthClient::new(server.address, KEY, binding()?, Duration::from_secs(1))?;
    assert!(matches!(
        client.probe(|| Ok(())),
        Err(HealthError::Identity)
    ));
    server.finish()?;
    let server = Server::start(1, |_, _, stream| {
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").map_err(|error| error.to_string())
    })?;
    let mut client =
        GatewayHealthClient::new(server.address, KEY, binding()?, Duration::from_secs(1))?;
    assert!(matches!(
        client.probe(|| Ok(())),
        Err(HealthError::Authentication)
    ));
    server.finish()
}

#[test]
fn trickled_headers_cannot_extend_the_absolute_deadline() -> TestResult {
    let server = Server::start(1, |_, _, stream| {
        for byte in b"HTTP/1.1 200 OK\r\n" {
            if stream.write_all(&[*byte]).is_err() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(30));
        }
        Ok(())
    })?;
    let mut client =
        GatewayHealthClient::new(server.address, KEY, binding()?, Duration::from_millis(100))?;
    let started = Instant::now();
    assert!(matches!(
        client.probe(|| Ok(())),
        Err(HealthError::Deadline)
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
    server.finish()
}
