//! Test-only synthetic host for watchdog recovery fault injection.
//!
//! This package is deliberately independent of the production watchdog and of
//! the gateway, harness, MCP, and game-mod implementation crates.  It exposes
//! the closed recovery sideband envelope, accepts the same operation identity
//! and fence fields, and also understands the frozen runtime-v3 route kinds.
//! Its `SQLite` state models the important crash window where a host effect is
//! durable before the receipt is durable.  An absent witness remains unknown.

use std::fmt::{Display, Formatter, Write as FmtWrite};
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Exact digest published by `watchdog-recovery-v1`.
pub const RECOVERY_SCHEMA_DIGEST: &str =
    "fb934d3157485aaf6e13e6ebbb213ec8a14c7fc6f5eeebc06b7a22c1f0009217";
/// Exact digest for the frozen runtime-v3 gameplay artifact used by the
/// companion mod/gateway sources.
pub const RUNTIME_V3_SCHEMA_DIGEST: &str =
    "8e99cea36b7ede97532348fd8efe302ca79260895265a7bf14ddf7e006d8ff63";
/// Recovery frame maximum from the companion contract.
pub const MAX_FRAME_BYTES: usize = 262_144;
/// Action/payload maximum from the companion contract.
pub const MAX_ACTION_BYTES: usize = 65_536;
/// Retained receipt bound used by the fixture's backpressure oracle.
pub const MAX_RECEIPTS: usize = 64;
/// A synthetic host effect is never represented as exactly-once proof.
pub const EFFECT_WITNESS_SOURCE: &str = "host_game_thread";

const MAX_LINE_BYTES: usize = MAX_FRAME_BYTES + 1;
const FIXTURE_TIMESTAMP: &str = "2026-09-06T00:00:00Z";

/// Faults are selected only by the test server process.  No production API
/// imports this enum or exposes these controls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultPoint {
    None,
    BeforeAdmission,
    AfterAdmission,
    BeforeMutation,
    AfterMutation,
    BeforeReceipt,
    AfterReceipt,
    ResponseLoss,
    MalformedResponse,
}

impl FaultPoint {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "before-admission" => Some(Self::BeforeAdmission),
            "after-admission" => Some(Self::AfterAdmission),
            "before-mutation" => Some(Self::BeforeMutation),
            "after-mutation" => Some(Self::AfterMutation),
            "before-receipt" => Some(Self::BeforeReceipt),
            "after-receipt" => Some(Self::AfterReceipt),
            "response-loss" => Some(Self::ResponseLoss),
            "malformed-response" => Some(Self::MalformedResponse),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::BeforeAdmission => "before-admission",
            Self::AfterAdmission => "after-admission",
            Self::BeforeMutation => "before-mutation",
            Self::AfterMutation => "after-mutation",
            Self::BeforeReceipt => "before-receipt",
            Self::AfterReceipt => "after-receipt",
            Self::ResponseLoss => "response-loss",
            Self::MalformedResponse => "malformed-response",
        }
    }

    const fn is_crash(self) -> bool {
        matches!(
            self,
            Self::BeforeAdmission
                | Self::AfterAdmission
                | Self::BeforeMutation
                | Self::AfterMutation
                | Self::BeforeReceipt
                | Self::AfterReceipt
        )
    }
}

/// The contract's actor object.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub principal_id: String,
    pub role: String,
}

/// The contract's authentication object.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    pub principal_id: String,
    pub capability: String,
    pub proof: Option<String>,
}

/// Closed recovery sideband envelope.  Payloads are parsed according to
/// `kind`, preserving the contract's top-level identity and capability fields.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub contract: String,
    pub schema_digest: String,
    pub message_id: String,
    pub correlation_id: String,
    pub sent_at: String,
    pub actor: Actor,
    pub auth: Auth,
    pub kind: String,
    pub payload: Value,
}

impl Frame {
    /// Build a valid fixture request with deterministic time and fresh UUIDs.
    #[must_use]
    pub fn request(kind: impl Into<String>, capability: impl Into<String>, payload: Value) -> Self {
        let principal = Uuid::new_v4().to_string();
        Self {
            contract: "watchdog-recovery-v1".to_owned(),
            schema_digest: RECOVERY_SCHEMA_DIGEST.to_owned(),
            message_id: Uuid::new_v4().to_string(),
            correlation_id: Uuid::new_v4().to_string(),
            sent_at: FIXTURE_TIMESTAMP.to_owned(),
            actor: Actor {
                principal_id: principal.clone(),
                role: "gateway".to_owned(),
            },
            auth: Auth {
                principal_id: principal,
                capability: capability.into(),
                proof: Some("fixture-proof".to_owned()),
            },
            kind: kind.into(),
            payload,
        }
    }

    fn response(&self, kind: &str, payload: Value) -> Self {
        let principal = Uuid::new_v4().to_string();
        Self {
            contract: "watchdog-recovery-v1".to_owned(),
            schema_digest: RECOVERY_SCHEMA_DIGEST.to_owned(),
            message_id: Uuid::new_v4().to_string(),
            correlation_id: self.correlation_id.clone(),
            sent_at: FIXTURE_TIMESTAMP.to_owned(),
            actor: Actor {
                principal_id: principal.clone(),
                role: "host".to_owned(),
            },
            auth: Auth {
                principal_id: principal,
                capability: "recovery_read".to_owned(),
                proof: None,
            },
            kind: kind.to_owned(),
            payload,
        }
    }

    fn validate(&self) -> Result<(), FixtureError> {
        if self.contract != "watchdog-recovery-v1" || self.schema_digest != RECOVERY_SCHEMA_DIGEST {
            return Err(FixtureError::ContractMismatch);
        }
        valid_v4(&self.message_id)?;
        valid_v4(&self.correlation_id)?;
        valid_v4(&self.actor.principal_id)?;
        valid_v4(&self.auth.principal_id)?;
        if self.actor.principal_id != self.auth.principal_id {
            return Err(FixtureError::Invalid(
                "actor/auth principal mismatch".to_owned(),
            ));
        }
        if self
            .auth
            .proof
            .as_ref()
            .is_some_and(|proof| proof.len() > 512)
        {
            return Err(FixtureError::Bounds("auth proof"));
        }
        if self.kind.is_empty() || self.payload.is_null() {
            return Err(FixtureError::Invalid("missing kind or payload".to_owned()));
        }
        Ok(())
    }
}

/// A bounded client for the fixture's one-frame-per-connection loopback wire.
#[derive(Clone, Copy, Debug)]
pub struct Client {
    address: SocketAddr,
}

impl Client {
    #[must_use]
    pub const fn new(address: SocketAddr) -> Self {
        Self { address }
    }

    #[must_use]
    pub const fn address(self) -> SocketAddr {
        self.address
    }

    /// Send one closed frame and decode its bounded response.
    ///
    /// # Errors
    ///
    /// Returns a transport, bounds, or JSON error when the peer is unavailable
    /// or does not return a closed response frame.
    pub fn request(&self, frame: &Frame) -> Result<Frame, FixtureError> {
        let bytes =
            serde_json::to_vec(frame).map_err(|error| FixtureError::Json(error.to_string()))?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(FixtureError::Bounds("request frame"));
        }
        let mut stream = TcpStream::connect(self.address).map_err(FixtureError::Io)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(FixtureError::Io)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(FixtureError::Io)?;
        stream.write_all(&bytes).map_err(FixtureError::Io)?;
        stream.write_all(b"\n").map_err(FixtureError::Io)?;
        stream.flush().map_err(FixtureError::Io)?;
        let mut reader = BufReader::new(stream);
        let Some(line) = read_bounded_line(&mut reader)? else {
            return Err(FixtureError::ResponseLost);
        };
        serde_json::from_slice::<Frame>(&line)
            .map_err(|error| FixtureError::Json(error.to_string()))
    }
}

/// Server settings.  `fault` is intentionally only constructible by this
/// test package and is never accepted by a production executable.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub database: PathBuf,
    pub bind: SocketAddr,
    pub fault: FaultPoint,
}

impl ServerConfig {
    #[must_use]
    pub fn loopback(database: impl Into<PathBuf>, fault: FaultPoint) -> Self {
        Self {
            database: database.into(),
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            fault,
        }
    }
}

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
    println!("LISTEN {address}");
    std::io::stdout().flush().map_err(FixtureError::Io)?;
    let store = Arc::new(Mutex::new(DurableHost::open(&config.database)?));
    let mut faults = FaultController::new(config.fault);
    for incoming in listener.incoming() {
        let stream = incoming.map_err(FixtureError::Io)?;
        match serve_connection(stream, &store, &mut faults)? {
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

fn serve_connection(
    mut stream: TcpStream,
    store: &Arc<Mutex<DurableHost>>,
    faults: &mut FaultController,
) -> Result<ConnectionAction, FixtureError> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(FixtureError::Io)?;
    let mut reader = BufReader::new(stream.try_clone().map_err(FixtureError::Io)?);
    let line = match read_bounded_line(&mut reader) {
        Ok(Some(line)) => line,
        Ok(None) => return Ok(ConnectionAction::Continue),
        Err(FixtureError::Bounds(_)) => {
            write_raw_response(&mut stream, b"{\"error\":\"frame_too_large\"}\n")?;
            return Ok(ConnectionAction::Continue);
        }
        Err(error) => return Err(error),
    };
    let frame = match serde_json::from_slice::<Frame>(&line) {
        Ok(frame) => frame,
        Err(error) => {
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
        write_frame(&mut stream, &response)?;
        return Ok(ConnectionAction::Continue);
    }
    let (response, action) = {
        let mut guard = store
            .lock()
            .map_err(|_| FixtureError::Invalid("store mutex poisoned".to_owned()))?;
        guard.handle(&frame, faults)?
    };
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

fn write_frame(stream: &mut TcpStream, frame: &Frame) -> Result<(), FixtureError> {
    let bytes = serde_json::to_vec(frame).map_err(|error| FixtureError::Json(error.to_string()))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(FixtureError::Bounds("response frame"));
    }
    write_raw_response(stream, &bytes)
}

fn write_raw_response(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), FixtureError> {
    stream.write_all(bytes).map_err(FixtureError::Io)?;
    if !bytes.ends_with(b"\n") {
        stream.write_all(b"\n").map_err(FixtureError::Io)?;
    }
    stream.flush().map_err(FixtureError::Io)
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

fn response_kind(request_kind: &str) -> String {
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

fn read_bounded_line<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, FixtureError> {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseAction {
    Send,
    Drop,
    Malformed,
    Crash,
}

struct FaultController {
    point: FaultPoint,
    fired: bool,
}

impl FaultController {
    const fn new(point: FaultPoint) -> Self {
        Self {
            point,
            fired: false,
        }
    }

    fn at(&mut self, point: FaultPoint) -> Option<ResponseAction> {
        if self.fired || self.point != point {
            return None;
        }
        self.fired = true;
        if point.is_crash() {
            Some(ResponseAction::Crash)
        } else if point == FaultPoint::ResponseLoss {
            Some(ResponseAction::Drop)
        } else if point == FaultPoint::MalformedResponse {
            Some(ResponseAction::Malformed)
        } else {
            None
        }
    }
}

/// Durable host store.  Each operation, effect witness, receipt, queue item,
/// and current fence is persisted independently so the effect/receipt crash
/// window is observable rather than hidden behind an in-memory counter.
pub struct DurableHost {
    connection: Connection,
}

type OperationRow = (
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    String,
    String,
    Option<String>,
);

impl DurableHost {
    /// Open or initialize the fixture database with full synchronous writes.
    ///
    /// # Errors
    ///
    /// Returns a persistence error when `SQLite` cannot open, configure, or
    /// initialize the database.
    pub fn open(path: &Path) -> Result<Self, FixtureError> {
        let connection = Connection::open(path).map_err(FixtureError::Sql)?;
        connection
            .busy_timeout(Duration::from_secs(2))
            .map_err(FixtureError::Sql)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(FixtureError::Sql)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(FixtureError::Sql)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS fence (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    boot_id TEXT NOT NULL,
                    instance_incarnation TEXT NOT NULL,
                    authority_generation INTEGER NOT NULL,
                    host_fence_id TEXT NOT NULL,
                    fence_generation INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS lease (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    lease_id TEXT NOT NULL,
                    lease_epoch INTEGER NOT NULL,
                    boot_id TEXT NOT NULL,
                    instance_incarnation TEXT NOT NULL,
                    host_fence_id TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS operations (
                    operation_id TEXT PRIMARY KEY,
                    payload_digest TEXT NOT NULL,
                    boot_id TEXT NOT NULL,
                    instance_incarnation TEXT NOT NULL,
                    lease_epoch INTEGER NOT NULL,
                    host_fence_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    uncertainty_reason TEXT,
                    action_json TEXT NOT NULL,
                    expected_boundary_json TEXT NOT NULL,
                    original_context_json TEXT NOT NULL,
                    ticket_json TEXT,
                    witness_json TEXT,
                    receipt_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS queue (
                    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
                    ticket_json TEXT NOT NULL,
                    enqueued_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS effects (
                    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
                    payload_digest TEXT NOT NULL,
                    witness_json TEXT NOT NULL,
                    effect_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS receipts (
                    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
                    receipt_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );",
            )
            .map_err(FixtureError::Sql)?;
        Ok(Self { connection })
    }

    fn handle(
        &mut self,
        frame: &Frame,
        faults: &mut FaultController,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        let result = match frame.kind.as_str() {
            "bootstrap_request" => self.bootstrap(frame),
            "host_fence_request" => self.host_fence(frame),
            "lease_acquire_request" => self.lease_acquire(frame),
            "lease_renew_request" => self.lease_renew(frame),
            "lease_revoke_request" => self.lease_revoke(frame),
            "operation_intent_request" => self.intent(frame),
            "operation_dispatch_request" => self.dispatch(frame, faults),
            "operation_lookup_request" => self.lookup(frame),
            "operation_reconcile_request" => self.reconcile(frame),
            "dispatch_action_request" => Self::v3_dispatch(frame, faults),
            "wait_request" => Ok(Self::v3_wait(frame)),
            "reobserve_request" => Ok(Self::v3_reobserve(frame)),
            "recover_request" => Ok(Self::v3_recover(frame)),
            "host_tick" => self.tick(frame, faults),
            "stats" => self.stats(frame),
            "shutdown" => Ok((
                frame.response("shutdown_response", json!({"result":{"status":"ACCEPTED","retryable":false,"retry_after_seconds":null}})),
                ResponseAction::Send,
            )),
            _ => Err(FixtureError::Invalid("unsupported request kind".to_owned())),
        }?;
        Ok(result)
    }

    fn bootstrap(&mut self, frame: &Frame) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "bootstrap")?;
        let deployment_id = field_string(&frame.payload, "deployment_id")?;
        let instance_id = field_string(&frame.payload, "instance_id")?;
        let incarnation = field_string(&frame.payload, "instance_incarnation")?;
        valid_v4(&deployment_id)?;
        valid_v4(&instance_id)?;
        valid_v4(&incarnation)?;
        let current: Option<i64> = self
            .connection
            .query_row(
                "SELECT authority_generation FROM fence WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let generation = current.map_or(1, |value| value.saturating_add(1));
        let boot_id = Uuid::new_v4().to_string();
        let fence_id = Uuid::new_v4().to_string();
        let tx = self.connection.transaction().map_err(FixtureError::Sql)?;
        tx.execute("DELETE FROM lease", [])
            .map_err(FixtureError::Sql)?;
        tx.execute(
            "INSERT OR REPLACE INTO fence(singleton, boot_id, instance_incarnation, authority_generation, host_fence_id, fence_generation)
             VALUES(1, ?1, ?2, ?3, ?4, ?3)",
            params![boot_id, incarnation, generation, fence_id],
        )
        .map_err(FixtureError::Sql)?;
        tx.commit().map_err(FixtureError::Sql)?;
        let boot = json!({
            "deployment_id": deployment_id,
            "instance_id": instance_id,
            "instance_incarnation": incarnation,
            "boot_id": boot_id,
            "authority_generation": generation,
            "release": frame.payload.get("release").cloned().unwrap_or_else(|| json!({
                "release_digest": digest("release"), "config_digest": digest("config"),
                "profile_digest": digest("profile"), "runtime_v3_schema_digest": RUNTIME_V3_SCHEMA_DIGEST
            })),
            "created_at": FIXTURE_TIMESTAMP,
            "state": "FENCE_REQUIRED"
        });
        let fence = json!({
            "host_fence_id": fence_id,
            "deployment_id": boot["deployment_id"],
            "instance_id": boot["instance_id"],
            "instance_incarnation": boot["instance_incarnation"],
            "boot_id": boot["boot_id"],
            "authority_generation": generation,
            "fence_generation": generation,
            "created_at": FIXTURE_TIMESTAMP
        });
        Ok((
            frame.response(
                "bootstrap_response",
                json!({"result":status("BOOT_AUTHORITY_CREATED"),"boot":boot,"fence":fence}),
            ),
            ResponseAction::Send,
        ))
    }

    fn host_fence(&mut self, frame: &Frame) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "host_fence")?;
        let boot = frame
            .payload
            .get("boot")
            .ok_or_else(|| FixtureError::Invalid("boot missing".to_owned()))?;
        let boot_id = field_string(boot, "boot_id")?;
        let incarnation = field_string(boot, "instance_incarnation")?;
        let generation = field_i64(boot, "authority_generation")?;
        let current: Option<(String, String, i64)> = self
            .connection
            .query_row(
                "SELECT boot_id, instance_incarnation, authority_generation FROM fence WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((current_boot, current_incarnation, current_generation)) = current else {
            return Err(FixtureError::HostNotReady);
        };
        if boot_id != current_boot
            || incarnation != current_incarnation
            || generation != current_generation
        {
            return Err(FixtureError::Stale("boot"));
        }
        let fence: (String, i64) = self
            .connection
            .query_row(
                "SELECT host_fence_id, fence_generation FROM fence WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(FixtureError::Sql)?;
        Ok((
            frame.response(
                "host_fence_response",
                json!({
                    "result": status("FENCE_ACCEPTED"),
                    "fence": fence_json(boot, &fence.0, fence.1)
                }),
            ),
            ResponseAction::Send,
        ))
    }

    fn lease_acquire(&mut self, frame: &Frame) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "lease_acquire")?;
        let boot = frame
            .payload
            .get("boot")
            .ok_or_else(|| FixtureError::Invalid("boot missing".to_owned()))?;
        let fence = frame
            .payload
            .get("fence")
            .ok_or_else(|| FixtureError::Invalid("fence missing".to_owned()))?;
        self.validate_fence_pair(boot, fence)?;
        let lease_id = Uuid::new_v4().to_string();
        let token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let epoch: i64 = self
            .connection
            .query_row(
                "SELECT COALESCE(MAX(lease_epoch), 0) + 1 FROM lease",
                [],
                |row| row.get(0),
            )
            .map_err(FixtureError::Sql)?;
        self.connection
            .execute("DELETE FROM lease", [])
            .map_err(FixtureError::Sql)?;
        self.connection
            .execute(
                "INSERT INTO lease(singleton, lease_id, lease_epoch, boot_id, instance_incarnation, host_fence_id, revoked)
                 VALUES(1, ?1, ?2, ?3, ?4, ?5, 0)",
                params![lease_id, epoch, field_string(boot, "boot_id")?, field_string(boot, "instance_incarnation")?, field_string(fence, "host_fence_id")?],
            )
            .map_err(FixtureError::Sql)?;
        let lease = json!({
            "deployment_id": boot["deployment_id"], "instance_id": boot["instance_id"],
            "instance_incarnation": boot["instance_incarnation"], "boot_id": boot["boot_id"],
            "authority_generation": boot["authority_generation"], "lease_id": lease_id,
            "lease_epoch": epoch, "host_fence_id": fence["host_fence_id"],
            "fence_token": token, "issued_at": FIXTURE_TIMESTAMP,
            "expires_at": FIXTURE_TIMESTAMP, "ttl_seconds": 30, "renewal_interval_seconds": 10
        });
        Ok((
            frame.response(
                "lease_acquire_response",
                json!({"result":status("LEASE_ACTIVE"),"lease":lease}),
            ),
            ResponseAction::Send,
        ))
    }

    fn lease_renew(&mut self, frame: &Frame) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "lease_renew")?;
        let lease = frame
            .payload
            .get("lease")
            .ok_or_else(|| FixtureError::Invalid("lease missing".to_owned()))?;
        self.validate_lease(lease)?;
        Ok((
            frame.response(
                "lease_renew_response",
                json!({"result":status("LEASE_RENEWED"),"lease":lease}),
            ),
            ResponseAction::Send,
        ))
    }

    fn lease_revoke(&mut self, frame: &Frame) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "lease_revoke")?;
        let lease = frame
            .payload
            .get("lease")
            .ok_or_else(|| FixtureError::Invalid("lease missing".to_owned()))?;
        self.validate_lease(lease)?;
        self.connection
            .execute("UPDATE lease SET revoked = 1 WHERE singleton = 1", [])
            .map_err(FixtureError::Sql)?;
        Ok((
            frame.response(
                "lease_revoke_response",
                json!({"result":status("LEASE_REVOKED")}),
            ),
            ResponseAction::Send,
        ))
    }

    fn intent(&mut self, frame: &Frame) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "operation_submit")?;
        let lease = frame
            .payload
            .get("lease")
            .ok_or_else(|| FixtureError::Invalid("lease missing".to_owned()))?;
        self.validate_lease(lease)?;
        let operation = frame
            .payload
            .get("operation")
            .ok_or_else(|| FixtureError::Invalid("operation missing".to_owned()))?;
        let id = field_string(operation, "operation_id")?;
        let digest_value = field_string(operation, "payload_digest")?;
        valid_v4(&id)?;
        validate_digest(&digest_value)?;
        let action = operation
            .get("action")
            .ok_or_else(|| FixtureError::Invalid("action missing".to_owned()))?;
        let action_json = bounded_json(action, MAX_ACTION_BYTES)?;
        let original_context = operation
            .get("original_context")
            .ok_or_else(|| FixtureError::Invalid("original context missing".to_owned()))?;
        let expected_boundary = operation
            .get("expected_boundary")
            .ok_or_else(|| FixtureError::Invalid("expected boundary missing".to_owned()))?;
        let context_json = bounded_json(original_context, 4096)?;
        let boundary_json = bounded_json(expected_boundary, 4096)?;
        let existing: Option<(String, String, String)> = self
            .connection
            .query_row(
                "SELECT payload_digest, state, original_context_json FROM operations WHERE operation_id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        if let Some((existing_digest, state, _)) = existing {
            if existing_digest != digest_value {
                return self.operation_response(frame, "CONFLICT", &id);
            }
            return self.operation_response(
                frame,
                if state == "SETTLED" {
                    "DUPLICATE"
                } else {
                    "INTENT_RECORDED"
                },
                &id,
            );
        }
        let now = FIXTURE_TIMESTAMP;
        self.connection
            .execute(
                "INSERT INTO operations(operation_id,payload_digest,boot_id,instance_incarnation,lease_epoch,host_fence_id,state,uncertainty_reason,action_json,expected_boundary_json,original_context_json,ticket_json,witness_json,receipt_json,created_at,updated_at)
                 VALUES(?1,?2,?3,?4,?5,?6,'INTENT_RECORDED',NULL,?7,?8,?9,NULL,NULL,NULL,?10,?10)",
                params![
                    id,
                    digest_value,
                    field_string(lease, "boot_id")?,
                    field_string(lease, "instance_incarnation")?,
                    field_i64(lease, "lease_epoch")?,
                    field_string(lease, "host_fence_id")?,
                    action_json,
                    boundary_json,
                    context_json,
                    now
                ],
            )
            .map_err(FixtureError::Sql)?;
        self.operation_response(frame, "INTENT_RECORDED", &id)
    }

    fn dispatch(
        &mut self,
        frame: &Frame,
        faults: &mut FaultController,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "operation_submit")?;
        let lease = frame
            .payload
            .get("lease")
            .ok_or_else(|| FixtureError::Invalid("lease missing".to_owned()))?;
        self.validate_lease(lease)?;
        let operation = frame
            .payload
            .get("operation")
            .ok_or_else(|| FixtureError::Invalid("operation missing".to_owned()))?;
        let id = field_string(operation, "operation_id")?;
        let digest_value = field_string(operation, "payload_digest")?;
        valid_v4(&id)?;
        validate_digest(&digest_value)?;
        let state: Option<String> = self
            .connection
            .query_row(
                "SELECT state FROM operations WHERE operation_id = ?1 AND payload_digest = ?2",
                params![id, digest_value],
                |row| row.get(0),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some(state) = state else {
            return self.operation_response(frame, "NOT_FOUND", &id);
        };
        if state == "SETTLED" || state == "RECONCILED" {
            return self.operation_response(frame, "DUPLICATE", &id);
        }
        if self.receipt_count()? >= MAX_RECEIPTS {
            return self.operation_response(frame, "BOUNDS_EXCEEDED", &id);
        }
        if let Some(action) = faults.at(FaultPoint::BeforeAdmission) {
            return self.operation_response_with_action(frame, "UNKNOWN", &id, action);
        }
        let ticket = Self::issue_ticket(&id, &digest_value, lease)?;
        self.connection
            .execute(
                "UPDATE operations SET state='MAY_HAVE_BEEN_DISPATCHED',ticket_json=?2,updated_at=?3 WHERE operation_id=?1",
                params![id, ticket.to_string(), FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        self.connection
            .execute("INSERT OR REPLACE INTO queue(operation_id,ticket_json,enqueued_at) VALUES(?1,?2,?3)", params![id, ticket.to_string(), FIXTURE_TIMESTAMP])
            .map_err(FixtureError::Sql)?;
        if let Some(action) = faults.at(FaultPoint::AfterAdmission) {
            return self.operation_response_with_action(
                frame,
                "MAY_HAVE_BEEN_DISPATCHED",
                &id,
                action,
            );
        }
        self.operation_response(frame, "MAY_HAVE_BEEN_DISPATCHED", &id)
    }

    fn issue_ticket(
        operation_id: &str,
        digest_value: &str,
        lease: &Value,
    ) -> Result<Value, FixtureError> {
        let fence_id = field_string(lease, "host_fence_id")?;
        let ticket_id = Uuid::new_v4().to_string();
        Ok(json!({
            "ticket_id": ticket_id, "operation_id": operation_id, "payload_digest": digest_value,
            "boot_id": lease["boot_id"], "instance_incarnation": lease["instance_incarnation"],
            "lease_epoch": lease["lease_epoch"], "host_fence_id": fence_id,
            "state": "ISSUED", "issued_at": FIXTURE_TIMESTAMP, "expires_at": FIXTURE_TIMESTAMP
        }))
    }

    #[allow(clippy::too_many_lines)]
    fn tick(
        &mut self,
        frame: &Frame,
        faults: &mut FaultController,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        let id = frame
            .payload
            .get("operation_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let Some(id) = id else {
            return Err(FixtureError::Invalid("operation_id missing".to_owned()));
        };
        let queued: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT ticket_json, operation_id FROM queue WHERE operation_id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((ticket_json, _)) = queued else {
            return self.operation_response(frame, "NOT_FOUND", &id);
        };
        let ticket: Value = serde_json::from_str(&ticket_json)
            .map_err(|error| FixtureError::Json(error.to_string()))?;
        let current_fence: Option<String> = self
            .connection
            .query_row(
                "SELECT host_fence_id FROM fence WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        if current_fence.as_deref() != ticket.get("host_fence_id").and_then(Value::as_str) {
            self.connection
                .execute("DELETE FROM queue WHERE operation_id=?1", params![id])
                .map_err(FixtureError::Sql)?;
            self.connection
                .execute(
                    "UPDATE operations SET state='REJECTED',updated_at=?2 WHERE operation_id=?1",
                    params![id, FIXTURE_TIMESTAMP],
                )
                .map_err(FixtureError::Sql)?;
            return self.operation_response(frame, "STALE_LEASE", &id);
        }
        if let Some(action) = faults.at(FaultPoint::BeforeMutation) {
            return self.operation_response_with_action(
                frame,
                "MAY_HAVE_BEEN_DISPATCHED",
                &id,
                action,
            );
        }
        let operation: (String, String) = self
            .connection
            .query_row(
                "SELECT payload_digest, action_json FROM operations WHERE operation_id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(FixtureError::Sql)?;
        let effect_digest = digest(&format!("effect:{id}:{}", operation.0));
        let witness = json!({
            "witness_id": Uuid::new_v4().to_string(), "operation_id": id,
            "payload_digest": operation.0, "boot_id": ticket["boot_id"],
            "instance_incarnation": ticket["instance_incarnation"],
            "host_fence_id": ticket["host_fence_id"], "source": EFFECT_WITNESS_SOURCE,
            "state_id": "00000000-0000-4000-8000-000000000001", "generation": 1,
            "effect_digest": effect_digest, "observed_at": FIXTURE_TIMESTAMP
        });
        let witness_text = witness.to_string();
        let transaction = self.connection.transaction().map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO effects(operation_id,payload_digest,witness_json,effect_digest,created_at) VALUES(?1,?2,?3,?4,?5)",
                params![id, operation.0, witness_text, witness["effect_digest"].as_str(), FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE operations SET state='UNKNOWN',uncertainty_reason='receipt_missing',witness_json=?2,updated_at=?3 WHERE operation_id=?1",
                params![id, witness_text, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        transaction.commit().map_err(FixtureError::Sql)?;
        if let Some(action) = faults.at(FaultPoint::AfterMutation) {
            return self.operation_response_with_action(frame, "UNKNOWN", &id, action);
        }
        if let Some(action) = faults.at(FaultPoint::BeforeReceipt) {
            return self.operation_response_with_action(frame, "UNKNOWN", &id, action);
        }
        let receipt = json!({
            "operation_id": id, "payload_digest": operation.0,
            "status": "settled", "effect_witness": witness
        });
        self.connection
            .execute("INSERT OR REPLACE INTO receipts(operation_id,receipt_json,created_at) VALUES(?1,?2,?3)", params![id, receipt.to_string(), FIXTURE_TIMESTAMP])
            .map_err(FixtureError::Sql)?;
        self.connection
            .execute("UPDATE operations SET state='SETTLED',uncertainty_reason=NULL,receipt_json=?2,updated_at=?3 WHERE operation_id=?1", params![id, receipt.to_string(), FIXTURE_TIMESTAMP])
            .map_err(FixtureError::Sql)?;
        self.connection
            .execute("DELETE FROM queue WHERE operation_id=?1", params![id])
            .map_err(FixtureError::Sql)?;
        if let Some(action) = faults.at(FaultPoint::AfterReceipt) {
            return self.operation_response_with_action(frame, "SETTLED", &id, action);
        }
        self.operation_response(frame, "SETTLED", &id)
    }

    fn lookup(&mut self, frame: &Frame) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "recovery_read")?;
        let operation = frame
            .payload
            .get("operation")
            .ok_or_else(|| FixtureError::Invalid("operation missing".to_owned()))?;
        let id = field_string(operation, "operation_id")?;
        let digest_value = field_string(operation, "payload_digest")?;
        let response = self.operation_value(&id, &digest_value)?;
        let (status_value, value) = match response {
            None => ("NOT_FOUND".to_owned(), Value::Null),
            Some(value) => (
                value["state"].as_str().unwrap_or("UNKNOWN").to_owned(),
                value,
            ),
        };
        Ok((
            frame.response("operation_lookup_response", json!({
                "result": status(&status_value), "operation": value, "mutation_authorized": false
            })),
            ResponseAction::Send,
        ))
    }

    fn reconcile(&mut self, frame: &Frame) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "recovery_reconcile")?;
        let strategy = frame
            .payload
            .get("strategy")
            .and_then(Value::as_str)
            .ok_or_else(|| FixtureError::Invalid("strategy missing".to_owned()))?;
        if !matches!(strategy, "reobserve" | "receipt_lookup" | "quarantine") {
            return Err(FixtureError::Invalid(
                "unsupported reconciliation strategy".to_owned(),
            ));
        }
        let current_fence = frame
            .payload
            .get("current_fence")
            .ok_or_else(|| FixtureError::Invalid("current fence missing".to_owned()))?;
        self.validate_current_fence(current_fence)?;
        let operation = frame
            .payload
            .get("operation")
            .ok_or_else(|| FixtureError::Invalid("operation missing".to_owned()))?;
        let id = field_string(operation, "operation_id")?;
        let digest_value = field_string(operation, "payload_digest")?;
        let Some(value) = self.operation_value(&id, &digest_value)? else {
            return Ok((
                frame.response(
                    "operation_reconcile_response",
                    json!({"result":status("NOT_FOUND"),"operation":null,"witness":null}),
                ),
                ResponseAction::Send,
            ));
        };
        let witness = value.get("witness").cloned().unwrap_or(Value::Null);
        if witness.is_null() {
            return Ok((
                frame.response(
                    "operation_reconcile_response",
                    json!({"result":status("UNKNOWN"),"operation":value,"witness":null}),
                ),
                ResponseAction::Send,
            ));
        }
        self.connection
            .execute("UPDATE operations SET state='RECONCILED',uncertainty_reason=NULL,updated_at=?2 WHERE operation_id=?1", params![id, FIXTURE_TIMESTAMP])
            .map_err(FixtureError::Sql)?;
        let operation = self.operation_value(&id, &digest_value)?.unwrap_or(value);
        Ok((
            frame.response(
                "operation_reconcile_response",
                json!({"result":status("RECONCILED"),"operation":operation,"witness":witness}),
            ),
            ResponseAction::Send,
        ))
    }

    fn stats(&mut self, frame: &Frame) -> Result<(Frame, ResponseAction), FixtureError> {
        let effect_count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM effects", [], |row| row.get(0))
            .map_err(FixtureError::Sql)?;
        let receipt_count = i64::try_from(self.receipt_count()?)
            .map_err(|_| FixtureError::Invalid("receipt count overflow".to_owned()))?;
        let queue_count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM queue", [], |row| row.get(0))
            .map_err(FixtureError::Sql)?;
        let unresolved_count: i64 = self.connection.query_row("SELECT COUNT(*) FROM operations WHERE state IN ('UNKNOWN','MAY_HAVE_BEEN_DISPATCHED')", [], |row| row.get(0)).map_err(FixtureError::Sql)?;
        Ok((frame.response("stats_response", json!({"result":status("ACCEPTED"),"effect_count":effect_count,"receipt_count":receipt_count,"queue_count":queue_count,"unresolved_count":unresolved_count,"receipt_capacity":MAX_RECEIPTS})), ResponseAction::Send))
    }

    fn v3_dispatch(
        frame: &Frame,
        _faults: &mut FaultController,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        // The frozen v3 route is intentionally represented as an accepted
        // transport shape.  Effect execution remains controlled by host_tick,
        // so this fixture cannot turn a route receipt into exactly-once proof.
        let operation_id = frame
            .payload
            .get("operation_id")
            .and_then(Value::as_str)
            .ok_or_else(|| FixtureError::Invalid("operation_id missing".to_owned()))?;
        let digest_value = digest(&frame.payload.to_string());
        Ok((frame.response("dispatch_action_response", json!({
            "protocol_version":"runtime-v3-gameplay", "schema_digest":RUNTIME_V3_SCHEMA_DIGEST,
            "kind":"dispatch_action_response", "operation_id":operation_id,
            "status":"unknown", "error_code":"fixture_sideband_required", "payload_digest":digest_value
        })), ResponseAction::Send))
    }

    fn v3_wait(frame: &Frame) -> (Frame, ResponseAction) {
        (frame.response("wait_response", json!({
            "protocol_version":"runtime-v3-gameplay", "schema_digest":RUNTIME_V3_SCHEMA_DIGEST,
            "kind":"wait_response", "operation_id":frame.payload.get("operation_id"), "status":"unknown",
            "error_code":"fixture_requires_recovery_sideband"
        })), ResponseAction::Send)
    }

    fn v3_reobserve(frame: &Frame) -> (Frame, ResponseAction) {
        (frame.response("reobserve_response", json!({
            "protocol_version":"runtime-v3-gameplay", "schema_digest":RUNTIME_V3_SCHEMA_DIGEST,
            "kind":"reobserve_response", "status":"unknown", "error_code":"synthetic_observation_only"
        })), ResponseAction::Send)
    }

    fn v3_recover(frame: &Frame) -> (Frame, ResponseAction) {
        (frame.response("recover_response", json!({
            "protocol_version":"runtime-v3-gameplay", "schema_digest":RUNTIME_V3_SCHEMA_DIGEST,
            "kind":"recover_response", "status":"unknown", "error_code":"fixture_requires_recovery_sideband"
        })), ResponseAction::Send)
    }

    fn operation_response(
        &mut self,
        frame: &Frame,
        status_value: &str,
        id: &str,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        self.operation_response_with_action(frame, status_value, id, ResponseAction::Send)
    }

    fn operation_response_with_action(
        &mut self,
        frame: &Frame,
        status_value: &str,
        id: &str,
        action: ResponseAction,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        let operation = self.operation_value(id, "")?.unwrap_or(Value::Null);
        Ok((
            frame.response(
                &response_kind(&frame.kind),
                json!({"result":status(status_value),"operation":operation}),
            ),
            action,
        ))
    }

    fn operation_value(&self, id: &str, digest_value: &str) -> Result<Option<Value>, FixtureError> {
        let row: Option<OperationRow> = self
            .connection
            .query_row(
                "SELECT operation_id,payload_digest,state,uncertainty_reason,witness_json,action_json,expected_boundary_json,original_context_json,ticket_json FROM operations WHERE operation_id=?1",
                params![id],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((
            operation_id,
            stored_digest,
            state,
            uncertainty,
            witness,
            action,
            boundary,
            context,
            ticket,
        )) = row
        else {
            return Ok(None);
        };
        if !digest_value.is_empty() && digest_value != stored_digest {
            return Err(FixtureError::Conflict);
        }
        let ticket_value = ticket.map_or(Value::Null, |text| {
            serde_json::from_str(&text).unwrap_or(Value::Null)
        });
        let witness_value = witness.map_or(Value::Null, |text| {
            serde_json::from_str(&text).unwrap_or(Value::Null)
        });
        Ok(Some(json!({
            "operation_id":operation_id,"state":state,"payload_digest":stored_digest,
            "original_context":serde_json::from_str::<Value>(&context).map_err(|error| FixtureError::Json(error.to_string()))?,
            "expected_boundary":serde_json::from_str::<Value>(&boundary).map_err(|error| FixtureError::Json(error.to_string()))?,
            "action":serde_json::from_str::<Value>(&action).map_err(|error| FixtureError::Json(error.to_string()))?,
            "ticket":ticket_value,"witness":witness_value,"uncertainty_reason":uncertainty,
            "created_at":FIXTURE_TIMESTAMP,"updated_at":FIXTURE_TIMESTAMP
        })))
    }

    fn receipt_count(&self) -> Result<usize, FixtureError> {
        let count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))
            .map_err(FixtureError::Sql)?;
        usize::try_from(count)
            .map_err(|_| FixtureError::Invalid("receipt count overflow".to_owned()))
    }

    fn validate_fence_pair(&self, boot: &Value, fence: &Value) -> Result<(), FixtureError> {
        let boot_id = field_string(boot, "boot_id")?;
        let fence_boot = field_string(fence, "boot_id")?;
        if boot_id != fence_boot {
            return Err(FixtureError::Stale("boot"));
        }
        self.validate_current_fence(fence)
    }

    fn validate_current_fence(&self, fence: &Value) -> Result<(), FixtureError> {
        let supplied = field_string(fence, "host_fence_id")?;
        let current: Option<String> = self
            .connection
            .query_row(
                "SELECT host_fence_id FROM fence WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        if current.as_deref() != Some(supplied.as_str()) {
            return Err(FixtureError::Stale("fence"));
        }
        Ok(())
    }

    fn validate_lease(&self, lease: &Value) -> Result<(), FixtureError> {
        let lease_id = field_string(lease, "lease_id")?;
        let epoch = field_i64(lease, "lease_epoch")?;
        let current: Option<(String, i64, i64)> = self
            .connection
            .query_row(
                "SELECT lease_id,lease_epoch,revoked FROM lease WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((current_id, current_epoch, revoked)) = current else {
            return Err(FixtureError::HostNotReady);
        };
        if revoked != 0 {
            return Err(FixtureError::Stale("revoked lease"));
        }
        if lease_id != current_id || epoch != current_epoch {
            return Err(FixtureError::Stale("lease"));
        }
        self.validate_current_fence(lease)
    }
}

fn status(value: &str) -> Value {
    json!({"status":value,"retryable":false,"retry_after_seconds":null})
}

fn fence_json(boot: &Value, fence_id: &str, generation: i64) -> Value {
    json!({"host_fence_id":fence_id,"deployment_id":boot["deployment_id"],"instance_id":boot["instance_id"],"instance_incarnation":boot["instance_incarnation"],"boot_id":boot["boot_id"],"authority_generation":boot["authority_generation"],"fence_generation":generation,"created_at":FIXTURE_TIMESTAMP})
}

fn require_capability(frame: &Frame, expected: &str) -> Result<(), FixtureError> {
    if frame.auth.capability != expected {
        return Err(FixtureError::Forbidden);
    }
    Ok(())
}

fn valid_v4(value: &str) -> Result<(), FixtureError> {
    if value.len() != 36 || value != value.to_ascii_lowercase() {
        return Err(FixtureError::Invalid("UUIDv4".to_owned()));
    }
    let id = Uuid::parse_str(value).map_err(|_| FixtureError::Invalid("UUID".to_owned()))?;
    if id.get_version_num() != 4 {
        return Err(FixtureError::Invalid("UUIDv4".to_owned()));
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), FixtureError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(FixtureError::Invalid("SHA-256 digest".to_owned()));
    }
    Ok(())
}

fn field_string(value: &Value, name: &str) -> Result<String, FixtureError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| FixtureError::Invalid(format!("missing string field {name}")))
}

fn field_i64(value: &Value, name: &str) -> Result<i64, FixtureError> {
    value
        .get(name)
        .and_then(Value::as_i64)
        .ok_or_else(|| FixtureError::Invalid(format!("missing integer field {name}")))
}

fn bounded_json(value: &Value, limit: usize) -> Result<String, FixtureError> {
    let text =
        serde_json::to_string(value).map_err(|error| FixtureError::Json(error.to_string()))?;
    if text.len() > limit {
        return Err(FixtureError::Bounds("JSON payload"));
    }
    Ok(text)
}

fn digest(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let mut result = String::with_capacity(64);
    for byte in hasher.finalize() {
        let _ = write!(&mut result, "{byte:02x}");
    }
    result
}

/// Typed fixture failures map to the contract's bounded status vocabulary.
#[derive(Debug)]
pub enum FixtureError {
    Io(std::io::Error),
    Sql(rusqlite::Error),
    Json(String),
    Invalid(String),
    Bounds(&'static str),
    ContractMismatch,
    Forbidden,
    Conflict,
    Stale(&'static str),
    HostNotReady,
    ResponseLost,
}

impl FixtureError {
    #[must_use]
    pub fn status(&self) -> &'static str {
        match self {
            Self::ContractMismatch => "CONTRACT_MISMATCH",
            Self::Forbidden => "FORBIDDEN",
            Self::Conflict => "CONFLICT",
            Self::Stale("lease" | "fence") => "STALE_LEASE",
            Self::Stale("revoked lease") => "LEASE_EXPIRED",
            Self::Stale("boot") => "STALE_BOOT",
            Self::Stale(_) => "STALE_INCARNATION",
            Self::HostNotReady => "HOST_NOT_READY",
            Self::Bounds(_) => "BOUNDS_EXCEEDED",
            Self::ResponseLost => "UNKNOWN",
            Self::Io(_) | Self::Sql(_) => "PERSISTENCE_UNAVAILABLE",
            Self::Json(_) | Self::Invalid(_) => "INVALID",
        }
    }
}

impl Display for FixtureError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O: {error}"),
            Self::Sql(error) => write!(formatter, "SQLite: {error}"),
            Self::Json(error) => write!(formatter, "JSON: {error}"),
            Self::Invalid(error) => write!(formatter, "invalid: {error}"),
            Self::Bounds(value) => write!(formatter, "bounds: {value}"),
            Self::ContractMismatch => formatter.write_str("contract mismatch"),
            Self::Forbidden => formatter.write_str("forbidden"),
            Self::Conflict => formatter.write_str("conflict"),
            Self::Stale(value) => write!(formatter, "stale {value}"),
            Self::HostNotReady => formatter.write_str("host not ready"),
            Self::ResponseLost => formatter.write_str("response lost"),
        }
    }
}

impl std::error::Error for FixtureError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_names_are_closed_and_bounded() {
        assert_eq!(
            FaultPoint::parse("after-mutation"),
            Some(FaultPoint::AfterMutation)
        );
        assert_eq!(FaultPoint::parse("delete-production"), None);
        assert_eq!(FaultPoint::AfterReceipt.as_str(), "after-receipt");
    }

    #[test]
    fn request_has_contract_digest_and_distinct_identities() {
        let first = Frame::request("stats", "recovery_read", json!({"ok":true}));
        let second = Frame::request("stats", "recovery_read", json!({"ok":true}));
        assert_eq!(first.schema_digest, RECOVERY_SCHEMA_DIGEST);
        assert_ne!(first.message_id, second.message_id);
        assert!(first.validate().is_ok());
    }

    #[test]
    fn digest_is_lower_hex_and_stable() {
        let value = digest("fixture");
        assert_eq!(value.len(), 64);
        assert!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert_eq!(value, digest("fixture"));
    }
}
