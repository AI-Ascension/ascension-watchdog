//! Test-only synthetic host for watchdog recovery fault injection.
//!
//! This package is deliberately independent of the production watchdog and of
//! the gateway, harness, MCP, and game-mod implementation crates.  It exposes
//! the closed recovery sideband envelope, accepts the same operation identity
//! and fence fields, and also understands the frozen runtime-v3 route kinds.
//! Its `SQLite` state models the important crash window where a host effect is
//! durable before the receipt is durable.  An absent witness remains unknown.

use std::fmt::{Display, Formatter, Write as FmtWrite};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension, params};
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
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
/// Exact bytes of the approved sideband schema consumed by this fixture.
pub const RECOVERY_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/artifacts/watchdog-recovery-v1/schema.json"
));
/// Exact bytes of the approved RCJ vector set consumed by this fixture.
pub const RCJ_VECTORS_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/artifacts/watchdog-recovery-v1/rcj-vectors.json"
));
/// Exact bytes of the frozen runtime-v3 schema used by the synthetic adapter.
pub const RUNTIME_V3_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/artifacts/runtime-v3-gameplay/schema.json"
));

const MAX_LINE_BYTES: usize = MAX_FRAME_BYTES + 1;
const FIXTURE_TIMESTAMP: &str = "2026-09-06T00:00:00Z";
const FIXTURE_TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const MAX_RUNTIME_INTEGER: i64 = 9_007_199_254_740_991;

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

#[derive(Clone, Debug)]
struct RuntimeSession {
    instance_id: String,
    session_id: String,
    lease_id: String,
    lease_epoch: i64,
    state_id: String,
    generation: i64,
    observation_json: String,
    legal_actions_json: String,
    last_operation_id: Option<String>,
    last_action_id: Option<String>,
    stopped: bool,
    updated_at: String,
}

/// Durable runtime-v3 admission state.  The runtime adapter deliberately uses
/// a separate journal from the recovery sideband operation table: a gameplay
/// request does not carry the sideband's boot/original-context envelope, but it
/// still needs an operation identity, immutable pre-state, and an at-most-once
/// drain boundary.
#[derive(Clone, Debug)]
struct RuntimeOperation {
    operation_id: String,
    instance_id: String,
    session_id: String,
    lease_id: String,
    lease_epoch: i64,
    action_json: String,
    action_digest: String,
    pre_state_id: String,
    pre_generation: i64,
    status: String,
    witness_json: Option<String>,
    result_json: Option<String>,
}

fn runtime_provenance() -> Value {
    json!({
        "artifact":"sts2-protocol/runtime-v3-gameplay",
        "source":"schemas/runtime-v3-gameplay.schema.json",
        "generator":"hand-authored"
    })
}

fn synthetic_observation(state_id: &str, generation: i64) -> Result<Value, FixtureError> {
    if !valid_identity(state_id) {
        return Err(FixtureError::Invalid("runtime state identity".to_owned()));
    }
    Ok(json!({
        "state_id":state_id, "generation":generation, "visible_seed":"fixture-seed-1",
        "player":{"hp":50,"max_hp":50,"energy":3,"gold":99,"hand":[],"deck":[],"discard":[],"exhaust":[]},
        "state":{"state":"combat","turn_index":1,"enemies":[]}
    }))
}

fn synthetic_legal_actions() -> Value {
    json!([
        {"action_id":"action-end-turn","action":{"kind":"end_turn"}},
        {"action_id":"action-start-run","action":{"kind":"start_run","character_id":"ironclad"}},
        {"action_id":"action-select-map-node","action":{"kind":"select_map_node","node_id":"node-1"}},
        {"action_id":"action-play-card","action":{"kind":"play_card","card_id":"strike","target_id":null}},
        {"action_id":"action-choose-reward","action":{"kind":"choose_reward","reward_id":"reward-1"}},
        {"action_id":"action-shop-purchase","action":{"kind":"shop_purchase","item_id":"item-1"}},
        {"action_id":"action-shop-remove","action":{"kind":"shop_remove","card_id":"card-1"}},
        {"action_id":"action-event-choice","action":{"kind":"event_choice","choice_id":"choice-1"}}
    ])
}

fn runtime_base(request: &Value, kind: &str, state: &RuntimeSession) -> Value {
    json!({
        "protocol_version":"runtime-v3-gameplay", "schema_digest":RUNTIME_V3_SCHEMA_DIGEST,
        "provenance":runtime_provenance(), "correlation_id":request["correlation_id"],
        "instance_id":request["instance_id"], "session_id":request["session_id"],
        "lease_id":request["lease_id"], "lease_epoch":request["lease_epoch"],
        "generation":state.generation, "kind":kind, "state_id":Value::Null,
        "operation_id":Value::Null, "observation":Value::Null, "legal_actions":Value::Null,
        "action":Value::Null, "status":Value::Null, "transition":Value::Null,
        "error_code":Value::Null, "wait_for_millis":Value::Null,
        "wait_outcome":Value::Null, "recovery":Value::Null
    })
}

fn stored_runtime_value(text: &str) -> Result<Value, FixtureError> {
    parse_value_no_duplicates(text.as_bytes())
}

fn runtime_observation_response(
    request: &Value,
    state: &RuntimeSession,
) -> Result<Value, FixtureError> {
    let mut response = runtime_base(request, "state_response", state);
    response["state_id"] = json!(state.state_id);
    response["observation"] = stored_runtime_value(&state.observation_json)?;
    response["legal_actions"] = stored_runtime_value(&state.legal_actions_json)?;
    Ok(response)
}

fn runtime_legal_actions_response(
    request: &Value,
    state: &RuntimeSession,
) -> Result<Value, FixtureError> {
    let mut response = runtime_base(request, "legal_actions_response", state);
    response["state_id"] = json!(state.state_id);
    response["legal_actions"] = stored_runtime_value(&state.legal_actions_json)?;
    Ok(response)
}

fn runtime_reobserve_response(
    request: &Value,
    state: &RuntimeSession,
) -> Result<Value, FixtureError> {
    let mut response = runtime_base(request, "reobserve_response", state);
    response["state_id"] = json!(state.state_id);
    response["observation"] = stored_runtime_value(&state.observation_json)?;
    response["legal_actions"] = stored_runtime_value(&state.legal_actions_json)?;
    Ok(response)
}

fn runtime_rejected_response(
    request: &Value,
    state: &RuntimeSession,
    operation_id: &str,
    error_code: &str,
) -> Result<Value, FixtureError> {
    let mut response = runtime_base(request, "dispatch_action_response", state);
    response["state_id"] = json!(state.state_id);
    response["operation_id"] = json!(operation_id);
    response["observation"] = stored_runtime_value(&state.observation_json)?;
    response["legal_actions"] = stored_runtime_value(&state.legal_actions_json)?;
    response["status"] = json!("rejected");
    response["error_code"] = json!(error_code);
    Ok(response)
}

fn runtime_error_response(
    request: &Value,
    request_kind: &str,
    error_code: &str,
    generation: i64,
    state: &RuntimeSession,
) -> Value {
    let response_kind = response_kind(request_kind);
    let mut response = runtime_base(request, &response_kind, state);
    response["generation"] = json!(generation);
    if matches!(
        request_kind,
        "dispatch_action_request" | "wait_request" | "recover_request"
    ) {
        let recovery_operation = request
            .get("recovery")
            .and_then(|recovery| recovery.get("operation_id"))
            .filter(|operation_id| !operation_id.is_null())
            .cloned();
        response["operation_id"] = request
            .get("operation_id")
            .filter(|operation_id| !operation_id.is_null())
            .cloned()
            .or(recovery_operation)
            .unwrap_or_else(|| json!(format!("recovery-{}", state.session_id)));
    }
    response["status"] = json!("unknown");
    response["error_code"] = json!(error_code);
    if request_kind == "wait_request" {
        response["wait_outcome"] = json!("recovery_required");
    }
    response
}

fn runtime_recovery_response(
    request: &Value,
    state: &RuntimeSession,
    status_value: &str,
    observation: Value,
    legal_actions: Value,
    transition: Value,
    error_code: Value,
) -> Value {
    let mut response = runtime_base(request, "recover_response", state);
    response["operation_id"] = request["recovery"]["operation_id"].clone();
    if response["operation_id"].is_null() {
        response["operation_id"] = json!(format!("recovery-{}", state.session_id));
    }
    response["state_id"] = json!(state.state_id);
    response["observation"] = observation;
    response["legal_actions"] = legal_actions;
    response["status"] = json!(status_value);
    response["transition"] = transition;
    response["error_code"] = error_code;
    response
}

fn runtime_accepted_response(
    request: &Value,
    state: &RuntimeSession,
    operation_id: &str,
) -> Result<Value, FixtureError> {
    let mut response = runtime_base(request, "dispatch_action_response", state);
    response["state_id"] = json!(state.state_id);
    response["operation_id"] = json!(operation_id);
    response["observation"] = stored_runtime_value(&state.observation_json)?;
    response["legal_actions"] = stored_runtime_value(&state.legal_actions_json)?;
    response["status"] = json!("accepted");
    Ok(response)
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
        let kind = kind.into();
        let principal = Uuid::new_v4().to_string();
        Self {
            contract: "watchdog-recovery-v1".to_owned(),
            schema_digest: RECOVERY_SCHEMA_DIGEST.to_owned(),
            message_id: Uuid::new_v4().to_string(),
            correlation_id: Uuid::new_v4().to_string(),
            sent_at: FIXTURE_TIMESTAMP.to_owned(),
            actor: Actor {
                principal_id: principal.clone(),
                role: request_role(&kind).to_owned(),
            },
            auth: Auth {
                principal_id: principal,
                capability: capability.into(),
                proof: Some("fixture-proof".to_owned()),
            },
            kind,
            payload,
        }
    }

    fn response(&self, kind: &str, payload: Value) -> Self {
        let principal = Uuid::new_v4().to_string();
        let (role, capability) = response_auth(kind);
        Self {
            contract: "watchdog-recovery-v1".to_owned(),
            schema_digest: RECOVERY_SCHEMA_DIGEST.to_owned(),
            message_id: Uuid::new_v4().to_string(),
            correlation_id: self.correlation_id.clone(),
            sent_at: FIXTURE_TIMESTAMP.to_owned(),
            actor: Actor {
                principal_id: principal.clone(),
                role: role.to_owned(),
            },
            auth: Auth {
                principal_id: principal,
                capability: capability.to_owned(),
                proof: Some("fixture-proof".to_owned()),
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
        valid_role(&self.actor.role)?;
        if self.actor.principal_id != self.auth.principal_id {
            return Err(FixtureError::Invalid(
                "actor/auth principal mismatch".to_owned(),
            ));
        }
        valid_capability(&self.auth.capability)?;
        if self
            .auth
            .proof
            .as_ref()
            .is_none_or(|proof| proof.is_empty() || proof.len() > 512)
        {
            return Err(FixtureError::Bounds("auth proof"));
        }
        if !valid_timestamp(&self.sent_at) {
            return Err(FixtureError::Invalid("timestamp".to_owned()));
        }
        if self.kind.is_empty() || self.payload.is_null() {
            return Err(FixtureError::Invalid("missing kind or payload".to_owned()));
        }
        if let Some(expected) = request_capability(&self.kind) {
            if self.auth.capability != expected {
                return Err(FixtureError::Forbidden);
            }
            if self.actor.role != request_role(&self.kind) {
                return Err(FixtureError::Forbidden);
            }
            validate_recovery_payload(&self.kind, &self.payload)?;
        } else if let Some((expected_role, expected_capability)) = response_auth_checked(&self.kind)
        {
            if self.actor.role != expected_role || self.auth.capability != expected_capability {
                return Err(FixtureError::Forbidden);
            }
            validate_recovery_payload(&self.kind, &self.payload)?;
        } else if is_runtime_v3_kind(&self.kind) {
            validate_runtime_v3_envelope(&self.kind, &self.payload)?;
        } else if matches!(
            self.kind.as_str(),
            "stats"
                | "shutdown"
                | "host_tick"
                | "stats_response"
                | "shutdown_response"
                | "host_tick_response"
        ) {
            // These are test-local control frames, outside the published
            // recovery-v1 18-frame schema. Their payload is validated by the
            // operation handler that owns the control point.
        } else {
            return Err(FixtureError::Invalid("unsupported frame kind".to_owned()));
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
        parse_json_no_duplicates::<Frame>(&line)
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
        let action = match serve_connection(stream, &store, &mut faults) {
            Ok(action) => action,
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
    let mut first = [0_u8; 1];
    let count = stream.peek(&mut first).map_err(FixtureError::Io)?;
    if count > 0 && matches!(first[0], b'G' | b'P' | b'H') {
        return serve_http_connection(stream, store, faults);
    }
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
) -> Result<ConnectionAction, FixtureError> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(FixtureError::Io)?;
    let mut reader = BufReader::new(stream.try_clone().map_err(FixtureError::Io)?);
    let request_line = read_bounded_line(&mut reader)?
        .ok_or_else(|| FixtureError::Invalid("HTTP request line missing".to_owned()))?;
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
    let mut headers = std::collections::BTreeMap::new();
    loop {
        let line = read_bounded_line(&mut reader)?
            .ok_or_else(|| FixtureError::Invalid("HTTP headers truncated".to_owned()))?;
        let line = String::from_utf8(line)
            .map_err(|_| FixtureError::Invalid("HTTP header encoding".to_owned()))?;
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| FixtureError::Invalid("HTTP header malformed".to_owned()))?;
        let name = name.trim().to_ascii_lowercase();
        if headers.contains_key(&name) {
            write_http_error(&mut stream, 400, "runtime_v3_duplicate_header")?;
            return Ok(ConnectionAction::Continue);
        }
        headers.insert(name, value.trim().to_owned());
    }
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
    write!(stream, "HTTP/1.1 {status_code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).map_err(FixtureError::Io)?;
    stream.write_all(&body).map_err(FixtureError::Io)?;
    stream.flush().map_err(FixtureError::Io)
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

/// `serde_json::Value` accepts duplicate object members with last-value-wins
/// semantics.  That is unsafe for an authenticated closed envelope: a
/// verifier and a consumer could observe different values.  Build values with
/// a recursive visitor so duplicate keys are rejected at every nesting level.
struct NoDuplicateValue(Value);

impl<'de> Deserialize<'de> for NoDuplicateValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ValueVisitor;

        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = NoDuplicateValue;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON value without duplicate object keys")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NoDuplicateValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NoDuplicateValue(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NoDuplicateValue(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let number = serde_json::Number::from_f64(value)
                    .ok_or_else(|| E::custom("non-finite JSON number"))?;
                Ok(NoDuplicateValue(Value::Number(number)))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NoDuplicateValue(Value::Null))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NoDuplicateValue(Value::String(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NoDuplicateValue(Value::String(value)))
            }

            fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = access.next_element::<NoDuplicateValue>()? {
                    values.push(value.0);
                }
                Ok(NoDuplicateValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = serde_json::Map::new();
                while let Some(key) = access.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom(format!(
                            "duplicate JSON object key: {key}"
                        )));
                    }
                    let value = access.next_value::<NoDuplicateValue>()?;
                    values.insert(key, value.0);
                }
                Ok(NoDuplicateValue(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(ValueVisitor)
    }
}

fn parse_value_no_duplicates(bytes: &[u8]) -> Result<Value, FixtureError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = NoDuplicateValue::deserialize(&mut deserializer)
        .map_err(|error| FixtureError::Json(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| FixtureError::Json(error.to_string()))?;
    Ok(value.0)
}

fn parse_json_no_duplicates<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, FixtureError> {
    let value = parse_value_no_duplicates(bytes)?;
    serde_json::from_value(value).map_err(|error| FixtureError::Json(error.to_string()))
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
    // The sidecar lock is held for the lifetime of the store.  SQLite's own
    // page locks serialize writes, but do not establish which fixture process
    // owns mutation authority.  A separate file avoids interfering with
    // SQLite's WAL file locks and is released by the OS after a crash.
    _lock: File,
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

fn migrate_columns(connection: &Connection) -> Result<(), FixtureError> {
    // The fixture is deliberately disposable, but retaining these additive
    // migrations makes a crash/restart against a database created by the
    // earlier fixture fail closed instead of silently dropping authority.
    let migrations = [
        (
            "fence",
            "deployment_id",
            "TEXT NOT NULL DEFAULT '00000000-0000-4000-8000-000000000000'",
        ),
        (
            "fence",
            "instance_id",
            "TEXT NOT NULL DEFAULT '00000000-0000-4000-8000-000000000000'",
        ),
        ("fence", "authority_state", "TEXT NOT NULL DEFAULT 'READY'"),
        ("fence", "lease_epoch_counter", "INTEGER NOT NULL DEFAULT 0"),
        ("fence", "lease_ttl_seconds", "INTEGER NOT NULL DEFAULT 30"),
        (
            "fence",
            "lease_renewal_interval_seconds",
            "INTEGER NOT NULL DEFAULT 10",
        ),
        (
            "lease",
            "deployment_id",
            "TEXT NOT NULL DEFAULT '00000000-0000-4000-8000-000000000000'",
        ),
        (
            "lease",
            "instance_id",
            "TEXT NOT NULL DEFAULT '00000000-0000-4000-8000-000000000000'",
        ),
        (
            "lease",
            "fence_token",
            "TEXT NOT NULL DEFAULT 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'",
        ),
        (
            "lease",
            "issued_at",
            "TEXT NOT NULL DEFAULT '2026-09-06T00:00:00Z'",
        ),
        (
            "lease",
            "expires_at",
            "TEXT NOT NULL DEFAULT '2026-09-06T00:00:30Z'",
        ),
        ("lease", "issued_tick", "INTEGER NOT NULL DEFAULT 0"),
        ("lease", "expires_tick", "INTEGER NOT NULL DEFAULT 30"),
        ("lease", "ttl_seconds", "INTEGER NOT NULL DEFAULT 30"),
        (
            "lease",
            "renewal_interval_seconds",
            "INTEGER NOT NULL DEFAULT 10",
        ),
        ("lease", "renew_sequence", "INTEGER NOT NULL DEFAULT 0"),
        (
            "operations",
            "deployment_id",
            "TEXT NOT NULL DEFAULT '00000000-0000-4000-8000-000000000000'",
        ),
        (
            "operations",
            "instance_id",
            "TEXT NOT NULL DEFAULT '00000000-0000-4000-8000-000000000000'",
        ),
        ("operations", "reconcile_strategy", "TEXT"),
        ("runtime_sessions", "last_operation_id", "TEXT"),
        ("runtime_sessions", "last_action_id", "TEXT"),
    ];
    for (table, column, declaration) in migrations {
        if !table_has_column(connection, table, column)? {
            connection
                .execute(
                    &format!("ALTER TABLE {table} ADD COLUMN {column} {declaration}"),
                    [],
                )
                .map_err(FixtureError::Sql)?;
        }
    }
    Ok(())
}

fn table_has_column(
    connection: &Connection,
    table: &str,
    column: &str,
) -> Result<bool, FixtureError> {
    let mut statement = connection
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(FixtureError::Sql)?;
    let mut rows = statement.query([]).map_err(FixtureError::Sql)?;
    while let Some(row) = rows.next().map_err(FixtureError::Sql)? {
        let name: String = row.get(1).map_err(FixtureError::Sql)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_database_path(path: &Path) -> Result<PathBuf, FixtureError> {
    if path.as_os_str().is_empty() || path.to_string_lossy().contains('\0') {
        return Err(FixtureError::Invalid(
            "database path is empty or contains NUL".to_owned(),
        ));
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| FixtureError::Invalid("database filename missing".to_owned()))?;
    if file_name == "." || file_name == ".." {
        return Err(FixtureError::Invalid("database filename unsafe".to_owned()));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent_metadata = fs::symlink_metadata(parent).map_err(FixtureError::Io)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(FixtureError::Invalid(
            "database parent must be a real directory".to_owned(),
        ));
    }
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(FixtureError::Invalid(
            "database must be a regular file".to_owned(),
        ));
    }
    let canonical_parent = fs::canonicalize(parent).map_err(FixtureError::Io)?;
    Ok(canonical_parent.join(file_name))
}

fn validate_lock_path(path: &Path) -> Result<(), FixtureError> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(FixtureError::Invalid(
            "database lock must be a regular file".to_owned(),
        ));
    }
    Ok(())
}

fn validate_database_integrity(connection: &Connection) -> Result<(), FixtureError> {
    let result: String = connection
        .pragma_query_value(None, "integrity_check", |row| row.get(0))
        .map_err(FixtureError::Sql)?;
    if result != "ok" {
        return Err(FixtureError::Invalid(format!(
            "SQLite integrity check failed: {result}"
        )));
    }
    Ok(())
}

impl DurableHost {
    /// Open or initialize the fixture database with full synchronous writes.
    ///
    /// # Errors
    ///
    /// Returns a persistence error when `SQLite` cannot open, configure, or
    /// initialize the database.
    #[allow(clippy::too_many_lines, clippy::suspicious_open_options)]
    pub fn open(path: &Path) -> Result<Self, FixtureError> {
        let database_path = validate_database_path(path)?;
        let lock_path = database_path.with_extension("sqlite.lock");
        validate_lock_path(&lock_path)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(FixtureError::Io)?;
        lock.try_lock_exclusive().map_err(|error| {
            if error.kind() == ErrorKind::WouldBlock {
                FixtureError::Busy
            } else {
                FixtureError::Io(error)
            }
        })?;
        let connection = Connection::open(&database_path).map_err(FixtureError::Sql)?;
        connection
            .busy_timeout(Duration::from_secs(2))
            .map_err(FixtureError::Sql)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(FixtureError::Sql)?;
        let journal_mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(FixtureError::Sql)?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(FixtureError::Invalid(
                "SQLite WAL journal required".to_owned(),
            ));
        }
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(FixtureError::Sql)?;
        let synchronous: i64 = connection
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .map_err(FixtureError::Sql)?;
        if synchronous != 2 {
            return Err(FixtureError::Invalid(
                "SQLite synchronous FULL required".to_owned(),
            ));
        }
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(FixtureError::Sql)?;
        let foreign_keys: i64 = connection
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .map_err(FixtureError::Sql)?;
        if foreign_keys != 1 {
            return Err(FixtureError::Invalid(
                "SQLite foreign keys required".to_owned(),
            ));
        }
        validate_database_integrity(&connection)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS fence (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    deployment_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    boot_id TEXT NOT NULL,
                    instance_incarnation TEXT NOT NULL,
                    authority_generation INTEGER NOT NULL,
                    host_fence_id TEXT NOT NULL,
                    fence_generation INTEGER NOT NULL,
                    authority_state TEXT NOT NULL DEFAULT 'READY',
                    lease_epoch_counter INTEGER NOT NULL DEFAULT 0,
                    lease_ttl_seconds INTEGER NOT NULL DEFAULT 30,
                    lease_renewal_interval_seconds INTEGER NOT NULL DEFAULT 10
                );
                CREATE TABLE IF NOT EXISTS lease (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    deployment_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    lease_id TEXT NOT NULL,
                    lease_epoch INTEGER NOT NULL,
                    boot_id TEXT NOT NULL,
                    instance_incarnation TEXT NOT NULL,
                    host_fence_id TEXT NOT NULL,
                    fence_token TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    issued_tick INTEGER NOT NULL,
                    expires_tick INTEGER NOT NULL,
                    ttl_seconds INTEGER NOT NULL,
                    renewal_interval_seconds INTEGER NOT NULL,
                    renew_sequence INTEGER NOT NULL DEFAULT 0,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS operations (
                    operation_id TEXT PRIMARY KEY,
                    payload_digest TEXT NOT NULL,
                    deployment_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
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
                    reconcile_strategy TEXT,
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
                );
                CREATE TABLE IF NOT EXISTS lease_history (
                    lease_id TEXT PRIMARY KEY,
                    lease_epoch INTEGER NOT NULL UNIQUE,
                    deployment_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    boot_id TEXT NOT NULL,
                    instance_incarnation TEXT NOT NULL,
                    host_fence_id TEXT NOT NULL,
                    fence_token_digest TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    issued_tick INTEGER NOT NULL,
                    expires_tick INTEGER NOT NULL,
                    ttl_seconds INTEGER NOT NULL,
                    renewal_interval_seconds INTEGER NOT NULL,
                    renew_sequence INTEGER NOT NULL DEFAULT 0,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS fixture_clock (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    tick INTEGER NOT NULL
                );
                INSERT OR IGNORE INTO fixture_clock(singleton, tick) VALUES(1, 0);
                CREATE TABLE IF NOT EXISTS runtime_sessions (
                    instance_id TEXT NOT NULL,
                    session_id TEXT PRIMARY KEY,
                    lease_id TEXT NOT NULL,
                    lease_epoch INTEGER NOT NULL,
                    state_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    observation_json TEXT NOT NULL,
                    legal_actions_json TEXT NOT NULL,
                    last_operation_id TEXT,
                    last_action_id TEXT,
                    stopped INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runtime_operations (
                    operation_id TEXT PRIMARY KEY,
                    instance_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    lease_id TEXT NOT NULL,
                    lease_epoch INTEGER NOT NULL,
                    action_json TEXT NOT NULL,
                    action_digest TEXT NOT NULL,
                    pre_state_id TEXT NOT NULL,
                    pre_generation INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    witness_json TEXT,
                    result_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runtime_queue (
                    operation_id TEXT PRIMARY KEY REFERENCES runtime_operations(operation_id),
                    enqueued_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS runtime_operations_active_session
                    ON runtime_operations(session_id)
                    WHERE status IN ('ADMITTED', 'EXECUTING', 'UNKNOWN');",
            )
            .map_err(FixtureError::Sql)?;
        migrate_columns(&connection)?;
        // Preserve the current singleton lease as historical evidence before
        // invalidating it. The history table is append-only; `lease` is only
        // the active projection.
        let transaction = connection
            .unchecked_transaction()
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO lease_history(lease_id,lease_epoch,deployment_id,instance_id,boot_id,instance_incarnation,host_fence_id,fence_token_digest,issued_at,expires_at,issued_tick,expires_tick,ttl_seconds,renewal_interval_seconds,renew_sequence,revoked)
                 SELECT lease_id,lease_epoch,deployment_id,instance_id,boot_id,instance_incarnation,host_fence_id,?1,issued_at,expires_at,issued_tick,expires_tick,ttl_seconds,renewal_interval_seconds,renew_sequence,revoked FROM lease WHERE singleton=1",
                params![digest(FIXTURE_TOKEN)],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE fence SET lease_epoch_counter=MAX(lease_epoch_counter,COALESCE((SELECT MAX(lease_epoch) FROM lease_history),0)) WHERE singleton=1",
                [],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE lease_history SET revoked=1 WHERE lease_id IN (SELECT lease_id FROM lease WHERE singleton=1)",
                [],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute("UPDATE lease SET revoked=1 WHERE singleton=1", [])
            .map_err(FixtureError::Sql)?;
        // An admitted or executing runtime operation crossed the prior host
        // boundary. The replacement cannot prove whether its effect happened,
        // so retain UNKNOWN and remove only the executable queue entry.
        transaction
            .execute(
                "UPDATE runtime_operations SET status='UNKNOWN',updated_at=?1 WHERE status IN ('ADMITTED','EXECUTING')",
                params![FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "DELETE FROM runtime_queue WHERE operation_id IN (SELECT operation_id FROM runtime_operations WHERE status='UNKNOWN')",
                [],
            )
            .map_err(FixtureError::Sql)?;
        // Legacy queue entries crossed the same process boundary. Preserve
        // their attempt identity as uncertainty; never leave them executable
        // for a replacement process with a different lease.
        transaction
            .execute(
                "UPDATE operations SET state='UNKNOWN',uncertainty_reason='authority_rotated',ticket_json=json_set(ticket_json,'$.state','UNKNOWN'),updated_at=?1 WHERE state='MAY_HAVE_BEEN_DISPATCHED'",
                params![FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "DELETE FROM queue WHERE operation_id IN (SELECT operation_id FROM operations WHERE state='UNKNOWN')",
                [],
            )
            .map_err(FixtureError::Sql)?;
        // Every process restart requires a fresh bootstrap/fence handshake;
        // retain the old fields for diagnostics but make them unusable as
        // current mutation authority.
        transaction
            .execute(
                "UPDATE fence SET authority_state='RESTART_REQUIRED' WHERE singleton=1",
                [],
            )
            .map_err(FixtureError::Sql)?;
        transaction.commit().map_err(FixtureError::Sql)?;
        validate_database_integrity(&connection)?;
        Ok(Self {
            connection,
            _lock: lock,
        })
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
            "state_request" | "legal_actions_request" | "dispatch_action_request"
            | "wait_request" | "reobserve_request" | "recover_request" => {
                self.v3_handle_frame(frame, faults)
            }
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

    #[allow(clippy::too_many_lines)]
    fn bootstrap(&mut self, frame: &Frame) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "bootstrap")?;
        let deployment_id = field_string(&frame.payload, "deployment_id")?;
        let instance_id = field_string(&frame.payload, "instance_id")?;
        let incarnation = field_string(&frame.payload, "instance_incarnation")?;
        let policy = frame
            .payload
            .get("lease_policy")
            .ok_or_else(|| FixtureError::Invalid("lease policy missing".to_owned()))?;
        validate_policy(policy)?;
        let ttl_seconds = field_i64(policy, "ttl_seconds")?;
        let renewal_interval_seconds = field_i64(policy, "renewal_interval_seconds")?;
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
        let generation = match current {
            None => 1,
            Some(value) if (1..MAX_RUNTIME_INTEGER).contains(&value) => value + 1,
            Some(_) => {
                return Err(FixtureError::Invalid(
                    "authority generation exhausted".to_owned(),
                ));
            }
        };
        let boot_id = Uuid::new_v4().to_string();
        let fence_id = Uuid::new_v4().to_string();
        let tx = self.connection.transaction().map_err(FixtureError::Sql)?;
        let fence_counter: Option<i64> = tx
            .query_row(
                "SELECT lease_epoch_counter FROM fence WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let history_counter: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(lease_epoch),0) FROM lease_history",
                [],
                |row| row.get(0),
            )
            .map_err(FixtureError::Sql)?;
        let lease_epoch_counter = fence_counter.unwrap_or(0).max(history_counter);
        if !(0..=MAX_RUNTIME_INTEGER).contains(&lease_epoch_counter) {
            return Err(FixtureError::Invalid(
                "lease epoch history exhausted".to_owned(),
            ));
        }
        tx.execute(
            "UPDATE lease_history SET revoked=1 WHERE lease_id IN (SELECT lease_id FROM lease WHERE singleton=1)",
            [],
        )
        .map_err(FixtureError::Sql)?;
        tx.execute("UPDATE lease SET revoked=1 WHERE singleton=1", [])
            .map_err(FixtureError::Sql)?;
        // Authority replacement makes every previously admitted runtime item
        // uncertain. Keep its journal row but remove the executable queue.
        tx.execute(
            "UPDATE runtime_operations SET status='UNKNOWN',updated_at=?1 WHERE status IN ('ADMITTED','EXECUTING')",
            params![FIXTURE_TIMESTAMP],
        )
        .map_err(FixtureError::Sql)?;
        tx.execute(
            "DELETE FROM runtime_queue WHERE operation_id IN (SELECT operation_id FROM runtime_operations WHERE status='UNKNOWN')",
            [],
        )
        .map_err(FixtureError::Sql)?;
        tx.execute(
            "UPDATE operations SET state='UNKNOWN',uncertainty_reason='authority_rotated',ticket_json=json_set(ticket_json,'$.state','UNKNOWN'),updated_at=?1 WHERE state='MAY_HAVE_BEEN_DISPATCHED'",
            params![FIXTURE_TIMESTAMP],
        )
        .map_err(FixtureError::Sql)?;
        tx.execute(
            "DELETE FROM queue WHERE operation_id IN (SELECT operation_id FROM operations WHERE state='UNKNOWN')",
            [],
        )
        .map_err(FixtureError::Sql)?;
        let updated = tx
            .execute(
                "UPDATE fence SET deployment_id=?1,instance_id=?2,boot_id=?3,instance_incarnation=?4,authority_generation=?5,host_fence_id=?6,fence_generation=?5,authority_state='FENCE_REQUIRED',lease_epoch_counter=?7,lease_ttl_seconds=?8,lease_renewal_interval_seconds=?9 WHERE singleton=1",
                params![
                    deployment_id,
                    instance_id,
                    boot_id,
                    incarnation,
                    generation,
                    fence_id,
                    lease_epoch_counter,
                    ttl_seconds,
                    renewal_interval_seconds,
                ],
            )
            .map_err(FixtureError::Sql)?;
        if updated == 0 {
            tx.execute(
                "INSERT INTO fence(singleton,deployment_id,instance_id,boot_id,instance_incarnation,authority_generation,host_fence_id,fence_generation,authority_state,lease_epoch_counter,lease_ttl_seconds,lease_renewal_interval_seconds)
                 VALUES(1,?1,?2,?3,?4,?5,?6,?5,'FENCE_REQUIRED',?7,?8,?9)",
                params![
                    deployment_id,
                    instance_id,
                    boot_id,
                    incarnation,
                    generation,
                    fence_id,
                    lease_epoch_counter,
                    ttl_seconds,
                    renewal_interval_seconds,
                ],
            )
            .map_err(FixtureError::Sql)?;
        }
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
        validate_boot_context(boot)?;
        let deployment_id = field_string(boot, "deployment_id")?;
        let instance_id = field_string(boot, "instance_id")?;
        let boot_id = field_string(boot, "boot_id")?;
        let incarnation = field_string(boot, "instance_incarnation")?;
        let generation = field_i64(boot, "authority_generation")?;
        let current: Option<(String, String, String, String, i64, String)> = self
            .connection
            .query_row(
                "SELECT deployment_id, instance_id, boot_id, instance_incarnation, authority_generation, authority_state FROM fence WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((
            current_deployment,
            current_instance,
            current_boot,
            current_incarnation,
            current_generation,
            authority_state,
        )) = current
        else {
            return Err(FixtureError::HostNotReady);
        };
        if deployment_id != current_deployment
            || instance_id != current_instance
            || boot_id != current_boot
            || incarnation != current_incarnation
            || generation != current_generation
        {
            return Err(FixtureError::Stale("boot"));
        }
        if !matches!(authority_state.as_str(), "FENCE_REQUIRED" | "READY") {
            return Err(FixtureError::HostNotReady);
        }
        // Fencing is the explicit transition that makes the freshly
        // bootstrapped authority usable. A restarted host remains blocked
        // until bootstrap replaces the old boot/fence fields.
        let changed = self
            .connection
            .execute(
                "UPDATE fence SET authority_state='READY' WHERE singleton=1 AND deployment_id=?1 AND instance_id=?2 AND boot_id=?3 AND instance_incarnation=?4 AND authority_generation=?5 AND authority_state IN ('FENCE_REQUIRED','READY')",
                params![deployment_id, instance_id, boot_id, incarnation, generation],
            )
            .map_err(FixtureError::Sql)?;
        if changed != 1 {
            return Err(FixtureError::HostNotReady);
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

    #[allow(clippy::too_many_lines)]
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
        validate_boot_context(boot)?;
        validate_host_fence(fence)?;
        let lease_id = Uuid::new_v4().to_string();
        let token = FIXTURE_TOKEN;
        let deployment_id = field_string(boot, "deployment_id")?;
        let instance_id = field_string(boot, "instance_id")?;
        let boot_id = field_string(boot, "boot_id")?;
        let incarnation = field_string(boot, "instance_incarnation")?;
        let host_fence_id = field_string(fence, "host_fence_id")?;
        let transaction = self.connection.transaction().map_err(FixtureError::Sql)?;
        let (counter, ttl_seconds, renewal_interval_seconds, authority_state): (i64, i64, i64, String) =
            transaction
                .query_row(
                    "SELECT lease_epoch_counter,lease_ttl_seconds,lease_renewal_interval_seconds,authority_state FROM fence WHERE singleton=1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(FixtureError::Sql)?
                .ok_or(FixtureError::HostNotReady)?;
        if authority_state != "READY" {
            return Err(FixtureError::HostNotReady);
        }
        validate_lease_policy_values(ttl_seconds, renewal_interval_seconds)?;
        let history_counter: i64 = transaction
            .query_row(
                "SELECT COALESCE(MAX(lease_epoch),0) FROM lease_history",
                [],
                |row| row.get(0),
            )
            .map_err(FixtureError::Sql)?;
        let counter = counter.max(history_counter);
        if !(0..MAX_RUNTIME_INTEGER).contains(&counter) {
            return Err(FixtureError::Invalid("lease epoch exhausted".to_owned()));
        }
        let epoch = counter + 1;
        let issued_tick: i64 = transaction
            .query_row(
                "SELECT tick FROM fixture_clock WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(FixtureError::Sql)?;
        let expires_tick = issued_tick.saturating_add(ttl_seconds);
        let issued_at = timestamp_for_tick(issued_tick);
        let expires_at = timestamp_for_tick(expires_tick);

        // Reacquiring in one fenced boot revokes the prior projection while
        // retaining its immutable history row. Any queued work under that
        // lease is now uncertain and must not remain executable.
        transaction
            .execute(
                "INSERT OR IGNORE INTO lease_history(lease_id,lease_epoch,deployment_id,instance_id,boot_id,instance_incarnation,host_fence_id,fence_token_digest,issued_at,expires_at,issued_tick,expires_tick,ttl_seconds,renewal_interval_seconds,renew_sequence,revoked)
                 SELECT lease_id,lease_epoch,deployment_id,instance_id,boot_id,instance_incarnation,host_fence_id,?1,issued_at,expires_at,issued_tick,expires_tick,ttl_seconds,renewal_interval_seconds,renew_sequence,revoked FROM lease WHERE singleton=1",
                params![digest(token)],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE lease_history SET revoked=1 WHERE lease_id IN (SELECT lease_id FROM lease WHERE singleton=1)",
                [],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute("UPDATE lease SET revoked=1 WHERE singleton=1", [])
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE runtime_operations SET status='UNKNOWN',updated_at=?1 WHERE status IN ('ADMITTED','EXECUTING')",
                params![FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "DELETE FROM runtime_queue WHERE operation_id IN (SELECT operation_id FROM runtime_operations WHERE status='UNKNOWN')",
                [],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE operations SET state='UNKNOWN',uncertainty_reason='authority_rotated',ticket_json=json_set(ticket_json,'$.state','UNKNOWN'),updated_at=?1 WHERE state='MAY_HAVE_BEEN_DISPATCHED'",
                params![FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "DELETE FROM queue WHERE operation_id IN (SELECT operation_id FROM operations WHERE state='UNKNOWN')",
                [],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE fence SET lease_epoch_counter=?1 WHERE singleton=1",
                params![epoch],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "INSERT INTO lease_history(lease_id,lease_epoch,deployment_id,instance_id,boot_id,instance_incarnation,host_fence_id,fence_token_digest,issued_at,expires_at,issued_tick,expires_tick,ttl_seconds,renewal_interval_seconds,renew_sequence,revoked)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,0,0)",
                params![
                    lease_id,
                    epoch,
                    deployment_id,
                    instance_id,
                    boot_id,
                    incarnation,
                    host_fence_id,
                    digest(token),
                    issued_at,
                    expires_at,
                    issued_tick,
                    expires_tick,
                    ttl_seconds,
                    renewal_interval_seconds,
                ],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "INSERT INTO lease(singleton,deployment_id,instance_id,lease_id,lease_epoch,boot_id,instance_incarnation,host_fence_id,fence_token,issued_at,expires_at,issued_tick,expires_tick,ttl_seconds,renewal_interval_seconds,renew_sequence,revoked)
                 VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,0,0)
                 ON CONFLICT(singleton) DO UPDATE SET deployment_id=excluded.deployment_id,instance_id=excluded.instance_id,lease_id=excluded.lease_id,lease_epoch=excluded.lease_epoch,boot_id=excluded.boot_id,instance_incarnation=excluded.instance_incarnation,host_fence_id=excluded.host_fence_id,fence_token=excluded.fence_token,issued_at=excluded.issued_at,expires_at=excluded.expires_at,issued_tick=excluded.issued_tick,expires_tick=excluded.expires_tick,ttl_seconds=excluded.ttl_seconds,renewal_interval_seconds=excluded.renewal_interval_seconds,renew_sequence=excluded.renew_sequence,revoked=excluded.revoked",
                params![
                    deployment_id,
                    instance_id,
                    lease_id,
                    epoch,
                    boot_id,
                    incarnation,
                    host_fence_id,
                    token,
                    issued_at,
                    expires_at,
                    issued_tick,
                    expires_tick,
                    ttl_seconds,
                    renewal_interval_seconds,
                ],
            )
            .map_err(FixtureError::Sql)?;
        transaction.commit().map_err(FixtureError::Sql)?;
        let lease = json!({
            "deployment_id": boot["deployment_id"], "instance_id": boot["instance_id"],
            "instance_incarnation": boot["instance_incarnation"], "boot_id": boot["boot_id"],
            "authority_generation": boot["authority_generation"], "lease_id": lease_id,
            "lease_epoch": epoch,
            "fence_token": token, "issued_at": issued_at,
            "expires_at": expires_at,
            "ttl_seconds": ttl_seconds, "renewal_interval_seconds": renewal_interval_seconds
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
        let renew_sequence = field_i64(&frame.payload, "renew_sequence")?;
        let (current_sequence, ttl_seconds, renewal_interval_seconds, expires_tick): (i64, i64, i64, i64) = self
            .connection
            .query_row(
                "SELECT renew_sequence,ttl_seconds,renewal_interval_seconds,expires_tick FROM lease WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(FixtureError::Sql)?;
        if renew_sequence != current_sequence.saturating_add(1) {
            return Err(FixtureError::Conflict);
        }
        let now_tick = current_tick(&self.connection)?
            .saturating_add(renewal_interval_seconds)
            .max(expires_tick.saturating_sub(ttl_seconds));
        let new_expires_tick = now_tick.saturating_add(ttl_seconds);
        let new_expires_at = timestamp_for_tick(new_expires_tick);
        let transaction = self.connection.transaction().map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE fixture_clock SET tick=?1 WHERE singleton=1",
                params![now_tick],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE lease SET expires_at=?1,expires_tick=?2,renew_sequence=?3 WHERE singleton=1 AND lease_id=?4",
                params![new_expires_at, new_expires_tick, renew_sequence, field_string(lease, "lease_id")?],
            )
            .map_err(FixtureError::Sql)?;
        let history_changed = transaction
            .execute(
                "UPDATE lease_history SET expires_at=?1,expires_tick=?2,renew_sequence=?3 WHERE lease_id=?4",
                params![new_expires_at, new_expires_tick, renew_sequence, field_string(lease, "lease_id")?],
            )
            .map_err(FixtureError::Sql)?;
        if history_changed != 1 {
            return Err(FixtureError::Conflict);
        }
        transaction.commit().map_err(FixtureError::Sql)?;
        let mut renewed = lease.clone();
        renewed["expires_at"] = Value::String(new_expires_at);
        Ok((
            frame.response(
                "lease_renew_response",
                json!({"result":status("LEASE_RENEWED"),"lease":renewed}),
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
        let transaction = self.connection.transaction().map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE lease SET revoked=1 WHERE singleton=1 AND lease_id=?1 AND lease_epoch=?2",
                params![
                    field_string(lease, "lease_id")?,
                    field_i64(lease, "lease_epoch")?
                ],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE lease_history SET revoked=1 WHERE lease_id=?1 AND lease_epoch=?2",
                params![
                    field_string(lease, "lease_id")?,
                    field_i64(lease, "lease_epoch")?
                ],
            )
            .map_err(FixtureError::Sql)?;
        transaction.commit().map_err(FixtureError::Sql)?;
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
        validate_operation_full(operation)?;
        validate_operation_context(operation, lease)?;
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
        let existing: Option<(String, String, String, String, String)> = self
            .connection
            .query_row(
                "SELECT payload_digest, state, original_context_json, action_json, expected_boundary_json FROM operations WHERE operation_id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        if let Some((
            existing_digest,
            state,
            existing_context,
            existing_action,
            existing_boundary,
        )) = existing
        {
            if existing_digest != digest_value
                || existing_context != context_json
                || existing_action != action_json
                || existing_boundary != boundary_json
            {
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
                "INSERT INTO operations(operation_id,payload_digest,deployment_id,instance_id,boot_id,instance_incarnation,lease_epoch,host_fence_id,state,uncertainty_reason,action_json,expected_boundary_json,original_context_json,ticket_json,witness_json,receipt_json,reconcile_strategy,created_at,updated_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'INTENT_RECORDED',NULL,?9,?10,?11,NULL,NULL,NULL,NULL,?12,?12)",
                params![
                    id,
                    digest_value,
                    field_string(lease, "deployment_id")?,
                    field_string(lease, "instance_id")?,
                    field_string(lease, "boot_id")?,
                    field_string(lease, "instance_incarnation")?,
                    field_i64(lease, "lease_epoch")?,
                    self.current_fence_id()?,
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
        validate_operation_ref(operation)?;
        let id = field_string(operation, "operation_id")?;
        let digest_value = field_string(operation, "payload_digest")?;
        valid_v4(&id)?;
        validate_digest(&digest_value)?;
        let original_context = operation
            .get("original_context")
            .ok_or_else(|| FixtureError::Invalid("original context missing".to_owned()))?;
        validate_original_context(original_context)?;
        self.validate_operation_ref_context(&id, &digest_value, original_context)?;
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
        if state == "UNKNOWN" {
            return self.operation_response(frame, "UNKNOWN", &id);
        }
        if state == "MAY_HAVE_BEEN_DISPATCHED" {
            return self.operation_response(frame, "MAY_HAVE_BEEN_DISPATCHED", &id);
        }
        if state != "INTENT_RECORDED" {
            return self.operation_response(frame, "REJECTED", &id);
        }
        if self.receipt_count()? >= MAX_RECEIPTS {
            return self.operation_response(frame, "BOUNDS_EXCEEDED", &id);
        }
        if let Some(action) = faults.at(FaultPoint::BeforeAdmission) {
            return self.operation_response_with_action(frame, "UNKNOWN", &id, action);
        }
        let ticket = self.issue_ticket(&id, &digest_value, lease)?;
        let transaction = self.connection.transaction().map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE operations SET state='MAY_HAVE_BEEN_DISPATCHED',ticket_json=?2,updated_at=?3 WHERE operation_id=?1",
                params![id, ticket.to_string(), FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "INSERT INTO queue(operation_id,ticket_json,enqueued_at) VALUES(?1,?2,?3)",
                params![id, ticket.to_string(), FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        transaction.commit().map_err(FixtureError::Sql)?;
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
        &self,
        operation_id: &str,
        digest_value: &str,
        lease: &Value,
    ) -> Result<Value, FixtureError> {
        validate_lease_context(lease)?;
        let fence_id = self.current_fence_id()?;
        let expires_at: String = self
            .connection
            .query_row(
                "SELECT expires_at FROM lease WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(FixtureError::Sql)?;
        let ticket_id = Uuid::new_v4().to_string();
        Ok(json!({
            "ticket_id": ticket_id, "operation_id": operation_id, "payload_digest": digest_value,
            "boot_id": lease["boot_id"], "instance_incarnation": lease["instance_incarnation"],
            "lease_epoch": lease["lease_epoch"], "host_fence_id": fence_id,
            "state": "ISSUED", "issued_at": FIXTURE_TIMESTAMP, "expires_at": expires_at
        }))
    }

    #[allow(clippy::too_many_lines)]
    fn tick(
        &mut self,
        frame: &Frame,
        faults: &mut FaultController,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "recovery_reconcile")?;
        let id = frame
            .payload
            .get("operation_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let Some(id) = id else {
            return Err(FixtureError::Invalid("operation_id missing".to_owned()));
        };
        let queued: Option<String> = self
            .connection
            .query_row(
                "SELECT ticket_json FROM queue WHERE operation_id=?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some(ticket_json) = queued else {
            return self.operation_response(frame, "NOT_FOUND", &id);
        };
        let ticket: Value = parse_value_no_duplicates(ticket_json.as_bytes())?;
        let operation_row: Option<(String, String, String, Option<String>)> = self
            .connection
            .query_row(
                "SELECT payload_digest,state,original_context_json,witness_json FROM operations WHERE operation_id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((payload_digest, state, context_json, witness_json)) = operation_row else {
            return self.operation_response(frame, "NOT_FOUND", &id);
        };
        if state == "SETTLED" || state == "RECONCILED" {
            self.connection
                .execute("DELETE FROM queue WHERE operation_id=?1", params![id])
                .map_err(FixtureError::Sql)?;
            return self.operation_response(frame, "DUPLICATE", &id);
        }
        if witness_json.is_some() || state == "UNKNOWN" {
            // A durable witness is the admission boundary for at-most-once
            // execution. A retry can only report uncertainty and reconcile;
            // it may never manufacture a second witness.
            self.connection
                .execute("DELETE FROM queue WHERE operation_id=?1", params![id])
                .map_err(FixtureError::Sql)?;
            self.set_ticket_state(&id, "UNKNOWN")?;
            return self.operation_response(frame, "UNKNOWN", &id);
        }
        if state != "MAY_HAVE_BEEN_DISPATCHED" {
            return self.operation_response(frame, "REJECTED", &id);
        }
        validate_ticket(&ticket, &id, &payload_digest, &context_json)?;
        if let Err(error) = self.validate_ticket_authority(&ticket) {
            self.connection
                .execute("DELETE FROM queue WHERE operation_id=?1", params![id])
                .map_err(FixtureError::Sql)?;
            self.connection
                .execute(
                    "UPDATE operations SET state='REJECTED',uncertainty_reason=NULL,updated_at=?2 WHERE operation_id=?1",
                    params![id, FIXTURE_TIMESTAMP],
                )
                .map_err(FixtureError::Sql)?;
            return self.operation_response(frame, error.status(), &id);
        }
        if let Some(action) = faults.at(FaultPoint::BeforeMutation) {
            return self.operation_response_with_action(
                frame,
                "MAY_HAVE_BEEN_DISPATCHED",
                &id,
                action,
            );
        }
        let operation: (String, String, String) = self
            .connection
            .query_row(
                "SELECT payload_digest, action_json, expected_boundary_json FROM operations WHERE operation_id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(FixtureError::Sql)?;
        let effect_digest = digest(&format!("effect:{id}:{}", operation.0));
        let boundary: Value = parse_value_no_duplicates(operation.2.as_bytes())?;
        let state_id = field_string(&boundary, "state_id")?;
        let generation = field_i64(&boundary, "generation")?;
        valid_v4(&state_id)?;
        let witness = json!({
            "witness_id": Uuid::new_v4().to_string(), "operation_id": id,
            "payload_digest": operation.0, "boot_id": ticket["boot_id"],
            "instance_incarnation": ticket["instance_incarnation"],
            "host_fence_id": ticket["host_fence_id"], "source": EFFECT_WITNESS_SOURCE,
            "state_id": state_id, "generation": generation,
            "effect_digest": effect_digest, "observed_at": FIXTURE_TIMESTAMP
        });
        validate_effect_witness(&witness, &id, &operation.0)?;
        let witness_text = witness.to_string();
        let transaction = self.connection.transaction().map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "INSERT INTO effects(operation_id,payload_digest,witness_json,effect_digest,created_at) VALUES(?1,?2,?3,?4,?5)",
                params![id, operation.0, witness_text, witness["effect_digest"].as_str(), FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        let operation_changed = transaction
            .execute(
                "UPDATE operations SET state='UNKNOWN',uncertainty_reason='receipt_missing',witness_json=?2,ticket_json=json_set(ticket_json,'$.state','EFFECT_WITNESS_RECORDED'),updated_at=?3 WHERE operation_id=?1",
                params![id, witness_text, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        if operation_changed != 1 {
            return Err(FixtureError::Conflict);
        }
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
        validate_receipt(&receipt, &witness, &id, &operation.0)?;
        let receipt_changed = self
            .connection
            .execute(
                "INSERT INTO receipts(operation_id,receipt_json,created_at) VALUES(?1,?2,?3)",
                params![id, receipt.to_string(), FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        if receipt_changed != 1 {
            return Err(FixtureError::Conflict);
        }
        let operation_changed = self
            .connection
            .execute("UPDATE operations SET state='SETTLED',uncertainty_reason=NULL,receipt_json=?2,ticket_json=json_set(ticket_json,'$.state','SETTLED'),updated_at=?3 WHERE operation_id=?1", params![id, receipt.to_string(), FIXTURE_TIMESTAMP])
            .map_err(FixtureError::Sql)?;
        if operation_changed != 1 {
            return Err(FixtureError::Conflict);
        }
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
        self.validate_operation_witness_consistency(&id, &digest_value, &witness)?;
        let state = value["state"].as_str().unwrap_or("UNKNOWN");
        if state == "SETTLED" || state == "RECONCILED" {
            return Ok((
                frame.response(
                    "operation_reconcile_response",
                    json!({"result":status("DUPLICATE"),"operation":value,"witness":witness}),
                ),
                ResponseAction::Send,
            ));
        }
        if strategy == "quarantine" {
            return Ok((
                frame.response(
                    "operation_reconcile_response",
                    json!({"result":status("UNKNOWN"),"operation":value,"witness":witness}),
                ),
                ResponseAction::Send,
            ));
        }
        let source = witness.get("source").and_then(Value::as_str);
        let strategy_matches = match strategy {
            // A receipt lookup may settle only when the durable effect witness
            // is host-generated; it cannot invent a receipt or a new witness.
            "receipt_lookup" => source == Some(EFFECT_WITNESS_SOURCE),
            // Reobserve is the only strategy allowed to consume an explicitly
            // authoritative observation witness.
            "reobserve" => source == Some("authoritative_reobserve"),
            _ => false,
        };
        if !strategy_matches {
            return Ok((
                frame.response(
                    "operation_reconcile_response",
                    json!({"result":status("UNKNOWN"),"operation":value,"witness":witness}),
                ),
                ResponseAction::Send,
            ));
        }
        self.connection
            .execute("UPDATE operations SET state='RECONCILED',uncertainty_reason=NULL,reconcile_strategy=?2,ticket_json=json_set(ticket_json,'$.state','SETTLED'),updated_at=?3 WHERE operation_id=?1", params![id, strategy, FIXTURE_TIMESTAMP])
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

    fn v3_handle_frame(
        &mut self,
        frame: &Frame,
        _faults: &mut FaultController,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        validate_runtime_v3_envelope(&frame.kind, &frame.payload)?;
        let response = self.v3_handle_value(&frame.payload)?;
        Ok((
            frame.response(&response_kind(&frame.kind), response),
            ResponseAction::Send,
        ))
    }

    fn v3_handle_value(&mut self, request: &Value) -> Result<Value, FixtureError> {
        let kind = field_string(request, "kind")?;
        let instance_id = field_string(request, "instance_id")?;
        let session_id = field_string(request, "session_id")?;
        let lease_id = field_string(request, "lease_id")?;
        let lease_epoch = field_i64(request, "lease_epoch")?;
        let request_generation = field_i64(request, "generation")?;
        let _correlation_id = field_string(request, "correlation_id")?;
        let authority_current =
            self.runtime_authority_current(&instance_id, &lease_id, lease_epoch)?;
        let mut state = self.runtime_session(&session_id)?;
        if state.is_none() {
            if !authority_current {
                return Err(FixtureError::Stale("lease"));
            }
            state = Some(self.create_runtime_session(
                &instance_id,
                &session_id,
                &lease_id,
                lease_epoch,
                request.get("state_id").and_then(Value::as_str),
                request_generation,
            )?);
        }
        let mut state = state.ok_or(FixtureError::HostNotReady)?;
        if !authority_current && kind == "dispatch_action_request" {
            return runtime_rejected_response(
                request,
                &state,
                &field_string(request, "operation_id")?,
                "stale_lease",
            );
        }
        // A replacement authority may finish recovery for a historical
        // session, but it must not rewrite that session's lease identity or
        // use its stale credentials for a new mutation. `v3_recover_value`
        // only marks a proved historical operation reconciled and retains the
        // operation/session rows as written under the old authority.
        if authority_current
            && kind == "recover_request"
            && request["recovery"]["kind"].as_str() == Some("reconcile")
            && (state.instance_id != instance_id
                || state.lease_id != lease_id
                || state.lease_epoch != lease_epoch)
        {
            return self.v3_recover_value(request, &mut state);
        }
        if !authority_current
            && (kind == "wait_request"
                || (kind == "recover_request"
                    && matches!(
                        request["recovery"]["kind"].as_str(),
                        Some("release_lease" | "stop_episode" | "reconcile")
                    )))
        {
            return Ok(runtime_error_response(
                request,
                &kind,
                "stale_lease",
                state.generation,
                &state,
            ));
        }
        if state.instance_id != instance_id
            || state.lease_id != lease_id
            || state.lease_epoch != lease_epoch
        {
            // The frozen runtime-v3 schema has no error form for read
            // responses.  Reads carry no mutation authority, so return the
            // current bounded observation while all mutating requests remain
            // explicitly unknown and require recovery.
            return match kind.as_str() {
                "state_request" => runtime_observation_response(request, &state),
                "legal_actions_request" => runtime_legal_actions_response(request, &state),
                "reobserve_request" => runtime_reobserve_response(request, &state),
                _ => Ok(runtime_error_response(
                    request,
                    &kind,
                    "stale_lease",
                    state.generation,
                    &state,
                )),
            };
        }
        if state.stopped {
            // The frozen contract has no error form for read responses.  A
            // stopped episode may still be inspected, and an explicit
            // reconcile request must be able to examine durable evidence;
            // only new execution/wait authority is refused.
            return match kind.as_str() {
                "state_request" => runtime_observation_response(request, &state),
                "legal_actions_request" => runtime_legal_actions_response(request, &state),
                "reobserve_request" => runtime_reobserve_response(request, &state),
                "recover_request" => self.v3_recover_value(request, &mut state),
                _ => Ok(runtime_error_response(
                    request,
                    &kind,
                    "episode_stopped",
                    state.generation,
                    &state,
                )),
            };
        }
        match kind.as_str() {
            "state_request" => runtime_observation_response(request, &state),
            "legal_actions_request" => runtime_legal_actions_response(request, &state),
            "reobserve_request" => runtime_reobserve_response(request, &state),
            "dispatch_action_request" => self.v3_dispatch_value(request, &mut state),
            "wait_request" => self.v3_wait_value(request, &mut state),
            "recover_request" => self.v3_recover_value(request, &mut state),
            _ => Err(FixtureError::Invalid(
                "unsupported runtime-v3 kind".to_owned(),
            )),
        }
    }

    fn runtime_authority_current(
        &self,
        instance_id: &str,
        lease_id: &str,
        lease_epoch: i64,
    ) -> Result<bool, FixtureError> {
        // Both transports hold the single DurableHost mutex across this check
        // and admission/execution. Runtime session identifiers are correlation,
        // not an independent source of mutation authority.
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM lease l JOIN fence f
                 ON l.deployment_id=f.deployment_id AND l.instance_id=f.instance_id
                 AND l.boot_id=f.boot_id AND l.instance_incarnation=f.instance_incarnation
                 AND l.host_fence_id=f.host_fence_id
                 WHERE l.singleton=1 AND f.singleton=1 AND l.instance_id=?1
                 AND l.lease_id=?2 AND l.lease_epoch=?3 AND l.revoked=0
                 AND l.expires_tick>?4 AND f.authority_generation BETWEEN 1 AND ?5
                 AND f.fence_generation=f.authority_generation
                 AND f.authority_state='READY')",
                params![
                    instance_id,
                    lease_id,
                    lease_epoch,
                    current_tick(&self.connection)?,
                    MAX_RUNTIME_INTEGER
                ],
                |row| row.get(0),
            )
            .map_err(FixtureError::Sql)
    }

    fn v3_dispatch_value(
        &mut self,
        request: &Value,
        state: &mut RuntimeSession,
    ) -> Result<Value, FixtureError> {
        let requested_generation = field_i64(request, "generation")?;
        let requested_state = field_string(request, "state_id")?;
        let operation_id = field_string(request, "operation_id")?;
        let action = request
            .get("action")
            .ok_or_else(|| FixtureError::Invalid("action missing".to_owned()))?;
        let action_json = bounded_json(action, MAX_ACTION_BYTES)?;
        let action_digest = sha256_hex(action_json.as_bytes());
        if let Some(existing) = self.runtime_operation(&operation_id)? {
            if existing.instance_id != state.instance_id
                || existing.session_id != state.session_id
                || existing.lease_id != state.lease_id
                || existing.lease_epoch != state.lease_epoch
            {
                return runtime_rejected_response(
                    request,
                    state,
                    &operation_id,
                    "operation_conflict",
                );
            }
            if existing.action_digest != action_digest || existing.action_json != action_json {
                return runtime_rejected_response(
                    request,
                    state,
                    &operation_id,
                    "operation_conflict",
                );
            }
            return self.runtime_operation_response(request, state, &existing);
        }

        if requested_generation != state.generation || requested_state != state.state_id {
            return runtime_rejected_response(request, state, &operation_id, "stale_generation");
        }
        let legal_actions = stored_runtime_value(&state.legal_actions_json)?;
        if !legal_actions
            .as_array()
            .is_some_and(|actions| actions.iter().any(|candidate| candidate == action))
        {
            return runtime_rejected_response(request, state, &operation_id, "illegal_action");
        }

        // A session admits at most one unresolved operation.  In particular,
        // a changed action id cannot leapfrog a queued or unknown operation.
        if self
            .active_runtime_operation(&state.session_id, None)?
            .is_some()
        {
            return runtime_rejected_response(request, state, &operation_id, "active_operation");
        }

        let operation = RuntimeOperation {
            operation_id: operation_id.clone(),
            instance_id: state.instance_id.clone(),
            session_id: state.session_id.clone(),
            lease_id: state.lease_id.clone(),
            lease_epoch: state.lease_epoch,
            action_json,
            action_digest,
            pre_state_id: state.state_id.clone(),
            pre_generation: state.generation,
            status: "ADMITTED".to_owned(),
            witness_json: None,
            result_json: None,
        };
        self.insert_runtime_operation(&operation)?;
        runtime_accepted_response(request, state, &operation_id)
    }

    fn v3_wait_value(
        &mut self,
        request: &Value,
        state: &mut RuntimeSession,
    ) -> Result<Value, FixtureError> {
        let operation_id = field_string(request, "operation_id")?;
        let Some(operation) = self.runtime_operation(&operation_id)? else {
            return Ok(runtime_error_response(
                request,
                "wait_request",
                "operation_not_found",
                state.generation,
                state,
            ));
        };
        if operation.instance_id != state.instance_id
            || operation.session_id != state.session_id
            || operation.lease_id != state.lease_id
            || operation.lease_epoch != state.lease_epoch
        {
            return Ok(runtime_error_response(
                request,
                "wait_request",
                "stale_lease",
                state.generation,
                state,
            ));
        }
        let result = self.drain_runtime_operation(request, state, &operation)?;
        let mut response = result;
        response["kind"] = json!("wait_response");
        if response["status"] == "settled" {
            response["wait_outcome"] = json!("successor");
        }
        Ok(response)
    }

    fn v3_recover_value(
        &mut self,
        request: &Value,
        state: &mut RuntimeSession,
    ) -> Result<Value, FixtureError> {
        let recovery = request
            .get("recovery")
            .ok_or_else(|| FixtureError::Invalid("recovery missing".to_owned()))?;
        let recovery_kind = field_string(recovery, "kind")?;
        match recovery_kind.as_str() {
            "reobserve" => {
                // An observation is useful recovery input, but it is not an
                // operation witness and must never settle a pending action.
                let observation = stored_runtime_value(&state.observation_json)?;
                let legal_actions = stored_runtime_value(&state.legal_actions_json)?;
                Ok(runtime_recovery_response(
                    request,
                    state,
                    "accepted",
                    observation,
                    legal_actions,
                    Value::Null,
                    Value::Null,
                ))
            }
            "reconcile" => {
                let operation_id = field_string(recovery, "operation_id")?;
                let Some(operation) = self.runtime_operation(&operation_id)? else {
                    return Ok(runtime_error_response(
                        request,
                        "recover_request",
                        "operation_not_found",
                        state.generation,
                        state,
                    ));
                };
                if operation.instance_id != state.instance_id
                    || operation.session_id != state.session_id
                    || operation.lease_id != state.lease_id
                    || operation.lease_epoch != state.lease_epoch
                {
                    return Ok(runtime_error_response(
                        request,
                        "recover_request",
                        "stale_lease",
                        state.generation,
                        state,
                    ));
                }
                match operation.status.as_str() {
                    "SETTLED" | "RECONCILED" => {
                        self.runtime_operation_response(request, state, &operation)
                    }
                    // A witness is required before a recovery path can claim
                    // settlement.  Reobserve alone only supplies state and is
                    // intentionally not accepted as an effect proof.
                    "UNKNOWN"
                        if operation.witness_json.is_some() && operation.result_json.is_some() =>
                    {
                        self.mark_runtime_reconciled(&operation_id)?;
                        let reconciled = self
                            .runtime_operation(&operation_id)?
                            .ok_or(FixtureError::HostNotReady)?;
                        self.runtime_operation_response(request, state, &reconciled)
                    }
                    _ => Ok(runtime_error_response(
                        request,
                        "recover_request",
                        "effect_witness_missing",
                        state.generation,
                        state,
                    )),
                }
            }
            "release_lease" | "stop_episode" => {
                if recovery_kind == "release_lease" {
                    let transaction = self.connection.transaction().map_err(FixtureError::Sql)?;
                    transaction
                        .execute(
                            "UPDATE lease SET revoked=1 WHERE singleton=1 AND lease_id=?1 AND lease_epoch=?2",
                            params![state.lease_id, state.lease_epoch],
                        )
                        .map_err(FixtureError::Sql)?;
                    transaction
                        .execute(
                            "UPDATE lease_history SET revoked=1 WHERE lease_id=?1 AND lease_epoch=?2",
                            params![state.lease_id, state.lease_epoch],
                        )
                        .map_err(FixtureError::Sql)?;
                    transaction.commit().map_err(FixtureError::Sql)?;
                }
                // Once a dispatch has been admitted, stopping cannot claim it
                // never reached the host.  Retain an unresolved journal row;
                // no later request may dispatch it under a new lease.
                self.mark_active_runtime_operations_unknown(&state.session_id)?;
                state.stopped = true;
                self.persist_runtime_session(state)?;
                let observation = stored_runtime_value(&state.observation_json)?;
                let legal_actions = stored_runtime_value(&state.legal_actions_json)?;
                Ok(runtime_recovery_response(
                    request,
                    state,
                    "cancelled",
                    observation,
                    legal_actions,
                    Value::Null,
                    json!("episode_stopped"),
                ))
            }
            _ => Err(FixtureError::Invalid(
                "unsupported recovery kind".to_owned(),
            )),
        }
    }

    fn runtime_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<RuntimeOperation>, FixtureError> {
        let operation = self
            .connection
            .query_row(
                "SELECT operation_id,instance_id,session_id,lease_id,lease_epoch,action_json,action_digest,pre_state_id,pre_generation,status,witness_json,result_json FROM runtime_operations WHERE operation_id=?1",
                params![operation_id],
                |row| {
                    Ok(RuntimeOperation {
                        operation_id: row.get(0)?,
                        instance_id: row.get(1)?,
                        session_id: row.get(2)?,
                        lease_id: row.get(3)?,
                        lease_epoch: row.get(4)?,
                        action_json: row.get(5)?,
                        action_digest: row.get(6)?,
                        pre_state_id: row.get(7)?,
                        pre_generation: row.get(8)?,
                        status: row.get(9)?,
                        witness_json: row.get(10)?,
                        result_json: row.get(11)?,
                    })
                },
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some(operation) = operation else {
            return Ok(None);
        };
        self.validate_runtime_operation(&operation)?;
        Ok(Some(operation))
    }

    #[allow(clippy::too_many_lines, clippy::unused_self)]
    fn validate_runtime_operation(&self, operation: &RuntimeOperation) -> Result<(), FixtureError> {
        if !valid_identity(&operation.operation_id)
            || !valid_identity(&operation.instance_id)
            || !valid_identity(&operation.session_id)
            || !valid_identity(&operation.lease_id)
            || !(0..=MAX_RUNTIME_INTEGER).contains(&operation.lease_epoch)
            || !valid_identity(&operation.pre_state_id)
            || !(0..=MAX_RUNTIME_INTEGER).contains(&operation.pre_generation)
            || !matches!(
                operation.status.as_str(),
                "ADMITTED" | "EXECUTING" | "UNKNOWN" | "SETTLED" | "RECONCILED" | "REJECTED"
            )
        {
            return Err(FixtureError::Invalid(
                "runtime operation journal".to_owned(),
            ));
        }
        validate_digest(&operation.action_digest)?;
        if operation.action_json.len() > MAX_ACTION_BYTES {
            return Err(FixtureError::Bounds("runtime action journal"));
        }
        let action = parse_value_no_duplicates(operation.action_json.as_bytes())?;
        validate_runtime_legal_action(&action)?;
        if sha256_hex(operation.action_json.as_bytes()) != operation.action_digest {
            return Err(FixtureError::Conflict);
        }
        if let Some(witness) = operation.witness_json.as_deref() {
            if witness.len() > MAX_FRAME_BYTES {
                return Err(FixtureError::Bounds("runtime witness journal"));
            }
            let witness = parse_value_no_duplicates(witness.as_bytes())?;
            validate_runtime_witness(&witness, &operation.operation_id, &operation.action_digest)?;
        }
        if let Some(result) = operation.result_json.as_deref() {
            if result.len() > MAX_FRAME_BYTES {
                return Err(FixtureError::Bounds("runtime result journal"));
            }
            let result = parse_value_no_duplicates(result.as_bytes())?;
            object_fields(
                &result,
                &[
                    "state_id",
                    "generation",
                    "observation",
                    "legal_actions",
                    "transition",
                ],
                &[
                    "state_id",
                    "generation",
                    "observation",
                    "legal_actions",
                    "transition",
                ],
            )?;
            if !valid_identity(&field_string(&result, "state_id")?)
                || !(0..=MAX_RUNTIME_INTEGER).contains(&field_i64(&result, "generation")?)
            {
                return Err(FixtureError::Invalid("runtime operation result".to_owned()));
            }
            validate_runtime_observation(&result["observation"])?;
            validate_runtime_legal_actions(&result["legal_actions"])?;
            validate_runtime_transition(&result["transition"])?;
            if result["observation"]["state_id"] != result["state_id"]
                || result["observation"]["generation"] != result["generation"]
                || result["transition"]["state_id"] != result["state_id"]
                || result["transition"]["to_generation"] != result["generation"]
                || result["transition"]["from_generation"] != operation.pre_generation
            {
                return Err(FixtureError::Invalid(
                    "runtime operation result relation".to_owned(),
                ));
            }
        }
        if let (Some(witness), Some(result)) = (
            operation.witness_json.as_deref(),
            operation.result_json.as_deref(),
        ) {
            let witness = parse_value_no_duplicates(witness.as_bytes())?;
            let result = parse_value_no_duplicates(result.as_bytes())?;
            if witness["pre_state_id"] != operation.pre_state_id
                || witness["pre_generation"] != operation.pre_generation
                || witness["state_id"] != result["state_id"]
                || witness["generation"] != result["generation"]
            {
                return Err(FixtureError::Invalid(
                    "runtime proof boundary relation".to_owned(),
                ));
            }
        }
        if matches!(operation.status.as_str(), "SETTLED" | "RECONCILED")
            && (operation.witness_json.is_none() || operation.result_json.is_none())
        {
            return Err(FixtureError::Invalid(
                "settled runtime operation lacks proof".to_owned(),
            ));
        }
        if matches!(
            operation.status.as_str(),
            "ADMITTED" | "EXECUTING" | "REJECTED"
        ) && (operation.witness_json.is_some() || operation.result_json.is_some())
        {
            return Err(FixtureError::Invalid(
                "unsettled runtime operation contains proof".to_owned(),
            ));
        }
        Ok(())
    }

    fn active_runtime_operation(
        &self,
        session_id: &str,
        excluding: Option<&str>,
    ) -> Result<Option<RuntimeOperation>, FixtureError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT operation_id FROM runtime_operations WHERE session_id=?1 AND status IN ('ADMITTED','EXECUTING','UNKNOWN') ORDER BY created_at,operation_id",
            )
            .map_err(FixtureError::Sql)?;
        let mut rows = statement
            .query(params![session_id])
            .map_err(FixtureError::Sql)?;
        while let Some(row) = rows.next().map_err(FixtureError::Sql)? {
            let operation_id: String = row.get(0).map_err(FixtureError::Sql)?;
            if excluding != Some(operation_id.as_str()) {
                return self.runtime_operation(&operation_id);
            }
        }
        Ok(None)
    }

    fn insert_runtime_operation(&self, operation: &RuntimeOperation) -> Result<(), FixtureError> {
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "INSERT INTO runtime_operations(operation_id,instance_id,session_id,lease_id,lease_epoch,action_json,action_digest,pre_state_id,pre_generation,status,witness_json,result_json,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,NULL,NULL,?11,?11)",
                params![
                    operation.operation_id,
                    operation.instance_id,
                    operation.session_id,
                    operation.lease_id,
                    operation.lease_epoch,
                    operation.action_json,
                    operation.action_digest,
                    operation.pre_state_id,
                    operation.pre_generation,
                    operation.status,
                    FIXTURE_TIMESTAMP,
                ],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "INSERT INTO runtime_queue(operation_id,enqueued_at) VALUES(?1,?2)",
                params![operation.operation_id, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        transaction.commit().map_err(FixtureError::Sql)
    }

    #[allow(clippy::unused_self)]
    fn runtime_operation_response(
        &self,
        request: &Value,
        state: &RuntimeSession,
        operation: &RuntimeOperation,
    ) -> Result<Value, FixtureError> {
        match operation.status.as_str() {
            "SETTLED" | "RECONCILED" => {
                let result_text = operation.result_json.as_deref().ok_or_else(|| {
                    FixtureError::Invalid("settled runtime result missing".to_owned())
                })?;
                let result = parse_value_no_duplicates(result_text.as_bytes())?;
                let response_kind = response_kind(field_string(request, "kind")?.as_str());
                let mut response = runtime_base(request, &response_kind, state);
                response["generation"] = result["generation"].clone();
                response["state_id"] = result["state_id"].clone();
                response["operation_id"] = json!(operation.operation_id);
                response["observation"] = result["observation"].clone();
                response["legal_actions"] = result["legal_actions"].clone();
                response["status"] = json!("settled");
                response["transition"] = result["transition"].clone();
                if response_kind == "wait_response" {
                    response["wait_outcome"] = json!("successor");
                }
                Ok(response)
            }
            "ADMITTED" => runtime_accepted_response(request, state, &operation.operation_id),
            "REJECTED" if field_string(request, "kind")? == "wait_request" => {
                Ok(runtime_error_response(
                    request,
                    "wait_request",
                    "operation_rejected",
                    state.generation,
                    state,
                ))
            }
            "REJECTED" => runtime_rejected_response(
                request,
                state,
                &operation.operation_id,
                "operation_rejected",
            ),
            "EXECUTING" | "UNKNOWN" => Ok(runtime_error_response(
                request,
                field_string(request, "kind")?.as_str(),
                "operation_unknown",
                state.generation,
                state,
            )),
            _ => Err(FixtureError::Invalid("runtime operation state".to_owned())),
        }
    }

    fn mark_runtime_reconciled(&self, operation_id: &str) -> Result<(), FixtureError> {
        let changed = self
            .connection
            .execute(
                "UPDATE runtime_operations SET status='RECONCILED',updated_at=?2 WHERE operation_id=?1 AND status='UNKNOWN' AND witness_json IS NOT NULL AND result_json IS NOT NULL",
                params![operation_id, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        if changed != 1 {
            return Err(FixtureError::Conflict);
        }
        self.connection
            .execute(
                "DELETE FROM runtime_queue WHERE operation_id=?1",
                params![operation_id],
            )
            .map_err(FixtureError::Sql)?;
        Ok(())
    }

    fn mark_active_runtime_operations_unknown(&self, session_id: &str) -> Result<(), FixtureError> {
        self.connection
            .execute(
                "UPDATE runtime_operations SET status='UNKNOWN',updated_at=?2 WHERE session_id=?1 AND status IN ('ADMITTED','EXECUTING')",
                params![session_id, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        self.connection
            .execute(
                "DELETE FROM runtime_queue WHERE operation_id IN (SELECT operation_id FROM runtime_operations WHERE session_id=?1 AND status='UNKNOWN')",
                params![session_id],
            )
            .map_err(FixtureError::Sql)?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn drain_runtime_operation(
        &mut self,
        request: &Value,
        state: &mut RuntimeSession,
        operation: &RuntimeOperation,
    ) -> Result<Value, FixtureError> {
        if operation.status != "ADMITTED" {
            return self.runtime_operation_response(request, state, operation);
        }
        // Revalidate the operation's original durable authority at execution,
        // not merely the caller's session at admission. A fence rotation never
        // authorizes draining queued work from its predecessor.
        if !self.runtime_authority_current(
            &operation.instance_id,
            &operation.lease_id,
            operation.lease_epoch,
        )? {
            return Ok(runtime_error_response(
                request,
                "wait_request",
                "stale_lease",
                state.generation,
                state,
            ));
        }
        if operation.pre_state_id != state.state_id || operation.pre_generation != state.generation
        {
            self.mark_runtime_operation_unknown(&operation.operation_id)?;
            return Ok(runtime_error_response(
                request,
                "wait_request",
                "prestate_changed",
                state.generation,
                state,
            ));
        }
        let queued: Option<i64> = self
            .connection
            .query_row(
                "SELECT 1 FROM runtime_queue WHERE operation_id=?1",
                params![operation.operation_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        if queued.is_none() {
            self.mark_runtime_operation_unknown(&operation.operation_id)?;
            return Ok(runtime_error_response(
                request,
                "wait_request",
                "queue_missing",
                state.generation,
                state,
            ));
        }
        let changed = self
            .connection
            .execute(
                "UPDATE runtime_operations SET status='EXECUTING',updated_at=?2 WHERE operation_id=?1 AND status='ADMITTED'",
                params![operation.operation_id, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        if changed != 1 {
            let current = self
                .runtime_operation(&operation.operation_id)?
                .ok_or(FixtureError::HostNotReady)?;
            return self.runtime_operation_response(request, state, &current);
        }
        let action = parse_value_no_duplicates(operation.action_json.as_bytes())?;
        let legal_actions = stored_runtime_value(&state.legal_actions_json)?;
        if !legal_actions
            .as_array()
            .is_some_and(|actions| actions.iter().any(|candidate| candidate == &action))
        {
            self.mark_runtime_operation_rejected(&operation.operation_id)?;
            return runtime_rejected_response(
                request,
                state,
                &operation.operation_id,
                "prestate_changed",
            );
        }
        let action_kind = field_string(
            action
                .get("action")
                .ok_or_else(|| FixtureError::Invalid("action payload missing".to_owned()))?,
            "kind",
        )?;
        let mut observation = stored_runtime_value(&state.observation_json)?;
        let from_generation = state.generation;
        let to_generation = from_generation
            .checked_add(1)
            .ok_or_else(|| FixtureError::Invalid("runtime generation exhausted".to_owned()))?;
        observation["generation"] = json!(to_generation);
        if action_kind == "end_turn" {
            let turn = observation["state"]["turn_index"].as_i64().unwrap_or(1);
            observation["state"]["turn_index"] = json!(turn.saturating_add(1));
        }
        validate_runtime_observation(&observation)?;
        let legal_actions = stored_runtime_value(&state.legal_actions_json)?;
        let transition = json!({
            "from_generation":from_generation,
            "to_generation":to_generation,
            "state_id":state.state_id,
            "effect_kind":format!("synthetic.{action_kind}_settled")
        });
        validate_runtime_transition(&transition)?;
        let result = json!({
            "state_id":state.state_id,
            "generation":to_generation,
            "observation":observation,
            "legal_actions":legal_actions,
            "transition":transition
        });
        let witness = json!({
            "witness_id":Uuid::new_v4().to_string(),
            "operation_id":operation.operation_id,
            "action_digest":operation.action_digest,
            "source":EFFECT_WITNESS_SOURCE,
            "pre_state_id":operation.pre_state_id,
            "pre_generation":operation.pre_generation,
            "state_id":state.state_id,
            "generation":to_generation,
            "effect_digest":digest(&format!("runtime-effect:{}:{}:{}", operation.operation_id, operation.action_digest, to_generation)),
            "observed_at":FIXTURE_TIMESTAMP
        });
        validate_runtime_witness(&witness, &operation.operation_id, &operation.action_digest)?;
        let mut next_state = state.clone();
        next_state.generation = to_generation;
        next_state.observation_json = observation.to_string();
        next_state.last_operation_id = Some(operation.operation_id.clone());
        next_state.last_action_id = Some(field_string(&action, "action_id")?);
        let witness_text = witness.to_string();
        let result_text = result.to_string();
        let transaction = self.connection.transaction().map_err(FixtureError::Sql)?;
        let operation_changed = transaction
            .execute(
                "UPDATE runtime_operations SET status='SETTLED',witness_json=?2,result_json=?3,updated_at=?4 WHERE operation_id=?1 AND status='EXECUTING'",
                params![operation.operation_id, witness_text, result_text, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        if operation_changed != 1 {
            return Err(FixtureError::Conflict);
        }
        let session_changed = transaction
            .execute(
                "UPDATE runtime_sessions SET generation=?2,observation_json=?3,last_operation_id=?4,last_action_id=?5,updated_at=?6 WHERE session_id=?1 AND generation=?7 AND state_id=?8",
                params![
                    next_state.session_id,
                    next_state.generation,
                    next_state.observation_json,
                    next_state.last_operation_id,
                    next_state.last_action_id,
                    FIXTURE_TIMESTAMP,
                    operation.pre_generation,
                    operation.pre_state_id,
                ],
            )
            .map_err(FixtureError::Sql)?;
        if session_changed != 1 {
            return Err(FixtureError::Conflict);
        }
        transaction
            .execute(
                "DELETE FROM runtime_queue WHERE operation_id=?1",
                params![operation.operation_id],
            )
            .map_err(FixtureError::Sql)?;
        transaction.commit().map_err(FixtureError::Sql)?;
        *state = next_state;
        let settled = self
            .runtime_operation(&operation.operation_id)?
            .ok_or(FixtureError::HostNotReady)?;
        self.runtime_operation_response(request, state, &settled)
    }

    fn mark_runtime_operation_unknown(&self, operation_id: &str) -> Result<(), FixtureError> {
        self.connection
            .execute(
                "UPDATE runtime_operations SET status='UNKNOWN',updated_at=?2 WHERE operation_id=?1 AND status IN ('ADMITTED','EXECUTING')",
                params![operation_id, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        self.connection
            .execute(
                "DELETE FROM runtime_queue WHERE operation_id=?1",
                params![operation_id],
            )
            .map_err(FixtureError::Sql)?;
        Ok(())
    }

    fn mark_runtime_operation_rejected(&self, operation_id: &str) -> Result<(), FixtureError> {
        self.connection
            .execute(
                "UPDATE runtime_operations SET status='REJECTED',updated_at=?2 WHERE operation_id=?1 AND status='EXECUTING'",
                params![operation_id, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        self.connection
            .execute(
                "DELETE FROM runtime_queue WHERE operation_id=?1",
                params![operation_id],
            )
            .map_err(FixtureError::Sql)?;
        Ok(())
    }

    fn runtime_session(&self, session_id: &str) -> Result<Option<RuntimeSession>, FixtureError> {
        let state = self
            .connection
            .query_row(
                "SELECT instance_id,session_id,lease_id,lease_epoch,state_id,generation,observation_json,legal_actions_json,last_operation_id,last_action_id,stopped,updated_at FROM runtime_sessions WHERE session_id=?1",
                params![session_id],
                |row| Ok(RuntimeSession {
                    instance_id: row.get(0)?, session_id: row.get(1)?, lease_id: row.get(2)?,
                    lease_epoch: row.get(3)?, state_id: row.get(4)?, generation: row.get(5)?,
                    observation_json: row.get(6)?, legal_actions_json: row.get(7)?,
                    last_operation_id: row.get(8)?, last_action_id: row.get(9)?,
                    stopped: row.get(10)?, updated_at: row.get(11)?,
                }),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some(state) = state else {
            return Ok(None);
        };
        if !valid_identity(&state.instance_id)
            || !valid_identity(&state.session_id)
            || !valid_identity(&state.lease_id)
            || !valid_identity(&state.state_id)
            || !(0..=MAX_RUNTIME_INTEGER).contains(&state.lease_epoch)
            || !(0..=MAX_RUNTIME_INTEGER).contains(&state.generation)
            || !valid_timestamp(&state.updated_at)
        {
            return Err(FixtureError::Invalid("runtime session identity".to_owned()));
        }
        let observation = stored_runtime_value(&state.observation_json)?;
        validate_runtime_observation(&observation)?;
        let legal_actions = stored_runtime_value(&state.legal_actions_json)?;
        validate_runtime_legal_actions(&legal_actions)?;
        if state
            .last_operation_id
            .as_deref()
            .is_some_and(|value| !valid_identity(value))
            || state
                .last_action_id
                .as_deref()
                .is_some_and(|value| !valid_identity(value))
        {
            return Err(FixtureError::Invalid("runtime session journal".to_owned()));
        }
        if observation["state_id"] != state.state_id
            || observation["generation"] != state.generation
        {
            return Err(FixtureError::Invalid("runtime session boundary".to_owned()));
        }
        Ok(Some(state))
    }

    fn create_runtime_session(
        &self,
        instance_id: &str,
        session_id: &str,
        lease_id: &str,
        lease_epoch: i64,
        requested_state_id: Option<&str>,
        generation: i64,
    ) -> Result<RuntimeSession, FixtureError> {
        let state_id = requested_state_id.unwrap_or("synthetic-state").to_owned();
        let observation = synthetic_observation(&state_id, generation)?;
        let legal_actions = synthetic_legal_actions();
        let state = RuntimeSession {
            instance_id: instance_id.to_owned(),
            session_id: session_id.to_owned(),
            lease_id: lease_id.to_owned(),
            lease_epoch,
            state_id,
            generation,
            observation_json: observation.to_string(),
            legal_actions_json: legal_actions.to_string(),
            last_operation_id: None,
            last_action_id: None,
            stopped: false,
            updated_at: FIXTURE_TIMESTAMP.to_owned(),
        };
        self.persist_runtime_session(&state)?;
        Ok(state)
    }

    fn persist_runtime_session(&self, state: &RuntimeSession) -> Result<(), FixtureError> {
        self.connection
            .execute(
                "INSERT OR REPLACE INTO runtime_sessions(instance_id,session_id,lease_id,lease_epoch,state_id,generation,observation_json,legal_actions_json,last_operation_id,last_action_id,stopped,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                params![
                    state.instance_id, state.session_id, state.lease_id, state.lease_epoch,
                    state.state_id, state.generation, state.observation_json, state.legal_actions_json,
                    state.last_operation_id, state.last_action_id, i64::from(state.stopped), state.updated_at,
                ],
            )
            .map_err(FixtureError::Sql)?;
        Ok(())
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
        let ticket_value = ticket.map_or(Ok(Value::Null), |text| {
            parse_value_no_duplicates(text.as_bytes())
        })?;
        let witness_value = witness.map_or(Ok(Value::Null), |text| {
            parse_value_no_duplicates(text.as_bytes())
        })?;
        Ok(Some(json!({
            "operation_id":operation_id,"state":state,"payload_digest":stored_digest,
            "original_context":parse_value_no_duplicates(context.as_bytes())?,
            "expected_boundary":parse_value_no_duplicates(boundary.as_bytes())?,
            "action":parse_value_no_duplicates(action.as_bytes())?,
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

    fn current_fence_id(&self) -> Result<String, FixtureError> {
        self.connection
            .query_row(
                "SELECT host_fence_id FROM fence WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(FixtureError::Sql)?
            .ok_or(FixtureError::HostNotReady)
    }

    fn set_ticket_state(&self, operation_id: &str, state: &str) -> Result<(), FixtureError> {
        self.connection
            .execute(
                "UPDATE operations SET ticket_json=json_set(ticket_json,'$.state',?2),updated_at=?3 WHERE operation_id=?1",
                params![operation_id, state, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn validate_ticket_authority(&self, ticket: &Value) -> Result<(), FixtureError> {
        let lease: Option<(
            String,
            String,
            String,
            i64,
            String,
            String,
            String,
            i64,
            i64,
            i64,
        )> = self
            .connection
            .query_row(
                "SELECT deployment_id,instance_id,boot_id,lease_epoch,instance_incarnation,host_fence_id,fence_token,expires_tick,issued_tick,revoked FROM lease WHERE singleton=1",
                [],
                |row| Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                    row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?,
                )),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((
            deployment_id,
            instance_id,
            boot_id,
            lease_epoch,
            incarnation,
            fence_id,
            _token,
            expires_tick,
            _issued_tick,
            revoked,
        )) = lease
        else {
            return Err(FixtureError::HostNotReady);
        };
        if revoked != 0 || current_tick(&self.connection)? >= expires_tick {
            return Err(FixtureError::Stale("revoked lease"));
        }
        if field_string(ticket, "boot_id")? != boot_id
            || field_string(ticket, "instance_incarnation")? != incarnation
            || field_i64(ticket, "lease_epoch")? != lease_epoch
            || field_string(ticket, "host_fence_id")? != fence_id
        {
            return Err(FixtureError::Stale("lease"));
        }
        let current_fence = self.current_fence_id()?;
        if current_fence != fence_id {
            return Err(FixtureError::Stale("fence"));
        }
        let _ = (deployment_id, instance_id);
        Ok(())
    }

    fn validate_operation_ref_context(
        &self,
        id: &str,
        digest_value: &str,
        context: &Value,
    ) -> Result<(), FixtureError> {
        let stored: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT payload_digest,original_context_json FROM operations WHERE operation_id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((stored_digest, stored_context)) = stored else {
            return Ok(());
        };
        let supplied = bounded_json(context, 4096)?;
        if stored_digest != digest_value || stored_context != supplied {
            return Err(FixtureError::Conflict);
        }
        Ok(())
    }

    fn validate_operation_witness_consistency(
        &self,
        id: &str,
        payload_digest: &str,
        witness: &Value,
    ) -> Result<(), FixtureError> {
        validate_effect_witness(witness, id, payload_digest)?;
        let witness_text = bounded_json(witness, 4096)?;
        let stored_effect: Option<(String, String, String)> = self
            .connection
            .query_row(
                "SELECT payload_digest,witness_json,effect_digest FROM effects WHERE operation_id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((effect_digest, effect_witness, effect_hash)) = stored_effect else {
            return Err(FixtureError::Conflict);
        };
        if effect_digest != payload_digest
            || effect_witness != witness_text
            || effect_hash != field_string(witness, "effect_digest")?
        {
            return Err(FixtureError::Conflict);
        }
        if let Some(receipt_text) = self
            .connection
            .query_row(
                "SELECT receipt_json FROM receipts WHERE operation_id=?1",
                params![id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(FixtureError::Sql)?
        {
            let receipt: Value = parse_value_no_duplicates(receipt_text.as_bytes())?;
            validate_receipt(&receipt, witness, id, payload_digest)?;
        }
        Ok(())
    }

    fn validate_fence_pair(&self, boot: &Value, fence: &Value) -> Result<(), FixtureError> {
        validate_boot_context(boot)?;
        validate_host_fence(fence)?;
        let boot_deployment = field_string(boot, "deployment_id")?;
        let fence_deployment = field_string(fence, "deployment_id")?;
        let boot_instance = field_string(boot, "instance_id")?;
        let fence_instance = field_string(fence, "instance_id")?;
        let boot_id = field_string(boot, "boot_id")?;
        let fence_boot = field_string(fence, "boot_id")?;
        if boot_deployment != fence_deployment
            || boot_instance != fence_instance
            || boot_id != fence_boot
            || field_string(boot, "instance_incarnation")?
                != field_string(fence, "instance_incarnation")?
            || field_i64(boot, "authority_generation")? != field_i64(fence, "authority_generation")?
        {
            return Err(FixtureError::Stale("boot"));
        }
        self.validate_current_fence(fence)
    }

    #[allow(clippy::type_complexity)]
    fn validate_current_fence(&self, fence: &Value) -> Result<(), FixtureError> {
        validate_host_fence(fence)?;
        let supplied = field_string(fence, "host_fence_id")?;
        let current: Option<(String, String, String, String, String, i64, i64, String)> = self
            .connection
            .query_row(
                "SELECT deployment_id, instance_id, boot_id, instance_incarnation, host_fence_id, authority_generation, fence_generation, authority_state FROM fence WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((
            deployment_id,
            instance_id,
            boot_id,
            incarnation,
            current_fence,
            authority_generation,
            fence_generation,
            authority_state,
        )) = current
        else {
            return Err(FixtureError::HostNotReady);
        };
        if authority_state != "READY" {
            return Err(FixtureError::HostNotReady);
        }
        if current_fence != supplied
            || field_string(fence, "deployment_id")? != deployment_id
            || field_string(fence, "instance_id")? != instance_id
            || field_string(fence, "boot_id")? != boot_id
            || field_string(fence, "instance_incarnation")? != incarnation
            || field_i64(fence, "authority_generation")? != authority_generation
            || field_i64(fence, "fence_generation")? != fence_generation
        {
            return Err(FixtureError::Stale("fence"));
        }
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn validate_lease(&self, lease: &Value) -> Result<(), FixtureError> {
        validate_lease_context(lease)?;
        let lease_id = field_string(lease, "lease_id")?;
        let epoch = field_i64(lease, "lease_epoch")?;
        let current: Option<(
            String,
            String,
            String,
            i64,
            String,
            String,
            String,
            String,
            String,
            String,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
        )> = self
            .connection
            .query_row(
                "SELECT deployment_id,instance_id,lease_id,lease_epoch,boot_id,instance_incarnation,host_fence_id,fence_token,issued_at,expires_at,issued_tick,expires_tick,ttl_seconds,renewal_interval_seconds,renew_sequence,revoked FROM lease WHERE singleton=1",
                [],
                |row| Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                    row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?,
                    row.get(10)?, row.get(11)?, row.get(12)?, row.get(13)?, row.get(14)?,
                    row.get(15)?,
                )),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((
            current_deployment,
            current_instance,
            current_id,
            current_epoch,
            current_boot,
            current_incarnation,
            current_fence,
            current_token,
            issued_at,
            expires_at,
            _issued_tick,
            expires_tick,
            ttl_seconds,
            renewal_interval_seconds,
            renew_sequence,
            revoked,
        )) = current
        else {
            return Err(FixtureError::HostNotReady);
        };
        validate_lease_policy_values(ttl_seconds, renewal_interval_seconds)?;
        if revoked != 0 {
            return Err(FixtureError::Stale("revoked lease"));
        }
        if lease_id != current_id
            || epoch != current_epoch
            || field_string(lease, "deployment_id")? != current_deployment
            || field_string(lease, "instance_id")? != current_instance
            || field_string(lease, "boot_id")? != current_boot
            || field_string(lease, "instance_incarnation")? != current_incarnation
            || field_string(lease, "fence_token")? != current_token
            || field_string(lease, "issued_at")? != issued_at
            || field_string(lease, "expires_at")? != expires_at
            || field_i64(lease, "ttl_seconds")? != ttl_seconds
            || field_i64(lease, "renewal_interval_seconds")? != renewal_interval_seconds
            || current_tick(&self.connection)? >= expires_tick
        {
            return Err(FixtureError::Stale("lease"));
        }
        self.validate_current_fence_fields(
            &field_string(lease, "deployment_id")?,
            &field_string(lease, "instance_id")?,
            &field_string(lease, "boot_id")?,
            &field_string(lease, "instance_incarnation")?,
            field_i64(lease, "authority_generation")?,
            &current_fence,
        )?;
        let _ = (renew_sequence, expires_at);
        Ok(())
    }

    fn validate_current_fence_fields(
        &self,
        deployment_id: &str,
        instance_id: &str,
        boot_id: &str,
        incarnation: &str,
        authority_generation: i64,
        fence_id: &str,
    ) -> Result<(), FixtureError> {
        let current: Option<(String, String, String, String, String, i64, String)> = self
            .connection
            .query_row(
                "SELECT deployment_id,instance_id,boot_id,instance_incarnation,host_fence_id,authority_generation,authority_state FROM fence WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((
            current_deployment,
            current_instance,
            current_boot,
            current_incarnation,
            current_fence,
            current_generation,
            authority_state,
        )) = current
        else {
            return Err(FixtureError::HostNotReady);
        };
        if authority_state != "READY" {
            return Err(FixtureError::HostNotReady);
        }
        if deployment_id != current_deployment
            || instance_id != current_instance
            || boot_id != current_boot
            || incarnation != current_incarnation
            || authority_generation != current_generation
            || fence_id != current_fence
        {
            return Err(FixtureError::Stale("lease"));
        }
        Ok(())
    }
}

fn response_auth(kind: &str) -> (&'static str, &'static str) {
    match kind {
        "bootstrap_response" => ("gateway", "bootstrap"),
        "host_fence_response" => ("host", "host_fence"),
        "lease_acquire_response" => ("gateway", "lease_acquire"),
        "lease_renew_response" => ("gateway", "lease_renew"),
        "lease_revoke_response" => ("gateway", "lease_revoke"),
        "operation_intent_response" | "operation_dispatch_response" => {
            ("gateway", "operation_submit")
        }
        "operation_lookup_response" => ("operator", "recovery_read"),
        "operation_reconcile_response" => ("gateway", "recovery_reconcile"),
        "state_response"
        | "legal_actions_response"
        | "dispatch_action_response"
        | "wait_response"
        | "reobserve_response"
        | "recover_response" => ("host", "operation_submit"),
        _ => ("host", "recovery_read"),
    }
}

fn response_auth_checked(kind: &str) -> Option<(&'static str, &'static str)> {
    matches!(
        kind,
        "bootstrap_response"
            | "host_fence_response"
            | "lease_acquire_response"
            | "lease_renew_response"
            | "lease_revoke_response"
            | "operation_intent_response"
            | "operation_dispatch_response"
            | "operation_lookup_response"
            | "operation_reconcile_response"
    )
    .then(|| response_auth(kind))
}

fn request_capability(kind: &str) -> Option<&'static str> {
    match kind {
        "bootstrap_request" => Some("bootstrap"),
        "host_fence_request" => Some("host_fence"),
        "lease_acquire_request" => Some("lease_acquire"),
        "lease_renew_request" => Some("lease_renew"),
        "lease_revoke_request" => Some("lease_revoke"),
        "operation_intent_request" | "operation_dispatch_request" => Some("operation_submit"),
        "operation_lookup_request" => Some("recovery_read"),
        "operation_reconcile_request" => Some("recovery_reconcile"),
        _ => None,
    }
}

fn request_role(kind: &str) -> &'static str {
    match kind {
        "operation_lookup_request" => "operator",
        _ => "gateway",
    }
}

fn valid_role(value: &str) -> Result<(), FixtureError> {
    if matches!(
        value,
        "gateway" | "watchdog" | "harness" | "host" | "mod" | "operator"
    ) {
        Ok(())
    } else {
        Err(FixtureError::Invalid("actor role".to_owned()))
    }
}

fn valid_capability(value: &str) -> Result<(), FixtureError> {
    if matches!(
        value,
        "bootstrap"
            | "host_fence"
            | "lease_acquire"
            | "lease_renew"
            | "lease_revoke"
            | "operation_submit"
            | "recovery_read"
            | "recovery_reconcile"
    ) {
        Ok(())
    } else {
        Err(FixtureError::Forbidden)
    }
}

fn is_runtime_v3_kind(kind: &str) -> bool {
    matches!(
        kind,
        "state_request"
            | "state_response"
            | "legal_actions_request"
            | "legal_actions_response"
            | "dispatch_action_request"
            | "dispatch_action_response"
            | "wait_request"
            | "wait_response"
            | "reobserve_request"
            | "reobserve_response"
            | "recover_request"
            | "recover_response"
    )
}

fn valid_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    (value.len() == 20 || (value.len() >= 22 && value.len() <= 30))
        && bytes.len() >= 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes.ends_with(b"Z")
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && bytes[17..19].iter().all(u8::is_ascii_digit)
        && (value.len() == 20
            || (bytes[19] == b'.' && bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit)))
}

fn timestamp_for_tick(tick: i64) -> String {
    let total = tick.max(0);
    let hours = total / 3_600;
    let minutes = (total % 3_600) / 60;
    let seconds = total % 60;
    format!("2026-09-06T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn current_tick(connection: &Connection) -> Result<i64, FixtureError> {
    connection
        .query_row(
            "SELECT tick FROM fixture_clock WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(FixtureError::Sql)
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:/-".contains(&byte))
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

fn object_fields(value: &Value, required: &[&str], allowed: &[&str]) -> Result<(), FixtureError> {
    let object = value
        .as_object()
        .ok_or_else(|| FixtureError::Invalid("object required".to_owned()))?;
    for name in required {
        if !object.contains_key(*name) {
            return Err(FixtureError::Invalid(format!("missing field {name}")));
        }
    }
    if object.keys().any(|name| !allowed.contains(&name.as_str())) {
        return Err(FixtureError::Invalid("unknown field".to_owned()));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_recovery_payload(kind: &str, payload: &Value) -> Result<(), FixtureError> {
    match kind {
        "bootstrap_request" => {
            object_fields(
                payload,
                &[
                    "deployment_id",
                    "instance_id",
                    "instance_incarnation",
                    "release",
                    "lease_policy",
                ],
                &[
                    "deployment_id",
                    "instance_id",
                    "instance_incarnation",
                    "release",
                    "lease_policy",
                ],
            )?;
            let deployment = field_string(payload, "deployment_id")?;
            let instance = field_string(payload, "instance_id")?;
            let incarnation = field_string(payload, "instance_incarnation")?;
            valid_v4(&deployment)?;
            valid_v4(&instance)?;
            valid_v4(&incarnation)?;
            validate_release(
                payload
                    .get("release")
                    .ok_or_else(|| FixtureError::Invalid("release missing".to_owned()))?,
            )?;
            validate_policy(
                payload
                    .get("lease_policy")
                    .ok_or_else(|| FixtureError::Invalid("lease policy missing".to_owned()))?,
            )?;
        }
        "bootstrap_response" => {
            object_fields(
                payload,
                &["result", "boot", "fence"],
                &["result", "boot", "fence"],
            )?;
            validate_result(&payload["result"])?;
            if !payload["boot"].is_null() {
                validate_boot_context(&payload["boot"])?;
            }
            if !payload["fence"].is_null() {
                validate_host_fence(&payload["fence"])?;
            }
        }
        "host_fence_request" => {
            object_fields(payload, &["boot"], &["boot"])?;
            validate_boot_context(&payload["boot"])?;
        }
        "host_fence_response" => {
            object_fields(payload, &["result", "fence"], &["result", "fence"])?;
            validate_result(&payload["result"])?;
            if !payload["fence"].is_null() {
                validate_host_fence(&payload["fence"])?;
            }
        }
        "lease_acquire_request" => {
            object_fields(payload, &["boot", "fence"], &["boot", "fence"])?;
            validate_boot_context(&payload["boot"])?;
            validate_host_fence(&payload["fence"])?;
        }
        "lease_acquire_response" | "lease_renew_response" => {
            object_fields(payload, &["result", "lease"], &["result", "lease"])?;
            validate_result(&payload["result"])?;
            if !payload["lease"].is_null() {
                validate_lease_context(&payload["lease"])?;
            }
        }
        "lease_renew_request" => {
            object_fields(
                payload,
                &["lease", "renew_sequence"],
                &["lease", "renew_sequence"],
            )?;
            validate_lease_context(&payload["lease"])?;
            let sequence = field_i64(payload, "renew_sequence")?;
            if sequence < 1 {
                return Err(FixtureError::Invalid("renew sequence".to_owned()));
            }
        }
        "lease_revoke_request" => {
            object_fields(payload, &["lease", "reason"], &["lease", "reason"])?;
            validate_lease_context(&payload["lease"])?;
            let reason = field_string(payload, "reason")?;
            if !matches!(
                reason.as_str(),
                "operator" | "shutdown" | "incarnation_replaced" | "suspend_ambiguous" | "rekey"
            ) {
                return Err(FixtureError::Invalid("revoke reason".to_owned()));
            }
        }
        "lease_revoke_response" => {
            object_fields(payload, &["result"], &["result"])?;
            validate_result(&payload["result"])?;
        }
        "operation_intent_request" => {
            object_fields(payload, &["lease", "operation"], &["lease", "operation"])?;
            validate_lease_context(&payload["lease"])?;
            validate_operation_full(&payload["operation"])?;
        }
        "operation_intent_response" | "operation_dispatch_response" => {
            object_fields(payload, &["result", "operation"], &["result", "operation"])?;
            validate_result(&payload["result"])?;
            if !payload["operation"].is_null() {
                validate_operation_record(&payload["operation"])?;
            }
        }
        "operation_dispatch_request" => {
            object_fields(payload, &["lease", "operation"], &["lease", "operation"])?;
            validate_lease_context(&payload["lease"])?;
            validate_operation_ref(&payload["operation"])?;
        }
        "operation_lookup_request" => {
            object_fields(
                payload,
                &["operation", "lookup_scope"],
                &["operation", "lookup_scope"],
            )?;
            validate_operation_ref(&payload["operation"])?;
            if payload["lookup_scope"] != "historical_read" {
                return Err(FixtureError::Invalid("lookup scope".to_owned()));
            }
        }
        "operation_lookup_response" => {
            object_fields(
                payload,
                &["result", "operation", "mutation_authorized"],
                &["result", "operation", "mutation_authorized"],
            )?;
            validate_result(&payload["result"])?;
            if payload["mutation_authorized"] != false {
                return Err(FixtureError::Forbidden);
            }
            if !payload["operation"].is_null() {
                validate_operation_record(&payload["operation"])?;
            }
        }
        "operation_reconcile_request" => {
            object_fields(
                payload,
                &["operation", "strategy", "current_fence"],
                &["operation", "strategy", "current_fence"],
            )?;
            validate_operation_ref(&payload["operation"])?;
            validate_host_fence(&payload["current_fence"])?;
            let strategy = field_string(payload, "strategy")?;
            if !matches!(
                strategy.as_str(),
                "reobserve" | "receipt_lookup" | "quarantine"
            ) {
                return Err(FixtureError::Invalid("strategy".to_owned()));
            }
        }
        "operation_reconcile_response" => {
            object_fields(
                payload,
                &["result", "operation", "witness"],
                &["result", "operation", "witness"],
            )?;
            validate_result(&payload["result"])?;
            if !payload["operation"].is_null() {
                validate_operation_record(&payload["operation"])?;
            }
            if !payload["witness"].is_null() {
                validate_effect_witness(&payload["witness"], "", "")?;
            }
        }
        _ => {
            return Err(FixtureError::Invalid(
                "unsupported recovery payload".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_result(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["status", "retryable", "retry_after_seconds"],
        &["status", "retryable", "retry_after_seconds"],
    )?;
    let status = field_string(value, "status")?;
    if !matches!(
        status.as_str(),
        "BOOT_AUTHORITY_CREATED"
            | "BOOT_READY"
            | "BOOT_BLOCKED"
            | "FENCE_ACCEPTED"
            | "FENCE_REJECTED"
            | "LEASE_ACTIVE"
            | "LEASE_RENEWED"
            | "LEASE_REVOKED"
            | "INTENT_RECORDED"
            | "MAY_HAVE_BEEN_DISPATCHED"
            | "ACCEPTED"
            | "SETTLED"
            | "REJECTED"
            | "UNKNOWN"
            | "RECONCILED"
            | "DUPLICATE"
            | "CONFLICT"
            | "NOT_FOUND"
            | "STALE_BOOT"
            | "STALE_INCARNATION"
            | "STALE_LEASE"
            | "LEASE_EXPIRED"
            | "AUTH_REQUIRED"
            | "FORBIDDEN"
            | "CONTRACT_MISMATCH"
            | "PERSISTENCE_UNAVAILABLE"
            | "HOST_NOT_READY"
            | "BOUNDS_EXCEEDED"
            | "INVALID"
            | "BUSY"
    ) {
        return Err(FixtureError::Invalid("response status".to_owned()));
    }
    if !value["retryable"].is_boolean()
        || (!value["retry_after_seconds"].is_null()
            && (value["retry_after_seconds"].as_i64().unwrap_or(0) < 1))
    {
        return Err(FixtureError::Invalid("response retry metadata".to_owned()));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_runtime_v3_envelope(expected_kind: &str, value: &Value) -> Result<(), FixtureError> {
    const FIELDS: &[&str] = &[
        "protocol_version",
        "schema_digest",
        "provenance",
        "correlation_id",
        "instance_id",
        "session_id",
        "lease_id",
        "lease_epoch",
        "generation",
        "kind",
        "state_id",
        "operation_id",
        "observation",
        "legal_actions",
        "action",
        "status",
        "transition",
        "error_code",
        "wait_for_millis",
        "wait_outcome",
        "recovery",
    ];
    object_fields(value, FIELDS, FIELDS)?;
    if value["protocol_version"] != "runtime-v3-gameplay"
        || value["schema_digest"] != RUNTIME_V3_SCHEMA_DIGEST
        || value["kind"] != expected_kind
    {
        return Err(FixtureError::ContractMismatch);
    }
    object_fields(
        &value["provenance"],
        &["artifact", "source", "generator"],
        &["artifact", "source", "generator"],
    )?;
    if value["provenance"]["artifact"] != "sts2-protocol/runtime-v3-gameplay"
        || value["provenance"]["source"] != "schemas/runtime-v3-gameplay.schema.json"
        || value["provenance"]["generator"] != "hand-authored"
    {
        return Err(FixtureError::ContractMismatch);
    }
    for name in ["correlation_id", "instance_id", "session_id", "lease_id"] {
        if !value[name].as_str().is_some_and(valid_identity) {
            return Err(FixtureError::Invalid("runtime identity".to_owned()));
        }
    }
    for name in ["lease_epoch", "generation"] {
        if value[name]
            .as_i64()
            .is_none_or(|number| !(0..=9_007_199_254_740_991).contains(&number))
        {
            return Err(FixtureError::Invalid("runtime integer".to_owned()));
        }
    }
    let kind = expected_kind;
    if !value["state_id"].is_null() && !value["state_id"].as_str().is_some_and(valid_identity) {
        return Err(FixtureError::Invalid("runtime state identity".to_owned()));
    }
    if !value["operation_id"].is_null()
        && !value["operation_id"].as_str().is_some_and(valid_identity)
    {
        return Err(FixtureError::Invalid(
            "runtime operation identity".to_owned(),
        ));
    }
    if !value["error_code"].is_null() && !value["error_code"].as_str().is_some_and(valid_identity) {
        return Err(FixtureError::Invalid("runtime error identity".to_owned()));
    }
    if !value["wait_for_millis"].is_null()
        && value["wait_for_millis"]
            .as_i64()
            .is_none_or(|number| !(1..=120_000).contains(&number))
    {
        return Err(FixtureError::Invalid("runtime wait bound".to_owned()));
    }
    if !value["status"].is_null()
        && !matches!(
            value["status"].as_str(),
            Some("accepted" | "settled" | "rejected" | "unknown" | "cancelled")
        )
    {
        return Err(FixtureError::Invalid("runtime status".to_owned()));
    }
    if !value["wait_outcome"].is_null()
        && !matches!(
            value["wait_outcome"].as_str(),
            Some("successor" | "same_state_mutation" | "timeout" | "recovery_required")
        )
    {
        return Err(FixtureError::Invalid("runtime wait outcome".to_owned()));
    }
    if !value["observation"].is_null() {
        validate_runtime_observation(&value["observation"])?;
        if value["observation"]["generation"] != value["generation"]
            || value["observation"]["state_id"] != value["state_id"]
        {
            return Err(FixtureError::Invalid(
                "runtime observation/envelope relation".to_owned(),
            ));
        }
    }
    if !value["legal_actions"].is_null() {
        validate_runtime_legal_actions(&value["legal_actions"])?;
    }
    if !value["action"].is_null() {
        validate_runtime_legal_action(&value["action"])?;
    }
    if !value["transition"].is_null() {
        validate_runtime_transition(&value["transition"])?;
        if value["transition"]["to_generation"] != value["generation"]
            || value["transition"]["state_id"] != value["state_id"]
        {
            return Err(FixtureError::Invalid(
                "runtime transition/envelope relation".to_owned(),
            ));
        }
    }
    if !value["recovery"].is_null() {
        validate_runtime_recovery(&value["recovery"])?;
    }

    match kind {
        "state_request" | "reobserve_request" => {
            require_nulls(
                value,
                &[
                    "state_id",
                    "operation_id",
                    "observation",
                    "legal_actions",
                    "action",
                    "status",
                    "transition",
                    "error_code",
                    "wait_for_millis",
                    "wait_outcome",
                    "recovery",
                ],
            )?;
        }
        "state_response" | "reobserve_response" => {
            require_present(value, &["state_id", "observation", "legal_actions"])?;
            require_nulls(
                value,
                &[
                    "operation_id",
                    "action",
                    "status",
                    "transition",
                    "error_code",
                    "wait_for_millis",
                    "wait_outcome",
                    "recovery",
                ],
            )?;
        }
        "legal_actions_request" => {
            require_present(value, &["state_id"])?;
            require_nulls(
                value,
                &[
                    "operation_id",
                    "observation",
                    "legal_actions",
                    "action",
                    "status",
                    "transition",
                    "error_code",
                    "wait_for_millis",
                    "wait_outcome",
                    "recovery",
                ],
            )?;
        }
        "legal_actions_response" => {
            require_present(value, &["state_id", "legal_actions"])?;
            require_nulls(
                value,
                &[
                    "operation_id",
                    "observation",
                    "action",
                    "status",
                    "transition",
                    "error_code",
                    "wait_for_millis",
                    "wait_outcome",
                    "recovery",
                ],
            )?;
        }
        "dispatch_action_request" => {
            require_present(value, &["state_id", "operation_id", "action"])?;
            require_nulls(
                value,
                &[
                    "observation",
                    "legal_actions",
                    "status",
                    "transition",
                    "error_code",
                    "wait_for_millis",
                    "wait_outcome",
                    "recovery",
                ],
            )?;
        }
        "wait_request" => {
            require_present(value, &["operation_id", "wait_for_millis"])?;
            require_nulls(
                value,
                &[
                    "state_id",
                    "observation",
                    "legal_actions",
                    "action",
                    "status",
                    "transition",
                    "error_code",
                    "wait_outcome",
                    "recovery",
                ],
            )?;
        }
        "recover_request" => {
            require_present(value, &["recovery"])?;
            require_nulls(
                value,
                &[
                    "state_id",
                    "operation_id",
                    "observation",
                    "legal_actions",
                    "action",
                    "status",
                    "transition",
                    "error_code",
                    "wait_for_millis",
                    "wait_outcome",
                ],
            )?;
        }
        "dispatch_action_response" => validate_runtime_action_response(value)?,
        "wait_response" => validate_runtime_wait_response(value)?,
        "recover_response" => validate_runtime_recover_response(value)?,
        _ => return Err(FixtureError::Invalid("runtime kind".to_owned())),
    }
    Ok(())
}

fn require_present(value: &Value, fields: &[&str]) -> Result<(), FixtureError> {
    if fields.iter().any(|field| value[*field].is_null()) {
        Err(FixtureError::Invalid("runtime required field".to_owned()))
    } else {
        Ok(())
    }
}

fn require_nulls(value: &Value, fields: &[&str]) -> Result<(), FixtureError> {
    if fields.iter().any(|field| !value[*field].is_null()) {
        Err(FixtureError::Invalid("runtime field relation".to_owned()))
    } else {
        Ok(())
    }
}

fn validate_runtime_action_response(value: &Value) -> Result<(), FixtureError> {
    require_present(value, &["operation_id", "status"])?;
    require_nulls(
        value,
        &["action", "wait_for_millis", "wait_outcome", "recovery"],
    )?;
    match value["status"].as_str() {
        Some("settled") => {
            require_present(
                value,
                &["state_id", "observation", "legal_actions", "transition"],
            )?;
            if !value["error_code"].is_null() {
                return Err(FixtureError::Invalid("settled error".to_owned()));
            }
        }
        Some("accepted") => {
            require_present(value, &["state_id", "observation", "legal_actions"])?;
            require_nulls(value, &["transition", "error_code"])?;
        }
        Some("rejected" | "cancelled") => {
            require_present(
                value,
                &["state_id", "observation", "legal_actions", "error_code"],
            )?;
            require_nulls(value, &["transition"])?;
        }
        Some("unknown") => {
            require_nulls(value, &["observation", "legal_actions", "transition"])?;
            require_present(value, &["error_code"])?;
        }
        _ => return Err(FixtureError::Invalid("runtime action status".to_owned())),
    }
    Ok(())
}

fn validate_runtime_wait_response(value: &Value) -> Result<(), FixtureError> {
    require_present(value, &["operation_id", "status", "wait_outcome"])?;
    require_nulls(value, &["action", "wait_for_millis", "recovery"])?;
    match value["wait_outcome"].as_str() {
        Some("successor" | "same_state_mutation") => {
            if value["status"] != "settled" {
                return Err(FixtureError::Invalid("wait settled relation".to_owned()));
            }
            require_present(
                value,
                &["state_id", "observation", "legal_actions", "transition"],
            )?;
            require_nulls(value, &["error_code"])?;
        }
        Some("timeout" | "recovery_required") => {
            if value["status"] != "unknown" {
                return Err(FixtureError::Invalid("wait unknown relation".to_owned()));
            }
            require_nulls(value, &["observation", "legal_actions", "transition"])?;
            require_present(value, &["error_code"])?;
        }
        _ => return Err(FixtureError::Invalid("wait outcome".to_owned())),
    }
    Ok(())
}

fn validate_runtime_recover_response(value: &Value) -> Result<(), FixtureError> {
    require_present(value, &["operation_id", "status"])?;
    require_nulls(
        value,
        &["action", "wait_for_millis", "wait_outcome", "recovery"],
    )?;
    match value["status"].as_str() {
        Some("settled") => {
            require_present(
                value,
                &["state_id", "observation", "legal_actions", "transition"],
            )?;
            require_nulls(value, &["error_code"])?;
        }
        Some("accepted") => {
            require_present(value, &["state_id", "observation", "legal_actions"])?;
            require_nulls(value, &["transition", "error_code"])?;
        }
        Some("cancelled") => {
            require_present(
                value,
                &["state_id", "observation", "legal_actions", "error_code"],
            )?;
            require_nulls(value, &["transition"])?;
        }
        Some("unknown") => {
            require_nulls(value, &["observation", "legal_actions", "transition"])?;
            require_present(value, &["error_code"])?;
        }
        _ => return Err(FixtureError::Invalid("recover status".to_owned())),
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_runtime_observation(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["state_id", "generation", "visible_seed", "player", "state"],
        &["state_id", "generation", "visible_seed", "player", "state"],
    )?;
    if !value["state_id"].as_str().is_some_and(valid_identity)
        || value["generation"]
            .as_i64()
            .is_none_or(|number| !(0..=MAX_RUNTIME_INTEGER).contains(&number))
    {
        return Err(FixtureError::Invalid("runtime observation".to_owned()));
    }
    if !value["visible_seed"].is_null() && !value["visible_seed"].as_str().is_some_and(valid_text) {
        return Err(FixtureError::Invalid("runtime visible seed".to_owned()));
    }
    object_fields(
        &value["player"],
        &[
            "hp", "max_hp", "energy", "gold", "hand", "deck", "discard", "exhaust",
        ],
        &[
            "hp", "max_hp", "energy", "gold", "hand", "deck", "discard", "exhaust",
        ],
    )?;
    for name in ["hp", "max_hp"] {
        if value["player"][name]
            .as_i64()
            .is_none_or(|number| !(0..=65_535).contains(&number))
        {
            return Err(FixtureError::Invalid("runtime player".to_owned()));
        }
    }
    if value["player"]["hp"].as_i64() > value["player"]["max_hp"].as_i64() {
        return Err(FixtureError::Invalid("runtime player health".to_owned()));
    }
    if value["player"]["energy"]
        .as_i64()
        .is_none_or(|number| !(0..=255).contains(&number))
        || value["player"]["gold"]
            .as_u64()
            .is_none_or(|number| number > 4_294_967_295)
    {
        return Err(FixtureError::Invalid("runtime player resources".to_owned()));
    }
    for name in ["hand", "deck", "discard", "exhaust"] {
        let Some(cards) = value["player"][name].as_array() else {
            return Err(FixtureError::Invalid("runtime card list".to_owned()));
        };
        if cards.len() > 256 {
            return Err(FixtureError::Bounds("runtime card list"));
        }
        for card in cards {
            validate_runtime_card(card)?;
        }
    }
    let state = &value["state"];
    let state_name = field_string(state, "state")?;
    match state_name.as_str() {
        "setup" => {
            object_fields(state, &["state", "characters"], &["state", "characters"])?;
            validate_runtime_identity_array(&state["characters"])?;
        }
        "map" => {
            object_fields(
                state,
                &["state", "node_id", "options"],
                &["state", "node_id", "options"],
            )?;
            if !state["node_id"].is_null() && !state["node_id"].as_str().is_some_and(valid_identity)
            {
                return Err(FixtureError::Invalid("runtime map node".to_owned()));
            }
            validate_runtime_identity_array(&state["options"])?;
        }
        "combat" => {
            object_fields(
                state,
                &["state", "turn_index", "enemies"],
                &["state", "turn_index", "enemies"],
            )?;
            if state["turn_index"]
                .as_i64()
                .is_none_or(|number| !(0..=65_535).contains(&number))
            {
                return Err(FixtureError::Invalid("runtime combat".to_owned()));
            }
            let Some(enemies) = state["enemies"].as_array() else {
                return Err(FixtureError::Invalid("runtime combat enemies".to_owned()));
            };
            if enemies.len() > 256 {
                return Err(FixtureError::Bounds("runtime enemies"));
            }
            for enemy in enemies {
                validate_runtime_enemy(enemy)?;
            }
        }
        "reward" | "rest" => {
            object_fields(state, &["state", "options"], &["state", "options"])?;
            validate_runtime_identity_array(&state["options"])?;
        }
        "shop" => {
            object_fields(state, &["state", "items"], &["state", "items"])?;
            let Some(items) = state["items"].as_array() else {
                return Err(FixtureError::Invalid("runtime shop items".to_owned()));
            };
            if items.len() > 256 {
                return Err(FixtureError::Bounds("runtime shop items"));
            }
            for item in items {
                validate_runtime_shop_item(item)?;
            }
        }
        "event" | "selection" => {
            object_fields(state, &["state", "choices"], &["state", "choices"])?;
            validate_runtime_identity_array(&state["choices"])?;
        }
        "victory" => {
            object_fields(state, &["state"], &["state"])?;
        }
        "defeat" => {
            object_fields(state, &["state", "reason"], &["state", "reason"])?;
            if !state["reason"].is_null() && !state["reason"].as_str().is_some_and(valid_text) {
                return Err(FixtureError::Invalid("runtime defeat reason".to_owned()));
            }
        }
        "recovery" => {
            object_fields(state, &["state", "code"], &["state", "code"])?;
            if !state["code"].as_str().is_some_and(valid_identity) {
                return Err(FixtureError::Invalid("runtime recovery code".to_owned()));
            }
        }
        _ => return Err(FixtureError::Invalid("runtime state".to_owned())),
    }
    Ok(())
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

fn validate_runtime_identity_array(value: &Value) -> Result<(), FixtureError> {
    let Some(values) = value.as_array() else {
        return Err(FixtureError::Invalid("runtime identity list".to_owned()));
    };
    if values.len() > 256
        || values
            .iter()
            .any(|item| !item.as_str().is_some_and(valid_identity))
    {
        return Err(FixtureError::Invalid("runtime identity list".to_owned()));
    }
    Ok(())
}

fn validate_runtime_card(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["card_id", "name", "cost", "upgraded"],
        &["card_id", "name", "cost", "upgraded"],
    )?;
    if !valid_identity(&field_string(value, "card_id")?)
        || !valid_text(&field_string(value, "name")?)
        || field_i64(value, "cost")?.is_negative()
        || field_i64(value, "cost")? > 255
        || !value["upgraded"].is_boolean()
    {
        return Err(FixtureError::Invalid("runtime card".to_owned()));
    }
    Ok(())
}

fn validate_runtime_enemy(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["enemy_id", "name", "hp", "max_hp", "intent"],
        &["enemy_id", "name", "hp", "max_hp", "intent"],
    )?;
    if !valid_identity(&field_string(value, "enemy_id")?)
        || !valid_text(&field_string(value, "name")?)
        || field_i64(value, "hp")?.is_negative()
        || field_i64(value, "hp")? > 65_535
        || field_i64(value, "max_hp")?.is_negative()
        || field_i64(value, "max_hp")? > 65_535
        || field_i64(value, "hp")? > field_i64(value, "max_hp")?
    {
        return Err(FixtureError::Invalid("runtime enemy".to_owned()));
    }
    let intent = &value["intent"];
    let kind = field_string(intent, "kind")?;
    match kind.as_str() {
        "attack" => {
            object_fields(
                intent,
                &["kind", "damage", "hits"],
                &["kind", "damage", "hits"],
            )?;
            if field_i64(intent, "damage")?.is_negative()
                || field_i64(intent, "damage")? > 65_535
                || field_i64(intent, "hits")? < 1
                || field_i64(intent, "hits")? > 255
            {
                return Err(FixtureError::Invalid("runtime enemy attack".to_owned()));
            }
        }
        "defend" | "buff" | "debuff" | "unknown" => {
            object_fields(intent, &["kind"], &["kind"])?;
        }
        _ => return Err(FixtureError::Invalid("runtime enemy intent".to_owned())),
    }
    Ok(())
}

fn validate_runtime_shop_item(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["item_id", "name", "price"],
        &["item_id", "name", "price"],
    )?;
    if !valid_identity(&field_string(value, "item_id")?)
        || !valid_text(&field_string(value, "name")?)
        || field_i64(value, "price")?.is_negative()
    {
        return Err(FixtureError::Invalid("runtime shop item".to_owned()));
    }
    // `price` is an unsigned 32-bit JSON integer in the frozen schema.
    if value["price"]
        .as_u64()
        .is_none_or(|price| price > 4_294_967_295)
    {
        return Err(FixtureError::Invalid("runtime shop price".to_owned()));
    }
    Ok(())
}

fn validate_runtime_legal_actions(value: &Value) -> Result<(), FixtureError> {
    let actions = value
        .as_array()
        .ok_or_else(|| FixtureError::Invalid("runtime legal actions".to_owned()))?;
    if actions.len() > 256 {
        return Err(FixtureError::Bounds("runtime legal actions"));
    }
    for (index, action) in actions.iter().enumerate() {
        validate_runtime_legal_action(action)?;
        if actions[..index]
            .iter()
            .any(|previous| previous["action_id"] == action["action_id"])
        {
            return Err(FixtureError::Invalid(
                "duplicate runtime action id".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_runtime_legal_action(value: &Value) -> Result<(), FixtureError> {
    object_fields(value, &["action_id", "action"], &["action_id", "action"])?;
    if !valid_identity(&field_string(value, "action_id")?) {
        return Err(FixtureError::Invalid("runtime action id".to_owned()));
    }
    let action = &value["action"];
    let kind = field_string(action, "kind")?;
    let required: &[&str] = match kind.as_str() {
        "end_turn" | "skip_reward" | "rest" | "confirm_victory" | "save_quit" | "proceed"
        | "confirm_selection" | "cancel_selection" => &[],
        "start_run" => &["character_id"],
        "select_map_node" => &["node_id"],
        "play_card" => &["card_id", "target_id"],
        "choose_reward" => &["reward_id"],
        "shop_purchase" => &["item_id"],
        "shop_remove" | "smith" | "select_card" => &["card_id"],
        "event_choice" => &["choice_id"],
        _ => return Err(FixtureError::Invalid("runtime action kind".to_owned())),
    };
    let mut allowed = vec!["kind"];
    allowed.extend(required.iter().copied());
    object_fields(action, &allowed, &allowed)?;
    for field in required {
        if *field == "target_id" && action[*field].is_null() {
            continue;
        }
        if !action[*field].as_str().is_some_and(valid_identity) {
            return Err(FixtureError::Invalid("runtime action argument".to_owned()));
        }
    }
    Ok(())
}

fn validate_runtime_transition(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "from_generation",
            "to_generation",
            "state_id",
            "effect_kind",
        ],
        &[
            "from_generation",
            "to_generation",
            "state_id",
            "effect_kind",
        ],
    )?;
    let from_generation = field_i64(value, "from_generation")?;
    let to_generation = field_i64(value, "to_generation")?;
    if !(0..=MAX_RUNTIME_INTEGER).contains(&from_generation)
        || !(0..=MAX_RUNTIME_INTEGER).contains(&to_generation)
        || to_generation <= from_generation
        || !valid_identity(&field_string(value, "state_id")?)
        || !valid_identity(&field_string(value, "effect_kind")?)
    {
        return Err(FixtureError::Invalid("runtime transition".to_owned()));
    }
    Ok(())
}

fn validate_runtime_witness(
    value: &Value,
    expected_operation_id: &str,
    expected_action_digest: &str,
) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "witness_id",
            "operation_id",
            "action_digest",
            "source",
            "pre_state_id",
            "pre_generation",
            "state_id",
            "generation",
            "effect_digest",
            "observed_at",
        ],
        &[
            "witness_id",
            "operation_id",
            "action_digest",
            "source",
            "pre_state_id",
            "pre_generation",
            "state_id",
            "generation",
            "effect_digest",
            "observed_at",
        ],
    )?;
    for name in ["witness_id", "operation_id"] {
        if !valid_identity(&field_string(value, name)?) {
            return Err(FixtureError::Invalid("runtime witness identity".to_owned()));
        }
    }
    if field_string(value, "operation_id")? != expected_operation_id
        || field_string(value, "action_digest")? != expected_action_digest
        || field_string(value, "source")? != EFFECT_WITNESS_SOURCE
        || !valid_identity(&field_string(value, "pre_state_id")?)
        || !valid_identity(&field_string(value, "state_id")?)
        || !(0..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "pre_generation")?)
        || !(0..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "generation")?)
        || field_i64(value, "generation")? <= field_i64(value, "pre_generation")?
    {
        return Err(FixtureError::Invalid("runtime witness relation".to_owned()));
    }
    validate_digest(&field_string(value, "action_digest")?)?;
    validate_digest(&field_string(value, "effect_digest")?)?;
    if !valid_timestamp(&field_string(value, "observed_at")?) {
        return Err(FixtureError::Invalid(
            "runtime witness timestamp".to_owned(),
        ));
    }
    Ok(())
}

fn validate_runtime_recovery(value: &Value) -> Result<(), FixtureError> {
    object_fields(value, &["kind", "operation_id"], &["kind", "operation_id"])?;
    let kind = field_string(value, "kind")?;
    if !matches!(
        kind.as_str(),
        "reobserve" | "reconcile" | "release_lease" | "stop_episode"
    ) {
        return Err(FixtureError::Invalid("runtime recovery kind".to_owned()));
    }
    if kind == "reconcile" {
        if !value["operation_id"].as_str().is_some_and(valid_identity) {
            return Err(FixtureError::Invalid("recovery operation".to_owned()));
        }
    } else if !value["operation_id"].is_null() {
        return Err(FixtureError::Invalid(
            "recovery operation relation".to_owned(),
        ));
    }
    Ok(())
}

fn validate_release(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "release_digest",
            "config_digest",
            "profile_digest",
            "runtime_v3_schema_digest",
        ],
        &[
            "release_digest",
            "config_digest",
            "profile_digest",
            "runtime_v3_schema_digest",
        ],
    )?;
    for name in [
        "release_digest",
        "config_digest",
        "profile_digest",
        "runtime_v3_schema_digest",
    ] {
        validate_digest(&field_string(value, name)?)?;
    }
    Ok(())
}

fn validate_policy(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["ttl_seconds", "renewal_interval_seconds"],
        &["ttl_seconds", "renewal_interval_seconds"],
    )?;
    let ttl = field_i64(value, "ttl_seconds")?;
    let renewal = field_i64(value, "renewal_interval_seconds")?;
    validate_lease_policy_values(ttl, renewal)
}

fn validate_lease_policy_values(ttl: i64, renewal: i64) -> Result<(), FixtureError> {
    if !(5..=300).contains(&ttl) || !(1..=100).contains(&renewal) || renewal >= ttl {
        return Err(FixtureError::Invalid("lease policy".to_owned()));
    }
    Ok(())
}

fn validate_boot_context(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "deployment_id",
            "instance_id",
            "instance_incarnation",
            "boot_id",
            "authority_generation",
            "release",
            "created_at",
            "state",
        ],
        &[
            "deployment_id",
            "instance_id",
            "instance_incarnation",
            "boot_id",
            "authority_generation",
            "release",
            "created_at",
            "state",
        ],
    )?;
    valid_v4(&field_string(value, "deployment_id")?)?;
    valid_v4(&field_string(value, "instance_id")?)?;
    valid_v4(&field_string(value, "instance_incarnation")?)?;
    valid_v4(&field_string(value, "boot_id")?)?;
    if !(1..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "authority_generation")?)
        || !valid_timestamp(&field_string(value, "created_at")?)
    {
        return Err(FixtureError::Invalid("boot context".to_owned()));
    }
    validate_release(&value["release"])?;
    if !matches!(
        field_string(value, "state")?.as_str(),
        "FENCE_REQUIRED" | "READY" | "BLOCKED" | "REVOKED"
    ) {
        return Err(FixtureError::Invalid("boot state".to_owned()));
    }
    Ok(())
}

fn validate_host_fence(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "host_fence_id",
            "deployment_id",
            "instance_id",
            "instance_incarnation",
            "boot_id",
            "authority_generation",
            "fence_generation",
            "created_at",
        ],
        &[
            "host_fence_id",
            "deployment_id",
            "instance_id",
            "instance_incarnation",
            "boot_id",
            "authority_generation",
            "fence_generation",
            "created_at",
        ],
    )?;
    for name in [
        "host_fence_id",
        "deployment_id",
        "instance_id",
        "instance_incarnation",
        "boot_id",
    ] {
        valid_v4(&field_string(value, name)?)?;
    }
    if !(1..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "authority_generation")?)
        || !(1..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "fence_generation")?)
        || !valid_timestamp(&field_string(value, "created_at")?)
    {
        return Err(FixtureError::Invalid("host fence".to_owned()));
    }
    Ok(())
}

fn validate_lease_context(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "deployment_id",
            "instance_id",
            "instance_incarnation",
            "boot_id",
            "authority_generation",
            "lease_id",
            "lease_epoch",
            "fence_token",
            "issued_at",
            "expires_at",
            "ttl_seconds",
            "renewal_interval_seconds",
        ],
        &[
            "deployment_id",
            "instance_id",
            "instance_incarnation",
            "boot_id",
            "authority_generation",
            "lease_id",
            "lease_epoch",
            "fence_token",
            "issued_at",
            "expires_at",
            "ttl_seconds",
            "renewal_interval_seconds",
        ],
    )?;
    for name in [
        "deployment_id",
        "instance_id",
        "instance_incarnation",
        "boot_id",
        "lease_id",
    ] {
        valid_v4(&field_string(value, name)?)?;
    }
    let token = field_string(value, "fence_token")?;
    if token.len() != 43
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(FixtureError::Invalid("fence token".to_owned()));
    }
    if !(1..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "authority_generation")?)
        || !(1..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "lease_epoch")?)
        || !valid_timestamp(&field_string(value, "issued_at")?)
        || !valid_timestamp(&field_string(value, "expires_at")?)
    {
        return Err(FixtureError::Invalid("lease context".to_owned()));
    }
    let ttl = field_i64(value, "ttl_seconds")?;
    let renewal = field_i64(value, "renewal_interval_seconds")?;
    validate_lease_policy_values(ttl, renewal)
}

fn validate_original_context(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "deployment_id",
            "instance_id",
            "instance_incarnation",
            "boot_id",
            "authority_generation",
            "lease_id",
            "lease_epoch",
        ],
        &[
            "deployment_id",
            "instance_id",
            "instance_incarnation",
            "boot_id",
            "authority_generation",
            "lease_id",
            "lease_epoch",
        ],
    )?;
    for name in [
        "deployment_id",
        "instance_id",
        "instance_incarnation",
        "boot_id",
        "lease_id",
    ] {
        valid_v4(&field_string(value, name)?)?;
    }
    if !(1..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "authority_generation")?)
        || !(1..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "lease_epoch")?)
    {
        return Err(FixtureError::Invalid("original context".to_owned()));
    }
    Ok(())
}

fn validate_expected_boundary(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["state_id", "generation", "catalog_digest"],
        &["state_id", "generation", "catalog_digest"],
    )?;
    valid_v4(&field_string(value, "state_id")?)?;
    if !(0..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "generation")?) {
        return Err(FixtureError::Invalid("boundary generation".to_owned()));
    }
    validate_digest(&field_string(value, "catalog_digest")?)
}

fn validate_operation_full(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "operation_id",
            "payload_digest",
            "original_context",
            "expected_boundary",
            "action",
        ],
        &[
            "operation_id",
            "payload_digest",
            "original_context",
            "expected_boundary",
            "action",
        ],
    )?;
    valid_v4(&field_string(value, "operation_id")?)?;
    let payload_digest = field_string(value, "payload_digest")?;
    validate_digest(&payload_digest)?;
    validate_original_context(&value["original_context"])?;
    validate_expected_boundary(&value["expected_boundary"])?;
    validate_v3_action(&value["action"], Some(&payload_digest))
}

fn validate_operation_ref(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["operation_id", "payload_digest", "original_context"],
        &["operation_id", "payload_digest", "original_context"],
    )?;
    valid_v4(&field_string(value, "operation_id")?)?;
    validate_digest(&field_string(value, "payload_digest")?)?;
    validate_original_context(&value["original_context"])
}

fn validate_operation_context(operation: &Value, lease: &Value) -> Result<(), FixtureError> {
    let context = operation
        .get("original_context")
        .ok_or_else(|| FixtureError::Invalid("original context missing".to_owned()))?;
    for name in [
        "deployment_id",
        "instance_id",
        "instance_incarnation",
        "boot_id",
        "authority_generation",
        "lease_id",
        "lease_epoch",
    ] {
        if context[name] != lease[name] {
            return Err(FixtureError::Stale("lease"));
        }
    }
    Ok(())
}

fn validate_v3_action(value: &Value, expected_digest: Option<&String>) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["schema_digest", "canonical_json_b64", "payload_digest"],
        &["schema_digest", "canonical_json_b64", "payload_digest"],
    )?;
    validate_digest(&field_string(value, "schema_digest")?)?;
    let encoded = field_string(value, "canonical_json_b64")?;
    if encoded.is_empty() || encoded.len() > MAX_ACTION_BYTES {
        return Err(FixtureError::Bounds("canonical action"));
    }
    let bytes = decode_base64_strict(&encoded)
        .ok_or_else(|| FixtureError::Invalid("canonical action base64".to_owned()))?;
    if bytes.len() > MAX_ACTION_BYTES || !rcj_action_valid(&bytes) {
        return Err(FixtureError::Invalid("canonical action".to_owned()));
    }
    let digest_value = field_string(value, "payload_digest")?;
    validate_digest(&digest_value)?;
    if sha256_hex(&bytes) != digest_value
        || expected_digest.is_some_and(|expected| expected != &digest_value)
    {
        return Err(FixtureError::Conflict);
    }
    Ok(())
}

fn validate_operation_record(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "operation_id",
            "state",
            "payload_digest",
            "original_context",
            "expected_boundary",
            "action",
            "ticket",
            "witness",
            "uncertainty_reason",
            "created_at",
            "updated_at",
        ],
        &[
            "operation_id",
            "state",
            "payload_digest",
            "original_context",
            "expected_boundary",
            "action",
            "ticket",
            "witness",
            "uncertainty_reason",
            "created_at",
            "updated_at",
        ],
    )?;
    valid_v4(&field_string(value, "operation_id")?)?;
    let payload_digest = field_string(value, "payload_digest")?;
    validate_digest(&payload_digest)?;
    validate_original_context(&value["original_context"])?;
    validate_expected_boundary(&value["expected_boundary"])?;
    validate_v3_action(&value["action"], Some(&payload_digest))?;
    if !value["ticket"].is_null() {
        validate_ticket_shape(&value["ticket"])?;
    }
    if !value["witness"].is_null() {
        validate_effect_witness(
            &value["witness"],
            &field_string(value, "operation_id")?,
            &payload_digest,
        )?;
    }
    if !value["uncertainty_reason"].is_null()
        && !matches!(
            value["uncertainty_reason"].as_str(),
            Some(
                "transport_lost"
                    | "timeout"
                    | "gateway_crash"
                    | "host_crash"
                    | "receipt_missing"
                    | "authority_rotated"
            )
        )
    {
        return Err(FixtureError::Invalid("uncertainty reason".to_owned()));
    }
    if !valid_timestamp(&field_string(value, "created_at")?)
        || !valid_timestamp(&field_string(value, "updated_at")?)
    {
        return Err(FixtureError::Invalid("operation timestamps".to_owned()));
    }
    if !matches!(
        field_string(value, "state")?.as_str(),
        "INTENT_RECORDED"
            | "MAY_HAVE_BEEN_DISPATCHED"
            | "ACCEPTED"
            | "SETTLED"
            | "REJECTED"
            | "UNKNOWN"
            | "RECONCILED"
    ) {
        return Err(FixtureError::Invalid("operation state".to_owned()));
    }
    Ok(())
}

fn validate_ticket_shape(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "ticket_id",
            "operation_id",
            "payload_digest",
            "boot_id",
            "instance_incarnation",
            "lease_epoch",
            "host_fence_id",
            "state",
            "issued_at",
            "expires_at",
        ],
        &[
            "ticket_id",
            "operation_id",
            "payload_digest",
            "boot_id",
            "instance_incarnation",
            "lease_epoch",
            "host_fence_id",
            "state",
            "issued_at",
            "expires_at",
        ],
    )?;
    for name in [
        "ticket_id",
        "operation_id",
        "boot_id",
        "instance_incarnation",
        "host_fence_id",
    ] {
        valid_v4(&field_string(value, name)?)?;
    }
    validate_digest(&field_string(value, "payload_digest")?)?;
    if !(1..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "lease_epoch")?)
        || !valid_timestamp(&field_string(value, "issued_at")?)
        || !valid_timestamp(&field_string(value, "expires_at")?)
    {
        return Err(FixtureError::Invalid("ticket".to_owned()));
    }
    if !matches!(
        field_string(value, "state")?.as_str(),
        "ISSUED"
            | "ADMITTED"
            | "EXECUTING"
            | "EFFECT_WITNESS_RECORDED"
            | "SETTLED"
            | "REJECTED"
            | "UNKNOWN"
    ) {
        return Err(FixtureError::Invalid("ticket state".to_owned()));
    }
    Ok(())
}

fn validate_ticket(
    value: &Value,
    id: &str,
    payload_digest: &str,
    context_json: &str,
) -> Result<(), FixtureError> {
    validate_ticket_shape(value)?;
    if field_string(value, "operation_id")? != id
        || field_string(value, "payload_digest")? != payload_digest
    {
        return Err(FixtureError::Conflict);
    }
    let context: Value = parse_value_no_duplicates(context_json.as_bytes())?;
    for name in ["instance_incarnation", "boot_id", "lease_epoch"] {
        if value[name] != context[name] {
            return Err(FixtureError::Stale("lease"));
        }
    }
    Ok(())
}

fn validate_effect_witness(
    value: &Value,
    expected_id: &str,
    expected_digest: &str,
) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "witness_id",
            "operation_id",
            "payload_digest",
            "boot_id",
            "instance_incarnation",
            "host_fence_id",
            "source",
            "state_id",
            "generation",
            "effect_digest",
            "observed_at",
        ],
        &[
            "witness_id",
            "operation_id",
            "payload_digest",
            "boot_id",
            "instance_incarnation",
            "host_fence_id",
            "source",
            "state_id",
            "generation",
            "effect_digest",
            "observed_at",
        ],
    )?;
    for name in [
        "witness_id",
        "operation_id",
        "boot_id",
        "instance_incarnation",
        "host_fence_id",
        "state_id",
    ] {
        valid_v4(&field_string(value, name)?)?;
    }
    let payload_digest = field_string(value, "payload_digest")?;
    validate_digest(&payload_digest)?;
    if (!expected_id.is_empty() && field_string(value, "operation_id")? != expected_id)
        || (!expected_digest.is_empty() && payload_digest != expected_digest)
    {
        return Err(FixtureError::Conflict);
    }
    if !matches!(
        field_string(value, "source")?.as_str(),
        "host_game_thread" | "host_receipt" | "authoritative_reobserve"
    ) || !(0..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "generation")?)
        || !valid_timestamp(&field_string(value, "observed_at")?)
    {
        return Err(FixtureError::Invalid("effect witness".to_owned()));
    }
    validate_digest(&field_string(value, "effect_digest")?)
}

fn validate_receipt(
    value: &Value,
    witness: &Value,
    id: &str,
    payload_digest: &str,
) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["operation_id", "payload_digest", "status", "effect_witness"],
        &["operation_id", "payload_digest", "status", "effect_witness"],
    )?;
    if field_string(value, "operation_id")? != id
        || field_string(value, "payload_digest")? != payload_digest
        || field_string(value, "status")? != "settled"
        || value["effect_witness"] != *witness
    {
        return Err(FixtureError::Conflict);
    }
    Ok(())
}

fn rcj_action_valid(bytes: &[u8]) -> bool {
    if bytes.is_empty()
        || bytes.iter().any(|byte| {
            !byte.is_ascii()
                || byte.is_ascii_whitespace()
                || *byte == b'\\'
                || byte.is_ascii_control()
        })
    {
        return false;
    }
    let Ok(value) = parse_value_no_duplicates(bytes) else {
        return false;
    };
    let Ok(canonical) = serde_json::to_vec(&value) else {
        return false;
    };
    if canonical != bytes {
        return false;
    }
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.len() != 2 || !object.contains_key("action") || !object.contains_key("action_id") {
        return false;
    }
    let Some(action_id) = object["action_id"].as_str() else {
        return false;
    };
    if !valid_identity(action_id) {
        return false;
    }
    let Some(action) = object["action"].as_object() else {
        return false;
    };
    let Some(kind) = action.get("kind").and_then(Value::as_str) else {
        return false;
    };
    let required: &[&str] = match kind {
        "end_turn" | "skip_reward" | "rest" | "confirm_victory" | "save_quit" | "proceed"
        | "confirm_selection" | "cancel_selection" => &[],
        "start_run" => &["character_id"],
        "select_map_node" => &["node_id"],
        "play_card" => &["card_id", "target_id"],
        "choose_reward" => &["reward_id"],
        "shop_purchase" => &["item_id"],
        "shop_remove" | "smith" | "select_card" => &["card_id"],
        "event_choice" => &["choice_id"],
        _ => return false,
    };
    action.len() == required.len() + 1
        && required.iter().all(|field| {
            action.get(*field).is_some_and(|entry| {
                (entry.is_null() && *field == "target_id")
                    || entry.as_str().is_some_and(valid_identity)
            })
        })
}

fn decode_base64_strict(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(4) {
        return None;
    }
    let mut output = Vec::with_capacity(value.len() / 4 * 3);
    for (index, chunk) in value.as_bytes().chunks(4).enumerate() {
        let is_last = index + 1 == value.len() / 4;
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c_padding = chunk[2] == b'=';
        let d_padding = chunk[3] == b'=';
        if c_padding {
            if !is_last || !d_padding {
                return None;
            }
            if b & 0x0f != 0 {
                return None;
            }
            output.push((a << 2) | (b >> 4));
        } else {
            let c = base64_value(chunk[2])?;
            if d_padding {
                if !is_last {
                    return None;
                }
                if c & 0x03 != 0 {
                    return None;
                }
                output.push((a << 2) | (b >> 4));
                output.push((b << 4) | (c >> 2));
            } else {
                let d = base64_value(chunk[3])?;
                output.push((a << 2) | (b >> 4));
                output.push((b << 4) | (c >> 2));
                output.push((c << 6) | d);
            }
        }
    }
    Some(output)
}

fn base64_value(value: u8) -> Option<u8> {
    match value {
        b'A'..=b'Z' => Some(value - b'A'),
        b'a'..=b'z' => Some(value - b'a' + 26),
        b'0'..=b'9' => Some(value - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut result = String::with_capacity(64);
    for byte in hasher.finalize() {
        let _ = write!(&mut result, "{byte:02x}");
    }
    result
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
    Busy,
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
            Self::Busy => "BUSY",
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
            Self::Busy => formatter.write_str("busy"),
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

    #[test]
    fn nested_duplicate_json_members_are_rejected() {
        let error = parse_value_no_duplicates(
            br#"{"outer":{"key":1,"key":2},"array":[{"same":true,"same":false}]}"#,
        )
        .expect_err("duplicate members must not use last-value-wins parsing");
        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    fn runtime_semantic_bounds_match_the_frozen_schema() {
        let empty_action = json!({
            "action_id":"",
            "action":{"kind":"end_turn"}
        });
        assert!(validate_runtime_legal_action(&empty_action).is_err());
        let empty_name = json!({
            "state_id":"state-1",
            "generation":0,
            "visible_seed":null,
            "player":{"hp":1,"max_hp":1,"energy":1,"gold":0,"hand":[],"deck":[],"discard":[],"exhaust":[]},
            "state":{"state":"combat","turn_index":0,"enemies":[{"enemy_id":"enemy-1","name":"","hp":0,"max_hp":0,"intent":{"kind":"unknown"}}]}
        });
        assert!(validate_runtime_observation(&empty_name).is_err());
    }

    #[test]
    fn database_sidecar_lock_rejects_a_second_owner() {
        let path =
            std::env::temp_dir().join(format!("watchdog-lock-test-{}.sqlite", Uuid::new_v4()));
        let owner = DurableHost::open(&path).expect("first owner opens");
        assert!(matches!(DurableHost::open(&path), Err(FixtureError::Busy)));
        drop(owner);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite-shm"));
        let _ = fs::remove_file(path.with_extension("sqlite.lock"));
    }
}
