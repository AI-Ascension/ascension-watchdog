//! Closed, bounded admin request and response types.

#![cfg_attr(
    not(unix),
    allow(
        dead_code,
        unused_imports,
        reason = "duplicate-key and payload helpers are used only by the Unix transport"
    )
)]

use super::{MAX_DEADLINE_MS, MAX_FRAME_BYTES, MAX_PAYLOAD_BYTES};
use crate::error::WatchdogError;
use serde::de::{DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer as _, Serialize, Serializer, de};
use serde_json::Deserializer;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use uuid::Uuid;

const MAX_ID_BYTES: usize = 128;
const MAX_REASON_BYTES: usize = 512;
const MAX_TOKEN_BYTES: usize = 4 * 1024;
const MAX_RELEASE_BYTES: usize = 128;
const MAX_RESULT_ITEMS: usize = 256;
const MAX_JOB_KIND_BYTES: usize = 128;

/// The two credentials are intentionally separate.  `Admin` is required for
/// every desired-state or recovery transition; a read credential can never
/// claim that capability.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Status, jobs, attempts and release inspection only.
    Read,
    /// Desired-state, recovery, backup, restore and activation operations.
    Admin,
}

/// Coarse identity of the principal that passed transport authentication.
///
/// This value is deliberately an enum rather than a token, SID, path, or
/// arbitrary provider claim.  It is safe to persist in a watchdog audit row
/// and is the only credential-related value that crosses the queue boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticatedPrincipalClass {
    /// The owner-local read credential authenticated the request.
    ReadToken,
    /// The owner-local administrator credential authenticated the request.
    AdminToken,
    /// The protected Windows named-pipe peer SID authenticated the request.
    WindowsOperator,
}

impl Capability {
    /// Whether this capability may satisfy the required capability.
    #[must_use]
    pub const fn includes(self, required: Self) -> bool {
        matches!(
            (self, required),
            (Self::Admin, _) | (Self::Read, Self::Read)
        )
    }
}

/// Fixed command names.  There is deliberately no `play`, `dispatch`,
/// `settle`, `send`, `mutate`, or generic proxy command in this enum.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandName {
    Status,
    Start,
    Pause,
    Resume,
    Drain,
    Stop,
    Jobs,
    Attempt,
    Quarantine,
    Retry,
    Reconcile,
    Backup,
    Restore,
    ReleaseInspect,
    ReleaseActivate,
}

impl CommandName {
    /// Capability required by a command.
    #[must_use]
    pub const fn required_capability(self) -> Capability {
        match self {
            Self::Status | Self::Jobs | Self::Attempt | Self::ReleaseInspect => Capability::Read,
            Self::Start
            | Self::Pause
            | Self::Resume
            | Self::Drain
            | Self::Stop
            | Self::Quarantine
            | Self::Retry
            | Self::Reconcile
            | Self::Backup
            | Self::Restore
            | Self::ReleaseActivate => Capability::Admin,
        }
    }
}

/// Empty parameters are still explicit on the wire (`params: {}`).  This
/// prevents command variants from growing an unreviewed free-form payload.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyParams {}

/// A bounded command request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdminCommand {
    Status(EmptyParams),
    Start(EmptyParams),
    Pause(EmptyParams),
    Resume(EmptyParams),
    Drain(EmptyParams),
    Stop(EmptyParams),
    Jobs(JobsRequest),
    Attempt(AttemptRequest),
    Quarantine(QuarantineRequest),
    Retry(RetryRequest),
    Reconcile(ReconcileRequest),
    Backup(BackupRequest),
    Restore(RestoreRequest),
    ReleaseInspect(ReleaseInspectRequest),
    ReleaseActivate(ReleaseActivateRequest),
}

impl AdminCommand {
    /// Return the closed command name.
    #[must_use]
    pub const fn name(&self) -> CommandName {
        match self {
            Self::Status(_) => CommandName::Status,
            Self::Start(_) => CommandName::Start,
            Self::Pause(_) => CommandName::Pause,
            Self::Resume(_) => CommandName::Resume,
            Self::Drain(_) => CommandName::Drain,
            Self::Stop(_) => CommandName::Stop,
            Self::Jobs(_) => CommandName::Jobs,
            Self::Attempt(_) => CommandName::Attempt,
            Self::Quarantine(_) => CommandName::Quarantine,
            Self::Retry(_) => CommandName::Retry,
            Self::Reconcile(_) => CommandName::Reconcile,
            Self::Backup(_) => CommandName::Backup,
            Self::Restore(_) => CommandName::Restore,
            Self::ReleaseInspect(_) => CommandName::ReleaseInspect,
            Self::ReleaseActivate(_) => CommandName::ReleaseActivate,
        }
    }

    /// Validate command-specific bounds and invariants.
    pub fn validate(&self) -> std::result::Result<(), String> {
        match self {
            Self::Status(_)
            | Self::Start(_)
            | Self::Pause(_)
            | Self::Resume(_)
            | Self::Drain(_)
            | Self::Stop(_) => Ok(()),
            Self::Jobs(value) => value.validate(),
            Self::Attempt(value) => value.validate(),
            Self::Quarantine(value) => value.validate(),
            Self::Retry(value) => value.validate(),
            Self::Reconcile(value) => value.validate(),
            Self::Backup(value) => value.validate(),
            Self::Restore(value) => value.validate(),
            Self::ReleaseInspect(value) => value.validate(),
            Self::ReleaseActivate(value) => value.validate(),
        }
    }
}

/// Custom serialization keeps the command envelope closed and deterministic.
impl Serialize for AdminCommand {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut envelope = serializer.serialize_struct("AdminCommand", 2)?;
        envelope.serialize_field("kind", &self.name())?;
        match self {
            Self::Status(params)
            | Self::Start(params)
            | Self::Pause(params)
            | Self::Resume(params)
            | Self::Drain(params)
            | Self::Stop(params) => envelope.serialize_field("params", params)?,
            Self::Jobs(params) => envelope.serialize_field("params", params)?,
            Self::Attempt(params) => envelope.serialize_field("params", params)?,
            Self::Quarantine(params) => envelope.serialize_field("params", params)?,
            Self::Retry(params) => envelope.serialize_field("params", params)?,
            Self::Reconcile(params) => envelope.serialize_field("params", params)?,
            Self::Backup(params) => envelope.serialize_field("params", params)?,
            Self::Restore(params) => envelope.serialize_field("params", params)?,
            Self::ReleaseInspect(params) => envelope.serialize_field("params", params)?,
            Self::ReleaseActivate(params) => envelope.serialize_field("params", params)?,
        }
        envelope.end()
    }
}

impl<'de> Deserialize<'de> for AdminCommand {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Envelope {
            kind: CommandName,
            params: serde_json::Value,
        }

        let envelope = Envelope::deserialize(deserializer)?;
        match envelope.kind {
            CommandName::Status => decode_params(envelope.params).map(Self::Status),
            CommandName::Start => decode_params(envelope.params).map(Self::Start),
            CommandName::Pause => decode_params(envelope.params).map(Self::Pause),
            CommandName::Resume => decode_params(envelope.params).map(Self::Resume),
            CommandName::Drain => decode_params(envelope.params).map(Self::Drain),
            CommandName::Stop => decode_params(envelope.params).map(Self::Stop),
            CommandName::Jobs => decode_params(envelope.params).map(Self::Jobs),
            CommandName::Attempt => decode_params(envelope.params).map(Self::Attempt),
            CommandName::Quarantine => decode_params(envelope.params).map(Self::Quarantine),
            CommandName::Retry => decode_params(envelope.params).map(Self::Retry),
            CommandName::Reconcile => decode_params(envelope.params).map(Self::Reconcile),
            CommandName::Backup => decode_params(envelope.params).map(Self::Backup),
            CommandName::Restore => decode_params(envelope.params).map(Self::Restore),
            CommandName::ReleaseInspect => decode_params(envelope.params).map(Self::ReleaseInspect),
            CommandName::ReleaseActivate => {
                decode_params(envelope.params).map(Self::ReleaseActivate)
            }
        }
    }
}

fn decode_params<T, E>(value: serde_json::Value) -> std::result::Result<T, E>
where
    T: DeserializeOwned,
    E: de::Error,
{
    serde_json::from_value(value).map_err(E::custom)
}

/// Jobs can be inspected without exposing payloads or results through the
/// sideband.  Payloads stay in the owner-local protected store.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobFilter {
    #[default]
    All,
    Queued,
    Running,
    Completed,
    Failed,
    Quarantined,
}

/// Read-only bounded job listing request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobsRequest {
    #[serde(default)]
    pub filter: JobFilter,
    #[serde(default = "default_job_limit")]
    pub limit: u16,
}

impl JobsRequest {
    fn validate(self) -> std::result::Result<(), String> {
        if self.limit == 0 || usize::from(self.limit) > MAX_RESULT_ITEMS {
            return Err(format!("job limit must be 1..={MAX_RESULT_ITEMS}"));
        }
        Ok(())
    }
}

fn default_job_limit() -> u16 {
    64
}

/// Read-only attempt inspection request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptRequest {
    pub attempt_id: String,
}

impl AttemptRequest {
    fn validate(&self) -> std::result::Result<(), String> {
        validate_identifier(&self.attempt_id, "attempt_id", MAX_ID_BYTES)
    }
}

/// Quarantine one watchdog-owned attempt.  It does not settle or mutate a
/// gameplay operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineRequest {
    pub attempt_id: String,
    pub reason: String,
}

impl QuarantineRequest {
    fn validate(&self) -> std::result::Result<(), String> {
        validate_identifier(&self.attempt_id, "attempt_id", MAX_ID_BYTES)?;
        validate_reason(&self.reason)
    }
}

/// Explicit retry policy for a failed/quarantined watchdog attempt.  No
/// `force` or game-action payload is available here.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryPolicy {
    Requeue,
    Reconstruction,
}

/// Retry one durable attempt using its existing lineage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetryRequest {
    pub attempt_id: String,
    pub policy: RetryPolicy,
}

impl RetryRequest {
    fn validate(&self) -> std::result::Result<(), String> {
        validate_identifier(&self.attempt_id, "attempt_id", MAX_ID_BYTES)
    }
}

/// Reconciliation targets are watchdog-owned records only.  Gateway lease,
/// host-fence, game dispatch and settlement controls are intentionally absent.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileTarget {
    Deployment,
    Component,
    Job,
    Attempt,
}

/// Request a bounded, explicitly scoped watchdog reconciliation pass.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileRequest {
    pub target: ReconcileTarget,
    #[serde(default)]
    pub id: Option<String>,
}

impl ReconcileRequest {
    fn validate(&self) -> std::result::Result<(), String> {
        if matches!(self.target, ReconcileTarget::Deployment) && self.id.is_some() {
            return Err("deployment reconciliation does not accept an id".to_string());
        }
        if !matches!(self.target, ReconcileTarget::Deployment) && self.id.is_none() {
            return Err("scoped reconciliation requires an id".to_string());
        }
        if let Some(id) = &self.id {
            validate_identifier(id, "reconcile id", MAX_ID_BYTES)?;
        }
        Ok(())
    }
}

/// Backup selection is an approved logical identifier, never an arbitrary
/// filesystem path supplied by an IPC client.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRequest {
    pub backup_id: String,
}

impl BackupRequest {
    fn validate(&self) -> std::result::Result<(), String> {
        validate_identifier(&self.backup_id, "backup_id", MAX_ID_BYTES)
    }
}

/// Restore requires an explicit rekey.  A restored counter or old namespace
/// must never silently regain authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRequest {
    pub backup_id: String,
    pub rekey: bool,
}

impl RestoreRequest {
    fn validate(&self) -> std::result::Result<(), String> {
        validate_identifier(&self.backup_id, "backup_id", MAX_ID_BYTES)?;
        if !self.rekey {
            return Err("restore requires explicit rekey=true".to_string());
        }
        Ok(())
    }
}

/// Release inspection is read-only and refers to an approved release record,
/// not a path or an arbitrary binary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseInspectRequest {
    pub release_id: String,
}

impl ReleaseInspectRequest {
    fn validate(&self) -> std::result::Result<(), String> {
        validate_identifier(&self.release_id, "release_id", MAX_RELEASE_BYTES)
    }
}

/// Activation requires the exact expected immutable release digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseActivateRequest {
    pub release_id: String,
    pub expected_release_digest: String,
}

impl ReleaseActivateRequest {
    fn validate(&self) -> std::result::Result<(), String> {
        validate_identifier(&self.release_id, "release_id", MAX_RELEASE_BYTES)?;
        validate_digest(&self.expected_release_digest)
    }
}

/// Request envelope.  The token is only used for transport authentication and
/// has no `Serialize`-safe status/audit representation.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRequest {
    pub contract: ContractVersion,
    pub request_id: String,
    pub idempotency_key: String,
    pub capability: Capability,
    pub token: String,
    pub deadline_ms: u32,
    pub command: AdminCommand,
}

/// Token-free, validated identity handed to the watchdog reconciliation loop.
///
/// A transport may retain the raw request only while authenticating it.  Once
/// this context is constructed, the request credential is dropped and cannot
/// be observed by an [`AdminDispatcher`] implementation.  The command
/// fingerprint is canonical: it covers the v1 contract, claimed capability,
/// and closed command payload, while excluding the request UUID, deadline,
/// transport identity, and credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchContext {
    request_id: Uuid,
    idempotency_key: String,
    capability: Capability,
    principal: AuthenticatedPrincipalClass,
    command_fingerprint: String,
}

impl DispatchContext {
    /// Construct and validate a queue context from an authenticated request.
    pub fn from_request(
        request: &AdminRequest,
        principal: AuthenticatedPrincipalClass,
    ) -> std::result::Result<Self, String> {
        request.validate()?;
        if !request
            .capability
            .includes(request.command.name().required_capability())
        {
            return Err("capability does not authorize the command".to_string());
        }
        let request_id = Uuid::parse_str(&request.request_id)
            .map_err(|_| "request_id is not a UUID".to_string())?;
        let context = Self {
            request_id,
            idempotency_key: request.idempotency_key.clone(),
            capability: request.capability,
            principal,
            command_fingerprint: request.fingerprint(),
        };
        context.validate()?;
        Ok(context)
    }

    /// Validate every field before the context crosses the transport queue.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.request_id.get_version_num() != 4 {
            return Err("request_id must be a UUIDv4".to_string());
        }
        validate_identifier(&self.idempotency_key, "idempotency_key", MAX_ID_BYTES)?;
        if self.command_fingerprint.len() != 64
            || !self
                .command_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("command fingerprint must be a SHA-256 hex digest".to_string());
        }
        Ok(())
    }

    /// Request UUID assigned by the authenticated caller.
    #[must_use]
    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    /// Durable idempotency key for the accepted command.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Claimed capability after transport authorization.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.capability
    }

    /// Coarse authenticated identity; no raw credential or OS path is exposed.
    #[must_use]
    pub const fn principal(&self) -> AuthenticatedPrincipalClass {
        self.principal
    }

    /// Canonical SHA-256 command fingerprint used for idempotency/audit.
    #[must_use]
    pub fn command_fingerprint(&self) -> &str {
        &self.command_fingerprint
    }
}

impl fmt::Debug for AdminRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminRequest")
            .field("contract", &self.contract)
            .field("request_id", &self.request_id)
            .field("idempotency_key", &self.idempotency_key)
            .field("capability", &self.capability)
            .field("token", &"<redacted>")
            .field("deadline_ms", &self.deadline_ms)
            .field("command", &self.command)
            .finish()
    }
}

impl AdminRequest {
    /// Validate closed values before queue admission.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.contract != ContractVersion::V1 {
            return Err("unsupported admin contract".to_string());
        }
        validate_uuid_v4(&self.request_id, "request_id")?;
        validate_identifier(&self.idempotency_key, "idempotency_key", MAX_ID_BYTES)?;
        if self.token.is_empty()
            || self.token.len() > MAX_TOKEN_BYTES
            || self.token.as_bytes().contains(&0)
            || !self.token.is_ascii()
        {
            return Err("token is empty or exceeds its bound".to_string());
        }
        if self.deadline_ms == 0 || self.deadline_ms > MAX_DEADLINE_MS {
            return Err(format!("deadline_ms must be 1..={MAX_DEADLINE_MS}"));
        }
        self.command.validate()?;
        if serde_json::to_vec(&self.command)
            .map_err(|error| error.to_string())?
            .len()
            > MAX_PAYLOAD_BYTES
        {
            return Err("command payload exceeds payload bound".to_string());
        }
        Ok(())
    }

    /// Digest the logical request without including credentials, request
    /// transport identity, or local deadline.  Reusing an idempotency key with
    /// a different command is a conflict, never a second dispatch.
    pub fn fingerprint(&self) -> String {
        #[derive(Serialize)]
        struct Fingerprint<'a> {
            contract: ContractVersion,
            capability: Capability,
            command: &'a AdminCommand,
        }
        let bytes = serde_json::to_vec(&Fingerprint {
            contract: self.contract,
            capability: self.capability,
            command: &self.command,
        })
        .unwrap_or_default();
        sha256_hex(&bytes)
    }

    /// Build the token-free context used by the main-loop dispatcher after
    /// transport authentication has selected a principal class.
    pub fn dispatch_context(
        &self,
        principal: AuthenticatedPrincipalClass,
    ) -> std::result::Result<DispatchContext, String> {
        DispatchContext::from_request(self, principal)
    }

    /// Construct a request using a fresh UUID identity.
    pub fn new(
        capability: Capability,
        token: String,
        idempotency_key: String,
        command: AdminCommand,
        deadline_ms: u32,
    ) -> std::result::Result<Self, String> {
        let request = Self {
            contract: ContractVersion::V1,
            request_id: Uuid::new_v4().to_string(),
            idempotency_key,
            capability,
            token,
            deadline_ms,
            command,
        };
        request.validate()?;
        Ok(request)
    }
}

/// Contract version is fixed until a new reviewable schema is published.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ContractVersion {
    #[serde(rename = "watchdog-admin-v1")]
    V1,
}

/// Bounded response status.  It deliberately carries no free-form error
/// string, which prevents paths, credentials and private payloads from
/// leaking through an operator-facing status response.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReplyStatus {
    Ok,
    Accepted,
    Unauthorized,
    Forbidden,
    Invalid,
    BoundsExceeded,
    Busy,
    InProgress,
    Conflict,
    NotFound,
    PersistenceUnavailable,
    Unsupported,
    Timeout,
    Internal,
}

/// Main reconciliation phase, not an I/O-thread heartbeat.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MainLoopPhase {
    #[default]
    Starting,
    Reconciling,
    Draining,
    Paused,
    Blocked,
    Stopped,
}

/// Bounded health published by the real reconciliation loop.  The admin I/O
/// thread only reads this snapshot; it never increments `heartbeat_seq` or
/// marks the service ready.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthSnapshot {
    pub phase: MainLoopPhase,
    pub ready: bool,
    pub heartbeat_seq: u64,
    pub progress_age_ms: Option<u64>,
    pub phase_deadline_at_ms: Option<u64>,
    pub queue_depth: u32,
    pub oldest_queue_age_ms: Option<u64>,
    pub pending_operations: u32,
    #[serde(default)]
    pub instance_incarnation: Option<String>,
    pub lease_remaining_ms: Option<u64>,
}

impl HealthSnapshot {
    /// Validate bounded health before publication.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if usize::try_from(self.queue_depth).unwrap_or(usize::MAX) > super::MAX_QUEUE {
            return Err("health queue depth exceeds queue bound".to_string());
        }
        if usize::try_from(self.pending_operations).unwrap_or(usize::MAX) > super::MAX_QUEUE {
            return Err("health pending operation count exceeds queue bound".to_string());
        }
        if let Some(instance) = &self.instance_incarnation {
            validate_identifier(instance, "instance_incarnation", MAX_ID_BYTES)?;
        }
        Ok(())
    }
}

/// Thread-safe publication point owned by the reconciliation loop.
#[derive(Clone, Debug)]
pub struct MainLoopHealth {
    current: Arc<RwLock<HealthState>>,
}

#[derive(Debug)]
struct HealthState {
    snapshot: HealthSnapshot,
    progress_started_at: Option<Instant>,
}

impl Default for MainLoopHealth {
    fn default() -> Self {
        Self::new()
    }
}

impl MainLoopHealth {
    /// Start unhealthy and not-ready until the main loop explicitly publishes
    /// a valid progress snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self {
            current: Arc::new(RwLock::new(HealthState {
                snapshot: HealthSnapshot::default(),
                progress_started_at: None,
            })),
        }
    }

    /// Publish one snapshot from the actual reconciliation thread.
    pub fn publish(&self, snapshot: HealthSnapshot) -> std::result::Result<(), String> {
        snapshot.validate()?;
        let mut current = self
            .current
            .write()
            .map_err(|_| "main-loop health state lock is poisoned".to_string())?;
        if snapshot.heartbeat_seq < current.snapshot.heartbeat_seq {
            return Err("main-loop heartbeat sequence regressed".to_string());
        }
        let now = Instant::now();
        if snapshot.heartbeat_seq > current.snapshot.heartbeat_seq {
            current.progress_started_at = snapshot.progress_age_ms.map(|_| now);
        } else if current.progress_started_at.is_none() && snapshot.progress_age_ms.is_some() {
            // Permit the first publication to establish an origin even when
            // the initial sequence is zero.  Later same-sequence updates
            // retain the origin, so a failure/phase update cannot reset age.
            current.progress_started_at = Some(now);
        }
        current.snapshot = snapshot;
        Ok(())
    }

    /// Read the last snapshot without changing readiness or heartbeat.
    #[must_use]
    pub fn snapshot(&self) -> HealthSnapshot {
        let Ok(current) = self.current.read() else {
            // A poisoned health lock must never preserve a stale ready bit.
            return HealthSnapshot {
                phase: MainLoopPhase::Blocked,
                ready: false,
                ..HealthSnapshot::default()
            };
        };
        let mut snapshot = current.snapshot.clone();
        if let Some(started_at) = current.progress_started_at {
            let age_ms = started_at.elapsed().as_millis();
            snapshot.progress_age_ms = Some(u64::try_from(age_ms).unwrap_or(u64::MAX));
        }
        snapshot
    }
}

/// Safe status payload.  It includes no database path, job payload, result,
/// executable path, token, or raw audit detail.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StatusView {
    pub desired_mode: AdminMode,
    pub health: HealthSnapshot,
    pub jobs_queued: u64,
    pub jobs_running: u64,
    pub jobs_completed: u64,
    pub jobs_quarantined: u64,
    pub restart_generation: u64,
    pub config_digest: String,
    pub approved_release_digest: Option<String>,
}

impl StatusView {
    fn validate(&self) -> std::result::Result<(), String> {
        self.health.validate()?;
        validate_digest(&self.config_digest)?;
        if let Some(digest) = &self.approved_release_digest {
            validate_digest(digest)?;
        }
        Ok(())
    }
}

/// Desired/deployment phase exposed to operators.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminMode {
    #[default]
    Stopped,
    Starting,
    Running,
    Suspect,
    Draining,
    Recovering,
    Backoff,
    Paused,
    Blocked,
    Quarantined,
    WaitingForSession,
}

/// Safe job summary.  Private payload and result values stay in the durable
/// owner-local store.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobView {
    pub id: String,
    pub kind: String,
    pub status: JobStatus,
    pub attempt_count: u32,
    pub created_at_ms: u64,
    pub next_retry_at_ms: Option<u64>,
}

/// Durable watchdog job status mirrored into the safe admin view.  This is a
/// protocol type rather than a direct dependency on the store's private SQL
/// representation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Quarantined,
}

impl JobView {
    fn validate(&self) -> std::result::Result<(), String> {
        validate_identifier(&self.id, "job id", MAX_ID_BYTES)?;
        validate_identifier(&self.kind, "job kind", MAX_JOB_KIND_BYTES)
    }
}

/// Read-only jobs result with an explicit truncation bit.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobsView {
    pub jobs: Vec<JobView>,
    pub truncated: bool,
}

impl JobsView {
    fn validate(&self) -> std::result::Result<(), String> {
        if self.jobs.len() > MAX_RESULT_ITEMS {
            return Err(format!("job result exceeds {MAX_RESULT_ITEMS} rows"));
        }
        self.jobs.iter().try_for_each(JobView::validate)
    }
}

/// Attempt status intentionally omits arbitrary outcome text.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptStatus {
    Running,
    Completed,
    Failed,
    Unknown,
    Quarantined,
}

/// Safe attempt summary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptView {
    pub attempt_id: String,
    pub job_id: String,
    pub sequence: u32,
    pub status: AttemptStatus,
    pub started_at_ms: u64,
    pub finished_at_ms: Option<u64>,
}

impl AttemptView {
    fn validate(&self) -> std::result::Result<(), String> {
        validate_identifier(&self.attempt_id, "attempt id", MAX_ID_BYTES)?;
        validate_identifier(&self.job_id, "job id", MAX_ID_BYTES)
    }
}

/// Explicit result for a recovery/desired-state transition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedView {
    pub command: CommandName,
    pub queued: bool,
}

/// Safe backup result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupView {
    pub backup_id: String,
    pub durable: bool,
}

impl BackupView {
    fn validate(&self) -> std::result::Result<(), String> {
        validate_identifier(&self.backup_id, "backup id", MAX_ID_BYTES)
    }
}

/// Safe restore result; no path or old authority is returned.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreView {
    pub backup_id: String,
    pub rekeyed: bool,
    pub blocked_until_fenced: bool,
}

impl RestoreView {
    fn validate(&self) -> std::result::Result<(), String> {
        validate_identifier(&self.backup_id, "backup id", MAX_ID_BYTES)?;
        if !self.rekeyed || !self.blocked_until_fenced {
            return Err("restore result must prove rekey and fenced blocking".to_string());
        }
        Ok(())
    }
}

/// Read-only release inspection result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseInspection {
    pub release_id: String,
    pub release_digest: String,
    pub compatible: bool,
    pub active: bool,
}

impl ReleaseInspection {
    fn validate(&self) -> std::result::Result<(), String> {
        validate_identifier(&self.release_id, "release id", MAX_RELEASE_BYTES)?;
        validate_digest(&self.release_digest)
    }
}

/// Typed result variants returned by the main-loop dispatcher.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value")]
pub enum AdminResult {
    Status(StatusView),
    Jobs(JobsView),
    Attempt(AttemptView),
    Accepted(AcceptedView),
    Backup(BackupView),
    Restore(RestoreView),
    ReleaseInspection(ReleaseInspection),
}

impl AdminResult {
    /// Validate response cardinality and redaction-safe fields.
    pub fn validate(&self) -> std::result::Result<(), String> {
        match self {
            Self::Status(value) => value.validate(),
            Self::Jobs(value) => value.validate(),
            Self::Attempt(value) => value.validate(),
            Self::Accepted(_) => Ok(()),
            Self::Backup(value) => value.validate(),
            Self::Restore(value) => value.validate(),
            Self::ReleaseInspection(value) => value.validate(),
        }
    }
}

/// Bounded response envelope.  It never contains the request credential.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminResponse {
    pub contract: ContractVersion,
    pub request_id: String,
    pub idempotency_key: String,
    pub status: ReplyStatus,
    pub result: Option<AdminResult>,
    pub health: HealthSnapshot,
}

impl AdminResponse {
    /// Construct a successful main-loop response.
    pub fn success(
        context: &DispatchContext,
        result: AdminResult,
        health: &MainLoopHealth,
    ) -> Self {
        Self {
            contract: ContractVersion::V1,
            request_id: context.request_id.to_string(),
            idempotency_key: context.idempotency_key.clone(),
            status: if matches!(result, AdminResult::Accepted(_)) {
                ReplyStatus::Accepted
            } else {
                ReplyStatus::Ok
            },
            result: Some(result),
            health: health.snapshot(),
        }
    }

    /// Construct an error for an already-authenticated token-free context.
    #[must_use]
    pub fn context_error(
        context: &DispatchContext,
        status: ReplyStatus,
        health: &MainLoopHealth,
    ) -> Self {
        Self::error(
            context.request_id.to_string(),
            context.idempotency_key.clone(),
            status,
            health,
        )
    }

    /// Construct an error without carrying arbitrary detail.
    #[must_use]
    pub fn error(
        request_id: impl Into<String>,
        idempotency_key: impl Into<String>,
        status: ReplyStatus,
        health: &MainLoopHealth,
    ) -> Self {
        Self {
            contract: ContractVersion::V1,
            request_id: request_id.into(),
            idempotency_key: idempotency_key.into(),
            status,
            result: None,
            health: health.snapshot(),
        }
    }

    /// Refresh only the live loop health for a replayed response.  The cached
    /// result itself is never re-dispatched.
    #[must_use]
    pub fn with_current_health(mut self, health: &MainLoopHealth) -> Self {
        self.health = health.snapshot();
        self
    }

    /// Validate response structure before framing.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.contract != ContractVersion::V1 {
            return Err("unsupported response contract".to_string());
        }
        if self.request_id.is_empty() {
            if self.result.is_some() {
                return Err("successful response requires request_id".to_string());
            }
        } else {
            validate_uuid_v4(&self.request_id, "request_id")?;
        }
        if !self.idempotency_key.is_empty() {
            validate_identifier(&self.idempotency_key, "idempotency_key", MAX_ID_BYTES)?;
        }
        self.health.validate()?;
        if let Some(result) = &self.result {
            result.validate()?;
        }
        if self.status == ReplyStatus::Ok || self.status == ReplyStatus::Accepted {
            if self.result.is_none() {
                return Err("successful response requires a result".to_string());
            }
        } else if self.result.is_some() {
            return Err("error response cannot contain a result".to_string());
        }
        Ok(())
    }

    /// Encode and enforce the response frame bound.
    pub fn encode(&self) -> std::result::Result<Vec<u8>, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err("response exceeds frame bound".to_string());
        }
        Ok(bytes)
    }
}

/// A main-loop dispatcher.  Implementations must be the watchdog's sole
/// SQLite writer and must not use this trait to invoke gateway/game lifecycle
/// operations.  All commands are already closed and capability-checked.
pub trait AdminDispatcher {
    /// Execute one accepted command on the actual reconciliation thread.
    fn dispatch(
        &mut self,
        context: &DispatchContext,
        command: &AdminCommand,
    ) -> std::result::Result<AdminResult, AdminDispatchError>;
}

/// Sanitized dispatcher failures.  No arbitrary detail is sent to clients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminDispatchError {
    Invalid,
    Unauthorized,
    NotFound,
    Conflict,
    Busy,
    PersistenceUnavailable,
    Unsupported,
    Timeout,
    Internal,
}

impl AdminDispatchError {
    /// Map to the wire status enum without exposing internal details.
    #[must_use]
    pub const fn status(self) -> ReplyStatus {
        match self {
            Self::Invalid => ReplyStatus::Invalid,
            Self::Unauthorized => ReplyStatus::Unauthorized,
            Self::NotFound => ReplyStatus::NotFound,
            Self::Conflict => ReplyStatus::Conflict,
            Self::Busy => ReplyStatus::Busy,
            Self::PersistenceUnavailable => ReplyStatus::PersistenceUnavailable,
            Self::Unsupported => ReplyStatus::Unsupported,
            Self::Timeout => ReplyStatus::Timeout,
            Self::Internal => ReplyStatus::Internal,
        }
    }
}

impl From<&WatchdogError> for AdminDispatchError {
    fn from(error: &WatchdogError) -> Self {
        match error {
            WatchdogError::InvalidInput(_) => Self::Invalid,
            WatchdogError::MissingState(_) | WatchdogError::NotFound(_) => Self::NotFound,
            WatchdogError::Busy(_) => Self::Busy,
            WatchdogError::Unauthorized(_) => Self::Unauthorized,
            WatchdogError::Conflict(_) | WatchdogError::IdentityMismatch(_) => Self::Conflict,
            WatchdogError::Timeout(_) => Self::Timeout,
            WatchdogError::Unsupported(_) => Self::Unsupported,
            WatchdogError::Sqlite(_) | WatchdogError::Io(_) => Self::PersistenceUnavailable,
            WatchdogError::Json(_) => Self::Invalid,
        }
    }
}

/// JSON duplicate member rejection is performed before typed deserialization.
/// `serde_json::Value` otherwise keeps only the last duplicate key, which is
/// unsafe for capability and command fields.
pub(crate) fn reject_duplicate_fields(bytes: &[u8]) -> std::result::Result<(), String> {
    let mut deserializer = Deserializer::from_slice(bytes);
    deserializer
        .deserialize_any(DuplicateVisitor)
        .map_err(|error| error.to_string())?;
    deserializer
        .end()
        .map_err(|error| format!("trailing JSON: {error}"))
}

struct DuplicateSeed;

impl<'de> DeserializeSeed<'de> for DuplicateSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateVisitor)
    }
}

struct DuplicateVisitor;

impl<'de> Visitor<'de> for DuplicateVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any JSON value with unique object member names")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut names = BTreeSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !names.insert(name) {
                return Err(de::Error::custom("duplicate JSON object field"));
            }
            map.next_value_seed(DuplicateSeed)?;
        }
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(DuplicateSeed)?.is_some() {}
        Ok(())
    }

    fn visit_bool<E>(self, _value: bool) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_bytes<E>(self, _value: &[u8]) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_byte_buf<E>(self, _value: Vec<u8>) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateVisitor)
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateVisitor)
    }
}

fn validate_identifier(
    value: &str,
    name: &str,
    max_bytes: usize,
) -> std::result::Result<(), String> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value.is_ascii()
        || value.as_bytes().contains(&0)
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"_.:/-".contains(&byte)))
    {
        return Err(format!(
            "{name} is empty, unsafe, or exceeds {max_bytes} bytes"
        ));
    }
    Ok(())
}

fn validate_reason(value: &str) -> std::result::Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_REASON_BYTES
        || value.as_bytes().contains(&0)
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "reason exceeds {MAX_REASON_BYTES} bytes or contains controls"
        ));
    }
    Ok(())
}

fn validate_uuid_v4(value: &str, name: &str) -> std::result::Result<(), String> {
    let parsed = Uuid::parse_str(value).map_err(|_| format!("{name} must be a UUIDv4"))?;
    if parsed.get_version_num() != 4 {
        return Err(format!("{name} must be a UUIDv4"));
    }
    Ok(())
}

fn validate_digest(value: &str) -> std::result::Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("digest must be 64 lowercase hexadecimal characters".to_string());
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Keep command payloads below the complete frame bound so framing overhead
/// and authentication fields cannot consume the entire transport budget.
pub(crate) fn payload_within_bound(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_PAYLOAD_BYTES && bytes.len() <= MAX_FRAME_BYTES
}
