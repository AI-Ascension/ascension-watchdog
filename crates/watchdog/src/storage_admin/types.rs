//! Operator ledger value types and their closed command vocabulary.
//!
//! This module owns the durable ledger's public value types: the closed
//! capability and command enumerations, the token-free authenticated command
//! context, the retained command receipt, the admission outcome, the ledger
//! retention constants and the strict field validators that guard bounded
//! identity and digest inputs.  It performs no SQL and opens no connection.

use super::super::{WatchdogError, validate_name};
use crate::config::{DesiredMode, validate_digest};
use crate::error::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Version of the additive operator-ledger table.  It is intentionally kept
/// separate from the watchdog core schema version so old owner stores can be
/// upgraded under the singleton lock without pretending to migrate unrelated
/// state.
pub const OPERATOR_LEDGER_SCHEMA_VERSION: i64 = 2;

/// Maximum rows retained in the durable command ledger.  Rows are never
/// evicted: a full ledger backpressures a new command until an explicit,
/// separately reviewed archival operation exists.
pub const MAX_OPERATOR_COMMANDS: i64 = 256;

/// One dedicated, bounded stop slot remains available after the normal
/// ledger and lifecycle reserve are exhausted. It is never used for start,
/// resume, or any other command.
pub const RESERVED_STOP_COMMANDS: i64 = 1;

/// Maximum retained rows including the explicit emergency stop slot.
pub const MAX_OPERATOR_COMMANDS_WITH_STOP_RESERVE: i64 =
    MAX_OPERATOR_COMMANDS + RESERVED_STOP_COMMANDS;

/// Reserve for lifecycle commands when ordinary administrative commands have
/// filled the normal ledger budget.  The reserve is capacity, not a deletion
/// policy; every retained idempotency key remains replayable.
pub const RESERVED_LIFECYCLE_COMMANDS: i64 = 8;

/// Maximum serialized response retained for a durable command admission.
pub const MAX_OPERATOR_RESPONSE_BYTES: usize = 8 * 1024;

/// Capability class supplied after transport authentication.  Raw credentials
/// never enter this type or the durable ledger.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorCapability {
    /// May execute only commands classified as read-only.
    Read,
    /// May execute lifecycle and administrative mutations.
    Admin,
}

impl OperatorCapability {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Admin => "admin",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "read" => Ok(Self::Read),
            "admin" => Ok(Self::Admin),
            other => Err(WatchdogError::Conflict(format!(
                "unknown operator capability class {other}"
            ))),
        }
    }
}

/// Closed command names mirrored by the admin transport without importing the
/// transport module into storage.  Command arguments are represented only by
/// the context's SHA-256 fingerprint.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorCommand {
    Status,
    Jobs,
    Attempt,
    ReleaseInspect,
    Start,
    Pause,
    Resume,
    Drain,
    Stop,
    Quarantine,
    Retry,
    Reconcile,
    Backup,
    Restore,
    ReleaseActivate,
    JobSubmit,
}

impl OperatorCommand {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Jobs => "jobs",
            Self::Attempt => "attempt",
            Self::ReleaseInspect => "release_inspect",
            Self::Start => "start",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Drain => "drain",
            Self::Stop => "stop",
            Self::Quarantine => "quarantine",
            Self::Retry => "retry",
            Self::Reconcile => "reconcile",
            Self::Backup => "backup",
            Self::Restore => "restore",
            Self::ReleaseActivate => "release_activate",
            Self::JobSubmit => "job_submit",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "status" => Ok(Self::Status),
            "jobs" => Ok(Self::Jobs),
            "attempt" => Ok(Self::Attempt),
            "release_inspect" => Ok(Self::ReleaseInspect),
            "start" => Ok(Self::Start),
            "pause" => Ok(Self::Pause),
            "resume" => Ok(Self::Resume),
            "drain" => Ok(Self::Drain),
            "stop" => Ok(Self::Stop),
            "quarantine" => Ok(Self::Quarantine),
            "retry" => Ok(Self::Retry),
            "reconcile" => Ok(Self::Reconcile),
            "backup" => Ok(Self::Backup),
            "restore" => Ok(Self::Restore),
            "release_activate" => Ok(Self::ReleaseActivate),
            "job_submit" => Ok(Self::JobSubmit),
            other => Err(WatchdogError::Conflict(format!(
                "unknown operator command {other}"
            ))),
        }
    }

    /// Whether dispatching this command must leave the durable store
    /// byte-for-byte unchanged.
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        matches!(
            self,
            Self::Status | Self::Jobs | Self::Attempt | Self::ReleaseInspect
        )
    }

    /// Desired mode, if this command carries a lifecycle transition.
    #[must_use]
    pub const fn desired_mode(self) -> Option<DesiredMode> {
        match self {
            Self::Start | Self::Resume => Some(DesiredMode::Running),
            Self::Pause => Some(DesiredMode::Paused),
            Self::Drain => Some(DesiredMode::Draining),
            Self::Stop => Some(DesiredMode::Stopped),
            _ => None,
        }
    }

    pub(crate) fn is_lifecycle(self) -> bool {
        self.desired_mode().is_some()
    }
}

/// Token-free authenticated context supplied by the transport's auth layer.
/// The caller must compute `command_fingerprint` over the closed command
/// envelope without credentials, request transport identity, or deadlines.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperatorCommandContext {
    pub request_id: String,
    pub idempotency_key: String,
    pub principal: String,
    pub capability: OperatorCapability,
    pub command_fingerprint: String,
}

impl OperatorCommandContext {
    /// Construct and validate a context without accepting a raw credential.
    pub fn new(
        request_id: impl Into<String>,
        idempotency_key: impl Into<String>,
        principal: impl Into<String>,
        capability: OperatorCapability,
        command_fingerprint: impl Into<String>,
    ) -> Result<Self> {
        let context = Self {
            request_id: request_id.into(),
            idempotency_key: idempotency_key.into(),
            principal: principal.into(),
            capability,
            command_fingerprint: command_fingerprint.into(),
        };
        context.validate()?;
        Ok(context)
    }

    /// Validate bounded identity and digest fields.
    pub fn validate(&self) -> Result<()> {
        validate_uuid_v4(&self.request_id, "request id")?;
        validate_name(&self.idempotency_key, "idempotency key", 128)?;
        validate_name(&self.principal, "operator principal", 128)?;
        validate_digest(&self.command_fingerprint).map_err(WatchdogError::InvalidInput)
    }
}

/// Durable receipt retained for an accepted mutation.  `replayed` is a
/// response-local marker and is not persisted as authority state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperatorCommandReceipt {
    pub sequence: u64,
    pub request_id: String,
    pub idempotency_key: String,
    pub principal: String,
    pub capability: OperatorCapability,
    pub command: OperatorCommand,
    pub command_fingerprint: String,
    pub desired_mode: Option<DesiredMode>,
    pub response: Value,
    pub recorded_at_ms: u64,
    pub replayed: bool,
}

/// Result of owner admission.  Read-only commands intentionally have no
/// receipt and perform no SQL write; accepted/replayed mutations carry the
/// durable response the transport may acknowledge or replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperatorCommandOutcome {
    ReadOnly,
    Accepted(OperatorCommandReceipt),
    Replayed(OperatorCommandReceipt),
}

pub(crate) fn validate_uuid_v4(value: &str, name: &str) -> Result<()> {
    let parsed = Uuid::parse_str(value)
        .map_err(|_| WatchdogError::InvalidInput(format!("{name} must be a UUIDv4")))?;
    if parsed.get_version_num() != 4 {
        return Err(WatchdogError::InvalidInput(format!(
            "{name} must be a UUIDv4"
        )));
    }
    Ok(())
}
