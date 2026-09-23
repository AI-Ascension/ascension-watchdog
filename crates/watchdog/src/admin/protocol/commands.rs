//! Closed administrative command payloads and their bounded validation.

use super::identity::CommandName;
use super::validation::{validate_digest, validate_identifier, validate_reason};
use super::{
    MAX_ID_BYTES, MAX_JOB_KIND_BYTES, MAX_JOB_PAYLOAD_BYTES, MAX_RELEASE_BYTES, MAX_RESULT_ITEMS,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize, Serializer, de};
use std::fmt;

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
    JobSubmit(JobSubmitRequest),
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
            Self::JobSubmit(_) => CommandName::JobSubmit,
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
            Self::JobSubmit(value) => value.validate(),
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
            Self::JobSubmit(params) => envelope.serialize_field("params", params)?,
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
            CommandName::JobSubmit => decode_params(envelope.params).map(Self::JobSubmit),
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

/// Authenticated submission of one watchdog-owned job. The payload is a
/// bounded JSON value rather than a generic command or an execution request;
/// the watchdog only queues it and never interprets it as a gameplay action.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobSubmitRequest {
    pub kind: String,
    pub payload: serde_json::Value,
}

impl std::fmt::Debug for JobSubmitRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobSubmitRequest")
            .field("kind", &self.kind)
            .field("payload", &"<redacted>")
            .finish()
    }
}

impl JobSubmitRequest {
    /// Construct and validate a bounded submission request.
    pub fn new(
        kind: impl Into<String>,
        payload: serde_json::Value,
    ) -> std::result::Result<Self, String> {
        let request = Self {
            kind: kind.into(),
            payload,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> std::result::Result<(), String> {
        validate_identifier(&self.kind, "job kind", MAX_JOB_KIND_BYTES)?;
        let payload = serde_json::to_vec(&self.payload).map_err(|error| error.to_string())?;
        if payload.len() > MAX_JOB_PAYLOAD_BYTES {
            return Err(format!("job payload exceeds {MAX_JOB_PAYLOAD_BYTES} bytes"));
        }
        Ok(())
    }
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
    /// When true, the target must exactly match the durably recorded previous
    /// release. Rollback never accepts an arbitrary catalog entry.
    #[serde(default)]
    pub rollback: bool,
}

impl ReleaseActivateRequest {
    fn validate(&self) -> std::result::Result<(), String> {
        validate_identifier(&self.release_id, "release_id", MAX_RELEASE_BYTES)?;
        validate_digest(&self.expected_release_digest)
    }
}
