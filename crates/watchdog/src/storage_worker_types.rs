//! Public worker handoff identity and lifecycle types.

use super::super::JobRecord;
use crate::error::{Result, WatchdogError};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerBinding {
    pub deployment_id: String,
    pub worker_owner_id: String,
    pub worker_profile_digest: String,
    pub release_digest: String,
    pub config_digest: String,
    pub schema_digest: String,
}

/// Mode accepted by the authenticated worker control ledger.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerControlMode {
    Running,
    Paused,
    Draining,
    Stopped,
}

impl WorkerControlMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Stopped => "stopped",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "running" => Ok(Self::Running),
            "paused" => Ok(Self::Paused),
            "draining" => Ok(Self::Draining),
            "stopped" => Ok(Self::Stopped),
            other => Err(WatchdogError::Conflict(format!(
                "unknown worker control mode {other}"
            ))),
        }
    }
}

/// Authenticated control witness bound to one watchdog and worker boot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerControlWitness {
    pub deployment_id: String,
    pub worker_owner_id: String,
    pub worker_profile_digest: String,
    pub watchdog_boot_id: String,
    pub worker_boot_id: String,
    pub mode: WorkerControlMode,
    pub mode_sequence: u64,
}

/// Exact preflight witness required to allocate a worker handoff.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerClaimWitness {
    pub deployment_id: String,
    pub worker_owner_id: String,
    pub worker_profile_digest: String,
    pub release_digest: String,
    pub config_digest: String,
    pub schema_digest: String,
    pub watchdog_boot_id: String,
    pub worker_boot_id: String,
    pub mode_sequence: u64,
}

/// The durable handoff lifecycle.  Terminal rows are retained as historical
/// deduplication evidence and never become a new queue claim.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerHandoffState {
    Prepared,
    MayHaveBeenDispatched,
    Admitted,
    Completed,
    Failed,
    Acknowledged,
    Rejected,
}

impl WorkerHandoffState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::MayHaveBeenDispatched => "may_have_been_dispatched",
            Self::Admitted => "admitted",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Acknowledged => "acknowledged",
            Self::Rejected => "rejected",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "may_have_been_dispatched" => Ok(Self::MayHaveBeenDispatched),
            "admitted" => Ok(Self::Admitted),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "acknowledged" => Ok(Self::Acknowledged),
            "rejected" => Ok(Self::Rejected),
            other => Err(WatchdogError::Conflict(format!(
                "unknown worker handoff state {other}"
            ))),
        }
    }

    pub(crate) fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Acknowledged)
    }
}

/// The complete durable tuple carried by worker protocol dispatch, lookup,
/// and acknowledgment messages.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerHandoffTuple {
    pub handoff_id: String,
    pub deployment_id: String,
    pub job_id: String,
    pub attempt_id: String,
    pub attempt_number: u32,
    pub worker_owner_id: String,
    pub worker_profile_digest: String,
    pub run_id: String,
    pub episode_id: String,
    pub trajectory_id: String,
    pub payload_digest: String,
}

/// One persisted handoff together with the job payload and dispatch binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerHandoff {
    pub handoff_id: String,
    pub deployment_id: String,
    pub job_id: String,
    pub attempt_id: String,
    pub attempt_number: u32,
    pub worker_owner_id: String,
    pub worker_profile_digest: String,
    pub run_id: String,
    pub episode_id: String,
    pub trajectory_id: String,
    pub payload_digest: String,
    pub watchdog_boot_id: String,
    pub worker_boot_id: String,
    pub mode_sequence: u64,
    pub operation: String,
    pub parameters: Value,
    pub state: WorkerHandoffState,
    pub job: JobRecord,
    pub terminal: Option<WorkerTerminalRecord>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

impl WorkerHandoff {
    /// Return the exact logical tuple without copying dispatch-only binding.
    #[must_use]
    pub fn tuple(&self) -> WorkerHandoffTuple {
        WorkerHandoffTuple {
            handoff_id: self.handoff_id.clone(),
            deployment_id: self.deployment_id.clone(),
            job_id: self.job_id.clone(),
            attempt_id: self.attempt_id.clone(),
            attempt_number: self.attempt_number,
            worker_owner_id: self.worker_owner_id.clone(),
            worker_profile_digest: self.worker_profile_digest.clone(),
            run_id: self.run_id.clone(),
            episode_id: self.episode_id.clone(),
            trajectory_id: self.trajectory_id.clone(),
            payload_digest: self.payload_digest.clone(),
        }
    }
}

/// Terminal worker evidence.  `result_digest` is the harness-owned terminal
/// result identity.  The worker wire does not carry those private result
/// bytes; the watchdog stores a separate compact receipt as the job result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerTerminalReceipt {
    pub status: WorkerTerminalStatus,
    pub checkpoint_sequence: u64,
    pub terminal_ref: String,
    pub result_digest: String,
}

/// The durable terminal receipt adds the watchdog-computed digest used by
/// acknowledgment. The worker protocol itself sends the four fields in
/// [`WorkerTerminalReceipt`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerTerminalRecord {
    pub status: WorkerTerminalStatus,
    pub checkpoint_sequence: u64,
    pub terminal_ref: String,
    pub result_digest: String,
    pub terminal_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerTerminalStatus {
    Completed,
    Failed,
}

impl WorkerTerminalStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            other => Err(WatchdogError::Conflict(format!(
                "unknown worker terminal status {other}"
            ))),
        }
    }
}

/// Result of an atomic terminal completion plus persisted acknowledgment
/// intent.  A transport may send the acknowledgment after this commits.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCompletion {
    pub handoff: WorkerHandoff,
    pub terminal_digest: String,
    pub already_completed: bool,
}

/// Result of an acknowledgment.  Matching repeats are harmless and are
/// reported separately so callers do not send a second terminal mutation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerAcknowledgment {
    pub handoff_id: String,
    pub terminal_digest: String,
    pub already_acknowledged: bool,
}
