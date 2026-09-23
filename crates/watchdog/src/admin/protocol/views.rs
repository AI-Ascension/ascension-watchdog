//! Bounded wire views, health snapshots and typed dispatcher results.

use super::identity::CommandName;
use super::validation::{validate_digest, validate_identifier};
use super::{MAX_ID_BYTES, MAX_JOB_KIND_BYTES, MAX_RELEASE_BYTES, MAX_RESULT_ITEMS};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::Instant;

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
        if usize::try_from(self.queue_depth).unwrap_or(usize::MAX) > crate::admin::MAX_QUEUE {
            return Err("health queue depth exceeds queue bound".to_string());
        }
        if usize::try_from(self.pending_operations).unwrap_or(usize::MAX) > crate::admin::MAX_QUEUE
        {
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

/// Successful authenticated job-submission response. The job identifier is
/// the only submission-specific value exposed; payload and private job state
/// remain in the owner-local store.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobSubmittedView {
    pub job_id: String,
}

/// Alias matching the command name for callers that use command-oriented
/// naming in their response handling.
pub type JobSubmitView = JobSubmittedView;

impl JobSubmittedView {
    fn validate(&self) -> std::result::Result<(), String> {
        validate_identifier(&self.job_id, "job id", MAX_ID_BYTES)
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

/// Durable result of an atomic release activation or rollback.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseActivationView {
    pub release_id: String,
    pub release_digest: String,
    pub previous_release_id: Option<String>,
    pub previous_release_digest: Option<String>,
    pub rollback: bool,
}

impl ReleaseActivationView {
    fn validate(&self) -> std::result::Result<(), String> {
        validate_identifier(&self.release_id, "release id", MAX_RELEASE_BYTES)?;
        validate_digest(&self.release_digest)?;
        if self.previous_release_id.is_some() != self.previous_release_digest.is_some() {
            return Err("previous release identity is incomplete".to_owned());
        }
        if let Some(id) = &self.previous_release_id {
            validate_identifier(id, "previous release id", MAX_RELEASE_BYTES)?;
        }
        if let Some(digest) = &self.previous_release_digest {
            validate_digest(digest)?;
        }
        Ok(())
    }
}

/// Typed result variants returned by the main-loop dispatcher.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value")]
pub enum AdminResult {
    Status(StatusView),
    Jobs(JobsView),
    JobSubmitted(JobSubmittedView),
    Attempt(AttemptView),
    Accepted(AcceptedView),
    Backup(BackupView),
    Restore(RestoreView),
    ReleaseInspection(ReleaseInspection),
    ReleaseActivation(ReleaseActivationView),
}

impl AdminResult {
    /// Validate response cardinality and redaction-safe fields.
    pub fn validate(&self) -> std::result::Result<(), String> {
        match self {
            Self::Status(value) => value.validate(),
            Self::Jobs(value) => value.validate(),
            Self::JobSubmitted(value) => value.validate(),
            Self::Attempt(value) => value.validate(),
            Self::Accepted(_) => Ok(()),
            Self::Backup(value) => value.validate(),
            Self::Restore(value) => value.validate(),
            Self::ReleaseInspection(value) => value.validate(),
            Self::ReleaseActivation(value) => value.validate(),
        }
    }
}
