//! Cross-table handoff, job, and attempt consistency checks.

use super::super::{JobRecord, JobStatus};
use super::storage_worker_queries_handoff::RawHandoff;
use super::storage_worker_queries_jobs::RawAttempt;
use super::storage_worker_queries_terminal::empty_parameters;
use super::storage_worker_schema::WORKER_HANDOFF_OPERATION;
use super::storage_worker_types::WorkerHandoffState;
use crate::config::hex_digest;
use crate::error::{Result, WatchdogError};
use serde_json::Value;

pub(super) fn validate_handoff_job(
    raw: &RawHandoff,
    job: &JobRecord,
    attempt: &RawAttempt,
    completion_digest: Option<&str>,
) -> Result<()> {
    if attempt.id != raw.attempt_id
        || attempt.job_id != raw.job_id
        || attempt.sequence != raw.attempt_number
        || attempt.lineage != format!("{}:{}", raw.job_id, raw.attempt_number)
        || attempt.worker_id.as_deref() != Some(raw.worker_owner_id.as_str())
        || job.attempt_count != raw.attempt_number
        || job.claimed_at_ms != Some(raw.created_at_ms)
    {
        return Err(WatchdogError::Conflict(
            "worker handoff attempt or claim history differs from its durable tuple".to_owned(),
        ));
    }
    if attempt.started_at_ms != raw.created_at_ms {
        return Err(WatchdogError::Conflict(
            "worker handoff and attempt phase clocks differ".to_owned(),
        ));
    }
    if job.id != raw.job_id
        || job.kind != WORKER_HANDOFF_OPERATION
        || job.payload_digest != raw.payload_digest
        || job.payload != empty_parameters()
    {
        return Err(WatchdogError::Conflict(
            "worker handoff job identity or payload differs from durable tuple".to_owned(),
        ));
    }
    match raw.state {
        WorkerHandoffState::Prepared
        | WorkerHandoffState::MayHaveBeenDispatched
        | WorkerHandoffState::Admitted => {
            if !matches!(job.status, JobStatus::Running | JobStatus::Quarantined)
                || job.result.is_some()
                || completion_digest.is_some()
                || (job.status == JobStatus::Running && attempt.status != "running")
                || (job.status == JobStatus::Quarantined && attempt.status != "unknown")
                || (job.status == JobStatus::Running && attempt.finished_at_ms.is_some())
                || job.worker_id.as_deref() != Some(raw.worker_owner_id.as_str())
            {
                return Err(WatchdogError::Conflict(
                    "non-terminal worker handoff references a non-running or completed job"
                        .to_owned(),
                ));
            }
        }
        WorkerHandoffState::Completed | WorkerHandoffState::Acknowledged => {
            let Some(result_text) = raw.terminal_result.as_deref() else {
                return Err(WatchdogError::Conflict(
                    "completed worker handoff is missing result".to_owned(),
                ));
            };
            let expected_result: Value = serde_json::from_str(result_text).map_err(|error| {
                WatchdogError::Conflict(format!("worker compact result is invalid JSON: {error}"))
            })?;
            if job.status != JobStatus::Completed
                || attempt.status != "completed"
                || attempt.finished_at_ms != raw.terminal_at_ms
                || job.result.as_ref() != Some(&expected_result)
                || job.completed_at_ms != raw.terminal_at_ms
                || job.last_error.is_some()
                || job.worker_id.as_deref() != Some(raw.worker_owner_id.as_str())
            {
                return Err(WatchdogError::Conflict(
                    "completed worker handoff does not match the completed job result".to_owned(),
                ));
            }
            let Some(digest) = completion_digest else {
                return Err(WatchdogError::Conflict(
                    "completed worker job is missing result digest".to_owned(),
                ));
            };
            if hex_digest(result_text.as_bytes()) != digest {
                return Err(WatchdogError::Conflict(
                    "worker compact result hash differs from job".to_owned(),
                ));
            }
        }
        WorkerHandoffState::Failed => {
            let Some(result_text) = raw.terminal_result.as_deref() else {
                return Err(WatchdogError::Conflict(
                    "failed worker handoff is missing result".to_owned(),
                ));
            };
            let expected_result: Value = serde_json::from_str(result_text).map_err(|error| {
                WatchdogError::Conflict(format!("worker compact result is invalid JSON: {error}"))
            })?;
            if job.status != JobStatus::Failed
                || attempt.status != "failed"
                || attempt.finished_at_ms != raw.terminal_at_ms
                || job.result.as_ref() != Some(&expected_result)
                || job.completed_at_ms.is_some()
                || job.worker_id.is_some()
                || job.last_error.as_deref()
                    != Some(
                        raw.terminal
                            .as_ref()
                            .map_or("", |receipt| receipt.terminal_ref.as_str()),
                    )
                || completion_digest.is_none()
            {
                return Err(WatchdogError::Conflict(
                    "failed worker handoff does not match the failed job result".to_owned(),
                ));
            }
            let Some(digest) = completion_digest else {
                return Err(WatchdogError::Conflict(
                    "failed worker job is missing result digest".to_owned(),
                ));
            };
            if hex_digest(result_text.as_bytes()) != digest {
                return Err(WatchdogError::Conflict(
                    "worker compact result hash differs from job".to_owned(),
                ));
            }
        }
        WorkerHandoffState::Rejected => {}
    }
    Ok(())
}
