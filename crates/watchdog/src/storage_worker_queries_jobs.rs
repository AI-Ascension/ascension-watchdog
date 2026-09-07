//! Bounded job and attempt projections used to validate handoffs.

use super::super::{JobRecord, JobStatus};
use super::super::{sqlite_optional_u64, sqlite_u32};
use super::storage_worker_claims_validation::validate_digest_value;
use super::storage_worker_queries_projection::required_text;
use super::{sqlite_u64, to_sqlite_error, validate_name};
use crate::config::hex_digest;
use crate::error::{Result, WatchdogError};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

const MAX_WORKER_TEXT_BYTES: usize = 128;

const JOB_SELECT: &str = "SELECT
    CASE WHEN typeof(id)='text' AND length(CAST(id AS BLOB)) <= 128 THEN id END,
    CASE WHEN typeof(kind)='text' AND length(CAST(kind AS BLOB)) <= 128 THEN kind END,
    CASE WHEN typeof(payload)='text' AND length(CAST(payload AS BLOB)) <= ?1 THEN payload END,
    CASE WHEN typeof(payload_digest)='text' AND length(CAST(payload_digest AS BLOB)) <= 64 THEN payload_digest END,
    CASE WHEN typeof(status)='text' AND length(CAST(status AS BLOB)) <= 32 THEN status END,
    created_at_ms, claimed_at_ms, completed_at_ms, attempt_count, next_retry_at_ms,
    CASE WHEN last_error IS NULL THEN NULL WHEN typeof(last_error)='text' AND length(CAST(last_error AS BLOB)) <= 16384 THEN last_error ELSE char(0) END,
    CASE WHEN result IS NULL THEN NULL WHEN typeof(result)='text' AND length(CAST(result AS BLOB)) <= 65536 THEN result ELSE char(1) END,
    CASE WHEN worker_id IS NULL THEN NULL WHEN typeof(worker_id)='text' AND length(CAST(worker_id AS BLOB)) <= 128 THEN worker_id ELSE char(1) END,
    CASE WHEN completion_digest IS NULL THEN NULL WHEN typeof(completion_digest)='text' AND length(CAST(completion_digest AS BLOB)) <= 64 THEN completion_digest ELSE char(1) END
    FROM jobs WHERE id=?2";

fn job_bound(max_payload_bytes: usize) -> Result<i64> {
    i64::try_from(max_payload_bytes).map_err(|_| {
        WatchdogError::InvalidInput("job payload bound exceeds SQLite range".to_owned())
    })
}

pub(super) fn load_job_conn(
    conn: &Connection,
    job_id: &str,
    max_payload_bytes: usize,
) -> Result<Option<(JobRecord, Option<String>)>> {
    let bound = job_bound(max_payload_bytes)?;
    conn.query_row(JOB_SELECT, params![bound, job_id], bounded_job_from_row)
        .optional()
        .map_err(Into::into)
}

pub(super) fn load_job_tx(
    tx: &Transaction<'_>,
    job_id: &str,
    max_payload_bytes: usize,
) -> Result<Option<(JobRecord, Option<String>)>> {
    let bound = job_bound(max_payload_bytes)?;
    tx.query_row(JOB_SELECT, params![bound, job_id], bounded_job_from_row)
        .optional()
        .map_err(Into::into)
}

fn bounded_job_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(JobRecord, Option<String>)> {
    let id = required_text(row, 0, "job id")?;
    let kind = required_text(row, 1, "job kind")?;
    let payload_text = required_text(row, 2, "job payload")?;
    let payload_digest = required_text(row, 3, "job payload digest")?;
    let status_text = required_text(row, 4, "job status")?;
    validate_name(&id, "job id", MAX_WORKER_TEXT_BYTES).map_err(to_sqlite_error)?;
    validate_name(&kind, "job kind", MAX_WORKER_TEXT_BYTES).map_err(to_sqlite_error)?;
    validate_digest_value(&payload_digest, "job payload digest").map_err(to_sqlite_error)?;
    if hex_digest(payload_text.as_bytes()) != payload_digest {
        return Err(to_sqlite_error(
            "job payload differs from its admission digest",
        ));
    }
    let payload = serde_json::from_str(&payload_text).map_err(to_sqlite_error)?;
    let status = JobStatus::parse(&status_text).map_err(to_sqlite_error)?;
    let result_text: Option<String> = row.get(11)?;
    let completion_digest: Option<String> = row.get(13)?;
    let last_error: Option<String> = row.get(10)?;
    let worker_id: Option<String> = row.get(12)?;
    if let Some(last_error) = &last_error
        && last_error.as_bytes().contains(&0)
    {
        return Err(to_sqlite_error("job last_error is oversized or malformed"));
    }
    if let Some(worker_id) = &worker_id {
        validate_name(worker_id, "job worker id", MAX_WORKER_TEXT_BYTES)
            .map_err(to_sqlite_error)?;
    }
    if completion_digest.is_some() != result_text.is_some() {
        return Err(to_sqlite_error(
            "job result and completion digest are partially persisted",
        ));
    }
    let result = result_text
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(to_sqlite_error)?;
    if let (Some(result_text), Some(completion_digest)) = (&result_text, &completion_digest) {
        validate_digest_value(completion_digest, "job completion digest")
            .map_err(to_sqlite_error)?;
        if hex_digest(result_text.as_bytes()) != *completion_digest {
            return Err(to_sqlite_error(
                "job result differs from its completion digest",
            ));
        }
    }
    let created_at_ms = sqlite_u64(row.get(5)?, "job created_at_ms")?;
    let claimed_at_ms = sqlite_optional_u64(row.get(6)?, "job claimed_at_ms")?;
    let completed_at_ms = sqlite_optional_u64(row.get(7)?, "job completed_at_ms")?;
    let next_retry_at_ms = sqlite_optional_u64(row.get(9)?, "job next_retry_at_ms")?;
    if claimed_at_ms.is_some_and(|value| value < created_at_ms)
        || completed_at_ms.is_some_and(|value| value < created_at_ms)
        || completed_at_ms
            .zip(claimed_at_ms)
            .is_some_and(|(completed, claimed)| completed < claimed)
    {
        return Err(to_sqlite_error("job phase timestamps are out of order"));
    }
    if !matches!(status, JobStatus::Queued) && next_retry_at_ms.is_some() {
        return Err(to_sqlite_error(
            "job retry timestamp is present outside the queued state",
        ));
    }
    if matches!(status, JobStatus::Running) && claimed_at_ms.is_none() {
        return Err(to_sqlite_error(
            "running job is missing its claim timestamp",
        ));
    }
    if matches!(status, JobStatus::Completed)
        && (claimed_at_ms.is_none() || completed_at_ms.is_none() || result.is_none())
    {
        return Err(to_sqlite_error(
            "completed job is missing claim, completion, or result evidence",
        ));
    }
    Ok((
        JobRecord {
            id,
            kind,
            payload,
            payload_digest,
            status,
            created_at_ms,
            claimed_at_ms,
            completed_at_ms,
            attempt_count: sqlite_u32(row.get(8)?, "job attempt_count")?,
            next_retry_at_ms,
            last_error,
            result,
            worker_id,
        },
        completion_digest,
    ))
}

#[derive(Clone, Debug)]
pub(super) struct RawAttempt {
    pub(super) id: String,
    pub(super) job_id: String,
    pub(super) sequence: u32,
    pub(super) lineage: String,
    pub(super) status: String,
    pub(super) started_at_ms: u64,
    pub(super) finished_at_ms: Option<u64>,
    pub(super) worker_id: Option<String>,
}

const ATTEMPT_SELECT: &str = "SELECT
    CASE WHEN typeof(id)='text' AND length(CAST(id AS BLOB)) <= 128 THEN id END,
    CASE WHEN typeof(job_id)='text' AND length(CAST(job_id AS BLOB)) <= 128 THEN job_id END,
    sequence,
    CASE WHEN typeof(lineage)='text' AND length(CAST(lineage AS BLOB)) <= 256 THEN lineage END,
    CASE WHEN typeof(status)='text' AND length(CAST(status AS BLOB)) <= 32 THEN status END,
    started_at_ms, finished_at_ms,
    CASE WHEN worker_id IS NULL THEN NULL WHEN typeof(worker_id)='text' AND length(CAST(worker_id AS BLOB)) <= 128 THEN worker_id ELSE char(1) END
    FROM attempts WHERE id=?1 AND job_id=?2";

pub(super) fn load_attempt_conn(conn: &Connection, attempt_id: &str) -> Result<Option<RawAttempt>> {
    conn.query_row(
        &ATTEMPT_SELECT.replace("WHERE id=?1 AND job_id=?2", "WHERE id=?1"),
        params![attempt_id],
        raw_attempt_from_row,
    )
    .optional()
    .map_err(Into::into)
}

pub(super) fn load_attempt_tx(
    tx: &Transaction<'_>,
    attempt_id: &str,
) -> Result<Option<RawAttempt>> {
    tx.query_row(
        &ATTEMPT_SELECT.replace("WHERE id=?1 AND job_id=?2", "WHERE id=?1"),
        params![attempt_id],
        raw_attempt_from_row,
    )
    .optional()
    .map_err(Into::into)
}

pub(super) fn raw_attempt_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawAttempt> {
    let id = required_text(row, 0, "attempt id")?;
    let job_id = required_text(row, 1, "attempt job id")?;
    let lineage = required_text(row, 3, "attempt lineage")?;
    let status = required_text(row, 4, "attempt status")?;
    let worker_id: Option<String> = row.get(7)?;
    if let Some(worker_id) = &worker_id {
        validate_name(worker_id, "attempt worker id", MAX_WORKER_TEXT_BYTES)
            .map_err(to_sqlite_error)?;
    }
    let attempt = RawAttempt {
        id,
        job_id,
        sequence: sqlite_u32(row.get(2)?, "attempt sequence")?,
        lineage,
        status,
        started_at_ms: sqlite_u64(row.get(5)?, "attempt started_at_ms")?,
        finished_at_ms: sqlite_optional_u64(row.get(6)?, "attempt finished_at_ms")?,
        worker_id,
    };
    if attempt.lineage.as_bytes().contains(&0) {
        return Err(to_sqlite_error("attempt lineage is malformed"));
    }
    if attempt
        .finished_at_ms
        .is_some_and(|finished| finished < attempt.started_at_ms)
    {
        return Err(to_sqlite_error("attempt finish time precedes its start"));
    }
    Ok(attempt)
}
