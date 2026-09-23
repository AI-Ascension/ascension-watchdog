//! Durable job queue, claim, completion and failure transactions.
//!
//! Extracted from `storage.rs` (issue #98) without behavior change: the public
//! job record/status/claim/completion types, the job row decoder, and the
//! transactional admission, claim, completion, quarantine and failure
//! primitives.  `Store` remains the facade type; this module owns only the
//! job-queue inherent methods and their shared row/transaction helpers.

use super::{
    Store, insert_audit_tx, metadata_from_conn, now_unix_ms, parse_mode, sqlite_optional_u64,
    sqlite_timestamp, sqlite_u32, sqlite_u64, to_sqlite_error, validate_detail, validate_name,
};
use crate::config::{DesiredMode, hex_digest};
use crate::error::{Result, WatchdogError};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

const MAX_RESULT_BYTES: usize = 64 * 1024;

/// A durable job row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JobRecord {
    pub id: String,
    pub kind: String,
    pub payload: Value,
    pub payload_digest: String,
    pub status: JobStatus,
    pub created_at_ms: u64,
    pub claimed_at_ms: Option<u64>,
    pub completed_at_ms: Option<u64>,
    pub attempt_count: u32,
    pub next_retry_at_ms: Option<u64>,
    pub last_error: Option<String>,
    pub result: Option<Value>,
    pub worker_id: Option<String>,
}

/// Job status transitions are persisted transactionally.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Quarantined,
}

impl JobStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Quarantined => "quarantined",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "quarantined" => Ok(Self::Quarantined),
            other => Err(WatchdogError::Conflict(format!(
                "unknown durable job status {other}"
            ))),
        }
    }
}

/// An atomic claim includes a distinct attempt identity and lineage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JobClaim {
    pub job: JobRecord,
    pub attempt_id: String,
    pub attempt_number: u32,
    pub lineage: String,
    pub claimed_by: String,
}

/// Durable completion result, including idempotent duplicate acknowledgments.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Completion {
    pub job_id: String,
    pub attempt_id: String,
    pub result: Value,
    pub already_completed: bool,
}

/// Shared transaction primitive for worker-local and authenticated operator
/// admission. The caller owns commit so a job and its replay receipt can be
/// published atomically; neither insert is acknowledged independently.
pub(crate) fn insert_job_tx(
    tx: &Transaction<'_>,
    id: &str,
    kind: &str,
    encoded: &[u8],
    digest: &str,
    max_jobs: u64,
    now_ms: u64,
) -> Result<()> {
    let jobs: i64 = tx.query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get(0))?;
    if u64::try_from(jobs).unwrap_or(u64::MAX) >= max_jobs {
        return Err(WatchdogError::Conflict(
            "job retention bound is full".to_owned(),
        ));
    }
    let payload = std::str::from_utf8(encoded)
        .map_err(|error| WatchdogError::InvalidInput(error.to_string()))?;
    tx.execute(
        "INSERT INTO jobs (id, kind, payload, payload_digest, status, created_at_ms, attempt_count, next_retry_at_ms) VALUES (?, ?, ?, ?, 'queued', ?, 0, ?)",
        params![id, kind, payload, digest, sqlite_timestamp(now_ms)?, sqlite_timestamp(now_ms)?],
    )?;
    insert_audit_tx(tx, "job_submitted", id, now_ms)
}

pub(crate) fn validate_claim_payload(
    text: &str,
    expected_digest: &str,
    bound: usize,
) -> Result<Value> {
    if text.len() > bound || hex_digest(text.as_bytes()) != expected_digest {
        return Err(WatchdogError::Conflict(
            "stored job payload exceeds its bound or differs from its admission digest".to_owned(),
        ));
    }
    serde_json::from_str(text)
        .map_err(|_| WatchdogError::Conflict("stored job payload is not valid JSON".to_owned()))
}

pub(crate) fn job_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobRecord> {
    let payload_text: String = row.get(2)?;
    let result_text: Option<String> = row.get(11)?;
    let status: String = row.get(4)?;
    Ok(JobRecord {
        id: row.get(0)?,
        kind: row.get(1)?,
        payload: serde_json::from_str(&payload_text).map_err(to_sqlite_error)?,
        payload_digest: row.get(3)?,
        status: JobStatus::parse(&status).map_err(to_sqlite_error)?,
        created_at_ms: sqlite_u64(row.get::<_, i64>(5)?, "job created_at_ms")?,
        claimed_at_ms: sqlite_optional_u64(row.get::<_, Option<i64>>(6)?, "job claimed_at_ms")?,
        completed_at_ms: sqlite_optional_u64(row.get::<_, Option<i64>>(7)?, "job completed_at_ms")?,
        attempt_count: sqlite_u32(row.get::<_, i64>(8)?, "job attempt_count")?,
        next_retry_at_ms: sqlite_optional_u64(
            row.get::<_, Option<i64>>(9)?,
            "job next_retry_at_ms",
        )?,
        last_error: row.get(10)?,
        result: result_text
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(to_sqlite_error)?,
        worker_id: row.get(12)?,
    })
}

impl Store {
    /// Submit a bounded JSON job.  The payload digest and row are committed in
    /// one transaction, before a worker can claim it.
    pub fn submit_job(&mut self, kind: &str, payload: &Value) -> Result<JobRecord> {
        self.submit_job_at(kind, payload, now_unix_ms())
    }

    /// Timestamp-controlled job submission.
    pub fn submit_job_at(&mut self, kind: &str, payload: &Value, now_ms: u64) -> Result<JobRecord> {
        validate_name(kind, "job kind", 128)?;
        let encoded = serde_json::to_vec(payload)?;
        if encoded.len() > self.max_payload_bytes {
            return Err(WatchdogError::InvalidInput(format!(
                "job payload exceeds {} bytes",
                self.max_payload_bytes
            )));
        }
        let id = Uuid::new_v4().to_string();
        let digest = hex_digest(&encoded);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_job_tx(&tx, &id, kind, &encoded, &digest, self.max_jobs, now_ms)?;
        tx.commit()?;
        self.get_job(&id)?
            .ok_or_else(|| WatchdogError::Conflict("job disappeared after commit".to_string()))
    }

    /// Atomically claim the oldest ready job, creating a new attempt lineage.
    /// Running rows are never silently returned to the queue after a process
    /// crash; callers must reconcile them explicitly.
    pub fn claim_next_job(&mut self, worker_id: &str, now_ms: u64) -> Result<Option<JobClaim>> {
        validate_name(worker_id, "worker id", 128)?;
        let payload_read_limit = self
            .max_payload_bytes
            .checked_add(1)
            .and_then(|limit| i64::try_from(limit).ok())
            .ok_or_else(|| {
                WatchdogError::InvalidInput("job payload bound exceeds SQLite range".to_owned())
            })?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let desired = metadata_from_conn(&tx, "desired_mode")?.ok_or_else(|| {
            WatchdogError::Conflict("desired mode metadata is missing".to_owned())
        })?;
        if parse_mode(&desired)? != DesiredMode::Running {
            tx.commit()?;
            return Ok(None);
        }
        // This store owns one single-instance deployment. Any running or
        // unknown attempt reserves that deployment, regardless of worker ID.
        // A replacement worker/daemon boot cannot evade unresolved history by
        // selecting a fresh name. Only explicit reconciliation/completion can
        // release this reservation; quarantine deliberately retains it.
        let unresolved_attempt: Option<String> = tx
            .query_row(
                "SELECT id FROM attempts WHERE status IN ('running','unknown') ORDER BY started_at_ms, sequence, id LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if unresolved_attempt.is_some() {
            tx.commit()?;
            return Ok(None);
        }
        let row: Option<(String, String, String, String, i64, i64, i64)> = tx
            .query_row(
                "SELECT id, kind, substr(payload, 1, ?2), payload_digest, created_at_ms, attempt_count, next_retry_at_ms FROM jobs WHERE status = 'queued' AND next_retry_at_ms <= ?1 ORDER BY created_at_ms, id LIMIT 1",
                params![sqlite_timestamp(now_ms)?, payload_read_limit],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((id, kind, payload_text, payload_digest, created_at, attempt_count, _next_retry)) =
            row
        else {
            tx.commit()?;
            return Ok(None);
        };
        validate_name(&id, "job id", 128)?;
        validate_name(&kind, "job kind", 128)?;
        let payload =
            validate_claim_payload(&payload_text, &payload_digest, self.max_payload_bytes)?;
        let created_at_ms = u64::try_from(created_at)
            .map_err(|_| WatchdogError::Conflict("job creation timestamp is invalid".to_owned()))?;
        let next_attempt = u32::try_from(attempt_count)
            .map_err(|_| WatchdogError::Conflict("job attempt counter overflow".to_string()))?
            .checked_add(1)
            .ok_or_else(|| WatchdogError::Conflict("job attempt counter exhausted".to_string()))?;
        let changed = tx.execute(
            "UPDATE jobs SET status='running', claimed_at_ms=?, worker_id=?, attempt_count=? WHERE id=? AND status='queued'",
            params![sqlite_timestamp(now_ms)?, worker_id, i64::from(next_attempt), id],
        )?;
        if changed != 1 {
            tx.rollback()?;
            return Ok(None);
        }
        let attempt_id = Uuid::new_v4().to_string();
        let lineage = format!("{id}:{next_attempt}");
        tx.execute(
            "INSERT INTO attempts (id, job_id, sequence, lineage, status, started_at_ms, worker_id) VALUES (?, ?, ?, ?, 'running', ?, ?)",
            params![attempt_id, id, i64::from(next_attempt), lineage, sqlite_timestamp(now_ms)?, worker_id],
        )?;
        insert_audit_tx(&tx, "job_claimed", &format!("{id}:{attempt_id}"), now_ms)?;
        tx.commit()?;
        Ok(Some(JobClaim {
            job: JobRecord {
                id,
                kind,
                payload,
                payload_digest,
                status: JobStatus::Running,
                created_at_ms,
                claimed_at_ms: Some(now_ms),
                completed_at_ms: None,
                attempt_count: next_attempt,
                next_retry_at_ms: None,
                last_error: None,
                result: None,
                worker_id: Some(worker_id.to_string()),
            },
            attempt_id,
            attempt_number: next_attempt,
            lineage,
            claimed_by: worker_id.to_string(),
        }))
    }

    /// Atomically persist attempt completion and job completion.  Repeating a
    /// completion after a crash is idempotent only when the existing completion
    /// has the same result digest.
    pub fn complete_job(
        &mut self,
        job_id: &str,
        attempt_id: &str,
        result: &Value,
    ) -> Result<Completion> {
        self.complete_job_at(job_id, attempt_id, result, now_unix_ms())
    }

    /// Timestamp-controlled completion transaction.
    pub fn complete_job_at(
        &mut self,
        job_id: &str,
        attempt_id: &str,
        result: &Value,
        now_ms: u64,
    ) -> Result<Completion> {
        let encoded = serde_json::to_vec(result)?;
        if encoded.len() > MAX_RESULT_BYTES {
            return Err(WatchdogError::InvalidInput(format!(
                "job result exceeds {MAX_RESULT_BYTES} bytes"
            )));
        }
        let result_text = String::from_utf8(encoded.clone())
            .map_err(|error| WatchdogError::InvalidInput(error.to_string()))?;
        let digest = hex_digest(&encoded);
        let tx = self.conn.transaction()?;
        let current: Option<(String, Option<String>, Option<String>)> = tx
            .query_row(
                "SELECT status, result, completion_digest FROM jobs WHERE id=?",
                params![job_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((status, existing_result, existing_digest)) = current else {
            tx.rollback()?;
            return Err(WatchdogError::NotFound(format!("job {job_id}")));
        };
        if status == "completed" {
            let completed_attempt: Option<String> = tx
                .query_row(
                    "SELECT id FROM attempts WHERE job_id=? AND status='completed' ORDER BY sequence DESC LIMIT 1",
                    params![job_id],
                    |row| row.get(0),
                )
                .optional()?;
            if completed_attempt.as_deref() != Some(attempt_id) {
                tx.rollback()?;
                return Err(WatchdogError::Conflict(
                    "completion attempt does not match the durable completed attempt".to_string(),
                ));
            }
            if existing_digest.as_deref() == Some(digest.as_str()) {
                let parsed = existing_result
                    .as_deref()
                    .map(serde_json::from_str)
                    .transpose()?
                    .unwrap_or(Value::Null);
                tx.commit()?;
                return Ok(Completion {
                    job_id: job_id.to_string(),
                    attempt_id: attempt_id.to_string(),
                    result: parsed,
                    already_completed: true,
                });
            }
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "job is completed with a different result".to_string(),
            ));
        }
        if status != "running" {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(format!(
                "job is {status}, not running"
            )));
        }
        let attempt_status: Option<String> = tx
            .query_row(
                "SELECT status FROM attempts WHERE id=? AND job_id=?",
                params![attempt_id, job_id],
                |row| row.get(0),
            )
            .optional()?;
        if attempt_status.as_deref() != Some("running") {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "attempt is not the active running claim".to_string(),
            ));
        }
        let attempt_changed = tx.execute(
            "UPDATE attempts SET status='completed', finished_at_ms=?, outcome=? WHERE id=? AND job_id=? AND status='running'",
            params![sqlite_timestamp(now_ms)?, result_text, attempt_id, job_id],
        )?;
        if attempt_changed != 1 {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "attempt completion changed concurrently".to_owned(),
            ));
        }
        let job_changed = tx.execute(
            "UPDATE jobs SET status='completed', completed_at_ms=?, result=?, completion_digest=?, last_error=NULL WHERE id=? AND status='running'",
            params![sqlite_timestamp(now_ms)?, serde_json::to_string(result)?, digest, job_id],
        )?;
        if job_changed != 1 {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "job completion changed concurrently".to_owned(),
            ));
        }
        insert_audit_tx(
            &tx,
            "job_completed",
            &format!("{job_id}:{attempt_id}"),
            now_ms,
        )?;
        tx.commit()?;
        Ok(Completion {
            job_id: job_id.to_string(),
            attempt_id: attempt_id.to_string(),
            result: result.clone(),
            already_completed: false,
        })
    }

    /// Mark an interrupted running claim as unknown/quarantined.  This is the
    /// conservative crash boundary: a new daemon never guesses that work did
    /// not execute and never reruns it automatically.
    pub fn quarantine_interrupted_jobs(&mut self, now_ms: u64) -> Result<u64> {
        let tx = self.conn.transaction()?;
        let mut stmt = tx.prepare("SELECT id FROM jobs WHERE status='running'")?;
        let ids: Vec<String> = stmt
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        drop(stmt);
        for job_id in &ids {
            let attempt_changed = tx.execute(
                "UPDATE attempts SET status='unknown', finished_at_ms=?, outcome='daemon_interrupted' WHERE job_id=? AND status='running'",
                params![sqlite_timestamp(now_ms)?, job_id],
            )?;
            if attempt_changed != 1 {
                tx.rollback()?;
                return Err(WatchdogError::Conflict(
                    "interrupted attempt changed concurrently".to_owned(),
                ));
            }
            let job_changed = tx.execute(
                "UPDATE jobs SET status='quarantined', last_error='daemon interrupted; outcome unknown' WHERE id=? AND status='running'",
                params![job_id],
            )?;
            if job_changed != 1 {
                tx.rollback()?;
                return Err(WatchdogError::Conflict(
                    "interrupted job changed concurrently".to_owned(),
                ));
            }
            insert_audit_tx(&tx, "job_quarantined_after_interruption", job_id, now_ms)?;
        }
        tx.commit()?;
        Ok(u64::try_from(ids.len()).unwrap_or(u64::MAX))
    }

    /// List a bounded number of jobs for operators.
    pub fn list_jobs(&self, limit: u64) -> Result<Vec<JobRecord>> {
        let limit = limit.min(self.max_jobs).min(1_024);
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, payload, payload_digest, status, created_at_ms, claimed_at_ms, completed_at_ms, attempt_count, next_retry_at_ms, last_error, result, worker_id FROM jobs ORDER BY created_at_ms, id LIMIT ?",
        )?;
        let rows = stmt.query_map(
            params![i64::try_from(limit).unwrap_or(i64::MAX)],
            job_from_row,
        )?;
        rows.collect::<rusqlite::Result<Vec<JobRecord>>>()
            .map_err(Into::into)
    }

    /// Fetch a job without mutating state.
    pub fn get_job(&self, id: &str) -> Result<Option<JobRecord>> {
        self.conn
            .query_row(
                "SELECT id, kind, payload, payload_digest, status, created_at_ms, claimed_at_ms, completed_at_ms, attempt_count, next_retry_at_ms, last_error, result, worker_id FROM jobs WHERE id=?",
                params![id],
                job_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Record a known failure with bounded persisted retry/backoff.  The job
    /// remains quarantined once the caller's retry budget is exhausted.
    pub fn fail_job_at(
        &mut self,
        job_id: &str,
        attempt_id: &str,
        error: &str,
        retry_at_ms: Option<u64>,
        now_ms: u64,
    ) -> Result<JobStatus> {
        validate_detail(error, "job error")?;
        let tx = self.conn.transaction()?;
        let status: Option<String> = tx
            .query_row(
                "SELECT status FROM jobs WHERE id=?",
                params![job_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(status) = status else {
            tx.rollback()?;
            return Err(WatchdogError::NotFound(format!("job {job_id}")));
        };
        if status != "running" {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(format!(
                "job is {status}, not running"
            )));
        }
        let attempt_status: Option<String> = tx
            .query_row(
                "SELECT status FROM attempts WHERE id=? AND job_id=?",
                params![attempt_id, job_id],
                |row| row.get(0),
            )
            .optional()?;
        if attempt_status.as_deref() != Some("running") {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "attempt is not running".to_string(),
            ));
        }
        let target = if retry_at_ms.is_some() {
            JobStatus::Queued
        } else {
            JobStatus::Quarantined
        };
        let attempt_changed = tx.execute(
            "UPDATE attempts SET status='failed', finished_at_ms=?, outcome=? WHERE id=? AND status='running'",
            params![sqlite_timestamp(now_ms)?, error, attempt_id],
        )?;
        if attempt_changed != 1 {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "attempt failure changed concurrently".to_owned(),
            ));
        }
        let job_changed = tx.execute(
            "UPDATE jobs SET status=?, next_retry_at_ms=?, last_error=?, worker_id=NULL WHERE id=? AND status='running'",
            params![
                target.as_str(),
                retry_at_ms.map(sqlite_timestamp).transpose()?,
                error,
                job_id
            ],
        )?;
        if job_changed != 1 {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "job failure changed concurrently".to_owned(),
            ));
        }
        insert_audit_tx(&tx, "job_failed", &format!("{job_id}:{target:?}"), now_ms)?;
        tx.commit()?;
        Ok(target)
    }

    pub(crate) fn job_count(&self, status: JobStatus) -> Result<u64> {
        u64::try_from(self.conn.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM jobs WHERE status=?",
            params![status.as_str()],
            |row| row.get(0),
        )?)
        .map_err(|_| WatchdogError::Conflict("job count overflow".to_string()))
    }
}
