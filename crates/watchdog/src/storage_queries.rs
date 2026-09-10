//! Bounded operator projections. Never load private payloads into an IPC view.

use super::{JobStatus, Store, validate_name};
use crate::error::{Result, WatchdogError};
use rusqlite::{OptionalExtension, params};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct JobSummary {
    pub id: String,
    pub kind: String,
    pub status: JobStatus,
    pub attempt_count: u32,
    pub created_at_ms: u64,
    pub next_retry_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct JobSummaryPage {
    pub jobs: Vec<JobSummary>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct AttemptSummary {
    pub attempt_id: String,
    pub job_id: String,
    pub sequence: u32,
    pub status: String,
    pub started_at_ms: u64,
    pub finished_at_ms: Option<u64>,
}

impl Store {
    /// Check one exact durable job identifier without loading its payload.
    /// This is used by scoped administrative reconciliation admission so a
    /// request cannot be acknowledged for an unknown job merely because a
    /// bounded list projection omitted it.
    pub fn job_exists(&self, job_id: &str) -> Result<bool> {
        validate_name(job_id, "job id", 128)?;
        let exists: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM jobs WHERE id=? LIMIT 1",
                params![job_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(exists.is_some())
    }

    /// Apply the filter before the bound; fetch one extra row to report truncation.
    pub fn job_summaries(&self, filter: Option<JobStatus>, limit: u16) -> Result<JobSummaryPage> {
        if limit == 0 || limit > 256 {
            return Err(WatchdogError::InvalidInput(
                "job limit must be 1..=256".to_owned(),
            ));
        }
        let mut statement = self.conn.prepare(
            "SELECT id, kind, status, attempt_count, created_at_ms, next_retry_at_ms FROM jobs WHERE (?1 IS NULL OR status=?1) ORDER BY created_at_ms, id LIMIT ?2",
        )?;
        let mut jobs = statement
            .query_map(
                params![filter.map(JobStatus::as_str), i64::from(limit) + 1],
                |row| {
                    let status: String = row.get(2)?;
                    let status = JobStatus::parse(&status).map_err(super::to_sqlite_error)?;
                    Ok(JobSummary {
                        id: row.get(0)?,
                        kind: row.get(1)?,
                        status,
                        attempt_count: row.get(3)?,
                        created_at_ms: timestamp(row, 4)?,
                        next_retry_at_ms: optional_timestamp(row, 5)?,
                    })
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let truncated = jobs.len() > usize::from(limit);
        jobs.truncate(usize::from(limit));
        Ok(JobSummaryPage { jobs, truncated })
    }

    /// Read one exact attempt without outcome text, worker identity or provider data.
    pub fn attempt_summary(&self, attempt_id: &str) -> Result<Option<AttemptSummary>> {
        validate_name(attempt_id, "attempt id", 128)?;
        self.conn.query_row(
            "SELECT id, job_id, sequence, status, started_at_ms, finished_at_ms FROM attempts WHERE id=?",
            params![attempt_id],
            |row| Ok(AttemptSummary {
                attempt_id: row.get(0)?, job_id: row.get(1)?, sequence: row.get(2)?,
                status: row.get(3)?, started_at_ms: timestamp(row, 4)?, finished_at_ms: optional_timestamp(row, 5)?,
            }),
        ).optional().map_err(Into::into)
    }
}

fn timestamp(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    u64::try_from(row.get::<_, i64>(index)?).map_err(super::to_sqlite_error)
}

fn optional_timestamp(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Option<u64>> {
    row.get::<_, Option<i64>>(index)?
        .map(u64::try_from)
        .transpose()
        .map_err(super::to_sqlite_error)
}
