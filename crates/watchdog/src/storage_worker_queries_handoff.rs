//! Worker handoff lookup and cross-table loading.

use super::Store;
use super::storage_worker_claims_validation::validate_tuple;
use super::storage_worker_queries_consistency::validate_handoff_job;
use super::storage_worker_queries_handoff_row::{HANDOFF_SELECT, raw_handoff_from_row};
use super::storage_worker_queries_jobs::{load_attempt_tx, load_job_tx};
use super::storage_worker_queries_projection::handoff_from_raw;
use super::storage_worker_queries_terminal::validate_uuid4;
use super::storage_worker_types::{WorkerHandoff, WorkerHandoffTuple};
use crate::error::{Result, WatchdogError};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

pub(super) use super::storage_worker_queries_handoff_row::RawHandoff;

impl Store {
    /// Rediscover the oldest retained handoff needing reconciliation or ACK.
    /// Loads at most one bounded record, including prepared and uncertain work.
    /// This query does not grant dispatch authority or clear its reservation.
    pub fn next_worker_handoff_for_reconciliation(&self) -> Result<Option<WorkerHandoff>> {
        let id: Option<String> = self.conn.query_row(
            "SELECT CASE WHEN typeof(handoff_id)='text' AND length(CAST(handoff_id AS BLOB))=36 THEN handoff_id END
             FROM worker_handoffs WHERE state NOT IN ('acknowledged','rejected') OR state IS NULL
             ORDER BY created_at_ms, handoff_id LIMIT 1",
            [],
            |row| row.get(0),
        ).optional()?;
        id.map(|id| {
            self.worker_handoff(&id)?.ok_or_else(|| {
                WatchdogError::Conflict(
                    "pending worker handoff disappeared during lookup".to_owned(),
                )
            })
        })
        .transpose()
    }

    /// Read one handoff without mutating state.
    pub fn worker_handoff(&self, handoff_id: &str) -> Result<Option<WorkerHandoff>> {
        validate_uuid4(handoff_id, "handoff id")?;
        load_handoff(&self.conn, handoff_id, self.max_payload_bytes)
    }

    /// Read one handoff while rejecting any tuple mismatch.
    pub fn lookup_worker_handoff(
        &self,
        tuple: &WorkerHandoffTuple,
    ) -> Result<Option<WorkerHandoff>> {
        validate_tuple(tuple)?;
        let Some(handoff) = self.worker_handoff(&tuple.handoff_id)? else {
            return Ok(None);
        };
        if handoff.tuple() != *tuple {
            return Err(WatchdogError::Conflict(
                "worker handoff tuple does not match durable history".to_owned(),
            ));
        }
        Ok(Some(handoff))
    }
}

pub(super) fn load_handoff(
    conn: &Connection,
    handoff_id: &str,
    max_payload_bytes: usize,
) -> Result<Option<WorkerHandoff>> {
    let raw = conn
        .query_row(HANDOFF_SELECT, params![handoff_id], raw_handoff_from_row)
        .optional()?;
    raw.map(|raw| handoff_from_raw(conn, raw, max_payload_bytes))
        .transpose()
}

pub(super) fn load_handoff_tx(
    tx: &Transaction<'_>,
    handoff_id: &str,
) -> Result<Option<RawHandoff>> {
    tx.query_row(HANDOFF_SELECT, params![handoff_id], raw_handoff_from_row)
        .optional()
        .map_err(Into::into)
}

pub(super) fn require_handoff_tx(
    tx: &Transaction<'_>,
    tuple: &WorkerHandoffTuple,
    max_payload_bytes: usize,
) -> Result<RawHandoff> {
    if let Some(raw) = load_handoff_tx(tx, &tuple.handoff_id)? {
        let (job, completion_digest) = load_job_tx(tx, &raw.job_id, max_payload_bytes)?
            .ok_or_else(|| {
                WatchdogError::Conflict("worker handoff references a missing job".to_owned())
            })?;
        let attempt = load_attempt_tx(tx, &raw.attempt_id)?.ok_or_else(|| {
            WatchdogError::Conflict("worker handoff references a missing attempt".to_owned())
        })?;
        validate_handoff_job(&raw, &job, &attempt, completion_digest.as_deref())?;
        return Ok(raw);
    }
    let historical_handoff: Option<String> = tx
        .query_row(
            "SELECT CASE WHEN typeof(handoff_id)='text' AND length(CAST(handoff_id AS BLOB)) <= 36 THEN handoff_id END
             FROM worker_handoffs WHERE job_id=? AND attempt_id=?",
            params![tuple.job_id, tuple.attempt_id],
            |row| row.get(0),
        )
        .optional()?;
    if historical_handoff.is_some() {
        return Err(WatchdogError::Conflict(
            "worker attempt already has a different durable handoff tuple".to_owned(),
        ));
    }
    Err(WatchdogError::NotFound(format!(
        "worker handoff {}",
        tuple.handoff_id
    )))
}
