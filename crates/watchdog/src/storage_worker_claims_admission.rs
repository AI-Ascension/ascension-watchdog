//! Atomic worker-handoff claim admission.

use super::storage_worker_claims_state::unresolved_handoff_exists;
use super::storage_worker_claims_validation::{validate_claim_witness, validate_claim_witness_tx};
use super::storage_worker_queries_terminal::{empty_parameters, new_uuid4, new_uuid4_distinct};
use super::storage_worker_schema::{WORKER_HANDOFF_OPERATION, WORKER_HANDOFF_PAYLOAD_DIGEST};
use super::storage_worker_types::{WorkerClaimWitness, WorkerHandoff};
use super::{Store, insert_audit_tx, sqlite_timestamp, validate_name};
use crate::error::{Result, WatchdogError};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

impl Store {
    /// Atomically claim the next eligible runtime-v3 episode and persist its
    /// complete tuple plus a `prepared` handoff before any worker IPC.
    pub fn claim_next_worker_handoff(
        &mut self,
        witness: &WorkerClaimWitness,
        now_ms: u64,
    ) -> Result<Option<WorkerHandoff>> {
        validate_claim_witness(witness)?;
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
        validate_claim_witness_tx(&tx, witness)?;
        let unresolved_attempt: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM attempts WHERE status IN ('running','unknown') LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if unresolved_attempt.is_some() || unresolved_handoff_exists(&tx)? {
            tx.commit()?;
            return Ok(None);
        }
        let row: Option<(String, String, String, String, i64, i64)> = tx
            .query_row(
                "SELECT
                    CASE WHEN typeof(id)='text' AND length(CAST(id AS BLOB)) <= 128 THEN id END,
                    CASE WHEN typeof(kind)='text' AND length(CAST(kind AS BLOB)) <= 128 THEN kind END,
                    substr(payload, 1, ?2),
                    CASE WHEN typeof(payload_digest)='text' AND length(CAST(payload_digest AS BLOB)) <= 64 THEN payload_digest END,
                    created_at_ms,
                    attempt_count
                 FROM jobs
                 WHERE status='queued' AND next_retry_at_ms IS NOT NULL AND next_retry_at_ms <= ?1 AND kind=?3 AND payload_digest=?4
                 ORDER BY created_at_ms, id LIMIT 1",
                params![
                    sqlite_timestamp(now_ms)?,
                    payload_read_limit,
                    WORKER_HANDOFF_OPERATION,
                    WORKER_HANDOFF_PAYLOAD_DIGEST
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((job_id, kind, payload_text, payload_digest, created_at, attempt_count)) = row
        else {
            tx.commit()?;
            return Ok(None);
        };
        validate_name(&job_id, "job id", 128)?;
        if kind != WORKER_HANDOFF_OPERATION {
            tx.commit()?;
            return Ok(None);
        }
        let payload =
            super::validate_claim_payload(&payload_text, &payload_digest, self.max_payload_bytes)?;
        if payload != empty_parameters() {
            tx.commit()?;
            return Ok(None);
        }
        let created_at_ms = u64::try_from(created_at)
            .map_err(|_| WatchdogError::Conflict("job creation timestamp is invalid".to_owned()))?;
        if created_at_ms > now_ms {
            tx.commit()?;
            return Ok(None);
        }
        let attempt_number = u32::try_from(attempt_count)
            .map_err(|_| WatchdogError::Conflict("job attempt counter overflow".to_owned()))?
            .checked_add(1)
            .ok_or_else(|| WatchdogError::Conflict("job attempt counter exhausted".to_owned()))?;
        let handoff_id = new_uuid4();
        let attempt_id = new_uuid4_distinct(&[&handoff_id]);
        let run_id = new_uuid4_distinct(&[&handoff_id, &attempt_id]);
        let episode_id = new_uuid4_distinct(&[&handoff_id, &attempt_id, &run_id]);
        let trajectory_id = new_uuid4_distinct(&[&handoff_id, &attempt_id, &run_id, &episode_id]);
        let changed = tx.execute(
            "UPDATE jobs SET status='running', claimed_at_ms=?, worker_id=?, attempt_count=?, next_retry_at_ms=NULL WHERE id=? AND status='queued' AND created_at_ms <= ? AND next_retry_at_ms IS NOT NULL AND next_retry_at_ms <= ?",
            params![
                sqlite_timestamp(now_ms)?,
                witness.worker_owner_id,
                i64::from(attempt_number),
                job_id,
                sqlite_timestamp(now_ms)?,
                sqlite_timestamp(now_ms)?
            ],
        )?;
        if changed != 1 {
            tx.rollback()?;
            return Ok(None);
        }
        tx.execute(
            "INSERT INTO attempts (id, job_id, sequence, lineage, status, started_at_ms, worker_id) VALUES (?, ?, ?, ?, 'running', ?, ?)",
            params![
                attempt_id,
                job_id,
                i64::from(attempt_number),
                format!("{job_id}:{attempt_number}"),
                sqlite_timestamp(now_ms)?,
                witness.worker_owner_id
            ],
        )?;
        tx.execute(
            "INSERT INTO worker_handoffs (handoff_id, deployment_id, job_id, attempt_id, attempt_number, worker_owner_id, worker_profile_digest, run_id, episode_id, trajectory_id, payload_digest, watchdog_boot_id, worker_boot_id, mode_sequence, operation, parameters, state, ack_intent, created_at_ms, updated_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', 0, ?, ?)",
            params![
                handoff_id,
                witness.deployment_id,
                job_id,
                attempt_id,
                i64::from(attempt_number),
                witness.worker_owner_id,
                witness.worker_profile_digest,
                run_id,
                episode_id,
                trajectory_id,
                payload_digest,
                witness.watchdog_boot_id,
                witness.worker_boot_id,
                sqlite_timestamp(witness.mode_sequence)?,
                WORKER_HANDOFF_OPERATION,
                serde_json::to_string(&payload)?,
                sqlite_timestamp(now_ms)?,
                sqlite_timestamp(now_ms)?
            ],
        )?;
        insert_audit_tx(
            &tx,
            "worker_handoff_prepared",
            &format!("{job_id}:{attempt_id}:{handoff_id}"),
            now_ms,
        )?;
        tx.commit()?;
        self.worker_handoff(&handoff_id)?
            .ok_or_else(|| {
                WatchdogError::Conflict("worker handoff disappeared after commit".to_owned())
            })
            .map(Some)
    }

    /// Convenience wrapper using the current wall clock.
    pub fn claim_next_worker_handoff_now(
        &mut self,
        witness: &WorkerClaimWitness,
    ) -> Result<Option<WorkerHandoff>> {
        self.claim_next_worker_handoff(witness, super::now_unix_ms())
    }
}
