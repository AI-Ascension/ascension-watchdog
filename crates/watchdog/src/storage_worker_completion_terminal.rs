//! Terminal completion accounting.

use super::storage_worker_claims_validation::{
    validate_current_worker_incarnation_tx, validate_digest_value, validate_tuple,
};
use super::storage_worker_queries_handoff::require_handoff_tx;
use super::storage_worker_queries_terminal::{
    compact_terminal_result, ensure_tuple_matches, terminal_digest,
    validate_current_worker_recovery_tx, validate_handoff_transition_time,
};
use super::storage_worker_schema::MAX_WORKER_WIRE_INTEGER;
use super::storage_worker_types::{
    WorkerCompletion, WorkerControlWitness, WorkerHandoffState, WorkerHandoffTuple,
    WorkerTerminalReceipt, WorkerTerminalStatus,
};
use super::{Store, insert_audit_tx, sqlite_timestamp, validate_name};
use crate::error::{Result, WatchdogError};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

const MAX_TERMINAL_REF_BYTES: usize = 1_024;

fn validate_terminal_receipt(receipt: &WorkerTerminalReceipt) -> Result<()> {
    validate_name(
        &receipt.terminal_ref,
        "terminal reference",
        MAX_TERMINAL_REF_BYTES,
    )?;
    validate_digest_value(&receipt.result_digest, "result digest")?;
    if receipt.checkpoint_sequence > MAX_WORKER_WIRE_INTEGER {
        return Err(WatchdogError::InvalidInput(
            "worker checkpoint sequence exceeds the wire integer bound".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum TerminalAuthority<'a> {
    OriginalIncarnation,
    CurrentRecovery(&'a WorkerControlWitness),
}

impl Store {
    /// Atomically commit matching job/attempt terminal completion and the
    /// acknowledgment intent.  The transport may acknowledge after commit;
    /// the job is never returned to the queue while the handoff is terminal.
    pub fn complete_worker_handoff_at(
        &mut self,
        tuple: &WorkerHandoffTuple,
        receipt: &WorkerTerminalReceipt,
        now_ms: u64,
    ) -> Result<WorkerCompletion> {
        self.complete_worker_handoff_with_authority_at(
            tuple,
            receipt,
            TerminalAuthority::OriginalIncarnation,
            now_ms,
        )
    }

    /// Complete a handoff using a current authenticated worker-control
    /// witness after a watchdog or worker replacement.  The witness is
    /// checked against the current durable control row, while the original
    /// handoff tuple and receipt remain the identity being completed.  This
    /// path only accepts an already-dispatched handoff; it never claims or
    /// dispatches a job and does not alter desired mode.
    pub fn complete_worker_handoff_with_recovery_at(
        &mut self,
        tuple: &WorkerHandoffTuple,
        receipt: &WorkerTerminalReceipt,
        recovery: &WorkerControlWitness,
        now_ms: u64,
    ) -> Result<WorkerCompletion> {
        self.complete_worker_handoff_with_authority_at(
            tuple,
            receipt,
            TerminalAuthority::CurrentRecovery(recovery),
            now_ms,
        )
    }

    fn complete_worker_handoff_with_authority_at(
        &mut self,
        tuple: &WorkerHandoffTuple,
        receipt: &WorkerTerminalReceipt,
        authority: TerminalAuthority<'_>,
        now_ms: u64,
    ) -> Result<WorkerCompletion> {
        validate_tuple(tuple)?;
        validate_terminal_receipt(receipt)?;
        let (result_text, compact_result_digest) = compact_terminal_result(receipt)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = require_handoff_tx(&tx, tuple, self.max_payload_bytes)?;
        ensure_tuple_matches(&current, tuple)?;
        if let TerminalAuthority::CurrentRecovery(recovery) = authority {
            validate_current_worker_recovery_tx(&tx, &current, recovery)?;
        }
        let expected_terminal_digest = terminal_digest(tuple, receipt)?;
        if current.state.is_terminal() {
            let Some(existing) = current.terminal.as_ref() else {
                tx.rollback()?;
                return Err(WatchdogError::Conflict(
                    "terminal handoff is missing its receipt".to_owned(),
                ));
            };
            if existing.terminal_digest == expected_terminal_digest
                && existing.result_digest == receipt.result_digest
            {
                tx.commit()?;
                let handoff = self.worker_handoff(&tuple.handoff_id)?.ok_or_else(|| {
                    WatchdogError::Conflict("worker handoff disappeared".to_owned())
                })?;
                return Ok(WorkerCompletion {
                    handoff,
                    terminal_digest: expected_terminal_digest,
                    already_completed: true,
                });
            }
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "handoff already has a different terminal receipt".to_owned(),
            ));
        }
        if matches!(authority, TerminalAuthority::OriginalIncarnation) {
            // A terminal row is immutable historical evidence and was handled
            // above without a current-incarnation check.  Only an unresolved
            // handoff requires the original live authority.
            validate_current_worker_incarnation_tx(&tx, &current)?;
        }
        if !matches!(
            current.state,
            WorkerHandoffState::MayHaveBeenDispatched | WorkerHandoffState::Admitted
        ) {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "handoff was never authorized for worker execution".to_owned(),
            ));
        }
        validate_handoff_transition_time(&current, now_ms, "terminal")?;
        let job_status: String = tx
            .query_row(
                "SELECT status FROM jobs WHERE id=?",
                params![tuple.job_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| WatchdogError::NotFound(format!("job {}", tuple.job_id)))?;
        let attempt_status: String = tx
            .query_row(
                "SELECT status FROM attempts WHERE id=? AND job_id=?",
                params![tuple.attempt_id, tuple.job_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| WatchdogError::NotFound(format!("attempt {}", tuple.attempt_id)))?;
        let active_pair = job_status == "running" && attempt_status == "running";
        let quarantined_pair = job_status == "quarantined" && attempt_status == "unknown";
        if !active_pair && !quarantined_pair {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(format!(
                "job/attempt history is not terminally admissible: job={job_status}, attempt={attempt_status}"
            )));
        }
        let state = match receipt.status {
            WorkerTerminalStatus::Completed => WorkerHandoffState::Completed,
            WorkerTerminalStatus::Failed => WorkerHandoffState::Failed,
        };
        let outcome = match receipt.status {
            WorkerTerminalStatus::Completed => "worker_completed",
            WorkerTerminalStatus::Failed => "worker_failed",
        };
        let attempt_changed = tx.execute(
            "UPDATE attempts SET status=?, finished_at_ms=?, outcome=? WHERE id=? AND job_id=? AND status=?",
            params![
                receipt.status.as_str(),
                sqlite_timestamp(now_ms)?,
                outcome,
                tuple.attempt_id,
                tuple.job_id,
                attempt_status
            ],
        )?;
        if attempt_changed != 1 {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "worker attempt changed concurrently during completion".to_owned(),
            ));
        }
        let target_job_status = job_status;
        match receipt.status {
            WorkerTerminalStatus::Completed => {
                let job_changed = tx.execute(
                    "UPDATE jobs SET status='completed', completed_at_ms=?, result=?, completion_digest=?, last_error=NULL WHERE id=? AND status=?",
                    params![
                        sqlite_timestamp(now_ms)?,
                        &result_text,
                        compact_result_digest,
                        tuple.job_id,
                        target_job_status
                    ],
                )?;
                if job_changed != 1 {
                    tx.rollback()?;
                    return Err(WatchdogError::Conflict(
                        "worker job changed concurrently during completion".to_owned(),
                    ));
                }
            }
            WorkerTerminalStatus::Failed => {
                let job_changed = tx.execute(
                    "UPDATE jobs SET status='failed', result=?, completion_digest=?, last_error=?, worker_id=NULL WHERE id=? AND status=?",
                    params![
                        &result_text,
                        compact_result_digest,
                        receipt.terminal_ref,
                        tuple.job_id,
                        target_job_status
                    ],
                )?;
                if job_changed != 1 {
                    tx.rollback()?;
                    return Err(WatchdogError::Conflict(
                        "worker job changed concurrently during completion".to_owned(),
                    ));
                }
            }
        }
        let handoff_changed = tx.execute(
            "UPDATE worker_handoffs SET state=?, terminal_status=?, checkpoint_sequence=?, terminal_ref=?, result_digest=?, terminal_digest=?, terminal_result=?, ack_intent=1, terminal_at_ms=?, updated_at_ms=? WHERE handoff_id=? AND state IN ('may_have_been_dispatched','admitted')",
            params![
                state.as_str(),
                receipt.status.as_str(),
                sqlite_timestamp(receipt.checkpoint_sequence)?,
                receipt.terminal_ref,
                receipt.result_digest,
                expected_terminal_digest,
                &result_text,
                sqlite_timestamp(now_ms)?,
                sqlite_timestamp(now_ms)?,
                tuple.handoff_id
            ],
        )?;
        if handoff_changed != 1 {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "worker handoff changed concurrently during completion".to_owned(),
            ));
        }
        insert_audit_tx(
            &tx,
            "worker_handoff_terminal_committed",
            &format!("{}:{}", tuple.handoff_id, receipt.status.as_str()),
            now_ms,
        )?;
        tx.commit()?;
        let handoff = self.worker_handoff(&tuple.handoff_id)?.ok_or_else(|| {
            WatchdogError::Conflict("worker handoff disappeared after completion".to_owned())
        })?;
        Ok(WorkerCompletion {
            handoff,
            terminal_digest: expected_terminal_digest,
            already_completed: false,
        })
    }

    /// Wall-clock convenience wrapper around terminal completion.
    pub fn complete_worker_handoff(
        &mut self,
        tuple: &WorkerHandoffTuple,
        receipt: &WorkerTerminalReceipt,
    ) -> Result<WorkerCompletion> {
        self.complete_worker_handoff_at(tuple, receipt, super::now_unix_ms())
    }

    /// Wall-clock convenience wrapper for current-authority historical
    /// completion.
    pub fn complete_worker_handoff_with_recovery(
        &mut self,
        tuple: &WorkerHandoffTuple,
        receipt: &WorkerTerminalReceipt,
        recovery: &WorkerControlWitness,
    ) -> Result<WorkerCompletion> {
        self.complete_worker_handoff_with_recovery_at(
            tuple,
            receipt,
            recovery,
            super::now_unix_ms(),
        )
    }
}
