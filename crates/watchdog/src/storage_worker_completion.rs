//! One-way dispatch marking, terminal accounting, and idempotent acknowledgment.

use super::storage_worker_claims::{
    validate_digest_value, validate_dispatch_control_tx, validate_tuple,
};
use super::storage_worker_queries::{ensure_tuple_matches, require_handoff_tx, terminal_digest};
use super::storage_worker_schema::MAX_WORKER_WIRE_INTEGER;
use super::storage_worker_types::{
    WorkerAcknowledgment, WorkerCompletion, WorkerHandoff, WorkerHandoffState, WorkerHandoffTuple,
    WorkerTerminalReceipt, WorkerTerminalStatus,
};
use super::{Store, insert_audit_tx, sqlite_timestamp, validate_name};
use crate::config::hex_digest;
use crate::error::{Result, WatchdogError};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

const MAX_TERMINAL_REF_BYTES: usize = 1_024;
const MAX_WORKER_RESULT_BYTES: usize = 64 * 1024;

fn current_ack_intent(tx: &rusqlite::Transaction<'_>, handoff_id: &str) -> Result<bool> {
    let value: i64 = tx.query_row(
        "SELECT ack_intent FROM worker_handoffs WHERE handoff_id=?",
        params![handoff_id],
        |row| row.get(0),
    )?;
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(WatchdogError::Conflict(
            "worker handoff acknowledgment marker is invalid".to_owned(),
        )),
    }
}

impl Store {
    /// Mark the prepared handoff immediately before the one authorized IPC
    /// send.  Once this succeeds, a crash permits lookup but never a second
    /// dispatch.
    pub fn mark_worker_handoff_may_have_been_dispatched_at(
        &mut self,
        tuple: &WorkerHandoffTuple,
        now_ms: u64,
    ) -> Result<WorkerHandoff> {
        validate_tuple(tuple)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = require_handoff_tx(&tx, tuple)?;
        ensure_tuple_matches(&current, tuple)?;
        if current.state != WorkerHandoffState::Prepared {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "handoff is already marked; lookup is allowed and redispatch is forbidden"
                    .to_owned(),
            ));
        }
        validate_dispatch_control_tx(&tx, &current)?;
        tx.execute(
            "UPDATE worker_handoffs SET state='may_have_been_dispatched', dispatched_at_ms=?, updated_at_ms=? WHERE handoff_id=? AND state='prepared'",
            params![sqlite_timestamp(now_ms)?, sqlite_timestamp(now_ms)?, tuple.handoff_id],
        )?;
        insert_audit_tx(
            &tx,
            "worker_handoff_may_have_been_dispatched",
            &tuple.handoff_id,
            now_ms,
        )?;
        tx.commit()?;
        self.worker_handoff(&tuple.handoff_id)?.ok_or_else(|| {
            WatchdogError::Conflict("worker handoff disappeared after dispatch marker".to_owned())
        })
    }

    /// Record worker-side admission after the authenticated dispatch has been
    /// persisted by the worker.  This is idempotent for the same handoff.
    pub fn mark_worker_handoff_admitted_at(
        &mut self,
        tuple: &WorkerHandoffTuple,
        now_ms: u64,
    ) -> Result<WorkerHandoff> {
        validate_tuple(tuple)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = require_handoff_tx(&tx, tuple)?;
        ensure_tuple_matches(&current, tuple)?;
        match current.state {
            WorkerHandoffState::Admitted => {
                tx.commit()?;
                return self.worker_handoff(&tuple.handoff_id)?.ok_or_else(|| {
                    WatchdogError::Conflict("worker handoff disappeared".to_owned())
                });
            }
            WorkerHandoffState::MayHaveBeenDispatched => {}
            _ => {
                tx.rollback()?;
                return Err(WatchdogError::Conflict(
                    "handoff is not awaiting worker admission".to_owned(),
                ));
            }
        }
        tx.execute(
            "UPDATE worker_handoffs SET state='admitted', admitted_at_ms=?, updated_at_ms=? WHERE handoff_id=? AND state='may_have_been_dispatched'",
            params![sqlite_timestamp(now_ms)?, sqlite_timestamp(now_ms)?, tuple.handoff_id],
        )?;
        insert_audit_tx(&tx, "worker_handoff_admitted", &tuple.handoff_id, now_ms)?;
        tx.commit()?;
        self.worker_handoff(&tuple.handoff_id)?.ok_or_else(|| {
            WatchdogError::Conflict("worker handoff disappeared after admission".to_owned())
        })
    }

    /// Atomically commit matching job/attempt terminal completion and the
    /// acknowledgment intent.  The transport may acknowledge after commit;
    /// the job is never returned to the queue while the handoff is terminal.
    pub fn complete_worker_handoff_at(
        &mut self,
        tuple: &WorkerHandoffTuple,
        receipt: &WorkerTerminalReceipt,
        now_ms: u64,
    ) -> Result<WorkerCompletion> {
        validate_tuple(tuple)?;
        validate_terminal_receipt(receipt)?;
        let (result_text, compact_result_digest) = compact_terminal_result(receipt)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = require_handoff_tx(&tx, tuple)?;
        ensure_tuple_matches(&current, tuple)?;
        let expected_terminal_digest = terminal_digest(tuple, receipt);
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
        if !matches!(
            current.state,
            WorkerHandoffState::MayHaveBeenDispatched | WorkerHandoffState::Admitted
        ) {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "handoff was never authorized for worker execution".to_owned(),
            ));
        }
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
        tx.execute(
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
        let target_job_status = job_status;
        match receipt.status {
            WorkerTerminalStatus::Completed => {
                tx.execute(
                    "UPDATE jobs SET status='completed', completed_at_ms=?, result=?, completion_digest=?, last_error=NULL WHERE id=? AND status=?",
                    params![
                        sqlite_timestamp(now_ms)?,
                        &result_text,
                        compact_result_digest,
                        tuple.job_id,
                        target_job_status
                    ],
                )?;
            }
            WorkerTerminalStatus::Failed => {
                tx.execute(
                    "UPDATE jobs SET status='failed', result=?, completion_digest=?, last_error=?, worker_id=NULL WHERE id=? AND status=?",
                    params![
                        &result_text,
                        compact_result_digest,
                        receipt.terminal_ref,
                        tuple.job_id,
                        target_job_status
                    ],
                )?;
            }
        }
        tx.execute(
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

    /// Commit a matching acknowledgment.  A duplicate matching acknowledgment
    /// is idempotent; mismatched terminal evidence is a conflict.
    pub fn acknowledge_worker_handoff_at(
        &mut self,
        tuple: &WorkerHandoffTuple,
        terminal_digest_value: &str,
        now_ms: u64,
    ) -> Result<WorkerAcknowledgment> {
        validate_tuple(tuple)?;
        validate_digest_value(terminal_digest_value, "terminal digest")?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = require_handoff_tx(&tx, tuple)?;
        ensure_tuple_matches(&current, tuple)?;
        let Some(receipt) = current.terminal.as_ref() else {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "handoff has no terminal acknowledgment intent".to_owned(),
            ));
        };
        if receipt.terminal_digest != terminal_digest_value {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "terminal acknowledgment digest does not match durable receipt".to_owned(),
            ));
        }
        if current.state == WorkerHandoffState::Acknowledged {
            tx.commit()?;
            return Ok(WorkerAcknowledgment {
                handoff_id: tuple.handoff_id.clone(),
                terminal_digest: terminal_digest_value.to_owned(),
                already_acknowledged: true,
            });
        }
        if !matches!(
            current.state,
            WorkerHandoffState::Completed | WorkerHandoffState::Failed
        ) || !current_ack_intent(&tx, &tuple.handoff_id)?
        {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "handoff is not awaiting terminal acknowledgment".to_owned(),
            ));
        }
        tx.execute(
            "UPDATE worker_handoffs SET state='acknowledged', acknowledged_at_ms=?, updated_at_ms=? WHERE handoff_id=? AND state IN ('completed','failed') AND ack_intent=1",
            params![sqlite_timestamp(now_ms)?, sqlite_timestamp(now_ms)?, tuple.handoff_id],
        )?;
        insert_audit_tx(
            &tx,
            "worker_handoff_acknowledged",
            &tuple.handoff_id,
            now_ms,
        )?;
        tx.commit()?;
        Ok(WorkerAcknowledgment {
            handoff_id: tuple.handoff_id.clone(),
            terminal_digest: terminal_digest_value.to_owned(),
            already_acknowledged: false,
        })
    }

    /// Wall-clock convenience wrapper around acknowledgment.
    pub fn acknowledge_worker_handoff(
        &mut self,
        tuple: &WorkerHandoffTuple,
        terminal_digest_value: &str,
    ) -> Result<WorkerAcknowledgment> {
        self.acknowledge_worker_handoff_at(tuple, terminal_digest_value, super::now_unix_ms())
    }
}

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

fn compact_terminal_result(receipt: &WorkerTerminalReceipt) -> Result<(String, String)> {
    let compact = serde_json::json!({
        "status": receipt.status,
        "checkpoint_sequence": receipt.checkpoint_sequence,
        "terminal_ref": receipt.terminal_ref,
        "result_digest": receipt.result_digest,
    });
    let encoded = serde_json::to_vec(&compact)?;
    if encoded.len() > MAX_WORKER_RESULT_BYTES {
        return Err(WatchdogError::InvalidInput(format!(
            "worker result exceeds {MAX_WORKER_RESULT_BYTES} bytes"
        )));
    }
    let text = String::from_utf8(encoded.clone())
        .map_err(|error| WatchdogError::InvalidInput(error.to_string()))?;
    Ok((text, hex_digest(&encoded)))
}
