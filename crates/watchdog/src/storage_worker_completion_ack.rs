//! Durable acknowledgment and terminal receipt validation.

use super::storage_worker_claims_validation::{validate_digest_value, validate_tuple};
use super::storage_worker_queries_handoff::require_handoff_tx;
use super::storage_worker_queries_terminal::{
    ensure_tuple_matches, validate_handoff_transition_time,
};
use super::storage_worker_types::{WorkerAcknowledgment, WorkerHandoffState, WorkerHandoffTuple};
use super::{Store, insert_audit_tx, sqlite_timestamp};
use crate::error::{Result, WatchdogError};
use rusqlite::{TransactionBehavior, params};

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
        let current = require_handoff_tx(&tx, tuple, self.max_payload_bytes)?;
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
        validate_handoff_transition_time(&current, now_ms, "acknowledgment")?;
        let changed = tx.execute(
            "UPDATE worker_handoffs SET state='acknowledged', acknowledged_at_ms=?, updated_at_ms=? WHERE handoff_id=? AND state IN ('completed','failed') AND ack_intent=1",
            params![sqlite_timestamp(now_ms)?, sqlite_timestamp(now_ms)?, tuple.handoff_id],
        )?;
        if changed != 1 {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "worker acknowledgment was changed concurrently".to_owned(),
            ));
        }
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
