//! One-way dispatch marking and worker admission.

use super::storage_worker_claims_validation::{
    validate_current_worker_incarnation_tx, validate_dispatch_control_tx, validate_tuple,
};
use super::storage_worker_queries_handoff::require_handoff_tx;
use super::storage_worker_queries_terminal::{
    ensure_tuple_matches, validate_handoff_transition_time,
};
use super::storage_worker_types::{WorkerHandoff, WorkerHandoffState, WorkerHandoffTuple};
use super::{Store, insert_audit_tx, sqlite_timestamp};
use crate::error::{Result, WatchdogError};
use rusqlite::{TransactionBehavior, params};

impl Store {
    pub fn mark_worker_handoff_may_have_been_dispatched_at(
        &mut self,
        tuple: &WorkerHandoffTuple,
        now_ms: u64,
    ) -> Result<WorkerHandoff> {
        validate_tuple(tuple)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = require_handoff_tx(&tx, tuple, self.max_payload_bytes)?;
        ensure_tuple_matches(&current, tuple)?;
        if current.state != WorkerHandoffState::Prepared {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "handoff is already marked; lookup is allowed and redispatch is forbidden"
                    .to_owned(),
            ));
        }
        validate_handoff_transition_time(&current, now_ms, "dispatch")?;
        validate_dispatch_control_tx(&tx, &current)?;
        let changed = tx.execute(
            "UPDATE worker_handoffs SET state='may_have_been_dispatched', dispatched_at_ms=?, updated_at_ms=? WHERE handoff_id=? AND state='prepared'",
            params![sqlite_timestamp(now_ms)?, sqlite_timestamp(now_ms)?, tuple.handoff_id],
        )?;
        if changed != 1 {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "worker handoff dispatch marker was changed concurrently".to_owned(),
            ));
        }
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
        let current = require_handoff_tx(&tx, tuple, self.max_payload_bytes)?;
        ensure_tuple_matches(&current, tuple)?;
        validate_current_worker_incarnation_tx(&tx, &current)?;
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
        validate_handoff_transition_time(&current, now_ms, "admission")?;
        let changed = tx.execute(
            "UPDATE worker_handoffs SET state='admitted', admitted_at_ms=?, updated_at_ms=? WHERE handoff_id=? AND state='may_have_been_dispatched'",
            params![sqlite_timestamp(now_ms)?, sqlite_timestamp(now_ms)?, tuple.handoff_id],
        )?;
        if changed != 1 {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "worker handoff admission was changed concurrently".to_owned(),
            ));
        }
        insert_audit_tx(&tx, "worker_handoff_admitted", &tuple.handoff_id, now_ms)?;
        tx.commit()?;
        self.worker_handoff(&tuple.handoff_id)?.ok_or_else(|| {
            WatchdogError::Conflict("worker handoff disappeared after admission".to_owned())
        })
    }
}
