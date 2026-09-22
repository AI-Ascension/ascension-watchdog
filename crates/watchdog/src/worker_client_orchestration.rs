//! Store-backed claim, dispatch and reconciliation orchestration.
//!
//! These methods own the durable ordering: the owner-local reservation is
//! committed before transport, and a matching terminal receipt is completed
//! and acknowledged before the handoff is reported settled.  A transport
//! failure leaves the reservation held for reconciliation.

use crate::error::{Result, WatchdogError};
use crate::storage::{
    Store, WorkerClaimWitness, WorkerControlWitness, WorkerHandoff, WorkerHandoffTuple,
};
use crate::worker_protocol::{
    AcknowledgeStatus, ControlScope, DispatchStatus, LookupStatus, TerminalReceipt,
};

use super::session::WorkerClient;
use super::validation::{
    storage_control_mode, storage_receipt, validate_claim_witness_for_client,
    validate_recovery_witness_for_client,
};

impl WorkerClient {
    /// Authenticate a control response and then commit the exact witness in
    /// the watchdog owner-local store.
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_control_mode_and_persist(
        &self,
        store: &mut Store,
        worker_boot_id: &str,
        scope: ControlScope,
        now_ms: u64,
    ) -> Result<WorkerControlWitness> {
        let response = self.set_control_mode(worker_boot_id, scope.clone())?;
        if response.status != crate::worker_protocol::ControlStatus::Accepted {
            return Err(WatchdogError::Conflict(
                "worker rejected the requested control mode".to_owned(),
            ));
        }
        let control = WorkerControlWitness {
            deployment_id: response.scope.deployment_id,
            worker_owner_id: response.scope.worker_owner_id,
            worker_profile_digest: response.scope.worker_profile_digest,
            watchdog_boot_id: self.watchdog_boot_id.clone(),
            worker_boot_id: worker_boot_id.to_owned(),
            mode: storage_control_mode(response.scope.mode),
            mode_sequence: response.scope.mode_sequence,
        };
        store.set_worker_control_at(&control, now_ms)
    }
    /// Claim one eligible job, durably mark it before transport, and dispatch
    /// exactly once.  A response-loss/transport error leaves the durable
    /// reservation held for [`Self::reconcile_handoff`].
    pub fn claim_and_dispatch(
        &self,
        store: &mut Store,
        witness: &WorkerClaimWitness,
        now_ms: u64,
    ) -> Result<Option<WorkerDispatchResult>> {
        validate_claim_witness_for_client(self, witness)?;
        self.probe_for_claim(witness)?;
        let Some(claim) = store.claim_next_worker_handoff(witness, now_ms)? else {
            return Ok(None);
        };
        let tuple = claim.tuple();
        let marked = store.mark_worker_handoff_may_have_been_dispatched_at(&tuple, now_ms)?;
        let response = self.dispatch(&marked)?;
        let mut final_handoff = marked;
        let mut acknowledged = false;
        match response.status {
            DispatchStatus::Accepted => {
                final_handoff = store.mark_worker_handoff_admitted_at(&tuple, now_ms)?;
            }
            DispatchStatus::Terminal | DispatchStatus::AlreadyCompleted => {
                let receipt = response.terminal.as_ref().ok_or_else(|| {
                    WatchdogError::Conflict(
                        "terminal worker dispatch response has no receipt".to_owned(),
                    )
                })?;
                let completion =
                    store.complete_worker_handoff_at(&tuple, &storage_receipt(receipt), now_ms)?;
                let ack_response =
                    self.acknowledge(&tuple, &witness.worker_boot_id, &completion.terminal_digest)?;
                if !matches!(
                    ack_response.status,
                    AcknowledgeStatus::Acknowledged | AcknowledgeStatus::AlreadyAcknowledged
                ) {
                    return Err(WatchdogError::Conflict(
                        "worker rejected terminal acknowledgment".to_owned(),
                    ));
                }
                let _ack = store.acknowledge_worker_handoff_at(
                    &tuple,
                    &completion.terminal_digest,
                    now_ms,
                )?;
                acknowledged = true;
                final_handoff = store.worker_handoff(&tuple.handoff_id)?.ok_or_else(|| {
                    WatchdogError::Conflict(
                        "worker handoff disappeared after acknowledgment".to_owned(),
                    )
                })?;
            }
            DispatchStatus::Busy | DispatchStatus::Rejected => {
                // The send was authorized and may have reached the worker.
                // Retain the may-have-been-dispatched reservation even when a
                // nonterminal response says it did not admit execution.
            }
        }
        Ok(Some(WorkerDispatchResult {
            handoff: final_handoff,
            status: response.status,
            terminal: response.terminal,
            acknowledged,
        }))
    }

    /// Resolve one held handoff by historical lookup, then complete and
    /// acknowledge a matching terminal receipt.  This method has no dispatch
    /// path and therefore cannot start a completed episode again.
    pub fn reconcile_handoff(
        &self,
        store: &mut Store,
        tuple: &WorkerHandoffTuple,
        current_control: &WorkerControlWitness,
        now_ms: u64,
    ) -> Result<WorkerReconcileResult> {
        validate_recovery_witness_for_client(self, current_control)?;
        let Some(existing) = store.lookup_worker_handoff(tuple)? else {
            return Err(WatchdogError::NotFound(format!(
                "worker handoff {}",
                tuple.handoff_id
            )));
        };
        let response = self.lookup(tuple, &current_control.worker_boot_id)?;
        let mut handoff = existing;
        let mut acknowledged = false;
        if response.status == LookupStatus::Terminal {
            let receipt = response.terminal.as_ref().ok_or_else(|| {
                WatchdogError::Conflict("terminal lookup response has no receipt".to_owned())
            })?;
            let completion = store.complete_worker_handoff_with_recovery_at(
                tuple,
                &storage_receipt(receipt),
                current_control,
                now_ms,
            )?;
            let ack_response = self.acknowledge(
                tuple,
                &current_control.worker_boot_id,
                &completion.terminal_digest,
            )?;
            if !matches!(
                ack_response.status,
                AcknowledgeStatus::Acknowledged | AcknowledgeStatus::AlreadyAcknowledged
            ) {
                return Err(WatchdogError::Conflict(
                    "worker rejected terminal acknowledgment".to_owned(),
                ));
            }
            let _ack = store.acknowledge_worker_handoff_with_recovery_at(
                tuple,
                &completion.terminal_digest,
                current_control,
                now_ms,
            )?;
            acknowledged = true;
            handoff = store.worker_handoff(&tuple.handoff_id)?.ok_or_else(|| {
                WatchdogError::Conflict(
                    "worker handoff disappeared after reconciliation".to_owned(),
                )
            })?;
        }
        Ok(WorkerReconcileResult {
            handoff,
            status: response.status,
            terminal: response.terminal,
            acknowledged,
        })
    }

    fn probe_for_claim(&self, witness: &WorkerClaimWitness) -> Result<()> {
        let response = self.probe()?;
        if !response.ready {
            return Err(WatchdogError::Conflict(
                "worker probe is not ready for admission".to_owned(),
            ));
        }
        if response.header.worker_boot_id.as_deref() != Some(witness.worker_boot_id.as_str()) {
            return Err(WatchdogError::IdentityMismatch(
                "worker probe boot differs from the durable claim witness".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Outcome of one bounded claim/dispatch exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerDispatchResult {
    pub handoff: WorkerHandoff,
    pub status: DispatchStatus,
    pub terminal: Option<TerminalReceipt>,
    pub acknowledged: bool,
}

/// Outcome of lookup-based historical reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerReconcileResult {
    pub handoff: WorkerHandoff,
    pub status: LookupStatus,
    pub terminal: Option<TerminalReceipt>,
    pub acknowledged: bool,
}
