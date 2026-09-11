//! Handoff projection and lifecycle-column consistency checks.

use super::super::to_sqlite_error;
use super::storage_worker_queries_consistency::validate_handoff_job;
use super::storage_worker_queries_handoff::RawHandoff;
use super::storage_worker_queries_jobs::{load_attempt_conn, load_job_conn};
use super::storage_worker_queries_terminal::{compact_terminal_result, terminal_digest};
use super::storage_worker_types::{
    WorkerHandoff, WorkerHandoffState, WorkerHandoffTuple, WorkerTerminalReceipt,
    WorkerTerminalRecord, WorkerTerminalStatus,
};
use crate::error::{Result, WatchdogError};
use rusqlite::Connection;

pub(super) fn handoff_from_raw(
    conn: &Connection,
    raw: RawHandoff,
    max_payload_bytes: usize,
) -> Result<WorkerHandoff> {
    let (job, completion_digest) = load_job_conn(conn, &raw.job_id, max_payload_bytes)?
        .ok_or_else(|| {
            WatchdogError::Conflict("worker handoff references a missing job".to_owned())
        })?;
    let attempt = load_attempt_conn(conn, &raw.attempt_id)?.ok_or_else(|| {
        WatchdogError::Conflict("worker handoff references a missing attempt".to_owned())
    })?;
    validate_handoff_job(&raw, &job, &attempt, completion_digest.as_deref())?;
    Ok(WorkerHandoff {
        handoff_id: raw.handoff_id,
        deployment_id: raw.deployment_id,
        job_id: raw.job_id,
        attempt_id: raw.attempt_id,
        attempt_number: raw.attempt_number,
        worker_owner_id: raw.worker_owner_id,
        worker_profile_digest: raw.worker_profile_digest,
        run_id: raw.run_id,
        episode_id: raw.episode_id,
        trajectory_id: raw.trajectory_id,
        payload_digest: raw.payload_digest,
        watchdog_boot_id: raw.watchdog_boot_id,
        worker_boot_id: raw.worker_boot_id,
        mode_sequence: raw.mode_sequence,
        operation: raw.operation,
        parameters: raw.parameters,
        state: raw.state,
        job,
        terminal: raw.terminal,
        created_at_ms: raw.created_at_ms,
        updated_at_ms: raw.updated_at_ms,
    })
}

pub(super) fn required_text(
    row: &rusqlite::Row<'_>,
    index: usize,
    field: &str,
) -> rusqlite::Result<String> {
    row.get::<_, Option<String>>(index)?.ok_or_else(|| {
        to_sqlite_error(format!(
            "worker {field} is missing, non-text, or exceeds its bound"
        ))
    })
}

pub(super) fn validate_terminal_projection(
    tuple: &WorkerHandoffTuple,
    state: WorkerHandoffState,
    terminal: Option<&WorkerTerminalRecord>,
    terminal_result: Option<&str>,
    ack_intent: bool,
    created_at_ms: u64,
    updated_at_ms: u64,
    dispatched_at_ms: Option<u64>,
    admitted_at_ms: Option<u64>,
    terminal_at_ms: Option<u64>,
    acknowledged_at_ms: Option<u64>,
) -> rusqlite::Result<()> {
    if updated_at_ms < created_at_ms {
        return Err(to_sqlite_error(
            "worker handoff updated time precedes creation",
        ));
    }
    for (name, value) in [
        ("dispatched", dispatched_at_ms),
        ("admitted", admitted_at_ms),
        ("terminal", terminal_at_ms),
        ("acknowledged", acknowledged_at_ms),
    ] {
        if let Some(value) = value
            && (value < created_at_ms || value > updated_at_ms)
        {
            return Err(to_sqlite_error(format!(
                "worker handoff {name} time is outside its creation/update interval"
            )));
        }
    }
    let terminal_state = state.is_terminal();
    if terminal_state != terminal.is_some() || terminal_state != terminal_result.is_some() {
        return Err(to_sqlite_error(
            "worker handoff terminal state and receipt columns disagree",
        ));
    }
    match state {
        WorkerHandoffState::Prepared | WorkerHandoffState::Rejected => {
            if ack_intent
                || dispatched_at_ms.is_some()
                || admitted_at_ms.is_some()
                || terminal_at_ms.is_some()
                || acknowledged_at_ms.is_some()
            {
                return Err(to_sqlite_error(
                    "worker handoff has lifecycle timestamps or acknowledgment intent before dispatch",
                ));
            }
        }
        WorkerHandoffState::MayHaveBeenDispatched => {
            if ack_intent
                || dispatched_at_ms.is_none()
                || admitted_at_ms.is_some()
                || terminal_at_ms.is_some()
                || acknowledged_at_ms.is_some()
            {
                return Err(to_sqlite_error(
                    "worker handoff dispatch lifecycle columns are inconsistent",
                ));
            }
        }
        WorkerHandoffState::Admitted => {
            if ack_intent
                || dispatched_at_ms.is_none()
                || admitted_at_ms.is_none()
                || terminal_at_ms.is_some()
                || acknowledged_at_ms.is_some()
            {
                return Err(to_sqlite_error(
                    "worker handoff admission lifecycle columns are inconsistent",
                ));
            }
        }
        WorkerHandoffState::Completed | WorkerHandoffState::Failed => {
            if !ack_intent
                || dispatched_at_ms.is_none()
                || terminal_at_ms.is_none()
                || acknowledged_at_ms.is_some()
            {
                return Err(to_sqlite_error(
                    "worker handoff terminal lifecycle columns are inconsistent",
                ));
            }
        }
        WorkerHandoffState::Acknowledged => {
            if !ack_intent
                || dispatched_at_ms.is_none()
                || terminal_at_ms.is_none()
                || acknowledged_at_ms.is_none()
            {
                return Err(to_sqlite_error(
                    "worker handoff acknowledgment lifecycle columns are inconsistent",
                ));
            }
        }
    }
    if let Some(admitted) = admitted_at_ms
        && let Some(dispatched) = dispatched_at_ms
        && admitted < dispatched
    {
        return Err(to_sqlite_error(
            "worker handoff admission precedes dispatch",
        ));
    }
    if let Some(terminal_at) = terminal_at_ms
        && let Some(admitted) = admitted_at_ms
        && terminal_at < admitted
    {
        return Err(to_sqlite_error(
            "worker handoff terminal time precedes admission",
        ));
    }
    if let Some(terminal_at) = terminal_at_ms
        && let Some(dispatched) = dispatched_at_ms
        && terminal_at < dispatched
    {
        return Err(to_sqlite_error(
            "worker handoff terminal time precedes dispatch",
        ));
    }
    if let Some(acknowledged_at) = acknowledged_at_ms
        && let Some(terminal_at) = terminal_at_ms
        && acknowledged_at < terminal_at
    {
        return Err(to_sqlite_error(
            "worker handoff acknowledgment precedes terminal commit",
        ));
    }
    if let Some(receipt) = terminal {
        let wire_receipt = WorkerTerminalReceipt {
            status: receipt.status,
            checkpoint_sequence: receipt.checkpoint_sequence,
            terminal_ref: receipt.terminal_ref.clone(),
            result_digest: receipt.result_digest.clone(),
        };
        let expected_digest = terminal_digest(tuple, &wire_receipt).map_err(to_sqlite_error)?;
        if receipt.terminal_digest != expected_digest {
            return Err(to_sqlite_error(
                "worker terminal digest does not match its exact tuple and receipt",
            ));
        }
        let (expected_result, _) =
            compact_terminal_result(&wire_receipt).map_err(to_sqlite_error)?;
        if terminal_result != Some(expected_result.as_str()) {
            return Err(to_sqlite_error(
                "worker compact terminal result does not match its receipt",
            ));
        }
        if state == WorkerHandoffState::Completed
            && receipt.status != WorkerTerminalStatus::Completed
            || state == WorkerHandoffState::Failed && receipt.status != WorkerTerminalStatus::Failed
        {
            return Err(to_sqlite_error(
                "worker handoff state does not match terminal receipt status",
            ));
        }
    }
    Ok(())
}
