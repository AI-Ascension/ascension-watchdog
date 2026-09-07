//! Bounded handoff-row schema projection and decoding.

use super::super::{sqlite_optional_u64, sqlite_u32};
use super::storage_worker_claims_validation::{validate_digest_value, validate_tuple};
use super::storage_worker_queries_projection::{required_text, validate_terminal_projection};
use super::storage_worker_queries_terminal::{empty_parameters, validate_uuid4};
use super::storage_worker_schema::{MAX_WORKER_WIRE_INTEGER, WORKER_HANDOFF_OPERATION};
use super::storage_worker_types::{
    WorkerHandoffState, WorkerHandoffTuple, WorkerTerminalRecord, WorkerTerminalStatus,
};
use super::{sqlite_u64, to_sqlite_error, validate_name};
use serde_json::Value;

const MAX_TERMINAL_REF_BYTES: usize = 1_024;

// Every potentially attacker-controlled text value is length/type checked by
// SQLite before rusqlite asks SQLite to materialize it as a Rust String.  A
// failing projection becomes NULL and is rejected by the row decoder below;
// this avoids pulling an arbitrarily large TEXT/BLOB value into process memory.
pub(super) const HANDOFF_SELECT: &str = "SELECT
    CASE WHEN typeof(handoff_id)='text' AND length(CAST(handoff_id AS BLOB)) <= 36 THEN handoff_id END,
    CASE WHEN typeof(deployment_id)='text' AND length(CAST(deployment_id AS BLOB)) <= 128 THEN deployment_id END,
    CASE WHEN typeof(job_id)='text' AND length(CAST(job_id AS BLOB)) <= 128 THEN job_id END,
    CASE WHEN typeof(attempt_id)='text' AND length(CAST(attempt_id AS BLOB)) <= 36 THEN attempt_id END,
    attempt_number,
    CASE WHEN typeof(worker_owner_id)='text' AND length(CAST(worker_owner_id AS BLOB)) <= 128 THEN worker_owner_id END,
    CASE WHEN typeof(worker_profile_digest)='text' AND length(CAST(worker_profile_digest AS BLOB)) <= 64 THEN worker_profile_digest END,
    CASE WHEN typeof(run_id)='text' AND length(CAST(run_id AS BLOB)) <= 36 THEN run_id END,
    CASE WHEN typeof(episode_id)='text' AND length(CAST(episode_id AS BLOB)) <= 36 THEN episode_id END,
    CASE WHEN typeof(trajectory_id)='text' AND length(CAST(trajectory_id AS BLOB)) <= 36 THEN trajectory_id END,
    CASE WHEN typeof(payload_digest)='text' AND length(CAST(payload_digest AS BLOB)) <= 64 THEN payload_digest END,
    CASE WHEN typeof(watchdog_boot_id)='text' AND length(CAST(watchdog_boot_id AS BLOB)) <= 36 THEN watchdog_boot_id END,
    CASE WHEN typeof(worker_boot_id)='text' AND length(CAST(worker_boot_id AS BLOB)) <= 36 THEN worker_boot_id END,
    mode_sequence,
    CASE WHEN typeof(operation)='text' AND length(CAST(operation AS BLOB)) <= 128 THEN operation END,
    CASE WHEN typeof(parameters)='text' AND length(CAST(parameters AS BLOB)) <= 65536 THEN parameters END,
    CASE WHEN typeof(state)='text' AND length(CAST(state AS BLOB)) <= 32 THEN state END,
    CASE WHEN terminal_status IS NULL THEN NULL WHEN typeof(terminal_status)='text' AND length(CAST(terminal_status AS BLOB)) <= 32 THEN terminal_status ELSE char(1) END,
    checkpoint_sequence,
    CASE WHEN terminal_ref IS NULL THEN NULL WHEN typeof(terminal_ref)='text' AND length(CAST(terminal_ref AS BLOB)) <= 1024 THEN terminal_ref ELSE char(1) END,
    CASE WHEN result_digest IS NULL THEN NULL WHEN typeof(result_digest)='text' AND length(CAST(result_digest AS BLOB)) <= 64 THEN result_digest ELSE char(1) END,
    CASE WHEN terminal_digest IS NULL THEN NULL WHEN typeof(terminal_digest)='text' AND length(CAST(terminal_digest AS BLOB)) <= 64 THEN terminal_digest ELSE char(1) END,
    CASE WHEN terminal_result IS NULL THEN NULL WHEN typeof(terminal_result)='text' AND length(CAST(terminal_result AS BLOB)) <= 65536 THEN terminal_result ELSE char(1) END,
    ack_intent, created_at_ms, updated_at_ms, dispatched_at_ms,
    admitted_at_ms, terminal_at_ms, acknowledged_at_ms
    FROM worker_handoffs WHERE handoff_id=?";

pub(super) struct RawHandoff {
    pub(super) handoff_id: String,
    pub(super) deployment_id: String,
    pub(super) job_id: String,
    pub(super) attempt_id: String,
    pub(super) attempt_number: u32,
    pub(super) worker_owner_id: String,
    pub(super) worker_profile_digest: String,
    pub(super) run_id: String,
    pub(super) episode_id: String,
    pub(super) trajectory_id: String,
    pub(super) payload_digest: String,
    pub(super) watchdog_boot_id: String,
    pub(super) worker_boot_id: String,
    pub(super) mode_sequence: u64,
    pub(super) operation: String,
    pub(super) parameters: Value,
    pub(super) state: WorkerHandoffState,
    pub(super) terminal: Option<WorkerTerminalRecord>,
    pub(super) terminal_result: Option<String>,
    pub(super) created_at_ms: u64,
    pub(super) updated_at_ms: u64,
    pub(super) dispatched_at_ms: Option<u64>,
    pub(super) admitted_at_ms: Option<u64>,
    pub(super) terminal_at_ms: Option<u64>,
    pub(super) acknowledged_at_ms: Option<u64>,
}

pub(super) fn raw_handoff_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawHandoff> {
    let handoff_id = required_text(row, 0, "handoff id")?;
    let deployment_id = required_text(row, 1, "deployment id")?;
    let job_id = required_text(row, 2, "job id")?;
    let attempt_id = required_text(row, 3, "attempt id")?;
    let worker_owner_id = required_text(row, 5, "worker owner id")?;
    let worker_profile_digest = required_text(row, 6, "worker profile digest")?;
    let run_id = required_text(row, 7, "run id")?;
    let episode_id = required_text(row, 8, "episode id")?;
    let trajectory_id = required_text(row, 9, "trajectory id")?;
    let payload_digest = required_text(row, 10, "payload digest")?;
    let watchdog_boot_id = required_text(row, 11, "watchdog boot id")?;
    let worker_boot_id = required_text(row, 12, "worker boot id")?;
    let operation = required_text(row, 14, "worker operation")?;
    if operation != WORKER_HANDOFF_OPERATION {
        return Err(to_sqlite_error("worker handoff operation is not admitted"));
    }
    let parameters_text = required_text(row, 15, "worker parameters")?;
    if parameters_text.as_bytes() != b"{}" {
        return Err(to_sqlite_error(
            "worker handoff parameters are not the canonical empty object",
        ));
    }
    let parameters: Value = serde_json::from_str(&parameters_text).map_err(to_sqlite_error)?;
    if parameters != empty_parameters() {
        return Err(to_sqlite_error("worker handoff parameters are not empty"));
    }
    let state_text = required_text(row, 16, "worker handoff state")?;
    let state = WorkerHandoffState::parse(&state_text).map_err(to_sqlite_error)?;
    let attempt_number = sqlite_u32(row.get(4)?, "worker attempt number")?;
    let mode_sequence = sqlite_u64(row.get(13)?, "worker mode sequence")?;
    let tuple = WorkerHandoffTuple {
        handoff_id: handoff_id.clone(),
        deployment_id: deployment_id.clone(),
        job_id: job_id.clone(),
        attempt_id: attempt_id.clone(),
        attempt_number,
        worker_owner_id: worker_owner_id.clone(),
        worker_profile_digest: worker_profile_digest.clone(),
        run_id: run_id.clone(),
        episode_id: episode_id.clone(),
        trajectory_id: trajectory_id.clone(),
        payload_digest: payload_digest.clone(),
    };
    validate_tuple(&tuple).map_err(to_sqlite_error)?;
    validate_uuid4(&watchdog_boot_id, "watchdog boot id").map_err(to_sqlite_error)?;
    validate_uuid4(&worker_boot_id, "worker boot id").map_err(to_sqlite_error)?;
    if watchdog_boot_id == worker_boot_id {
        return Err(to_sqlite_error(
            "watchdog and worker boot identities must be distinct",
        ));
    }
    validate_digest_value(&worker_profile_digest, "worker profile digest")
        .map_err(to_sqlite_error)?;
    validate_digest_value(&payload_digest, "payload digest").map_err(to_sqlite_error)?;
    if mode_sequence == 0 || mode_sequence > MAX_WORKER_WIRE_INTEGER {
        return Err(to_sqlite_error(
            "worker mode sequence exceeds the wire integer bound",
        ));
    }

    let terminal_status: Option<String> = row.get(17)?;
    let terminal_ref: Option<String> = row.get(19)?;
    let result_digest: Option<String> = row.get(20)?;
    let terminal_digest_value: Option<String> = row.get(21)?;
    let checkpoint_sequence: Option<i64> = row.get(18)?;
    let terminal = match (
        terminal_status,
        terminal_ref,
        result_digest,
        terminal_digest_value,
        checkpoint_sequence,
    ) {
        (None, None, None, None, None) => None,
        (
            Some(status),
            Some(terminal_ref),
            Some(result_digest),
            Some(terminal_digest_value),
            Some(checkpoint_sequence),
        ) => {
            let checkpoint_sequence =
                sqlite_u64(checkpoint_sequence, "worker checkpoint sequence")?;
            if checkpoint_sequence > MAX_WORKER_WIRE_INTEGER {
                return Err(to_sqlite_error(
                    "worker checkpoint sequence exceeds the wire integer bound",
                ));
            }
            validate_name(&terminal_ref, "terminal reference", MAX_TERMINAL_REF_BYTES)
                .map_err(to_sqlite_error)?;
            validate_digest_value(&result_digest, "worker result digest")
                .map_err(to_sqlite_error)?;
            validate_digest_value(&terminal_digest_value, "worker terminal digest")
                .map_err(to_sqlite_error)?;
            Some(WorkerTerminalRecord {
                status: WorkerTerminalStatus::parse(&status).map_err(to_sqlite_error)?,
                checkpoint_sequence,
                terminal_ref,
                result_digest,
                terminal_digest: terminal_digest_value,
            })
        }
        _ => {
            return Err(to_sqlite_error(
                "worker handoff terminal receipt is partially persisted",
            ));
        }
    };
    let terminal_result: Option<String> = row.get(22)?;
    let ack_intent = match row.get::<_, i64>(23)? {
        0 => false,
        1 => true,
        _ => return Err(to_sqlite_error("worker handoff ack intent is invalid")),
    };
    let dispatched_at_ms = sqlite_optional_u64(row.get(26)?, "worker handoff dispatched_at_ms")?;
    let admitted_at_ms = sqlite_optional_u64(row.get(27)?, "worker handoff admitted_at_ms")?;
    let terminal_at_ms = sqlite_optional_u64(row.get(28)?, "worker handoff terminal_at_ms")?;
    let acknowledged_at_ms =
        sqlite_optional_u64(row.get(29)?, "worker handoff acknowledged_at_ms")?;
    validate_terminal_projection(
        &tuple,
        state,
        terminal.as_ref(),
        terminal_result.as_deref(),
        ack_intent,
        sqlite_u64(row.get(24)?, "worker handoff created_at_ms")?,
        sqlite_u64(row.get(25)?, "worker handoff updated_at_ms")?,
        dispatched_at_ms,
        admitted_at_ms,
        terminal_at_ms,
        acknowledged_at_ms,
    )?;
    Ok(RawHandoff {
        handoff_id,
        deployment_id,
        job_id,
        attempt_id,
        attempt_number,
        worker_owner_id,
        worker_profile_digest,
        run_id,
        episode_id,
        trajectory_id,
        payload_digest,
        watchdog_boot_id,
        worker_boot_id,
        mode_sequence,
        operation,
        parameters,
        state,
        terminal,
        terminal_result,
        created_at_ms: sqlite_u64(row.get(24)?, "worker handoff created_at_ms")?,
        updated_at_ms: sqlite_u64(row.get(25)?, "worker handoff updated_at_ms")?,
        dispatched_at_ms,
        admitted_at_ms,
        terminal_at_ms,
        acknowledged_at_ms,
    })
}
