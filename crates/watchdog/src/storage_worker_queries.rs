//! Read-side worker handoff projections and tuple identity helpers.

use super::storage_worker_claims::validate_tuple;
use super::storage_worker_schema::{MAX_WORKER_WIRE_INTEGER, WORKER_HANDOFF_OPERATION};
use super::storage_worker_types::{
    WorkerHandoff, WorkerHandoffState, WorkerHandoffTuple, WorkerTerminalReceipt,
    WorkerTerminalRecord, WorkerTerminalStatus,
};
use super::{Store, sqlite_u32, sqlite_u64, to_sqlite_error, validate_name};
use crate::config::hex_digest;
use crate::error::{Result, WatchdogError};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

const HANDOFF_SELECT: &str = "SELECT handoff_id, deployment_id, job_id, attempt_id,
    attempt_number, worker_owner_id, worker_profile_digest, run_id, episode_id,
    trajectory_id, payload_digest, watchdog_boot_id, worker_boot_id,
    mode_sequence, operation, parameters, state, terminal_status,
    checkpoint_sequence, terminal_ref, result_digest, terminal_digest,
    terminal_result, ack_intent, created_at_ms, updated_at_ms, dispatched_at_ms,
    admitted_at_ms, terminal_at_ms, acknowledged_at_ms
    FROM worker_handoffs WHERE handoff_id=?";

impl Store {
    /// Read one handoff without mutating state.
    pub fn worker_handoff(&self, handoff_id: &str) -> Result<Option<WorkerHandoff>> {
        validate_uuid4(handoff_id, "handoff id")?;
        load_handoff(&self.conn, handoff_id)
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

#[derive(Clone, Debug)]
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
    pub(super) created_at_ms: u64,
    pub(super) updated_at_ms: u64,
}

pub(super) fn load_handoff(conn: &Connection, handoff_id: &str) -> Result<Option<WorkerHandoff>> {
    let raw = conn
        .query_row(HANDOFF_SELECT, params![handoff_id], raw_handoff_from_row)
        .optional()?;
    raw.map(|raw| handoff_from_raw(conn, raw)).transpose()
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
) -> Result<RawHandoff> {
    if let Some(raw) = load_handoff_tx(tx, &tuple.handoff_id)? {
        return Ok(raw);
    }
    let historical_handoff: Option<String> = tx
        .query_row(
            "SELECT handoff_id FROM worker_handoffs WHERE job_id=? AND attempt_id=?",
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

fn raw_handoff_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawHandoff> {
    let state_text: String = row.get(16)?;
    let state = WorkerHandoffState::parse(&state_text).map_err(to_sqlite_error)?;
    let parameters_text: String = row.get(15)?;
    let parameters: Value = serde_json::from_str(&parameters_text).map_err(to_sqlite_error)?;
    if parameters != empty_parameters() {
        return Err(to_sqlite_error(
            "worker handoff parameters are not the canonical empty object",
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
            validate_name(&terminal_ref, "terminal reference", 1_024).map_err(to_sqlite_error)?;
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
    let terminal_result_text: Option<String> = row.get(22)?;
    if let Some(terminal_result) = terminal_result_text.as_deref() {
        let _: Value = serde_json::from_str(terminal_result).map_err(to_sqlite_error)?;
    }
    let ack_intent: i64 = row.get(23)?;
    match ack_intent {
        0 | 1 => {}
        _ => return Err(to_sqlite_error("worker handoff ack intent is invalid")),
    }
    let mode_sequence = sqlite_u64(row.get(13)?, "worker mode sequence")?;
    if mode_sequence == 0 || mode_sequence > MAX_WORKER_WIRE_INTEGER {
        return Err(to_sqlite_error(
            "worker mode sequence exceeds the wire integer bound",
        ));
    }
    let operation: String = row.get(14)?;
    if operation != WORKER_HANDOFF_OPERATION {
        return Err(to_sqlite_error("worker handoff operation is not admitted"));
    }
    Ok(RawHandoff {
        handoff_id: row.get(0)?,
        deployment_id: row.get(1)?,
        job_id: row.get(2)?,
        attempt_id: row.get(3)?,
        attempt_number: sqlite_u32(row.get(4)?, "worker attempt number")?,
        worker_owner_id: row.get(5)?,
        worker_profile_digest: row.get(6)?,
        run_id: row.get(7)?,
        episode_id: row.get(8)?,
        trajectory_id: row.get(9)?,
        payload_digest: row.get(10)?,
        watchdog_boot_id: row.get(11)?,
        worker_boot_id: row.get(12)?,
        mode_sequence,
        operation,
        parameters,
        state,
        terminal,
        created_at_ms: sqlite_u64(row.get(24)?, "worker handoff created_at_ms")?,
        updated_at_ms: sqlite_u64(row.get(25)?, "worker handoff updated_at_ms")?,
    })
}

fn handoff_from_raw(conn: &Connection, raw: RawHandoff) -> Result<WorkerHandoff> {
    let job = conn
        .query_row(
            "SELECT id, kind, payload, payload_digest, status, created_at_ms, claimed_at_ms, completed_at_ms, attempt_count, next_retry_at_ms, last_error, result, worker_id FROM jobs WHERE id=?",
            params![raw.job_id],
            super::super::job_from_row,
        )
        .optional()?
        .ok_or_else(|| WatchdogError::Conflict("worker handoff references a missing job".to_owned()))?;
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

pub(super) fn ensure_tuple_matches(raw: &RawHandoff, tuple: &WorkerHandoffTuple) -> Result<()> {
    let matches = raw.handoff_id == tuple.handoff_id
        && raw.deployment_id == tuple.deployment_id
        && raw.job_id == tuple.job_id
        && raw.attempt_id == tuple.attempt_id
        && raw.attempt_number == tuple.attempt_number
        && raw.worker_owner_id == tuple.worker_owner_id
        && raw.worker_profile_digest == tuple.worker_profile_digest
        && raw.run_id == tuple.run_id
        && raw.episode_id == tuple.episode_id
        && raw.trajectory_id == tuple.trajectory_id
        && raw.payload_digest == tuple.payload_digest;
    if matches {
        Ok(())
    } else {
        Err(WatchdogError::Conflict(
            "worker handoff tuple does not match durable history".to_owned(),
        ))
    }
}

pub(super) fn terminal_digest(
    tuple: &WorkerHandoffTuple,
    receipt: &WorkerTerminalReceipt,
) -> String {
    #[derive(Serialize)]
    struct Material<'a> {
        handoff_id: &'a str,
        deployment_id: &'a str,
        job_id: &'a str,
        attempt_id: &'a str,
        attempt_number: u32,
        worker_owner_id: &'a str,
        worker_profile_digest: &'a str,
        run_id: &'a str,
        episode_id: &'a str,
        trajectory_id: &'a str,
        payload_digest: &'a str,
        status: WorkerTerminalStatus,
        checkpoint_sequence: u64,
        terminal_ref: &'a str,
        result_digest: &'a str,
    }
    let material = Material {
        handoff_id: &tuple.handoff_id,
        deployment_id: &tuple.deployment_id,
        job_id: &tuple.job_id,
        attempt_id: &tuple.attempt_id,
        attempt_number: tuple.attempt_number,
        worker_owner_id: &tuple.worker_owner_id,
        worker_profile_digest: &tuple.worker_profile_digest,
        run_id: &tuple.run_id,
        episode_id: &tuple.episode_id,
        trajectory_id: &tuple.trajectory_id,
        payload_digest: &tuple.payload_digest,
        status: receipt.status,
        checkpoint_sequence: receipt.checkpoint_sequence,
        terminal_ref: &receipt.terminal_ref,
        result_digest: &receipt.result_digest,
    };
    hex_digest(&serde_json::to_vec(&material).expect("terminal digest serialization is infallible"))
}

pub(super) fn empty_parameters() -> Value {
    Value::Object(serde_json::Map::new())
}

pub(super) fn validate_uuid4(value: &str, field: &str) -> Result<()> {
    let parsed = Uuid::parse_str(value).map_err(|error| {
        WatchdogError::InvalidInput(format!("{field} is not a canonical UUIDv4: {error}"))
    })?;
    if parsed.get_version_num() != 4 || parsed.to_string() != value {
        return Err(WatchdogError::InvalidInput(format!(
            "{field} must be a lowercase canonical UUIDv4"
        )));
    }
    Ok(())
}

pub(super) fn new_uuid4() -> String {
    Uuid::new_v4().to_string()
}

pub(super) fn new_uuid4_distinct(existing: &[&str]) -> String {
    loop {
        let value = new_uuid4();
        if !existing.iter().any(|other| *other == value) {
            return value;
        }
    }
}
