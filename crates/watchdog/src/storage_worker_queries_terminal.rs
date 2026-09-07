//! Terminal receipt hashing, compact results, and UUID helpers.

use super::storage_worker_queries_handoff::RawHandoff;
use super::storage_worker_types::{
    WorkerHandoffTuple, WorkerTerminalReceipt, WorkerTerminalStatus,
};
use crate::config::hex_digest;
use crate::error::{Result, WatchdogError};
use serde::Serialize;
use serde_json::Value;
use uuid::{Uuid, Variant};

const MAX_WORKER_RESULT_BYTES: usize = 64 * 1024;

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

pub(super) fn validate_handoff_transition_time(
    raw: &RawHandoff,
    now_ms: u64,
    phase: &str,
) -> Result<()> {
    let prior_phase_at_ms = match phase {
        "dispatch" => raw.created_at_ms,
        "admission" => raw.dispatched_at_ms.unwrap_or(raw.created_at_ms),
        "terminal" => raw
            .admitted_at_ms
            .or(raw.dispatched_at_ms)
            .unwrap_or(raw.created_at_ms),
        "acknowledgment" => raw
            .acknowledged_at_ms
            .or(raw.terminal_at_ms)
            .unwrap_or(raw.created_at_ms),
        _ => raw.updated_at_ms,
    };
    if now_ms < raw.updated_at_ms || now_ms < prior_phase_at_ms {
        return Err(WatchdogError::Conflict(format!(
            "worker handoff {phase} timestamp moves backwards"
        )));
    }
    Ok(())
}

pub(super) fn terminal_digest(
    tuple: &WorkerHandoffTuple,
    receipt: &WorkerTerminalReceipt,
) -> Result<String> {
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
    Ok(hex_digest(&serde_json::to_vec(&material)?))
}

pub(super) fn compact_terminal_result(receipt: &WorkerTerminalReceipt) -> Result<(String, String)> {
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

pub(super) fn empty_parameters() -> Value {
    Value::Object(serde_json::Map::new())
}

pub(super) fn validate_uuid4(value: &str, field: &str) -> Result<()> {
    let parsed = Uuid::parse_str(value).map_err(|error| {
        WatchdogError::InvalidInput(format!("{field} is not a canonical UUIDv4: {error}"))
    })?;
    if parsed.get_version_num() != 4
        || parsed.get_variant() != Variant::RFC4122
        || parsed.to_string() != value
    {
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
