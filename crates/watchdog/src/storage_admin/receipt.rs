//! Operator ledger receipt, replay, capacity and row decoding.
//!
//! This module owns the read/replay side of the operator ledger: the durable
//! select statements, the idempotency-key and request-id lookups, the bounded
//! retention capacity check, response validation, and the strict decode of a
//! persisted receipt row.  It performs no admission and opens no transaction.

use super::super::{
    Transaction, WatchdogError, parse_mode, sqlite_u64, to_sqlite_error, validate_name,
};
use super::types::{
    MAX_OPERATOR_COMMANDS, MAX_OPERATOR_COMMANDS_WITH_STOP_RESERVE, MAX_OPERATOR_RESPONSE_BYTES,
    OperatorCapability, OperatorCommand, OperatorCommandReceipt, RESERVED_LIFECYCLE_COMMANDS,
    validate_uuid_v4,
};
use crate::config::validate_digest;
use crate::error::Result;
use rusqlite::{OptionalExtension, params};
use serde_json::Value;

pub(crate) const OPERATOR_SELECT: &str = "SELECT sequence, request_id, idempotency_key, principal, capability, command, command_fingerprint, desired_mode, response_json, recorded_at_ms FROM operator_commands WHERE idempotency_key=?";

pub(crate) fn find_operator_by_key(
    tx: &Transaction<'_>,
    key: &str,
) -> Result<Option<OperatorCommandReceipt>> {
    tx.query_row(OPERATOR_SELECT, params![key], operator_receipt_from_row)
        .optional()
        .map_err(Into::into)
}

pub(crate) fn find_operator_by_request(
    tx: &Transaction<'_>,
    request_id: &str,
) -> Result<Option<OperatorCommandReceipt>> {
    tx.query_row(
        "SELECT sequence, request_id, idempotency_key, principal, capability, command, command_fingerprint, desired_mode, response_json, recorded_at_ms FROM operator_commands WHERE request_id=?",
        params![request_id],
        operator_receipt_from_row,
    )
    .optional()
    .map_err(Into::into)
}

pub(crate) fn enforce_ledger_capacity(
    tx: &Transaction<'_>,
    command: OperatorCommand,
) -> Result<()> {
    let count: i64 = tx.query_row("SELECT COUNT(*) FROM operator_commands", [], |row| {
        row.get(0)
    })?;
    let limit = if command == OperatorCommand::Stop {
        MAX_OPERATOR_COMMANDS_WITH_STOP_RESERVE
    } else if command.is_lifecycle() {
        MAX_OPERATOR_COMMANDS
    } else {
        MAX_OPERATOR_COMMANDS - RESERVED_LIFECYCLE_COMMANDS
    };
    if count >= limit {
        return Err(WatchdogError::Busy(
            "operator command ledger retention bound is full".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_response(response: &Value) -> Result<()> {
    if response.is_null() {
        return Err(WatchdogError::InvalidInput(
            "operator response must not be null".to_string(),
        ));
    }
    let bytes = serde_json::to_vec(response)?;
    if bytes.len() > MAX_OPERATOR_RESPONSE_BYTES {
        return Err(WatchdogError::InvalidInput(format!(
            "operator response exceeds {MAX_OPERATOR_RESPONSE_BYTES} bytes"
        )));
    }
    if bytes.contains(&0) {
        return Err(WatchdogError::InvalidInput(
            "operator response contains NUL".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn job_id_from_response(response: &Value) -> Result<String> {
    let job_id = response
        .get("value")
        .and_then(Value::as_object)
        .and_then(|value| value.get("job_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            WatchdogError::Conflict("job submission receipt has no job id".to_string())
        })?;
    validate_name(job_id, "job id", 128)?;
    Ok(job_id.to_string())
}

pub(crate) fn operator_receipt_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<OperatorCommandReceipt> {
    let request_id: String = row.get(1)?;
    validate_uuid_v4(&request_id, "operator request id").map_err(to_sqlite_error)?;
    let idempotency_key: String = row.get(2)?;
    validate_name(&idempotency_key, "operator idempotency key", 128).map_err(to_sqlite_error)?;
    let principal: String = row.get(3)?;
    validate_name(&principal, "operator principal", 128).map_err(to_sqlite_error)?;
    let capability_text: String = row.get(4)?;
    let capability = OperatorCapability::parse(&capability_text).map_err(to_sqlite_error)?;
    if capability != OperatorCapability::Admin {
        return Err(to_sqlite_error(
            "operator ledger contains a non-mutating capability",
        ));
    }
    let command_text: String = row.get(5)?;
    let command = OperatorCommand::parse(&command_text).map_err(to_sqlite_error)?;
    if command.is_read_only() {
        return Err(to_sqlite_error(
            "operator ledger contains a read-only command",
        ));
    }
    let response_text: String = row.get(8)?;
    if response_text.len() > MAX_OPERATOR_RESPONSE_BYTES {
        return Err(to_sqlite_error(
            "operator response exceeds its persisted bound",
        ));
    }
    let command_fingerprint: String = row.get(6)?;
    validate_digest(&command_fingerprint).map_err(to_sqlite_error)?;
    let desired_mode_text: Option<String> = row.get(7)?;
    let desired_mode = desired_mode_text
        .as_deref()
        .map(parse_mode)
        .transpose()
        .map_err(to_sqlite_error)?;
    if desired_mode != command.desired_mode() {
        return Err(to_sqlite_error(
            "operator ledger desired mode does not match its command",
        ));
    }
    let response: Value = serde_json::from_str(&response_text).map_err(to_sqlite_error)?;
    if response.is_null() {
        return Err(to_sqlite_error("operator response must not be null"));
    }
    let sequence = sqlite_u64(row.get::<_, i64>(0)?, "operator command sequence")?;
    if sequence == 0 {
        return Err(to_sqlite_error(
            "operator command sequence must be positive",
        ));
    }
    let recorded_at_ms = sqlite_u64(row.get::<_, i64>(9)?, "operator recorded_at_ms")?;
    Ok(OperatorCommandReceipt {
        sequence,
        request_id,
        idempotency_key,
        principal,
        capability,
        command,
        command_fingerprint,
        desired_mode,
        response,
        recorded_at_ms,
        replayed: false,
    })
}

impl OperatorCommandReceipt {
    pub(crate) fn with_replayed(mut self, replayed: bool) -> Self {
        self.replayed = replayed;
        self
    }
}
