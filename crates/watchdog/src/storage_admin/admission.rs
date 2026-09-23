//! Durable operator command admission.
//!
//! This module owns the write side of the operator ledger: read-only
//! admission, atomic mutation admission under the singleton owner, job
//! submission admission and the bounded read projections used by status and
//! diagnostics.  Replay, capacity and row decoding live in the sibling
//! `receipt` module; the ledger value types live in `types`.

use super::super::{
    SingletonLock, Store, TransactionBehavior, WatchdogError, ensure_owner_lock, insert_audit_tx,
    insert_job_tx, mode_as_str, sqlite_timestamp, sqlite_u64, update_metadata_tx, validate_name,
};
use super::receipt::{
    OPERATOR_SELECT, enforce_ledger_capacity, find_operator_by_key, find_operator_by_request,
    job_id_from_response, operator_receipt_from_row, validate_response,
};
use super::types::{
    MAX_OPERATOR_COMMANDS_WITH_STOP_RESERVE, OperatorCapability, OperatorCommand,
    OperatorCommandContext, OperatorCommandOutcome, OperatorCommandReceipt,
};
use crate::config::hex_digest;
use crate::error::Result;
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use uuid::Uuid;

impl Store {
    /// Validate a read-only operator command without requiring a singleton
    /// lock or opening a write transaction.  Callers with a read-only SQLite
    /// connection can use this path for status/inspection admission.
    pub fn admit_operator_read(
        &self,
        context: &OperatorCommandContext,
        command: OperatorCommand,
    ) -> Result<()> {
        context.validate()?;
        if !command.is_read_only() {
            return Err(WatchdogError::InvalidInput(
                "operator read admission requires a read-only command".to_string(),
            ));
        }
        if !matches!(
            context.capability,
            OperatorCapability::Read | OperatorCapability::Admin
        ) {
            return Err(WatchdogError::Unauthorized(
                "operator capability class is not recognized".to_string(),
            ));
        }
        Ok(())
    }

    /// Atomically admit one authenticated operator mutation under the
    /// singleton owner.  The transaction records the mode intent, ledger row,
    /// and audit event together before this method returns.  A duplicate key
    /// returns its original response and never reapplies the stored mode.
    ///
    /// `response` must be a bounded, transport-redacted response prepared by
    /// the caller.  Credentials and command payloads are intentionally absent
    /// from the context and are never written by this API.
    pub fn admit_operator_command(
        &mut self,
        owner: &SingletonLock,
        context: &OperatorCommandContext,
        command: OperatorCommand,
        response: &Value,
        now_ms: u64,
    ) -> Result<OperatorCommandOutcome> {
        ensure_owner_lock(&self.path, owner)?;
        context.validate()?;
        if command.is_read_only() {
            self.admit_operator_read(context, command)?;
            return Ok(OperatorCommandOutcome::ReadOnly);
        }
        if context.capability != OperatorCapability::Admin {
            return Err(WatchdogError::Unauthorized(
                "read capability cannot admit a mutating operator command".to_string(),
            ));
        }
        let desired_mode = command.desired_mode();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(existing) = find_operator_by_key(&tx, &context.idempotency_key)? {
            if existing.principal != context.principal || existing.capability != context.capability
            {
                return Err(WatchdogError::Unauthorized(
                    "idempotency key belongs to another operator context".to_string(),
                ));
            }
            if existing.command_fingerprint != context.command_fingerprint
                || existing.command != command
            {
                return Err(WatchdogError::Conflict(
                    "idempotency key was reused with a different command fingerprint".to_string(),
                ));
            }
            tx.rollback()?;
            return Ok(OperatorCommandOutcome::Replayed(
                existing.with_replayed(true),
            ));
        }
        if let Some(existing) = find_operator_by_request(&tx, &context.request_id)? {
            return Err(WatchdogError::Conflict(format!(
                "request id already belongs to idempotency key {}",
                existing.idempotency_key
            )));
        }
        enforce_ledger_capacity(&tx, command)?;
        // Validate and encode only a new admission.  A replay returns the
        // retained response above and must not be rejected because a caller
        // supplied a different (or oversized) transient response.
        validate_response(response)?;
        let response_text = serde_json::to_string(response)?;

        // All three writes share this transaction.  In particular, a mode
        // transition can never become visible without its replayable receipt
        // and audit record, and a receipt cannot exist without the intent.
        if let Some(mode) = desired_mode {
            update_metadata_tx(&tx, "desired_mode", mode_as_str(mode))?;
            update_metadata_tx(&tx, "updated_at_ms", &now_ms.to_string())?;
        }
        tx.execute(
            "INSERT INTO operator_commands (request_id, idempotency_key, principal, capability, command, command_fingerprint, desired_mode, response_json, recorded_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                context.request_id,
                context.idempotency_key,
                context.principal,
                context.capability.as_str(),
                command.as_str(),
                context.command_fingerprint,
                desired_mode.map(mode_as_str),
                response_text,
                sqlite_timestamp(now_ms)?,
            ],
        )?;
        let sequence_i64 = tx.last_insert_rowid();
        let detail = format!(
            "sequence={};request_id={};key={};principal={};capability={};command={};fingerprint={}",
            sequence_i64,
            context.request_id,
            context.idempotency_key,
            context.principal,
            context.capability.as_str(),
            command.as_str(),
            context.command_fingerprint,
        );
        let audit_action = if command == OperatorCommand::Stop {
            "operator_command_stop_accepted"
        } else {
            "operator_command_accepted"
        };
        insert_audit_tx(&tx, audit_action, &detail, now_ms)?;
        let sequence = u64::try_from(sequence_i64).map_err(|_| {
            WatchdogError::Conflict("operator command sequence overflow".to_string())
        })?;
        tx.commit()?;
        Ok(OperatorCommandOutcome::Accepted(OperatorCommandReceipt {
            sequence,
            request_id: context.request_id.clone(),
            idempotency_key: context.idempotency_key.clone(),
            principal: context.principal.clone(),
            capability: context.capability,
            command,
            command_fingerprint: context.command_fingerprint.clone(),
            desired_mode,
            response: response.clone(),
            recorded_at_ms: now_ms,
            replayed: false,
        }))
    }

    /// Atomically admit one authenticated job submission. The job row, the
    /// replayable operator receipt, and both audit records share one SQLite
    /// transaction. A replay is accepted even when the original job is
    /// completed or the deployment is stopped; it never changes desired mode
    /// and therefore cannot revive the scheduler.
    pub fn admit_operator_job_submission(
        &mut self,
        owner: &SingletonLock,
        context: &OperatorCommandContext,
        kind: &str,
        payload: &Value,
        now_ms: u64,
    ) -> Result<OperatorCommandOutcome> {
        ensure_owner_lock(&self.path, owner)?;
        context.validate()?;
        if context.capability != OperatorCapability::Admin {
            return Err(WatchdogError::Unauthorized(
                "read capability cannot admit a job submission".to_string(),
            ));
        }
        validate_name(kind, "job kind", 128)?;
        let encoded = serde_json::to_vec(payload)?;
        if encoded.len() > self.max_payload_bytes {
            return Err(WatchdogError::InvalidInput(format!(
                "job payload exceeds {} bytes",
                self.max_payload_bytes
            )));
        }
        let payload_digest = hex_digest(&encoded);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(existing) = find_operator_by_key(&tx, &context.idempotency_key)? {
            if existing.principal != context.principal || existing.capability != context.capability
            {
                return Err(WatchdogError::Unauthorized(
                    "idempotency key belongs to another operator context".to_string(),
                ));
            }
            if existing.command_fingerprint != context.command_fingerprint
                || existing.command != OperatorCommand::JobSubmit
            {
                return Err(WatchdogError::Conflict(
                    "idempotency key was reused with a different command fingerprint".to_string(),
                ));
            }
            let job_id = job_id_from_response(&existing.response)?;
            let stored: Option<(String, String)> = tx
                .query_row(
                    "SELECT kind, payload_digest FROM jobs WHERE id=?",
                    params![job_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let Some((stored_kind, stored_digest)) = stored else {
                return Err(WatchdogError::Conflict(
                    "job submission receipt has no durable job row".to_string(),
                ));
            };
            if stored_kind != kind || stored_digest != payload_digest {
                return Err(WatchdogError::Conflict(
                    "idempotency key was reused with a different job payload".to_string(),
                ));
            }
            tx.rollback()?;
            return Ok(OperatorCommandOutcome::Replayed(
                existing.with_replayed(true),
            ));
        }
        if let Some(existing) = find_operator_by_request(&tx, &context.request_id)? {
            return Err(WatchdogError::Conflict(format!(
                "request id already belongs to idempotency key {}",
                existing.idempotency_key
            )));
        }
        enforce_ledger_capacity(&tx, OperatorCommand::JobSubmit)?;

        let job_id = Uuid::new_v4().to_string();
        let response = json!({
            "kind": "JobSubmitted",
            "value": {"job_id": job_id},
        });
        validate_response(&response)?;
        let response_text = serde_json::to_string(&response)?;
        insert_job_tx(
            &tx,
            &job_id,
            kind,
            &encoded,
            &payload_digest,
            self.max_jobs,
            now_ms,
        )?;
        tx.execute(
            "INSERT INTO operator_commands (request_id, idempotency_key, principal, capability, command, command_fingerprint, desired_mode, response_json, recorded_at_ms) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)",
            params![
                context.request_id,
                context.idempotency_key,
                context.principal,
                context.capability.as_str(),
                OperatorCommand::JobSubmit.as_str(),
                context.command_fingerprint,
                response_text,
                sqlite_timestamp(now_ms)?,
            ],
        )?;
        let sequence_i64 = tx.last_insert_rowid();
        let detail = format!(
            "sequence={};request_id={};key={};principal={};capability={};command={};fingerprint={}",
            sequence_i64,
            context.request_id,
            context.idempotency_key,
            context.principal,
            context.capability.as_str(),
            OperatorCommand::JobSubmit.as_str(),
            context.command_fingerprint,
        );
        insert_audit_tx(&tx, "operator_command_accepted", &detail, now_ms)?;
        let sequence = u64::try_from(sequence_i64).map_err(|_| {
            WatchdogError::Conflict("operator command sequence overflow".to_string())
        })?;
        tx.commit()?;
        Ok(OperatorCommandOutcome::Accepted(OperatorCommandReceipt {
            sequence,
            request_id: context.request_id.clone(),
            idempotency_key: context.idempotency_key.clone(),
            principal: context.principal.clone(),
            capability: context.capability,
            command: OperatorCommand::JobSubmit,
            command_fingerprint: context.command_fingerprint.clone(),
            desired_mode: None,
            response,
            recorded_at_ms: now_ms,
            replayed: false,
        }))
    }

    /// Compatibility spelling for callers that mirror the wire command name.
    pub fn admit_operator_job_submit(
        &mut self,
        owner: &SingletonLock,
        context: &OperatorCommandContext,
        kind: &str,
        payload: &Value,
        now_ms: u64,
    ) -> Result<OperatorCommandOutcome> {
        self.admit_operator_job_submission(owner, context, kind, payload, now_ms)
    }

    /// Read one retained mutation receipt without changing the database.
    pub fn operator_command(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<OperatorCommandReceipt>> {
        validate_name(idempotency_key, "idempotency key", 128)?;
        self.conn
            .query_row(
                OPERATOR_SELECT,
                params![idempotency_key],
                operator_receipt_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// List retained mutation receipts in durable sequence order.  The limit
    /// is bounded even if a future caller supplies an untrusted value.
    pub fn list_operator_commands(&self, limit: u64) -> Result<Vec<OperatorCommandReceipt>> {
        let limit = limit.min(MAX_OPERATOR_COMMANDS_WITH_STOP_RESERVE as u64);
        let mut statement = self.conn.prepare(
            "SELECT sequence, request_id, idempotency_key, principal, capability, command, command_fingerprint, desired_mode, response_json, recorded_at_ms FROM operator_commands ORDER BY sequence LIMIT ?",
        )?;
        let rows = statement
            .query_map(params![i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
                operator_receipt_from_row(row)
            })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Number of retained command receipts, used for bounded diagnostics and
    /// fault tests.
    pub fn operator_command_count(&self) -> Result<u64> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM operator_commands", [], |row| {
                    row.get(0)
                })?;
        Ok(sqlite_u64(count, "operator command count")?)
    }
}
