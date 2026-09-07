//! Transactional admission for the authenticated attempt-quarantine command.
//!
//! Quarantine is a watchdog-owned disposition.  It preserves an uncertain
//! running attempt as `unknown`, moves its job out of the scheduler, and
//! records the operator receipt and audits in the same SQLite transaction.
//! No gateway, host, provider, or gameplay effect is implied by this method.

use super::storage_admin::{
    enforce_ledger_capacity, find_operator_by_key, find_operator_by_request, validate_response,
};
use super::{
    OperatorCapability, OperatorCommand, OperatorCommandContext, OperatorCommandOutcome,
    SingletonLock, Store, TransactionBehavior, WatchdogError, ensure_owner_lock, insert_audit_tx,
    sqlite_timestamp, validate_name,
};
use crate::error::Result;
use rusqlite::{OptionalExtension, params};
use serde_json::Value;

const MAX_QUARANTINE_REASON_BYTES: usize = 512;

impl Store {
    /// Atomically quarantine one watchdog-owned attempt and admit its
    /// authenticated operator receipt.  A completed attempt/job is immutable
    /// and is rejected; an uncertain running attempt is never represented as
    /// completed and cannot be claimed again by the scheduler.
    pub fn admit_operator_quarantine(
        &mut self,
        owner: &SingletonLock,
        context: &OperatorCommandContext,
        attempt_id: &str,
        reason: &str,
        response: &Value,
        now_ms: u64,
    ) -> Result<OperatorCommandOutcome> {
        ensure_owner_lock(&self.path, owner)?;
        context.validate()?;
        if context.capability != OperatorCapability::Admin {
            return Err(WatchdogError::Unauthorized(
                "read capability cannot admit attempt quarantine".to_string(),
            ));
        }
        validate_name(attempt_id, "attempt id", 128)?;
        validate_name(reason, "quarantine reason", MAX_QUARANTINE_REASON_BYTES)?;

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
                || existing.command != OperatorCommand::Quarantine
            {
                return Err(WatchdogError::Conflict(
                    "idempotency key was reused with a different command fingerprint".to_string(),
                ));
            }
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
        enforce_ledger_capacity(&tx, OperatorCommand::Quarantine)?;
        validate_response(response)?;
        let response_text = serde_json::to_string(response)?;

        let current: Option<(String, String, String)> = tx
            .query_row(
                "SELECT a.job_id, a.status, j.status FROM attempts a JOIN jobs j ON j.id=a.job_id WHERE a.id=?",
                params![attempt_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((job_id, attempt_status, job_status)) = current else {
            return Err(WatchdogError::NotFound(format!("attempt {attempt_id}")));
        };
        if attempt_status == "completed" || job_status == "completed" {
            return Err(WatchdogError::Conflict(
                "completed attempt cannot be quarantined".to_string(),
            ));
        }
        if job_status == "quarantined" {
            return Err(WatchdogError::Conflict(
                "attempt job is already quarantined".to_string(),
            ));
        }
        let latest_attempt_id: String = tx.query_row(
            "SELECT id FROM attempts WHERE job_id=? ORDER BY sequence DESC, id DESC LIMIT 1",
            params![job_id],
            |row| row.get(0),
        )?;
        if latest_attempt_id != attempt_id {
            return Err(WatchdogError::Conflict(
                "attempt is not the latest durable attempt for its job".to_string(),
            ));
        }
        if !matches!(job_status.as_str(), "running" | "failed") {
            return Err(WatchdogError::Conflict(format!(
                "attempt job is {job_status}, not eligible for quarantine"
            )));
        }

        let timestamp = sqlite_timestamp(now_ms)?;
        if attempt_status == "running" {
            let outcome = format!("operator_quarantine:{reason}");
            let changed = tx.execute(
                "UPDATE attempts SET status='unknown', finished_at_ms=?, outcome=? WHERE id=? AND status='running'",
                params![timestamp, outcome, attempt_id],
            )?;
            if changed != 1 {
                return Err(WatchdogError::Conflict(
                    "attempt changed before quarantine admission".to_string(),
                ));
            }
        }
        let changed = tx.execute(
            "UPDATE jobs SET status='quarantined', next_retry_at_ms=NULL, last_error=? WHERE id=? AND status IN ('running','failed')",
            params![reason, job_id],
        )?;
        if changed != 1 {
            return Err(WatchdogError::Conflict(
                "job changed before quarantine admission".to_string(),
            ));
        }

        insert_audit_tx(
            &tx,
            "attempt_quarantined",
            &format!("attempt_id={attempt_id};job_id={job_id};reason={reason}"),
            now_ms,
        )?;
        tx.execute(
            "INSERT INTO operator_commands (request_id, idempotency_key, principal, capability, command, command_fingerprint, desired_mode, response_json, recorded_at_ms) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)",
            params![
                context.request_id,
                context.idempotency_key,
                context.principal,
                context.capability.as_str(),
                OperatorCommand::Quarantine.as_str(),
                context.command_fingerprint,
                response_text,
                timestamp,
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
            OperatorCommand::Quarantine.as_str(),
            context.command_fingerprint,
        );
        insert_audit_tx(&tx, "operator_command_accepted", &detail, now_ms)?;
        let sequence = u64::try_from(sequence_i64).map_err(|_| {
            WatchdogError::Conflict("operator command sequence overflow".to_string())
        })?;
        tx.commit()?;
        Ok(OperatorCommandOutcome::Accepted(
            super::OperatorCommandReceipt {
                sequence,
                request_id: context.request_id.clone(),
                idempotency_key: context.idempotency_key.clone(),
                principal: context.principal.clone(),
                capability: context.capability,
                command: OperatorCommand::Quarantine,
                command_fingerprint: context.command_fingerprint.clone(),
                desired_mode: None,
                response: response.clone(),
                recorded_at_ms: now_ms,
                replayed: false,
            },
        ))
    }
}
