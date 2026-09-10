//! Transactional admission for a bounded, known-failure retry.
//!
//! Retrying an attempt is safe only after the previous attempt is a durable
//! known failure.  An `unknown` attempt is never requeued by this module: it
//! may have reached the authoritative effect boundary and requires the
//! harness/gateway reconstruction policy, not a watchdog-only retry.

use super::storage_admin::{
    enforce_ledger_capacity, find_operator_by_key, find_operator_by_request, validate_response,
};
use super::{
    OperatorCapability, OperatorCommand, OperatorCommandContext, OperatorCommandOutcome,
    OperatorCommandReceipt, SingletonLock, Store, TransactionBehavior, WatchdogError,
    ensure_owner_lock, insert_audit_tx, sqlite_timestamp, validate_name,
};
use crate::error::Result;
use rusqlite::{OptionalExtension, params};
use serde_json::Value;

const MAX_RETRY_ID_BYTES: usize = 128;

impl Store {
    /// Atomically requeue one latest known-failed attempt and record the
    /// authenticated operator receipt.  The original attempt row and lineage
    /// remain immutable; a later claim creates the next attempt number.  This
    /// method deliberately rejects unknown/quarantined-unknown work and the
    /// reconstruction policy until a harness checkpoint adapter is present.
    pub fn admit_operator_retry(
        &mut self,
        owner: &SingletonLock,
        context: &OperatorCommandContext,
        attempt_id: &str,
        reconstruction: bool,
        response: &Value,
        now_ms: u64,
    ) -> Result<OperatorCommandOutcome> {
        ensure_owner_lock(&self.path, owner)?;
        context.validate()?;
        if context.capability != OperatorCapability::Admin {
            return Err(WatchdogError::Unauthorized(
                "read capability cannot retry an attempt".to_owned(),
            ));
        }
        validate_name(attempt_id, "attempt id", MAX_RETRY_ID_BYTES)?;

        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = find_operator_by_key(&tx, &context.idempotency_key)? {
            if existing.principal != context.principal || existing.capability != context.capability
            {
                return Err(WatchdogError::Unauthorized(
                    "idempotency key belongs to another operator context".to_owned(),
                ));
            }
            if existing.command_fingerprint != context.command_fingerprint
                || existing.command != OperatorCommand::Retry
            {
                return Err(WatchdogError::Conflict(
                    "idempotency key was reused with a different command fingerprint".to_owned(),
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
        if reconstruction {
            return Err(WatchdogError::Unsupported(
                "reconstruction retry requires the harness checkpoint adapter".to_owned(),
            ));
        }
        // Validate and encode only a new admission. A replay returns the
        // retained response above and must not be rejected because a caller
        // supplied a different (or oversized) transient response.
        validate_response(response)?;
        enforce_ledger_capacity(&tx, OperatorCommand::Retry)?;

        let current: Option<(
            String,
            String,
            String,
            Option<i64>,
            Option<String>,
            Option<String>,
        )> = tx
            .query_row(
                "SELECT a.job_id, a.status, j.status, j.completed_at_ms, j.result, j.completion_digest FROM attempts a JOIN jobs j ON j.id=a.job_id WHERE a.id=?",
                params![attempt_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((job_id, attempt_status, job_status, completed_at_ms, result, completion_digest)) =
            current
        else {
            return Err(WatchdogError::NotFound(format!("attempt {attempt_id}")));
        };
        let latest_attempt_id: String = tx.query_row(
            "SELECT id FROM attempts WHERE job_id=? ORDER BY sequence DESC, id DESC LIMIT 1",
            params![job_id],
            |row| row.get(0),
        )?;
        if latest_attempt_id != attempt_id {
            return Err(WatchdogError::Conflict(
                "attempt is not the latest durable attempt for its job".to_owned(),
            ));
        }
        if attempt_status == "unknown" {
            return Err(WatchdogError::Conflict(
                "unknown attempt requires authorized reconciliation or reconstruction".to_owned(),
            ));
        }
        if attempt_status != "failed" || !matches!(job_status.as_str(), "failed" | "quarantined") {
            return Err(WatchdogError::Conflict(format!(
                "only a known-failed latest attempt can be requeued: attempt={attempt_status}, job={job_status}"
            )));
        }
        if completed_at_ms.is_some() || result.is_some() || completion_digest.is_some() {
            return Err(WatchdogError::Conflict(
                "terminal job result cannot be retried by watchdog".to_owned(),
            ));
        }
        let has_worker_handoff: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM worker_handoffs WHERE job_id=? OR attempt_id=?)",
            params![job_id, attempt_id],
            |row| row.get(0),
        )?;
        if has_worker_handoff {
            return Err(WatchdogError::Conflict(
                "worker handoff requires its own terminal reconciliation path".to_owned(),
            ));
        }

        let timestamp = sqlite_timestamp(now_ms)?;
        let changed = tx.execute(
            "UPDATE jobs SET status='queued', next_retry_at_ms=?, worker_id=NULL WHERE id=? AND status IN ('failed','quarantined')",
            params![timestamp, job_id],
        )?;
        if changed != 1 {
            return Err(WatchdogError::Conflict(
                "job changed before retry admission".to_owned(),
            ));
        }
        insert_audit_tx(
            &tx,
            "attempt_retry_queued",
            &format!("attempt_id={attempt_id};job_id={job_id}"),
            now_ms,
        )?;
        let response_text = serde_json::to_string(response)?;
        tx.execute(
            "INSERT INTO operator_commands (request_id, idempotency_key, principal, capability, command, command_fingerprint, desired_mode, response_json, recorded_at_ms) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)",
            params![
                context.request_id,
                context.idempotency_key,
                context.principal,
                context.capability.as_str(),
                OperatorCommand::Retry.as_str(),
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
            OperatorCommand::Retry.as_str(),
            context.command_fingerprint,
        );
        insert_audit_tx(&tx, "operator_command_accepted", &detail, now_ms)?;
        let sequence = u64::try_from(sequence_i64).map_err(|_| {
            WatchdogError::Conflict("operator command sequence overflow".to_owned())
        })?;
        tx.commit()?;
        Ok(OperatorCommandOutcome::Accepted(OperatorCommandReceipt {
            sequence,
            request_id: context.request_id.clone(),
            idempotency_key: context.idempotency_key.clone(),
            principal: context.principal.clone(),
            capability: context.capability,
            command: OperatorCommand::Retry,
            command_fingerprint: context.command_fingerprint.clone(),
            desired_mode: None,
            response: response.clone(),
            recorded_at_ms: now_ms,
            replayed: false,
        }))
    }
}
