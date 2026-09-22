//! Release activation and rollback transactions.
//!
//! This module owns the durable write side of the selector: the `prepared`
//! recovery marker retained across a crash, the atomic publication of the
//! active digest, previous-release rollback target, audit event and replayable
//! operator receipt, and the clearing transaction used by restore/rekey.  It
//! never revalidates release bytes or changes authority generations.

use super::super::storage_admin::{
    enforce_ledger_capacity, find_operator_by_key, find_operator_by_request, validate_response,
};
use super::super::{
    OperatorCapability, OperatorCommand, OperatorCommandContext, OperatorCommandOutcome,
    OperatorCommandReceipt, SingletonLock, Store, TransactionBehavior, WatchdogError,
    ensure_owner_lock, insert_audit_tx, metadata_from_conn, mode_as_str, sqlite_timestamp,
    upsert_metadata_tx, validate_digest, validate_name,
};
use super::identity::{
    ACTIVE_DIGEST_KEY, ACTIVE_ID_KEY, PENDING_DIGEST_KEY, PENDING_ID_KEY, PENDING_IDEMPOTENCY_KEY,
    PENDING_PREVIOUS_DIGEST_KEY, PENDING_PREVIOUS_ID_KEY, PENDING_REQUEST_KEY,
    PENDING_ROLLBACK_KEY, PREVIOUS_DIGEST_KEY, PREVIOUS_ID_KEY, PendingReleaseActivation,
    ReleaseIdentity, ReleaseSelection, STATE_KEY,
};
use super::queries::read_selection;
use crate::config::DesiredMode;
use crate::error::Result;
use serde_json::Value;
use std::collections::BTreeSet;

impl Store {
    /// Prepare one exact release request. This transaction records the
    /// recovery marker before the final byte revalidation. It is safe to call
    /// again after a crash with the same request; another request is blocked
    /// until the marker is completed or explicitly resolved by that retry.
    pub fn prepare_release_activation(
        &mut self,
        owner: &SingletonLock,
        request_id: &str,
        idempotency_key: &str,
        release_id: &str,
        release_digest: &str,
        rollback: bool,
        now_ms: u64,
    ) -> Result<ReleaseSelection> {
        ensure_owner_lock(&self.path, owner)?;
        validate_name(request_id, "release activation request id", 128)?;
        validate_name(idempotency_key, "release activation idempotency key", 128)?;
        validate_name(release_id, "release activation release id", 128)?;
        validate_digest(release_digest).map_err(WatchdogError::InvalidInput)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let desired = metadata_from_conn(&tx, "desired_mode")?.ok_or_else(|| {
            WatchdogError::Conflict("desired mode metadata is missing".to_owned())
        })?;
        if desired != mode_as_str(DesiredMode::Stopped) {
            return Err(WatchdogError::Conflict(
                "release activation requires durably stopped mode".to_owned(),
            ));
        }
        let current = read_selection(&tx)?;
        if let Some(pending) = &current.pending {
            if pending.release.release_id == release_id
                && pending.release.release_digest == release_digest
                && pending.rollback == rollback
                && pending.request_id == request_id
                && pending.idempotency_key == idempotency_key
            {
                tx.rollback()?;
                return Ok(current);
            }
            return Err(WatchdogError::Conflict(
                "another release activation is prepared; retry its exact idempotency key first"
                    .to_owned(),
            ));
        }
        // Reserve the request and idempotency namespaces before writing a
        // prepared marker. A reused request UUID must fail here, rather than
        // leaving a marker that can never be completed by the colliding
        // operator receipt.
        if let Some(existing) = find_operator_by_key(&tx, idempotency_key)? {
            return Err(WatchdogError::Conflict(format!(
                "idempotency key already belongs to {}",
                existing.command.as_str()
            )));
        }
        if let Some(existing) = find_operator_by_request(&tx, request_id)? {
            return Err(WatchdogError::Conflict(format!(
                "request id already belongs to idempotency key {}",
                existing.idempotency_key
            )));
        }
        if rollback {
            let Some(previous) = &current.previous else {
                return Err(WatchdogError::Conflict(
                    "no previous release is available for rollback".to_owned(),
                ));
            };
            if previous.release_id != release_id || previous.release_digest != release_digest {
                return Err(WatchdogError::Conflict(
                    "rollback target is not the durably recorded previous release".to_owned(),
                ));
            }
            if current.active.is_none() {
                return Err(WatchdogError::Conflict(
                    "rollback requires an active release".to_owned(),
                ));
            }
        } else if current.active.as_ref().is_some_and(|active| {
            active.release_id == release_id && active.release_digest == release_digest
        }) {
            return Err(WatchdogError::Conflict(
                "requested release is already active".to_owned(),
            ));
        }
        let pending = PendingReleaseActivation {
            release: ReleaseIdentity {
                release_id: release_id.to_owned(),
                release_digest: release_digest.to_owned(),
            },
            rollback,
            request_id: request_id.to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            previous: current.active.clone(),
        };
        write_pending(&tx, &pending)?;
        insert_audit_tx(
            &tx,
            "release_activation_prepared",
            &format!(
                "release_id={release_id};digest={release_digest};rollback={rollback};request_id={request_id}"
            ),
            now_ms,
        )?;
        tx.commit()?;
        self.release_selection()
    }

    /// Finalize a prepared activation and its operator receipt in one SQLite
    /// transaction. Selector state can never become visible without a
    /// replayable receipt and audit record.
    pub fn complete_release_activation(
        &mut self,
        owner: &SingletonLock,
        context: &OperatorCommandContext,
        release_id: &str,
        release_digest: &str,
        rollback: bool,
        response: &Value,
        now_ms: u64,
    ) -> Result<OperatorCommandOutcome> {
        ensure_owner_lock(&self.path, owner)?;
        context.validate()?;
        if context.capability != OperatorCapability::Admin {
            return Err(WatchdogError::Unauthorized(
                "read capability cannot activate a release".to_owned(),
            ));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = find_operator_by_key(&tx, &context.idempotency_key)? {
            verify_duplicate_context(&existing, context)?;
            if existing.command != OperatorCommand::ReleaseActivate {
                return Err(WatchdogError::Conflict(
                    "idempotency key was reused for another operator command".to_owned(),
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
        enforce_ledger_capacity(&tx, OperatorCommand::ReleaseActivate)?;
        validate_response(response)?;
        let selection = read_selection(&tx)?;
        let Some(pending) = selection.pending else {
            return Err(WatchdogError::Conflict(
                "release activation has no prepared recovery marker".to_owned(),
            ));
        };
        if pending.release.release_id != release_id
            || pending.release.release_digest != release_digest
            || pending.rollback != rollback
            || pending.request_id != context.request_id
            || pending.idempotency_key != context.idempotency_key
        {
            return Err(WatchdogError::Conflict(
                "prepared release activation does not match this request".to_owned(),
            ));
        }
        validate_activation_response(response, &pending)?;
        // The previous identity was captured in the prepared marker. Reject
        // any valid-but-different active selector that appeared while the
        // final protected verification was interrupted; never rewrite the
        // rollback target from mutable metadata observed on retry.
        if selection.active != pending.previous {
            return Err(WatchdogError::Conflict(
                "active release changed while activation was prepared".to_owned(),
            ));
        }
        write_active(&tx, &pending.release, pending.previous.as_ref())?;
        clear_pending(&tx)?;
        let response_text = serde_json::to_string(response)?;
        tx.execute(
            "INSERT INTO operator_commands (request_id, idempotency_key, principal, capability, command, command_fingerprint, desired_mode, response_json, recorded_at_ms) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)",
            rusqlite::params![
                context.request_id,
                context.idempotency_key,
                context.principal,
                context.capability.as_str(),
                OperatorCommand::ReleaseActivate.as_str(),
                context.command_fingerprint,
                response_text,
                sqlite_timestamp(now_ms)?,
            ],
        )?;
        let sequence_i64 = tx.last_insert_rowid();
        let detail = format!(
            "sequence={sequence_i64};request_id={};key={};principal={};capability={};command=release_activate;fingerprint={};rollback={rollback}",
            context.request_id,
            context.idempotency_key,
            context.principal,
            context.capability.as_str(),
            context.command_fingerprint,
        );
        insert_audit_tx(
            &tx,
            "operator_command_release_activate_accepted",
            &detail,
            now_ms,
        )?;
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
            command: OperatorCommand::ReleaseActivate,
            command_fingerprint: context.command_fingerprint.clone(),
            desired_mode: None,
            response: response.clone(),
            recorded_at_ms: now_ms,
            replayed: false,
        }))
    }
}

fn verify_duplicate_context(
    existing: &OperatorCommandReceipt,
    context: &OperatorCommandContext,
) -> Result<()> {
    if existing.principal != context.principal {
        return Err(WatchdogError::Unauthorized(
            "idempotency key belongs to another operator context".to_owned(),
        ));
    }
    if existing.capability != context.capability
        || existing.command_fingerprint != context.command_fingerprint
    {
        return Err(WatchdogError::Conflict(
            "idempotency key was reused with a different command fingerprint".to_owned(),
        ));
    }
    Ok(())
}

fn write_pending(tx: &rusqlite::Transaction<'_>, pending: &PendingReleaseActivation) -> Result<()> {
    upsert_metadata_tx(tx, STATE_KEY, "prepared")?;
    upsert_metadata_tx(tx, PENDING_ID_KEY, &pending.release.release_id)?;
    upsert_metadata_tx(tx, PENDING_DIGEST_KEY, &pending.release.release_digest)?;
    upsert_metadata_tx(
        tx,
        PENDING_ROLLBACK_KEY,
        if pending.rollback { "1" } else { "0" },
    )?;
    upsert_metadata_tx(tx, PENDING_REQUEST_KEY, &pending.request_id)?;
    upsert_metadata_tx(tx, PENDING_IDEMPOTENCY_KEY, &pending.idempotency_key)?;
    match &pending.previous {
        Some(previous) => {
            upsert_metadata_tx(tx, PENDING_PREVIOUS_ID_KEY, &previous.release_id)?;
            upsert_metadata_tx(tx, PENDING_PREVIOUS_DIGEST_KEY, &previous.release_digest)?;
        }
        None => {
            tx.execute(
                "DELETE FROM metadata WHERE key IN (?, ?)",
                rusqlite::params![PENDING_PREVIOUS_ID_KEY, PENDING_PREVIOUS_DIGEST_KEY],
            )?;
        }
    }
    Ok(())
}

fn write_active(
    tx: &rusqlite::Transaction<'_>,
    active: &ReleaseIdentity,
    previous: Option<&ReleaseIdentity>,
) -> Result<()> {
    upsert_metadata_tx(tx, STATE_KEY, "active")?;
    upsert_metadata_tx(tx, ACTIVE_ID_KEY, &active.release_id)?;
    upsert_metadata_tx(tx, ACTIVE_DIGEST_KEY, &active.release_digest)?;
    match previous {
        Some(previous) => {
            upsert_metadata_tx(tx, PREVIOUS_ID_KEY, &previous.release_id)?;
            upsert_metadata_tx(tx, PREVIOUS_DIGEST_KEY, &previous.release_digest)?;
        }
        None => {
            tx.execute(
                "DELETE FROM metadata WHERE key IN (?, ?)",
                rusqlite::params![PREVIOUS_ID_KEY, PREVIOUS_DIGEST_KEY],
            )?;
        }
    }
    Ok(())
}

fn clear_pending(tx: &rusqlite::Transaction<'_>) -> Result<()> {
    tx.execute(
        "DELETE FROM metadata WHERE key IN (?, ?, ?, ?, ?, ?, ?)",
        rusqlite::params![
            PENDING_ID_KEY,
            PENDING_DIGEST_KEY,
            PENDING_ROLLBACK_KEY,
            PENDING_REQUEST_KEY,
            PENDING_IDEMPOTENCY_KEY,
            PENDING_PREVIOUS_ID_KEY,
            PENDING_PREVIOUS_DIGEST_KEY
        ],
    )?;
    Ok(())
}

/// Rekey/restore starts with no selected release. The restored namespace must
/// establish fresh authority and an explicit release activation before any
/// executable can be admitted.
pub(crate) fn clear_release_selection_tx(tx: &rusqlite::Transaction<'_>) -> Result<()> {
    upsert_metadata_tx(tx, STATE_KEY, "none")?;
    tx.execute(
        "DELETE FROM metadata WHERE key IN (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rusqlite::params![
            ACTIVE_ID_KEY,
            ACTIVE_DIGEST_KEY,
            PREVIOUS_ID_KEY,
            PREVIOUS_DIGEST_KEY,
            PENDING_ID_KEY,
            PENDING_DIGEST_KEY,
            PENDING_ROLLBACK_KEY,
            PENDING_REQUEST_KEY,
            PENDING_IDEMPOTENCY_KEY,
            PENDING_PREVIOUS_ID_KEY,
            PENDING_PREVIOUS_DIGEST_KEY
        ],
    )?;
    Ok(())
}

/// The selector and its retained operator receipt are one durable decision.
/// Validate the typed response at this storage boundary as well as at the
/// transport boundary so a lower-level caller cannot commit a receipt that
/// describes a different release or rollback target.
fn validate_activation_response(
    response: &Value,
    pending: &PendingReleaseActivation,
) -> Result<()> {
    let response_keys = response
        .as_object()
        .map(|object| object.keys().map(String::as_str).collect::<BTreeSet<_>>())
        .ok_or_else(|| {
            WatchdogError::Conflict("release activation response must be an object".to_owned())
        })?;
    if response_keys != BTreeSet::from(["kind", "value"]) {
        return Err(WatchdogError::Conflict(
            "release activation response has unknown or missing fields".to_owned(),
        ));
    }
    let value = response
        .get("value")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            WatchdogError::Conflict(
                "release activation response is missing its typed value".to_owned(),
            )
        })?;
    let value_keys = value.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if value_keys
        != BTreeSet::from([
            "release_id",
            "release_digest",
            "previous_release_id",
            "previous_release_digest",
            "rollback",
        ])
    {
        return Err(WatchdogError::Conflict(
            "release activation value has unknown or missing fields".to_owned(),
        ));
    }
    if response.get("kind").and_then(Value::as_str) != Some("ReleaseActivation")
        || value.get("release_id").and_then(Value::as_str)
            != Some(pending.release.release_id.as_str())
        || value.get("release_digest").and_then(Value::as_str)
            != Some(pending.release.release_digest.as_str())
        || value.get("rollback").and_then(Value::as_bool) != Some(pending.rollback)
    {
        return Err(WatchdogError::Conflict(
            "release activation response does not match the prepared selector".to_owned(),
        ));
    }
    let previous_id = value.get("previous_release_id").and_then(Value::as_str);
    let previous_digest = value.get("previous_release_digest").and_then(Value::as_str);
    match (&pending.previous, previous_id, previous_digest) {
        (Some(previous), Some(id), Some(digest))
            if previous.release_id == id && previous.release_digest == digest => {}
        (None, None, None) => {}
        _ => {
            return Err(WatchdogError::Conflict(
                "release activation response has a different previous selector".to_owned(),
            ));
        }
    }
    Ok(())
}
