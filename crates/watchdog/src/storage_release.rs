//! Durable release-selection state owned by the watchdog store.
//!
//! Release bytes are validated by the protected catalog before these methods
//! are called.  This module owns only the small, transactional selector and
//! its recovery marker; it never opens an executable or changes authority
//! generations.  A `prepared` marker is intentionally retained across a
//! crash so the exact idempotency key can retry the final verification and
//! commit without allowing another release to leapfrog it.

use super::storage_admin::{
    enforce_ledger_capacity, find_operator_by_key, find_operator_by_request, validate_response,
};
use super::{
    OperatorCapability, OperatorCommand, OperatorCommandContext, OperatorCommandOutcome,
    OperatorCommandReceipt, SingletonLock, Store, TransactionBehavior, WatchdogError,
    ensure_owner_lock, insert_audit_tx, metadata_from_conn, mode_as_str, upsert_metadata_tx,
    validate_digest, validate_name,
};
use crate::config::DesiredMode;
use crate::error::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

const STATE_KEY: &str = "release_selection_state";
const ACTIVE_ID_KEY: &str = "active_release_id";
const ACTIVE_DIGEST_KEY: &str = "approved_release_digest";
const PREVIOUS_ID_KEY: &str = "previous_release_id";
const PREVIOUS_DIGEST_KEY: &str = "previous_release_digest";
const PENDING_ID_KEY: &str = "pending_release_id";
const PENDING_DIGEST_KEY: &str = "pending_release_digest";
const PENDING_ROLLBACK_KEY: &str = "pending_release_rollback";
const PENDING_REQUEST_KEY: &str = "pending_release_request_id";
const PENDING_IDEMPOTENCY_KEY: &str = "pending_release_idempotency_key";
const PENDING_PREVIOUS_ID_KEY: &str = "pending_release_previous_id";
const PENDING_PREVIOUS_DIGEST_KEY: &str = "pending_release_previous_digest";

/// Durable selector state. `Prepared` means an activation was admitted and
/// must be retried with its exact request after an interrupted final check.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseSelectionState {
    None,
    Prepared,
    Active,
}

/// One immutable release identity. The digest is the exact manifest-byte
/// digest, not a reserialized representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIdentity {
    pub release_id: String,
    pub release_digest: String,
}

/// A pending activation marker retained across process and machine restart.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingReleaseActivation {
    pub release: ReleaseIdentity,
    pub rollback: bool,
    pub request_id: String,
    pub idempotency_key: String,
    pub previous: Option<ReleaseIdentity>,
}

/// Read-only selector projection for status, recovery and tests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSelection {
    pub state: ReleaseSelectionState,
    pub active: Option<ReleaseIdentity>,
    pub previous: Option<ReleaseIdentity>,
    pub pending: Option<PendingReleaseActivation>,
}

impl Store {
    /// Read and validate the durable selector without changing state.
    pub fn release_selection(&self) -> Result<ReleaseSelection> {
        read_selection(&self.conn)
    }

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
                super::sqlite_timestamp(now_ms)?,
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

    /// Validate selector metadata during every owner/read-only open. Missing
    /// optional keys mean the store has never selected a release; malformed or
    /// half-written pairs are corruption, never defaults.
    pub(crate) fn validate_release_selection_metadata(&self) -> Result<()> {
        let _ = self.release_selection()?;
        Ok(())
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

fn read_selection(conn: &rusqlite::Connection) -> Result<ReleaseSelection> {
    let state_text = metadata_from_conn(conn, STATE_KEY)?.unwrap_or_else(|| "none".to_owned());
    let state = match state_text.as_str() {
        "none" => ReleaseSelectionState::None,
        "prepared" => ReleaseSelectionState::Prepared,
        "active" => ReleaseSelectionState::Active,
        _ => {
            return Err(WatchdogError::Conflict(
                "release selector state is malformed".to_owned(),
            ));
        }
    };
    let active = read_identity(conn, ACTIVE_ID_KEY, ACTIVE_DIGEST_KEY, "active release")?;
    let previous = read_identity(
        conn,
        PREVIOUS_ID_KEY,
        PREVIOUS_DIGEST_KEY,
        "previous release",
    )?;
    let pending_id = metadata_from_conn(conn, PENDING_ID_KEY)?;
    let pending_digest = metadata_from_conn(conn, PENDING_DIGEST_KEY)?;
    let pending_rollback = metadata_from_conn(conn, PENDING_ROLLBACK_KEY)?;
    let pending_request = metadata_from_conn(conn, PENDING_REQUEST_KEY)?;
    let pending_key = metadata_from_conn(conn, PENDING_IDEMPOTENCY_KEY)?;
    let pending_previous_id = metadata_from_conn(conn, PENDING_PREVIOUS_ID_KEY)?;
    let pending_previous_digest = metadata_from_conn(conn, PENDING_PREVIOUS_DIGEST_KEY)?;
    let any_pending = pending_id.is_some()
        || pending_digest.is_some()
        || pending_rollback.is_some()
        || pending_request.is_some()
        || pending_key.is_some()
        || pending_previous_id.is_some()
        || pending_previous_digest.is_some();
    let pending = if any_pending {
        let (Some(id), Some(digest), Some(rollback), Some(request_id), Some(idempotency_key)) = (
            pending_id,
            pending_digest,
            pending_rollback,
            pending_request,
            pending_key,
        ) else {
            return Err(WatchdogError::Conflict(
                "release selector pending marker is incomplete".to_owned(),
            ));
        };
        validate_name(&id, "pending release id", 128)?;
        validate_digest(&digest).map_err(WatchdogError::Conflict)?;
        let rollback = match rollback.as_str() {
            "0" => false,
            "1" => true,
            _ => {
                return Err(WatchdogError::Conflict(
                    "pending release rollback marker is malformed".to_owned(),
                ));
            }
        };
        validate_name(&request_id, "pending release request id", 128)?;
        validate_name(&idempotency_key, "pending release idempotency key", 128)?;
        let previous = read_identity_values(
            pending_previous_id,
            pending_previous_digest,
            "pending previous release",
        )?;
        Some(PendingReleaseActivation {
            release: ReleaseIdentity {
                release_id: id,
                release_digest: digest,
            },
            rollback,
            request_id,
            idempotency_key,
            previous,
        })
    } else {
        None
    };
    if state == ReleaseSelectionState::Prepared && pending.is_none() {
        return Err(WatchdogError::Conflict(
            "prepared release selector has no pending marker".to_owned(),
        ));
    }
    if state != ReleaseSelectionState::Prepared && pending.is_some() {
        return Err(WatchdogError::Conflict(
            "non-prepared release selector has a pending marker".to_owned(),
        ));
    }
    if state == ReleaseSelectionState::Active && active.is_none() {
        return Err(WatchdogError::Conflict(
            "active release selector has no active identity".to_owned(),
        ));
    }
    if state == ReleaseSelectionState::None && active.is_some() {
        return Err(WatchdogError::Conflict(
            "empty release selector has an active identity".to_owned(),
        ));
    }
    Ok(ReleaseSelection {
        state,
        active,
        previous,
        pending,
    })
}

fn read_identity(
    conn: &rusqlite::Connection,
    id_key: &str,
    digest_key: &str,
    label: &str,
) -> Result<Option<ReleaseIdentity>> {
    let id = metadata_from_conn(conn, id_key)?;
    let digest = metadata_from_conn(conn, digest_key)?;
    match (id, digest) {
        (None, None) => Ok(None),
        (Some(id), Some(digest)) => {
            validate_name(&id, label, 128)?;
            validate_digest(&digest).map_err(WatchdogError::Conflict)?;
            Ok(Some(ReleaseIdentity {
                release_id: id,
                release_digest: digest,
            }))
        }
        _ => Err(WatchdogError::Conflict(format!(
            "{label} identity is incomplete"
        ))),
    }
}

fn read_identity_values(
    id: Option<String>,
    digest: Option<String>,
    label: &str,
) -> Result<Option<ReleaseIdentity>> {
    match (id, digest) {
        (None, None) => Ok(None),
        (Some(id), Some(digest)) => {
            validate_name(&id, label, 128)?;
            validate_digest(&digest).map_err(WatchdogError::Conflict)?;
            Ok(Some(ReleaseIdentity {
                release_id: id,
                release_digest: digest,
            }))
        }
        _ => Err(WatchdogError::Conflict(format!(
            "{label} identity is incomplete"
        ))),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WatchdogConfig;
    use serde_json::json;
    use tempfile::TempDir;
    use uuid::Uuid;

    fn context(key: &str, request_id: &str) -> OperatorCommandContext {
        OperatorCommandContext::new(
            request_id,
            key,
            "AdminToken",
            OperatorCapability::Admin,
            "a".repeat(64),
        )
        .expect("valid operator context")
    }

    fn response(id: &str, digest: &str, rollback: bool) -> Value {
        response_with_previous(id, digest, rollback, None)
    }

    fn response_with_previous(
        id: &str,
        digest: &str,
        rollback: bool,
        previous: Option<(&str, &str)>,
    ) -> Value {
        json!({
            "kind": "ReleaseActivation",
            "value": {
                "release_id": id,
                "release_digest": digest,
                "previous_release_id": previous.map(|value| value.0),
                "previous_release_digest": previous.map(|value| value.1),
                "rollback": rollback,
            }
        })
    }

    fn fixture() -> (TempDir, WatchdogConfig, Store, SingletonLock) {
        let temp = tempfile::tempdir().expect("temporary release selector store");
        let config = WatchdogConfig {
            database: temp.path().join("watchdog.sqlite3"),
            ..WatchdogConfig::default()
        };
        let store = Store::initialize(&config.database, &config).expect("initialize store");
        let owner = SingletonLock::acquire(&config.database).expect("owner lock");
        (temp, config, store, owner)
    }

    #[test]
    fn prepared_activation_survives_reopen_and_exact_retry_commits_once() -> Result<()> {
        let (_temp, config, mut store, owner) = fixture();
        let first = context("activate-one", &Uuid::new_v4().to_string());
        let digest = "b".repeat(64);
        let prepared = store.prepare_release_activation(
            &owner,
            &first.request_id,
            &first.idempotency_key,
            "release-one",
            &digest,
            false,
            10,
        )?;
        assert_eq!(prepared.state, ReleaseSelectionState::Prepared);
        drop(store);
        drop(owner);

        let mut reopened = Store::open(&config.database, &config)?;
        let pending = reopened.release_selection()?;
        assert_eq!(pending.state, ReleaseSelectionState::Prepared);
        assert_eq!(
            pending
                .pending
                .as_ref()
                .map(|value| value.release.release_id.as_str()),
            Some("release-one")
        );
        let owner = SingletonLock::acquire(&config.database)?;
        let replay_prepare = reopened.prepare_release_activation(
            &owner,
            &first.request_id,
            &first.idempotency_key,
            "release-one",
            &digest,
            false,
            11,
        )?;
        assert_eq!(replay_prepare.state, ReleaseSelectionState::Prepared);
        let response = response("release-one", &digest, false);
        let committed = reopened.complete_release_activation(
            &owner,
            &first,
            "release-one",
            &digest,
            false,
            &response,
            12,
        )?;
        assert!(matches!(committed, OperatorCommandOutcome::Accepted(_)));
        let active = reopened.release_selection()?;
        assert_eq!(active.state, ReleaseSelectionState::Active);
        assert_eq!(
            active
                .active
                .as_ref()
                .map(|value| value.release_id.as_str()),
            Some("release-one")
        );
        assert!(active.pending.is_none());

        let replay = reopened.complete_release_activation(
            &owner,
            &first,
            "release-one",
            &digest,
            false,
            &response,
            13,
        )?;
        assert!(matches!(replay, OperatorCommandOutcome::Replayed(_)));
        assert_eq!(reopened.operator_command_count()?, 1);
        Ok(())
    }

    #[test]
    fn rollback_is_bound_to_previous_release_and_cannot_toggle_arbitrary_catalog_entries()
    -> Result<()> {
        let (_temp, _config, mut store, owner) = fixture();
        let first = context("activate-one", &Uuid::new_v4().to_string());
        let first_digest = "b".repeat(64);
        store.prepare_release_activation(
            &owner,
            &first.request_id,
            &first.idempotency_key,
            "release-one",
            &first_digest,
            false,
            10,
        )?;
        let first_response = response("release-one", &first_digest, false);
        store.complete_release_activation(
            &owner,
            &first,
            "release-one",
            &first_digest,
            false,
            &first_response,
            11,
        )?;

        let second = context("activate-two", &Uuid::new_v4().to_string());
        let second_digest = "c".repeat(64);
        store.prepare_release_activation(
            &owner,
            &second.request_id,
            &second.idempotency_key,
            "release-two",
            &second_digest,
            false,
            12,
        )?;
        let second_response = response_with_previous(
            "release-two",
            &second_digest,
            false,
            Some(("release-one", first_digest.as_str())),
        );
        store.complete_release_activation(
            &owner,
            &second,
            "release-two",
            &second_digest,
            false,
            &second_response,
            13,
        )?;

        let rollback = context("rollback-two", &Uuid::new_v4().to_string());
        assert!(
            store
                .prepare_release_activation(
                    &owner,
                    &rollback.request_id,
                    &rollback.idempotency_key,
                    "not-the-previous-release",
                    &first_digest,
                    true,
                    14,
                )
                .is_err()
        );
        store.prepare_release_activation(
            &owner,
            &rollback.request_id,
            &rollback.idempotency_key,
            "release-one",
            &first_digest,
            true,
            15,
        )?;
        let rollback_response = response_with_previous(
            "release-one",
            &first_digest,
            true,
            Some(("release-two", second_digest.as_str())),
        );
        store.complete_release_activation(
            &owner,
            &rollback,
            "release-one",
            &first_digest,
            true,
            &rollback_response,
            16,
        )?;
        let selection = store.release_selection()?;
        assert_eq!(
            selection
                .active
                .as_ref()
                .map(|value| value.release_id.as_str()),
            Some("release-one")
        );
        assert_eq!(
            selection
                .previous
                .as_ref()
                .map(|value| value.release_id.as_str()),
            Some("release-two")
        );
        Ok(())
    }

    #[test]
    fn activation_receipt_must_describe_the_prepared_selector() -> Result<()> {
        let (_temp, _config, mut store, owner) = fixture();
        let activation = context("activate-one", &Uuid::new_v4().to_string());
        let digest = "b".repeat(64);
        store.prepare_release_activation(
            &owner,
            &activation.request_id,
            &activation.idempotency_key,
            "release-one",
            &digest,
            false,
            10,
        )?;
        let error = store
            .complete_release_activation(
                &owner,
                &activation,
                "release-one",
                &digest,
                false,
                &response("different-release", &digest, false),
                11,
            )
            .expect_err("a mismatched receipt cannot publish the selector");
        assert!(error.to_string().contains("response does not match"));
        assert_eq!(
            store.release_selection()?.state,
            ReleaseSelectionState::Prepared
        );
        assert_eq!(store.operator_command_count()?, 0);
        Ok(())
    }

    #[test]
    fn prepared_activation_rejects_a_request_id_already_in_the_operator_ledger() -> Result<()> {
        let (_temp, _config, mut store, owner) = fixture();
        let existing = context("existing-command", &Uuid::new_v4().to_string());
        store.admit_operator_command(
            &owner,
            &existing,
            OperatorCommand::JobSubmit,
            &json!({"kind": "accepted", "value": {"queued": true}}),
            10,
        )?;
        let collision = context("new-activation", &existing.request_id);
        let error = store
            .prepare_release_activation(
                &owner,
                &collision.request_id,
                &collision.idempotency_key,
                "release-one",
                &"b".repeat(64),
                false,
                11,
            )
            .expect_err("a reused request UUID must not strand a prepared marker");
        assert!(error.to_string().contains("request id already belongs"));
        assert_eq!(
            store.release_selection()?.state,
            ReleaseSelectionState::None
        );
        Ok(())
    }

    #[test]
    fn prepared_activation_rejects_a_changed_active_identity() -> Result<()> {
        let (_temp, _config, mut store, owner) = fixture();
        let first = context("activate-one", &Uuid::new_v4().to_string());
        let first_digest = "b".repeat(64);
        store.prepare_release_activation(
            &owner,
            &first.request_id,
            &first.idempotency_key,
            "release-one",
            &first_digest,
            false,
            10,
        )?;
        store.complete_release_activation(
            &owner,
            &first,
            "release-one",
            &first_digest,
            false,
            &response("release-one", &first_digest, false),
            11,
        )?;

        let second = context("activate-two", &Uuid::new_v4().to_string());
        let second_digest = "c".repeat(64);
        store.prepare_release_activation(
            &owner,
            &second.request_id,
            &second.idempotency_key,
            "release-two",
            &second_digest,
            false,
            12,
        )?;
        store.conn.execute(
            "UPDATE metadata SET value=? WHERE key=?",
            rusqlite::params!["d".repeat(64), ACTIVE_DIGEST_KEY],
        )?;
        let error = store
            .complete_release_activation(
                &owner,
                &second,
                "release-two",
                &second_digest,
                false,
                &response_with_previous(
                    "release-two",
                    &second_digest,
                    false,
                    Some(("release-one", first_digest.as_str())),
                ),
                13,
            )
            .expect_err("changed active identity must block completion");
        assert!(error.to_string().contains("active release changed"));
        assert_eq!(
            store.release_selection()?.state,
            ReleaseSelectionState::Prepared
        );
        Ok(())
    }
}
