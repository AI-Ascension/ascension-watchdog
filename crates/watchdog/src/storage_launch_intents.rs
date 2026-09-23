//! Launch-intent admission, proof recording and recovery records.
//!
//! Extracted from `storage.rs` (issue #100) without behavior change: the
//! durable launch-intent state and its row decoder, the pre-spawn admission
//! reservation, ownership-proof recording, activation, cleanup and the
//! unsettled-intent recovery queries.  `Store` remains the facade type; this
//! module owns only the launch-intent inherent methods and helpers.

use super::{
    Store, insert_audit_tx, metadata_from_conn, parse_mode, sqlite_timestamp, sqlite_u64,
    to_sqlite_error, validate_metadata_identifier, validate_name, validate_name_sqlite,
};
use crate::config::{DesiredMode, validate_digest};
use crate::error::{Result, WatchdogError};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

// Reserved for the platform launch-intent adapter. Keep the bound alongside
// the storage contract until the native adapter consumes the intent proof.
#[allow(dead_code)]
const MAX_LAUNCH_PROOF_BYTES: usize = 8 * 1024;

/// Durable pre-spawn ownership admission. The platform adapter supplies the
/// closed proof after it has created the exact process/container; runtime
/// validates that proof against the immutable binding before storage records
/// it. A missing binding marks a migrated legacy row and is never inferred.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LaunchIntent {
    pub id: String,
    pub deployment_id: String,
    pub component_id: String,
    pub launch_nonce: String,
    /// The incarnation selected before the platform launch.  This is
    /// optional only for rows migrated from schema v1; those rows are legacy
    /// and must be quarantined rather than rebinding a proof to a new value.
    pub expected_incarnation: Option<String>,
    /// Digest of the complete bounded launch specification selected before
    /// the platform launch.  Secrets are never persisted; the digest binds
    /// recovery to the original request without retaining its environment.
    pub expected_launch_spec_digest: Option<String>,
    pub planned_containment_id: Option<String>,
    pub state: LaunchIntentState,
    pub ownership_proof_json: Option<Value>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

/// State machine for a durable launch intent. Only an intent with a recorded
/// opaque ownership proof may become active.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchIntentState {
    Prepared,
    ProofRecorded,
    Active,
    Cleaned,
}

#[allow(dead_code)]
impl LaunchIntentState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::ProofRecorded => "proof_recorded",
            Self::Active => "active",
            Self::Cleaned => "cleaned",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "proof_recorded" => Ok(Self::ProofRecorded),
            "active" => Ok(Self::Active),
            "cleaned" => Ok(Self::Cleaned),
            other => Err(WatchdogError::Conflict(format!(
                "unknown launch intent state {other}"
            ))),
        }
    }
}

pub(crate) fn require_running_launch_intent(tx: &Transaction<'_>) -> Result<()> {
    let desired = metadata_from_conn(tx, "desired_mode")?
        .ok_or_else(|| WatchdogError::Conflict("desired mode metadata is missing".to_owned()))?;
    if parse_mode(&desired)? != DesiredMode::Running {
        return Err(WatchdogError::Conflict(
            "durable desired mode does not authorize launch admission or activation".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn launch_intent_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LaunchIntent> {
    let state: String = row.get(7)?;
    let expected_incarnation: Option<String> = row.get(4)?;
    let expected_launch_spec_digest: Option<String> = row.get(5)?;
    if expected_incarnation.is_some() != expected_launch_spec_digest.is_some() {
        return Err(to_sqlite_error(
            "launch intent has a partially persisted launch binding",
        ));
    }
    if let Some(incarnation) = &expected_incarnation {
        validate_name_sqlite(incarnation, "expected launch incarnation", 256)?;
    }
    if let Some(digest) = &expected_launch_spec_digest {
        validate_digest(digest).map_err(to_sqlite_error)?;
    }
    let proof_text: Option<String> = row.get(8)?;
    if proof_text
        .as_ref()
        .is_some_and(|value| value.len() > MAX_LAUNCH_PROOF_BYTES)
    {
        return Err(to_sqlite_error(
            "launch ownership proof exceeds its persisted bound",
        ));
    }
    let parsed_proof = proof_text
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(to_sqlite_error)?;
    let parsed_state = LaunchIntentState::parse(&state).map_err(to_sqlite_error)?;
    if matches!(
        parsed_state,
        LaunchIntentState::ProofRecorded | LaunchIntentState::Active
    ) && parsed_proof.is_none()
    {
        return Err(to_sqlite_error(
            "launch intent state requires a recorded ownership proof",
        ));
    }
    if matches!(parsed_state, LaunchIntentState::Prepared) && parsed_proof.is_some() {
        return Err(to_sqlite_error(
            "prepared launch intent unexpectedly contains an ownership proof",
        ));
    }
    Ok(LaunchIntent {
        id: row.get(0)?,
        deployment_id: row.get(1)?,
        component_id: row.get(2)?,
        launch_nonce: row.get(3)?,
        expected_incarnation,
        expected_launch_spec_digest,
        planned_containment_id: row.get(6)?,
        state: parsed_state,
        ownership_proof_json: parsed_proof,
        created_at_ms: sqlite_u64(row.get::<_, i64>(9)?, "launch intent created_at_ms")?,
        updated_at_ms: sqlite_u64(row.get::<_, i64>(10)?, "launch intent updated_at_ms")?,
    })
}

impl Store {
    /// Record the durable pre-spawn admission for one component. The caller
    /// supplies the original incarnation and a digest of the complete launch
    /// specification before creating a process. A component may have at most
    /// one non-cleaned intent, which prevents an untracked duplicate child.
    pub fn prepare_launch_intent(
        &mut self,
        component_id: &str,
        launch_nonce: &str,
        expected_incarnation: &str,
        expected_launch_spec_digest: &str,
        planned_containment_id: Option<&str>,
        now_ms: u64,
    ) -> Result<LaunchIntent> {
        validate_name(component_id, "component id", 128)?;
        validate_name(launch_nonce, "launch nonce", 128)?;
        validate_name(expected_incarnation, "expected launch incarnation", 256)?;
        validate_digest(expected_launch_spec_digest).map_err(WatchdogError::InvalidInput)?;
        if let Some(containment_id) = planned_containment_id {
            validate_name(containment_id, "planned containment id", 256)?;
        }
        let deployment_id = self.metadata("deployment_id")?.ok_or_else(|| {
            WatchdogError::Conflict("deployment_id metadata is missing".to_string())
        })?;
        validate_metadata_identifier("deployment_id", &deployment_id)?;
        let id = Uuid::new_v4().to_string();
        let now = sqlite_timestamp(now_ms)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_running_launch_intent(&tx)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT id FROM launch_intents WHERE component_id=? AND state <> 'cleaned' LIMIT 1",
                params![component_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(format!(
                "component {component_id} already has an unsettled launch intent {existing}"
            )));
        }
        tx.execute(
            "INSERT INTO launch_intents (id, deployment_id, component_id, launch_nonce, expected_incarnation, expected_launch_spec_digest, planned_containment_id, state, ownership_proof_json, created_at_ms, updated_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, 'prepared', NULL, ?, ?)",
            params![
                id,
                deployment_id,
                component_id,
                launch_nonce,
                expected_incarnation,
                expected_launch_spec_digest,
                planned_containment_id,
                now,
                now
            ],
        )?;
        insert_audit_tx(
            &tx,
            "launch_intent_prepared",
            &format!("{component_id}:{id}"),
            now_ms,
        )?;
        tx.commit()?;
        self.launch_intent(&id)?.ok_or_else(|| {
            WatchdogError::Conflict("launch intent disappeared after commit".to_string())
        })
    }

    /// Retain the bounded platform ownership proof for a bound intent. Runtime
    /// validates its typed context before calling this storage primitive; this
    /// method still rejects migrated rows with no original binding.
    pub fn record_launch_proof(
        &mut self,
        intent_id: &str,
        ownership_proof: &Value,
        now_ms: u64,
    ) -> Result<LaunchIntent> {
        validate_name(intent_id, "launch intent id", 128)?;
        if ownership_proof.is_null() {
            return Err(WatchdogError::InvalidInput(
                "launch ownership proof must not be null".to_string(),
            ));
        }
        let encoded = serde_json::to_string(ownership_proof)?;
        if encoded.len() > MAX_LAUNCH_PROOF_BYTES {
            return Err(WatchdogError::InvalidInput(
                "launch ownership proof exceeds its bound".to_string(),
            ));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state_and_binding: Option<(String, Option<String>, Option<String>)> = tx
            .query_row(
                "SELECT state, expected_incarnation, expected_launch_spec_digest FROM launch_intents WHERE id=?",
                params![intent_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((state, expected_incarnation, expected_digest)) = state_and_binding else {
            tx.rollback()?;
            return Err(WatchdogError::NotFound(format!(
                "launch intent {intent_id}"
            )));
        };
        if expected_incarnation.is_none() || expected_digest.is_none() {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(format!(
                "launch intent {intent_id} has no persisted launch binding"
            )));
        }
        if state != "prepared" {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(format!(
                "launch intent {intent_id} is {state}, not prepared"
            )));
        }
        tx.execute(
            "UPDATE launch_intents SET state='proof_recorded', ownership_proof_json=?, updated_at_ms=? WHERE id=? AND state='prepared'",
            params![encoded, sqlite_timestamp(now_ms)?, intent_id],
        )?;
        insert_audit_tx(&tx, "launch_proof_recorded", intent_id, now_ms)?;
        tx.commit()?;
        self.launch_intent(intent_id)?.ok_or_else(|| {
            WatchdogError::Conflict("launch intent disappeared after proof commit".to_string())
        })
    }

    /// Mark an intent active after the platform has created the exact child
    /// and the complete process identity has been persisted.  A proof is
    /// mandatory; no caller may promote a bare PID or a planned path.
    pub fn activate_launch_intent(&mut self, intent_id: &str, now_ms: u64) -> Result<LaunchIntent> {
        validate_name(intent_id, "launch intent id", 128)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_running_launch_intent(&tx)?;
        let state_and_proof: Option<(
            String,
            Option<String>,
            Option<String>,
            Option<String>,
        )> = tx
            .query_row(
                "SELECT state, ownership_proof_json, expected_incarnation, expected_launch_spec_digest FROM launch_intents WHERE id=?",
                params![intent_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((state, proof, expected_incarnation, expected_digest)) = state_and_proof else {
            tx.rollback()?;
            return Err(WatchdogError::NotFound(format!(
                "launch intent {intent_id}"
            )));
        };
        if expected_incarnation.is_none() || expected_digest.is_none() {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(format!(
                "launch intent {intent_id} has no persisted launch binding"
            )));
        }
        if state != "proof_recorded" || proof.is_none() {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(format!(
                "launch intent {intent_id} lacks a recorded ownership proof"
            )));
        }
        tx.execute(
            "UPDATE launch_intents SET state='active', updated_at_ms=? WHERE id=? AND state='proof_recorded'",
            params![sqlite_timestamp(now_ms)?, intent_id],
        )?;
        insert_audit_tx(&tx, "launch_intent_activated", intent_id, now_ms)?;
        tx.commit()?;
        self.launch_intent(intent_id)?.ok_or_else(|| {
            WatchdogError::Conflict("launch intent disappeared after activation".to_string())
        })
    }

    /// Mark a prepared, proof-recorded, or active intent cleaned after the
    /// designated process authority has completed exact containment cleanup.
    /// This is a durable fact only; it does not itself terminate a process.
    pub fn clean_launch_intent(&mut self, intent_id: &str, now_ms: u64) -> Result<LaunchIntent> {
        validate_name(intent_id, "launch intent id", 128)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state: Option<String> = tx
            .query_row(
                "SELECT state FROM launch_intents WHERE id=?",
                params![intent_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(state) = state else {
            tx.rollback()?;
            return Err(WatchdogError::NotFound(format!(
                "launch intent {intent_id}"
            )));
        };
        if state == "cleaned" {
            tx.commit()?;
            return self.launch_intent(intent_id)?.ok_or_else(|| {
                WatchdogError::Conflict("launch intent disappeared after cleanup".to_string())
            });
        }
        if !matches!(state.as_str(), "prepared" | "proof_recorded" | "active") {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(format!(
                "launch intent {intent_id} has unknown state {state}"
            )));
        }
        tx.execute(
            "UPDATE launch_intents SET state='cleaned', updated_at_ms=? WHERE id=? AND state=?",
            params![sqlite_timestamp(now_ms)?, intent_id, state],
        )?;
        insert_audit_tx(&tx, "launch_intent_cleaned", intent_id, now_ms)?;
        tx.commit()?;
        self.launch_intent(intent_id)?.ok_or_else(|| {
            WatchdogError::Conflict("launch intent disappeared after cleanup".to_string())
        })
    }

    /// Fetch one launch intent for platform-authority reconciliation.
    pub fn launch_intent(&self, intent_id: &str) -> Result<Option<LaunchIntent>> {
        validate_name(intent_id, "launch intent id", 128)?;
        self.conn
            .query_row(
                "SELECT id, deployment_id, component_id, launch_nonce, expected_incarnation, expected_launch_spec_digest, planned_containment_id, state, ownership_proof_json, created_at_ms, updated_at_ms FROM launch_intents WHERE id=?",
                params![intent_id],
                launch_intent_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// List unsettled intents in creation order.  A replacement controller
    /// must reconcile these through the exact platform authority before any
    /// new launch is admitted.
    pub fn unsettled_launch_intents(&self) -> Result<Vec<LaunchIntent>> {
        let mut statement = self.conn.prepare(
            "SELECT id, deployment_id, component_id, launch_nonce, expected_incarnation, expected_launch_spec_digest, planned_containment_id, state, ownership_proof_json, created_at_ms, updated_at_ms FROM launch_intents WHERE state <> 'cleaned' ORDER BY created_at_ms, id",
        )?;
        let rows = statement.query_map([], launch_intent_from_row)?;
        rows.collect::<rusqlite::Result<Vec<LaunchIntent>>>()
            .map_err(Into::into)
    }
}
