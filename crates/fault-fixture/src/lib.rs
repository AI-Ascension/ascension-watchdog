//! Test-only synthetic host for watchdog recovery fault injection.
//!
//! This package is deliberately independent of the production watchdog and of
//! the gateway, harness, MCP, and game-mod implementation crates.  It exposes
//! the closed recovery sideband envelope, accepts the same operation identity
//! and fence fields, and also understands the frozen runtime-v3 route kinds.
//! Its `SQLite` state models the important crash window where a host effect is
//! durable before the receipt is durable.  An absent witness remains unknown.

mod db;
mod encoding;
mod error;
mod journal;
mod lease;
mod runtime;
mod runtime_store;
mod runtime_validate;
mod server;
mod transport;
mod validate;
mod wire;

pub use error::FixtureError;
pub use journal::FaultPoint;
pub use server::run_server;
pub use wire::{Actor, Auth, Client, Frame, ServerConfig};

use db::{OperationRow, SidecarLock};
use encoding::{digest, sha256_hex};
use journal::FaultController;
use runtime_validate::{
    validate_runtime_legal_action, validate_runtime_legal_actions, validate_runtime_observation,
    validate_runtime_transition, validate_runtime_v3_envelope, validate_runtime_witness,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use server::response_kind;
use uuid::Uuid;
use validate::{
    validate_boot_context, validate_effect_witness, validate_host_fence, validate_lease_context,
    validate_lease_policy_values, validate_operation_context, validate_operation_full,
    validate_operation_ref, validate_original_context, validate_policy, validate_receipt,
    validate_recovery_payload, validate_ticket,
};
use wire::parse_value_no_duplicates;

/// Exact digest published by `watchdog-recovery-v1`.
pub const RECOVERY_SCHEMA_DIGEST: &str =
    "fb934d3157485aaf6e13e6ebbb213ec8a14c7fc6f5eeebc06b7a22c1f0009217";
/// Exact digest for the frozen runtime-v3 gameplay artifact used by the
/// companion mod/gateway sources.
pub const RUNTIME_V3_SCHEMA_DIGEST: &str =
    "8e99cea36b7ede97532348fd8efe302ca79260895265a7bf14ddf7e006d8ff63";
/// Recovery frame maximum from the companion contract.
pub const MAX_FRAME_BYTES: usize = 262_144;
/// Action/payload maximum from the companion contract.
pub const MAX_ACTION_BYTES: usize = 65_536;
/// Retained receipt bound used by the fixture's backpressure oracle.
pub const MAX_RECEIPTS: usize = 64;
/// Runtime operation journal bound. Backpressure retains every row so
/// unresolved work and operation-id deduplication are never evicted.
pub const MAX_RUNTIME_OPERATIONS: usize = 64;
/// A synthetic host effect is never represented as exactly-once proof.
pub const EFFECT_WITNESS_SOURCE: &str = "host_game_thread";
/// Exact bytes of the approved sideband schema consumed by this fixture.
pub const RECOVERY_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/artifacts/watchdog-recovery-v1/schema.json"
));
/// Exact bytes of the approved RCJ vector set consumed by this fixture.
pub const RCJ_VECTORS_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/artifacts/watchdog-recovery-v1/rcj-vectors.json"
));
/// Exact bytes of the frozen runtime-v3 schema used by the synthetic adapter.
pub const RUNTIME_V3_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/artifacts/runtime-v3-gameplay/schema.json"
));

const MAX_LINE_BYTES: usize = MAX_FRAME_BYTES + 1;
const FIXTURE_TIMESTAMP: &str = "2026-09-06T00:00:00Z";
const FIXTURE_TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const MAX_RUNTIME_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseAction {
    Send,
    Drop,
    Malformed,
    Crash,
}

/// Durable host store.  Each operation, effect witness, receipt, queue item,
/// and current fence is persisted independently so the effect/receipt crash
/// window is observable rather than hidden behind an in-memory counter.
pub struct DurableHost {
    connection: Connection,
    // The sidecar lock is held for the lifetime of the store.  SQLite's own
    // page locks serialize writes, but do not establish which fixture process
    // owns mutation authority.  A separate file avoids interfering with
    // SQLite's WAL file locks and is released by the OS after a crash.
    _lock: SidecarLock,
}

impl DurableHost {
    fn handle(
        &mut self,
        frame: &Frame,
        faults: &mut FaultController,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        let result = match frame.kind.as_str() {
            "bootstrap_request" => self.bootstrap(frame),
            "host_fence_request" => self.host_fence(frame),
            "lease_acquire_request" => self.lease_acquire(frame),
            "lease_renew_request" => self.lease_renew(frame),
            "lease_revoke_request" => self.lease_revoke(frame),
            "operation_intent_request" => self.intent(frame),
            "operation_dispatch_request" => self.dispatch(frame, faults),
            "operation_lookup_request" => self.lookup(frame),
            "operation_reconcile_request" => self.reconcile(frame),
            "state_request" | "legal_actions_request" | "dispatch_action_request"
            | "wait_request" | "reobserve_request" | "recover_request" => {
                self.v3_handle_frame(frame, faults)
            }
            "host_tick" => self.tick(frame, faults),
            "stats" => self.stats(frame),
            "shutdown" => Ok((
                frame.response("shutdown_response", json!({"result":{"status":"ACCEPTED","retryable":false,"retry_after_seconds":null}})),
                ResponseAction::Send,
            )),
            _ => Err(FixtureError::Invalid("unsupported request kind".to_owned())),
        }?;
        Ok(result)
    }

    fn stats(&mut self, frame: &Frame) -> Result<(Frame, ResponseAction), FixtureError> {
        let effect_count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM effects", [], |row| row.get(0))
            .map_err(FixtureError::Sql)?;
        let receipt_count = i64::try_from(self.receipt_count()?)
            .map_err(|_| FixtureError::Invalid("receipt count overflow".to_owned()))?;
        let queue_count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM queue", [], |row| row.get(0))
            .map_err(FixtureError::Sql)?;
        let unresolved_count: i64 = self.connection.query_row("SELECT COUNT(*) FROM operations WHERE state IN ('UNKNOWN','MAY_HAVE_BEEN_DISPATCHED')", [], |row| row.get(0)).map_err(FixtureError::Sql)?;
        Ok((frame.response("stats_response", json!({"result":status("ACCEPTED"),"effect_count":effect_count,"receipt_count":receipt_count,"queue_count":queue_count,"unresolved_count":unresolved_count,"receipt_capacity":MAX_RECEIPTS})), ResponseAction::Send))
    }

    fn operation_response(
        &mut self,
        frame: &Frame,
        status_value: &str,
        id: &str,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        self.operation_response_with_action(frame, status_value, id, ResponseAction::Send)
    }

    fn operation_response_with_action(
        &mut self,
        frame: &Frame,
        status_value: &str,
        id: &str,
        action: ResponseAction,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        let operation = self.operation_value(id, "")?.unwrap_or(Value::Null);
        Ok((
            frame.response(
                &response_kind(&frame.kind),
                json!({"result":status(status_value),"operation":operation}),
            ),
            action,
        ))
    }

    fn operation_value(&self, id: &str, digest_value: &str) -> Result<Option<Value>, FixtureError> {
        let row: Option<OperationRow> = self
            .connection
            .query_row(
                "SELECT operation_id,payload_digest,state,uncertainty_reason,witness_json,action_json,expected_boundary_json,original_context_json,ticket_json FROM operations WHERE operation_id=?1",
                params![id],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((
            operation_id,
            stored_digest,
            state,
            uncertainty,
            witness,
            action,
            boundary,
            context,
            ticket,
        )) = row
        else {
            return Ok(None);
        };
        if !digest_value.is_empty() && digest_value != stored_digest {
            return Err(FixtureError::Conflict);
        }
        let ticket_value = ticket.map_or(Ok(Value::Null), |text| {
            parse_value_no_duplicates(text.as_bytes())
        })?;
        let witness_value = witness.map_or(Ok(Value::Null), |text| {
            parse_value_no_duplicates(text.as_bytes())
        })?;
        Ok(Some(json!({
            "operation_id":operation_id,"state":state,"payload_digest":stored_digest,
            "original_context":parse_value_no_duplicates(context.as_bytes())?,
            "expected_boundary":parse_value_no_duplicates(boundary.as_bytes())?,
            "action":parse_value_no_duplicates(action.as_bytes())?,
            "ticket":ticket_value,"witness":witness_value,"uncertainty_reason":uncertainty,
            "created_at":FIXTURE_TIMESTAMP,"updated_at":FIXTURE_TIMESTAMP
        })))
    }

    fn receipt_count(&self) -> Result<usize, FixtureError> {
        let count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))
            .map_err(FixtureError::Sql)?;
        usize::try_from(count)
            .map_err(|_| FixtureError::Invalid("receipt count overflow".to_owned()))
    }

    fn current_fence_id(&self) -> Result<String, FixtureError> {
        self.connection
            .query_row(
                "SELECT host_fence_id FROM fence WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(FixtureError::Sql)?
            .ok_or(FixtureError::HostNotReady)
    }

    fn set_ticket_state(&self, operation_id: &str, state: &str) -> Result<(), FixtureError> {
        self.connection
            .execute(
                "UPDATE operations SET ticket_json=json_set(ticket_json,'$.state',?2),updated_at=?3 WHERE operation_id=?1",
                params![operation_id, state, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        Ok(())
    }

    fn quarantine_queued_operation(&mut self, operation_id: &str) -> Result<(), FixtureError> {
        // Keep the journal transition ahead of queue removal. If the process
        // fails between these statements, restart sees an UNKNOWN attempt and
        // can safely remove the leftover queue row without executing it.
        let transaction = self.connection.transaction().map_err(FixtureError::Sql)?;
        let changed = transaction
            .execute(
                "UPDATE operations SET state='UNKNOWN',uncertainty_reason='authority_rotated',ticket_json=json_set(ticket_json,'$.state','UNKNOWN'),updated_at=?2 WHERE operation_id=?1 AND state='MAY_HAVE_BEEN_DISPATCHED'",
                params![operation_id, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        if changed != 1 {
            return Err(FixtureError::Conflict);
        }
        transaction
            .execute(
                "DELETE FROM queue WHERE operation_id=?1",
                params![operation_id],
            )
            .map_err(FixtureError::Sql)?;
        transaction.commit().map_err(FixtureError::Sql)
    }

    #[allow(clippy::type_complexity)]
    fn validate_ticket_authority(&self, ticket: &Value) -> Result<(), FixtureError> {
        let lease: Option<(
            String,
            String,
            String,
            i64,
            String,
            String,
            String,
            i64,
            i64,
            i64,
        )> = self
            .connection
            .query_row(
                "SELECT deployment_id,instance_id,boot_id,lease_epoch,instance_incarnation,host_fence_id,fence_token,expires_tick,issued_tick,revoked FROM lease WHERE singleton=1",
                [],
                |row| Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                    row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?,
                )),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((
            deployment_id,
            instance_id,
            boot_id,
            lease_epoch,
            incarnation,
            fence_id,
            _token,
            expires_tick,
            _issued_tick,
            revoked,
        )) = lease
        else {
            return Err(FixtureError::HostNotReady);
        };
        if revoked != 0 || current_tick(&self.connection)? >= expires_tick {
            return Err(FixtureError::Stale("revoked lease"));
        }
        if field_string(ticket, "boot_id")? != boot_id
            || field_string(ticket, "instance_incarnation")? != incarnation
            || field_i64(ticket, "lease_epoch")? != lease_epoch
            || field_string(ticket, "host_fence_id")? != fence_id
        {
            return Err(FixtureError::Stale("lease"));
        }
        let current_fence = self.current_fence_id()?;
        if current_fence != fence_id {
            return Err(FixtureError::Stale("fence"));
        }
        let _ = (deployment_id, instance_id);
        Ok(())
    }

    fn validate_operation_ref_context(
        &self,
        id: &str,
        digest_value: &str,
        context: &Value,
    ) -> Result<(), FixtureError> {
        let stored: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT payload_digest,original_context_json FROM operations WHERE operation_id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((stored_digest, stored_context)) = stored else {
            return Ok(());
        };
        let supplied = bounded_json(context, 4096)?;
        if stored_digest != digest_value || stored_context != supplied {
            return Err(FixtureError::Conflict);
        }
        Ok(())
    }

    fn validate_operation_witness_consistency(
        &self,
        id: &str,
        payload_digest: &str,
        witness: &Value,
    ) -> Result<(), FixtureError> {
        validate_effect_witness(witness, id, payload_digest)?;
        let witness_text = bounded_json(witness, 4096)?;
        let stored_effect: Option<(String, String, String)> = self
            .connection
            .query_row(
                "SELECT payload_digest,witness_json,effect_digest FROM effects WHERE operation_id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((effect_digest, effect_witness, effect_hash)) = stored_effect else {
            return Err(FixtureError::Conflict);
        };
        if effect_digest != payload_digest
            || effect_witness != witness_text
            || effect_hash != field_string(witness, "effect_digest")?
        {
            return Err(FixtureError::Conflict);
        }
        if let Some(receipt_text) = self
            .connection
            .query_row(
                "SELECT receipt_json FROM receipts WHERE operation_id=?1",
                params![id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(FixtureError::Sql)?
        {
            let receipt: Value = parse_value_no_duplicates(receipt_text.as_bytes())?;
            validate_receipt(&receipt, witness, id, payload_digest)?;
        }
        Ok(())
    }
}

fn response_auth(kind: &str) -> (&'static str, &'static str) {
    match kind {
        "bootstrap_response" => ("gateway", "bootstrap"),
        "host_fence_response" => ("host", "host_fence"),
        "lease_acquire_response" => ("gateway", "lease_acquire"),
        "lease_renew_response" => ("gateway", "lease_renew"),
        "lease_revoke_response" => ("gateway", "lease_revoke"),
        "operation_intent_response" | "operation_dispatch_response" => {
            ("gateway", "operation_submit")
        }
        "operation_lookup_response" => ("operator", "recovery_read"),
        "operation_reconcile_response" => ("gateway", "recovery_reconcile"),
        "state_response"
        | "legal_actions_response"
        | "dispatch_action_response"
        | "wait_response"
        | "reobserve_response"
        | "recover_response" => ("host", "operation_submit"),
        _ => ("host", "recovery_read"),
    }
}

fn response_auth_checked(kind: &str) -> Option<(&'static str, &'static str)> {
    matches!(
        kind,
        "bootstrap_response"
            | "host_fence_response"
            | "lease_acquire_response"
            | "lease_renew_response"
            | "lease_revoke_response"
            | "operation_intent_response"
            | "operation_dispatch_response"
            | "operation_lookup_response"
            | "operation_reconcile_response"
    )
    .then(|| response_auth(kind))
}

fn request_capability(kind: &str) -> Option<&'static str> {
    match kind {
        "bootstrap_request" => Some("bootstrap"),
        "host_fence_request" => Some("host_fence"),
        "lease_acquire_request" => Some("lease_acquire"),
        "lease_renew_request" => Some("lease_renew"),
        "lease_revoke_request" => Some("lease_revoke"),
        "operation_intent_request" | "operation_dispatch_request" => Some("operation_submit"),
        "operation_lookup_request" => Some("recovery_read"),
        "operation_reconcile_request" => Some("recovery_reconcile"),
        _ => None,
    }
}

fn request_role(kind: &str) -> &'static str {
    match kind {
        "operation_lookup_request" => "operator",
        _ => "gateway",
    }
}

fn valid_role(value: &str) -> Result<(), FixtureError> {
    if matches!(
        value,
        "gateway" | "watchdog" | "harness" | "host" | "mod" | "operator"
    ) {
        Ok(())
    } else {
        Err(FixtureError::Invalid("actor role".to_owned()))
    }
}

fn valid_capability(value: &str) -> Result<(), FixtureError> {
    if matches!(
        value,
        "bootstrap"
            | "host_fence"
            | "lease_acquire"
            | "lease_renew"
            | "lease_revoke"
            | "operation_submit"
            | "recovery_read"
            | "recovery_reconcile"
    ) {
        Ok(())
    } else {
        Err(FixtureError::Forbidden)
    }
}

fn is_runtime_v3_kind(kind: &str) -> bool {
    matches!(
        kind,
        "state_request"
            | "state_response"
            | "legal_actions_request"
            | "legal_actions_response"
            | "dispatch_action_request"
            | "dispatch_action_response"
            | "wait_request"
            | "wait_response"
            | "reobserve_request"
            | "reobserve_response"
            | "recover_request"
            | "recover_response"
    )
}

fn valid_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    (value.len() == 20 || (value.len() >= 22 && value.len() <= 30))
        && bytes.len() >= 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes.ends_with(b"Z")
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && bytes[17..19].iter().all(u8::is_ascii_digit)
        && (value.len() == 20
            || (bytes[19] == b'.' && bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit)))
}

fn timestamp_for_tick(tick: i64) -> String {
    let total = tick.max(0);
    let hours = total / 3_600;
    let minutes = (total % 3_600) / 60;
    let seconds = total % 60;
    format!("2026-09-06T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn current_tick(connection: &Connection) -> Result<i64, FixtureError> {
    connection
        .query_row(
            "SELECT tick FROM fixture_clock WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(FixtureError::Sql)
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:/-".contains(&byte))
}

fn status(value: &str) -> Value {
    json!({"status":value,"retryable":false,"retry_after_seconds":null})
}

fn fence_json(boot: &Value, fence_id: &str, generation: i64) -> Value {
    json!({"host_fence_id":fence_id,"deployment_id":boot["deployment_id"],"instance_id":boot["instance_id"],"instance_incarnation":boot["instance_incarnation"],"boot_id":boot["boot_id"],"authority_generation":boot["authority_generation"],"fence_generation":generation,"created_at":FIXTURE_TIMESTAMP})
}

fn require_capability(frame: &Frame, expected: &str) -> Result<(), FixtureError> {
    if frame.auth.capability != expected {
        return Err(FixtureError::Forbidden);
    }
    Ok(())
}

fn valid_v4(value: &str) -> Result<(), FixtureError> {
    if value.len() != 36 || value != value.to_ascii_lowercase() {
        return Err(FixtureError::Invalid("UUIDv4".to_owned()));
    }
    let id = Uuid::parse_str(value).map_err(|_| FixtureError::Invalid("UUID".to_owned()))?;
    if id.get_version_num() != 4 {
        return Err(FixtureError::Invalid("UUIDv4".to_owned()));
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), FixtureError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(FixtureError::Invalid("SHA-256 digest".to_owned()));
    }
    Ok(())
}

fn field_string(value: &Value, name: &str) -> Result<String, FixtureError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| FixtureError::Invalid(format!("missing string field {name}")))
}

fn field_i64(value: &Value, name: &str) -> Result<i64, FixtureError> {
    value
        .get(name)
        .and_then(Value::as_i64)
        .ok_or_else(|| FixtureError::Invalid(format!("missing integer field {name}")))
}

fn bounded_json(value: &Value, limit: usize) -> Result<String, FixtureError> {
    let text =
        serde_json::to_string(value).map_err(|error| FixtureError::Json(error.to_string()))?;
    if text.len() > limit {
        return Err(FixtureError::Bounds("JSON payload"));
    }
    Ok(text)
}

fn object_fields(value: &Value, required: &[&str], allowed: &[&str]) -> Result<(), FixtureError> {
    let object = value
        .as_object()
        .ok_or_else(|| FixtureError::Invalid("object required".to_owned()))?;
    for name in required {
        if !object.contains_key(*name) {
            return Err(FixtureError::Invalid(format!("missing field {name}")));
        }
    }
    if object.keys().any(|name| !allowed.contains(&name.as_str())) {
        return Err(FixtureError::Invalid("unknown field".to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn fault_names_are_closed_and_bounded() {
        assert_eq!(
            FaultPoint::parse("after-mutation"),
            Some(FaultPoint::AfterMutation)
        );
        assert_eq!(FaultPoint::parse("delete-production"), None);
        assert_eq!(FaultPoint::AfterReceipt.as_str(), "after-receipt");
    }

    #[test]
    fn request_has_contract_digest_and_distinct_identities() {
        let first = Frame::request("stats", "recovery_read", json!({"ok":true}));
        let second = Frame::request("stats", "recovery_read", json!({"ok":true}));
        assert_eq!(first.schema_digest, RECOVERY_SCHEMA_DIGEST);
        assert_ne!(first.message_id, second.message_id);
        assert!(first.validate().is_ok());
    }

    #[test]
    fn digest_is_lower_hex_and_stable() {
        let value = digest("fixture");
        assert_eq!(value.len(), 64);
        assert!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert_eq!(value, digest("fixture"));
    }

    #[test]
    fn nested_duplicate_json_members_are_rejected() {
        let error = parse_value_no_duplicates(
            br#"{"outer":{"key":1,"key":2},"array":[{"same":true,"same":false}]}"#,
        )
        .expect_err("duplicate members must not use last-value-wins parsing");
        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    fn runtime_semantic_bounds_match_the_frozen_schema() {
        let empty_action = json!({
            "action_id":"",
            "action":{"kind":"end_turn"}
        });
        assert!(validate_runtime_legal_action(&empty_action).is_err());
        let empty_name = json!({
            "state_id":"state-1",
            "generation":0,
            "visible_seed":null,
            "player":{"hp":1,"max_hp":1,"energy":1,"gold":0,"hand":[],"deck":[],"discard":[],"exhaust":[]},
            "state":{"state":"combat","turn_index":0,"enemies":[{"enemy_id":"enemy-1","name":"","hp":0,"max_hp":0,"intent":{"kind":"unknown"}}]}
        });
        assert!(validate_runtime_observation(&empty_name).is_err());
    }

    #[test]
    fn database_sidecar_lock_rejects_a_second_owner() {
        let path =
            std::env::temp_dir().join(format!("watchdog-lock-test-{}.sqlite", Uuid::new_v4()));
        let owner = DurableHost::open(&path).expect("first owner opens");
        assert!(matches!(DurableHost::open(&path), Err(FixtureError::Busy)));
        drop(owner);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite-shm"));
        let _ = fs::remove_file(path.with_extension("sqlite.lock"));
    }
}
