//! Recovery operation journal and fault injection for the synthetic fixture.
//!
//! Owns the `FaultPoint` selector and `FaultController`, and the durable
//! recovery journal handlers: intent-before-effect admission, dispatch,
//! ticket issue, host tick, lookup and reconciliation.  Extracted verbatim
//! from `lib.rs` by the recovery-journal-and-fault-injection split (issue #76);
//! the crate root keeps the `DurableHost` struct definition and re-exports
//! `FaultPoint`.

use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    DurableHost, EFFECT_WITNESS_SOURCE, FIXTURE_TIMESTAMP, FixtureError, Frame, MAX_ACTION_BYTES,
    MAX_RECEIPTS, ResponseAction, bounded_json, current_tick, digest, field_i64, field_string,
    parse_value_no_duplicates, require_capability, status, valid_v4, validate_digest,
    validate_effect_witness, validate_lease_context, validate_operation_context,
    validate_operation_full, validate_operation_ref, validate_original_context, validate_receipt,
    validate_ticket,
};

/// Faults are selected only by the test server process.  No production API
/// imports this enum or exposes these controls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultPoint {
    None,
    BeforeAdmission,
    AfterAdmission,
    BeforeMutation,
    AfterMutation,
    BeforeReceipt,
    AfterReceipt,
    ResponseLoss,
    MalformedResponse,
}

impl FaultPoint {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "before-admission" => Some(Self::BeforeAdmission),
            "after-admission" => Some(Self::AfterAdmission),
            "before-mutation" => Some(Self::BeforeMutation),
            "after-mutation" => Some(Self::AfterMutation),
            "before-receipt" => Some(Self::BeforeReceipt),
            "after-receipt" => Some(Self::AfterReceipt),
            "response-loss" => Some(Self::ResponseLoss),
            "malformed-response" => Some(Self::MalformedResponse),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::BeforeAdmission => "before-admission",
            Self::AfterAdmission => "after-admission",
            Self::BeforeMutation => "before-mutation",
            Self::AfterMutation => "after-mutation",
            Self::BeforeReceipt => "before-receipt",
            Self::AfterReceipt => "after-receipt",
            Self::ResponseLoss => "response-loss",
            Self::MalformedResponse => "malformed-response",
        }
    }

    const fn is_crash(self) -> bool {
        matches!(
            self,
            Self::BeforeAdmission
                | Self::AfterAdmission
                | Self::BeforeMutation
                | Self::AfterMutation
                | Self::BeforeReceipt
                | Self::AfterReceipt
        )
    }
}

pub(crate) struct FaultController {
    point: FaultPoint,
    fired: bool,
}

impl FaultController {
    pub(crate) const fn new(point: FaultPoint) -> Self {
        Self {
            point,
            fired: false,
        }
    }

    pub(crate) fn at(&mut self, point: FaultPoint) -> Option<ResponseAction> {
        if self.fired || self.point != point {
            return None;
        }
        self.fired = true;
        if point.is_crash() {
            Some(ResponseAction::Crash)
        } else if point == FaultPoint::ResponseLoss {
            Some(ResponseAction::Drop)
        } else if point == FaultPoint::MalformedResponse {
            Some(ResponseAction::Malformed)
        } else {
            None
        }
    }
}

impl DurableHost {
    pub(crate) fn intent(
        &mut self,
        frame: &Frame,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "operation_submit")?;
        let lease = frame
            .payload
            .get("lease")
            .ok_or_else(|| FixtureError::Invalid("lease missing".to_owned()))?;
        self.validate_lease(lease)?;
        let operation = frame
            .payload
            .get("operation")
            .ok_or_else(|| FixtureError::Invalid("operation missing".to_owned()))?;
        validate_operation_full(operation)?;
        validate_operation_context(operation, lease)?;
        let id = field_string(operation, "operation_id")?;
        let digest_value = field_string(operation, "payload_digest")?;
        valid_v4(&id)?;
        validate_digest(&digest_value)?;
        let action = operation
            .get("action")
            .ok_or_else(|| FixtureError::Invalid("action missing".to_owned()))?;
        let action_json = bounded_json(action, MAX_ACTION_BYTES)?;
        let original_context = operation
            .get("original_context")
            .ok_or_else(|| FixtureError::Invalid("original context missing".to_owned()))?;
        let expected_boundary = operation
            .get("expected_boundary")
            .ok_or_else(|| FixtureError::Invalid("expected boundary missing".to_owned()))?;
        let context_json = bounded_json(original_context, 4096)?;
        let boundary_json = bounded_json(expected_boundary, 4096)?;
        let existing: Option<(String, String, String, String, String)> = self
            .connection
            .query_row(
                "SELECT payload_digest, state, original_context_json, action_json, expected_boundary_json FROM operations WHERE operation_id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        if let Some((
            existing_digest,
            state,
            existing_context,
            existing_action,
            existing_boundary,
        )) = existing
        {
            if existing_digest != digest_value
                || existing_context != context_json
                || existing_action != action_json
                || existing_boundary != boundary_json
            {
                return self.operation_response(frame, "CONFLICT", &id);
            }
            return self.operation_response(
                frame,
                if state == "SETTLED" {
                    "DUPLICATE"
                } else {
                    "INTENT_RECORDED"
                },
                &id,
            );
        }
        let now = FIXTURE_TIMESTAMP;
        self.connection
            .execute(
                "INSERT INTO operations(operation_id,payload_digest,deployment_id,instance_id,boot_id,instance_incarnation,lease_epoch,host_fence_id,state,uncertainty_reason,action_json,expected_boundary_json,original_context_json,ticket_json,witness_json,receipt_json,reconcile_strategy,created_at,updated_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'INTENT_RECORDED',NULL,?9,?10,?11,NULL,NULL,NULL,NULL,?12,?12)",
                params![
                    id,
                    digest_value,
                    field_string(lease, "deployment_id")?,
                    field_string(lease, "instance_id")?,
                    field_string(lease, "boot_id")?,
                    field_string(lease, "instance_incarnation")?,
                    field_i64(lease, "lease_epoch")?,
                    self.current_fence_id()?,
                    action_json,
                    boundary_json,
                    context_json,
                    now
                ],
            )
            .map_err(FixtureError::Sql)?;
        self.operation_response(frame, "INTENT_RECORDED", &id)
    }

    pub(crate) fn dispatch(
        &mut self,
        frame: &Frame,
        faults: &mut FaultController,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "operation_submit")?;
        let lease = frame
            .payload
            .get("lease")
            .ok_or_else(|| FixtureError::Invalid("lease missing".to_owned()))?;
        self.validate_lease(lease)?;
        let operation = frame
            .payload
            .get("operation")
            .ok_or_else(|| FixtureError::Invalid("operation missing".to_owned()))?;
        validate_operation_ref(operation)?;
        let id = field_string(operation, "operation_id")?;
        let digest_value = field_string(operation, "payload_digest")?;
        valid_v4(&id)?;
        validate_digest(&digest_value)?;
        let original_context = operation
            .get("original_context")
            .ok_or_else(|| FixtureError::Invalid("original context missing".to_owned()))?;
        validate_original_context(original_context)?;
        self.validate_operation_ref_context(&id, &digest_value, original_context)?;
        let state: Option<String> = self
            .connection
            .query_row(
                "SELECT state FROM operations WHERE operation_id = ?1 AND payload_digest = ?2",
                params![id, digest_value],
                |row| row.get(0),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some(state) = state else {
            return self.operation_response(frame, "NOT_FOUND", &id);
        };
        if state == "SETTLED" || state == "RECONCILED" {
            return self.operation_response(frame, "DUPLICATE", &id);
        }
        if state == "UNKNOWN" {
            return self.operation_response(frame, "UNKNOWN", &id);
        }
        if state == "MAY_HAVE_BEEN_DISPATCHED" {
            return self.operation_response(frame, "MAY_HAVE_BEEN_DISPATCHED", &id);
        }
        if state != "INTENT_RECORDED" {
            return self.operation_response(frame, "REJECTED", &id);
        }
        if self.receipt_count()? >= MAX_RECEIPTS {
            return self.operation_response(frame, "BOUNDS_EXCEEDED", &id);
        }
        if let Some(action) = faults.at(FaultPoint::BeforeAdmission) {
            return self.operation_response_with_action(frame, "UNKNOWN", &id, action);
        }
        let (ticket, ticket_expires_tick) = self.issue_ticket(&id, &digest_value, lease)?;
        let transaction = self.connection.transaction().map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE operations SET state='MAY_HAVE_BEEN_DISPATCHED',ticket_json=?2,ticket_expires_tick=?3,updated_at=?4 WHERE operation_id=?1",
                params![id, ticket.to_string(), ticket_expires_tick, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "INSERT INTO queue(operation_id,ticket_json,enqueued_at) VALUES(?1,?2,?3)",
                params![id, ticket.to_string(), FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        transaction.commit().map_err(FixtureError::Sql)?;
        if let Some(action) = faults.at(FaultPoint::AfterAdmission) {
            return self.operation_response_with_action(
                frame,
                "MAY_HAVE_BEEN_DISPATCHED",
                &id,
                action,
            );
        }
        self.operation_response(frame, "MAY_HAVE_BEEN_DISPATCHED", &id)
    }

    pub(crate) fn issue_ticket(
        &self,
        operation_id: &str,
        digest_value: &str,
        lease: &Value,
    ) -> Result<(Value, i64), FixtureError> {
        validate_lease_context(lease)?;
        let fence_id = self.current_fence_id()?;
        let (expires_at, expires_tick): (String, i64) = self
            .connection
            .query_row(
                "SELECT expires_at,expires_tick FROM lease WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(FixtureError::Sql)?;
        let ticket_id = Uuid::new_v4().to_string();
        Ok((
            json!({
                "ticket_id": ticket_id, "operation_id": operation_id, "payload_digest": digest_value,
                "boot_id": lease["boot_id"], "instance_incarnation": lease["instance_incarnation"],
                "lease_epoch": lease["lease_epoch"], "host_fence_id": fence_id,
                "state": "ISSUED", "issued_at": FIXTURE_TIMESTAMP, "expires_at": expires_at
            }),
            expires_tick,
        ))
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn tick(
        &mut self,
        frame: &Frame,
        faults: &mut FaultController,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "recovery_reconcile")?;
        let id = frame
            .payload
            .get("operation_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let Some(id) = id else {
            return Err(FixtureError::Invalid("operation_id missing".to_owned()));
        };
        let queued: Option<String> = self
            .connection
            .query_row(
                "SELECT ticket_json FROM queue WHERE operation_id=?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some(ticket_json) = queued else {
            return self.operation_response(frame, "NOT_FOUND", &id);
        };
        let ticket: Value = parse_value_no_duplicates(ticket_json.as_bytes())?;
        let operation_row: Option<(String, String, String, Option<String>, i64)> = self
            .connection
            .query_row(
                "SELECT payload_digest,state,original_context_json,witness_json,ticket_expires_tick FROM operations WHERE operation_id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((payload_digest, state, context_json, witness_json, ticket_expires_tick)) =
            operation_row
        else {
            return self.operation_response(frame, "NOT_FOUND", &id);
        };
        if state == "SETTLED" || state == "RECONCILED" {
            self.connection
                .execute("DELETE FROM queue WHERE operation_id=?1", params![id])
                .map_err(FixtureError::Sql)?;
            return self.operation_response(frame, "DUPLICATE", &id);
        }
        if witness_json.is_some() || state == "UNKNOWN" {
            // A durable witness is the admission boundary for at-most-once
            // execution. A retry can only report uncertainty and reconcile;
            // it may never manufacture a second witness.
            self.connection
                .execute("DELETE FROM queue WHERE operation_id=?1", params![id])
                .map_err(FixtureError::Sql)?;
            self.set_ticket_state(&id, "UNKNOWN")?;
            return self.operation_response(frame, "UNKNOWN", &id);
        }
        if state != "MAY_HAVE_BEEN_DISPATCHED" {
            return self.operation_response(frame, "REJECTED", &id);
        }
        // The admission ticket carries an immutable deadline. Lease renewal
        // extends only the current lease; it must never extend an already
        // admitted operation's execution window.
        if current_tick(&self.connection)? >= ticket_expires_tick {
            self.quarantine_queued_operation(&id)?;
            return self.operation_response(frame, "LEASE_EXPIRED", &id);
        }
        validate_ticket(&ticket, &id, &payload_digest, &context_json)?;
        if let Err(error) = self.validate_ticket_authority(&ticket) {
            // A queued ticket crossed an authority boundary. Preserve the
            // attempt as UNKNOWN before removing its executable queue entry;
            // it may never be represented as a clean rejection.
            self.quarantine_queued_operation(&id)?;
            return self.operation_response(frame, error.status(), &id);
        }
        if let Some(action) = faults.at(FaultPoint::BeforeMutation) {
            return self.operation_response_with_action(
                frame,
                "MAY_HAVE_BEEN_DISPATCHED",
                &id,
                action,
            );
        }
        let operation: (String, String, String) = self
            .connection
            .query_row(
                "SELECT payload_digest, action_json, expected_boundary_json FROM operations WHERE operation_id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(FixtureError::Sql)?;
        let effect_digest = digest(&format!("effect:{id}:{}", operation.0));
        let boundary: Value = parse_value_no_duplicates(operation.2.as_bytes())?;
        let state_id = field_string(&boundary, "state_id")?;
        let generation = field_i64(&boundary, "generation")?;
        valid_v4(&state_id)?;
        let witness = json!({
            "witness_id": Uuid::new_v4().to_string(), "operation_id": id,
            "payload_digest": operation.0, "boot_id": ticket["boot_id"],
            "instance_incarnation": ticket["instance_incarnation"],
            "host_fence_id": ticket["host_fence_id"], "source": EFFECT_WITNESS_SOURCE,
            "state_id": state_id, "generation": generation,
            "effect_digest": effect_digest, "observed_at": FIXTURE_TIMESTAMP
        });
        validate_effect_witness(&witness, &id, &operation.0)?;
        let witness_text = witness.to_string();
        let transaction = self.connection.transaction().map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "INSERT INTO effects(operation_id,payload_digest,witness_json,effect_digest,created_at) VALUES(?1,?2,?3,?4,?5)",
                params![id, operation.0, witness_text, witness["effect_digest"].as_str(), FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        let operation_changed = transaction
            .execute(
                "UPDATE operations SET state='UNKNOWN',uncertainty_reason='receipt_missing',witness_json=?2,ticket_json=json_set(ticket_json,'$.state','EFFECT_WITNESS_RECORDED'),updated_at=?3 WHERE operation_id=?1",
                params![id, witness_text, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        if operation_changed != 1 {
            return Err(FixtureError::Conflict);
        }
        transaction.commit().map_err(FixtureError::Sql)?;
        if let Some(action) = faults.at(FaultPoint::AfterMutation) {
            return self.operation_response_with_action(frame, "UNKNOWN", &id, action);
        }
        if let Some(action) = faults.at(FaultPoint::BeforeReceipt) {
            return self.operation_response_with_action(frame, "UNKNOWN", &id, action);
        }
        let receipt = json!({
            "operation_id": id, "payload_digest": operation.0,
            "status": "settled", "effect_witness": witness
        });
        validate_receipt(&receipt, &witness, &id, &operation.0)?;
        let receipt_changed = self
            .connection
            .execute(
                "INSERT INTO receipts(operation_id,receipt_json,created_at) VALUES(?1,?2,?3)",
                params![id, receipt.to_string(), FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        if receipt_changed != 1 {
            return Err(FixtureError::Conflict);
        }
        let operation_changed = self
            .connection
            .execute("UPDATE operations SET state='SETTLED',uncertainty_reason=NULL,receipt_json=?2,ticket_json=json_set(ticket_json,'$.state','SETTLED'),updated_at=?3 WHERE operation_id=?1", params![id, receipt.to_string(), FIXTURE_TIMESTAMP])
            .map_err(FixtureError::Sql)?;
        if operation_changed != 1 {
            return Err(FixtureError::Conflict);
        }
        self.connection
            .execute("DELETE FROM queue WHERE operation_id=?1", params![id])
            .map_err(FixtureError::Sql)?;
        if let Some(action) = faults.at(FaultPoint::AfterReceipt) {
            return self.operation_response_with_action(frame, "SETTLED", &id, action);
        }
        self.operation_response(frame, "SETTLED", &id)
    }

    pub(crate) fn lookup(
        &mut self,
        frame: &Frame,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "recovery_read")?;
        let operation = frame
            .payload
            .get("operation")
            .ok_or_else(|| FixtureError::Invalid("operation missing".to_owned()))?;
        let id = field_string(operation, "operation_id")?;
        let digest_value = field_string(operation, "payload_digest")?;
        let original_context = operation
            .get("original_context")
            .ok_or_else(|| FixtureError::Invalid("original context missing".to_owned()))?;
        validate_original_context(original_context)?;
        self.validate_operation_ref_context(&id, &digest_value, original_context)?;
        let response = self.operation_value(&id, &digest_value)?;
        let (status_value, value) = match response {
            None => ("NOT_FOUND".to_owned(), Value::Null),
            Some(value) => (
                value["state"].as_str().unwrap_or("UNKNOWN").to_owned(),
                value,
            ),
        };
        Ok((
            frame.response("operation_lookup_response", json!({
                "result": status(&status_value), "operation": value, "mutation_authorized": false
            })),
            ResponseAction::Send,
        ))
    }

    pub(crate) fn reconcile(
        &mut self,
        frame: &Frame,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "recovery_reconcile")?;
        let strategy = frame
            .payload
            .get("strategy")
            .and_then(Value::as_str)
            .ok_or_else(|| FixtureError::Invalid("strategy missing".to_owned()))?;
        if !matches!(strategy, "reobserve" | "receipt_lookup" | "quarantine") {
            return Err(FixtureError::Invalid(
                "unsupported reconciliation strategy".to_owned(),
            ));
        }
        let current_fence = frame
            .payload
            .get("current_fence")
            .ok_or_else(|| FixtureError::Invalid("current fence missing".to_owned()))?;
        self.validate_current_fence(current_fence)?;
        let operation = frame
            .payload
            .get("operation")
            .ok_or_else(|| FixtureError::Invalid("operation missing".to_owned()))?;
        let id = field_string(operation, "operation_id")?;
        let digest_value = field_string(operation, "payload_digest")?;
        let original_context = operation
            .get("original_context")
            .ok_or_else(|| FixtureError::Invalid("original context missing".to_owned()))?;
        validate_original_context(original_context)?;
        self.validate_operation_ref_context(&id, &digest_value, original_context)?;
        let Some(value) = self.operation_value(&id, &digest_value)? else {
            return Ok((
                frame.response(
                    "operation_reconcile_response",
                    json!({"result":status("NOT_FOUND"),"operation":null,"witness":null}),
                ),
                ResponseAction::Send,
            ));
        };
        let witness = value.get("witness").cloned().unwrap_or(Value::Null);
        if witness.is_null() {
            return Ok((
                frame.response(
                    "operation_reconcile_response",
                    json!({"result":status("UNKNOWN"),"operation":value,"witness":null}),
                ),
                ResponseAction::Send,
            ));
        }
        self.validate_operation_witness_consistency(&id, &digest_value, &witness)?;
        let state = value["state"].as_str().unwrap_or("UNKNOWN");
        if state == "SETTLED" || state == "RECONCILED" {
            return Ok((
                frame.response(
                    "operation_reconcile_response",
                    json!({"result":status("DUPLICATE"),"operation":value,"witness":witness}),
                ),
                ResponseAction::Send,
            ));
        }
        if strategy == "quarantine" {
            return Ok((
                frame.response(
                    "operation_reconcile_response",
                    json!({"result":status("UNKNOWN"),"operation":value,"witness":witness}),
                ),
                ResponseAction::Send,
            ));
        }
        let source = witness.get("source").and_then(Value::as_str);
        let strategy_matches = match strategy {
            // A receipt lookup may settle only when the durable effect witness
            // is host-generated; it cannot invent a receipt or a new witness.
            "receipt_lookup" => source == Some(EFFECT_WITNESS_SOURCE),
            // Reobserve is the only strategy allowed to consume an explicitly
            // authoritative observation witness.
            "reobserve" => source == Some("authoritative_reobserve"),
            _ => false,
        };
        if !strategy_matches {
            return Ok((
                frame.response(
                    "operation_reconcile_response",
                    json!({"result":status("UNKNOWN"),"operation":value,"witness":witness}),
                ),
                ResponseAction::Send,
            ));
        }
        self.connection
            .execute("UPDATE operations SET state='RECONCILED',uncertainty_reason=NULL,reconcile_strategy=?2,ticket_json=json_set(ticket_json,'$.state','SETTLED'),updated_at=?3 WHERE operation_id=?1", params![id, strategy, FIXTURE_TIMESTAMP])
            .map_err(FixtureError::Sql)?;
        let operation = self.operation_value(&id, &digest_value)?.unwrap_or(value);
        Ok((
            frame.response(
                "operation_reconcile_response",
                json!({"result":status("RECONCILED"),"operation":operation,"witness":witness}),
            ),
            ResponseAction::Send,
        ))
    }
}
