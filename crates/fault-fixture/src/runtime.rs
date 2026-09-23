//! Runtime-v3 types, frozen response builders and request execution.
//!
//! Owns `RuntimeSession`/`RuntimeOperation`, the frozen runtime-v3 response
//! builders and the v3 request path (frame handling, dispatch, wait and
//! recover).  Extracted verbatim from `lib.rs` by the runtime-v3-execution-
//! and-persistence split (issue #77); the durable operation/session store
//! lives in `runtime_store`.

use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};

use crate::server::response_kind;
use crate::wire::parse_value_no_duplicates;
use crate::{
    DurableHost, FaultController, FixtureError, Frame, MAX_ACTION_BYTES, MAX_RUNTIME_INTEGER,
    MAX_RUNTIME_OPERATIONS, RUNTIME_V3_SCHEMA_DIGEST, ResponseAction, bounded_json, current_tick,
    field_i64, field_string, sha256_hex, valid_identity, validate_runtime_v3_envelope,
};

#[derive(Clone, Debug)]
pub(crate) struct RuntimeSession {
    pub(crate) instance_id: String,
    pub(crate) session_id: String,
    pub(crate) lease_id: String,
    pub(crate) lease_epoch: i64,
    pub(crate) state_id: String,
    pub(crate) generation: i64,
    pub(crate) observation_json: String,
    pub(crate) legal_actions_json: String,
    pub(crate) last_operation_id: Option<String>,
    pub(crate) last_action_id: Option<String>,
    pub(crate) stopped: bool,
    pub(crate) updated_at: String,
}

/// Durable runtime-v3 admission state.  The runtime adapter deliberately uses
/// a separate journal from the recovery sideband operation table: a gameplay
/// request does not carry the sideband's boot/original-context envelope, but it
/// still needs an operation identity, immutable pre-state, and an at-most-once
/// drain boundary.
#[derive(Clone, Debug)]
pub(crate) struct RuntimeOperation {
    pub(crate) operation_id: String,
    pub(crate) instance_id: String,
    pub(crate) session_id: String,
    pub(crate) lease_id: String,
    pub(crate) lease_epoch: i64,
    pub(crate) action_json: String,
    pub(crate) action_digest: String,
    pub(crate) pre_state_id: String,
    pub(crate) pre_generation: i64,
    pub(crate) status: String,
    pub(crate) witness_json: Option<String>,
    pub(crate) result_json: Option<String>,
}

pub(crate) fn runtime_provenance() -> Value {
    json!({
        "artifact":"sts2-protocol/runtime-v3-gameplay",
        "source":"schemas/runtime-v3-gameplay.schema.json",
        "generator":"hand-authored"
    })
}

pub(crate) fn synthetic_observation(
    state_id: &str,
    generation: i64,
) -> Result<Value, FixtureError> {
    if !valid_identity(state_id) {
        return Err(FixtureError::Invalid("runtime state identity".to_owned()));
    }
    Ok(json!({
        "state_id":state_id, "generation":generation, "visible_seed":"fixture-seed-1",
        "player":{"hp":50,"max_hp":50,"energy":3,"gold":99,"hand":[],"deck":[],"discard":[],"exhaust":[]},
        "state":{"state":"combat","turn_index":1,"enemies":[]}
    }))
}

pub(crate) fn synthetic_legal_actions() -> Value {
    json!([
        {"action_id":"action-end-turn","action":{"kind":"end_turn"}},
        {"action_id":"action-start-run","action":{"kind":"start_run","character_id":"ironclad"}},
        {"action_id":"action-select-map-node","action":{"kind":"select_map_node","node_id":"node-1"}},
        {"action_id":"action-play-card","action":{"kind":"play_card","card_id":"strike","target_id":null}},
        {"action_id":"action-choose-reward","action":{"kind":"choose_reward","reward_id":"reward-1"}},
        {"action_id":"action-shop-purchase","action":{"kind":"shop_purchase","item_id":"item-1"}},
        {"action_id":"action-shop-remove","action":{"kind":"shop_remove","card_id":"card-1"}},
        {"action_id":"action-event-choice","action":{"kind":"event_choice","choice_id":"choice-1"}}
    ])
}

pub(crate) fn runtime_base(request: &Value, kind: &str, state: &RuntimeSession) -> Value {
    json!({
        "protocol_version":"runtime-v3-gameplay", "schema_digest":RUNTIME_V3_SCHEMA_DIGEST,
        "provenance":runtime_provenance(), "correlation_id":request["correlation_id"],
        "instance_id":request["instance_id"], "session_id":request["session_id"],
        "lease_id":request["lease_id"], "lease_epoch":request["lease_epoch"],
        "generation":state.generation, "kind":kind, "state_id":Value::Null,
        "operation_id":Value::Null, "observation":Value::Null, "legal_actions":Value::Null,
        "action":Value::Null, "status":Value::Null, "transition":Value::Null,
        "error_code":Value::Null, "wait_for_millis":Value::Null,
        "wait_outcome":Value::Null, "recovery":Value::Null
    })
}

pub(crate) fn stored_runtime_value(text: &str) -> Result<Value, FixtureError> {
    parse_value_no_duplicates(text.as_bytes())
}

pub(crate) fn runtime_observation_response(
    request: &Value,
    state: &RuntimeSession,
) -> Result<Value, FixtureError> {
    let mut response = runtime_base(request, "state_response", state);
    response["state_id"] = json!(state.state_id);
    response["observation"] = stored_runtime_value(&state.observation_json)?;
    response["legal_actions"] = stored_runtime_value(&state.legal_actions_json)?;
    Ok(response)
}

pub(crate) fn runtime_legal_actions_response(
    request: &Value,
    state: &RuntimeSession,
) -> Result<Value, FixtureError> {
    let mut response = runtime_base(request, "legal_actions_response", state);
    response["state_id"] = json!(state.state_id);
    response["legal_actions"] = stored_runtime_value(&state.legal_actions_json)?;
    Ok(response)
}

pub(crate) fn runtime_reobserve_response(
    request: &Value,
    state: &RuntimeSession,
) -> Result<Value, FixtureError> {
    let mut response = runtime_base(request, "reobserve_response", state);
    response["state_id"] = json!(state.state_id);
    response["observation"] = stored_runtime_value(&state.observation_json)?;
    response["legal_actions"] = stored_runtime_value(&state.legal_actions_json)?;
    Ok(response)
}

pub(crate) fn runtime_rejected_response(
    request: &Value,
    state: &RuntimeSession,
    operation_id: &str,
    error_code: &str,
) -> Result<Value, FixtureError> {
    let mut response = runtime_base(request, "dispatch_action_response", state);
    response["state_id"] = json!(state.state_id);
    response["operation_id"] = json!(operation_id);
    response["observation"] = stored_runtime_value(&state.observation_json)?;
    response["legal_actions"] = stored_runtime_value(&state.legal_actions_json)?;
    response["status"] = json!("rejected");
    response["error_code"] = json!(error_code);
    Ok(response)
}

pub(crate) fn runtime_error_response(
    request: &Value,
    request_kind: &str,
    error_code: &str,
    generation: i64,
    state: &RuntimeSession,
) -> Value {
    let response_kind = response_kind(request_kind);
    let mut response = runtime_base(request, &response_kind, state);
    response["generation"] = json!(generation);
    if matches!(
        request_kind,
        "dispatch_action_request" | "wait_request" | "recover_request"
    ) {
        let recovery_operation = request
            .get("recovery")
            .and_then(|recovery| recovery.get("operation_id"))
            .filter(|operation_id| !operation_id.is_null())
            .cloned();
        response["operation_id"] = request
            .get("operation_id")
            .filter(|operation_id| !operation_id.is_null())
            .cloned()
            .or(recovery_operation)
            .unwrap_or_else(|| json!(format!("recovery-{}", state.session_id)));
    }
    response["status"] = json!("unknown");
    response["error_code"] = json!(error_code);
    if request_kind == "wait_request" {
        response["wait_outcome"] = json!("recovery_required");
    }
    response
}

pub(crate) fn runtime_recovery_response(
    request: &Value,
    state: &RuntimeSession,
    status_value: &str,
    observation: Value,
    legal_actions: Value,
    transition: Value,
    error_code: Value,
) -> Value {
    let mut response = runtime_base(request, "recover_response", state);
    response["operation_id"] = request["recovery"]["operation_id"].clone();
    if response["operation_id"].is_null() {
        response["operation_id"] = json!(format!("recovery-{}", state.session_id));
    }
    response["state_id"] = json!(state.state_id);
    response["observation"] = observation;
    response["legal_actions"] = legal_actions;
    response["status"] = json!(status_value);
    response["transition"] = transition;
    response["error_code"] = error_code;
    response
}

pub(crate) fn runtime_accepted_response(
    request: &Value,
    state: &RuntimeSession,
    operation_id: &str,
) -> Result<Value, FixtureError> {
    let mut response = runtime_base(request, "dispatch_action_response", state);
    response["state_id"] = json!(state.state_id);
    response["operation_id"] = json!(operation_id);
    response["observation"] = stored_runtime_value(&state.observation_json)?;
    response["legal_actions"] = stored_runtime_value(&state.legal_actions_json)?;
    response["status"] = json!("accepted");
    Ok(response)
}

impl DurableHost {
    pub(crate) fn v3_handle_frame(
        &mut self,
        frame: &Frame,
        _faults: &mut FaultController,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        validate_runtime_v3_envelope(&frame.kind, &frame.payload)?;
        let response = self.v3_handle_value(&frame.payload)?;
        Ok((
            frame.response(&response_kind(&frame.kind), response),
            ResponseAction::Send,
        ))
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn v3_handle_value(&mut self, request: &Value) -> Result<Value, FixtureError> {
        let kind = field_string(request, "kind")?;
        let instance_id = field_string(request, "instance_id")?;
        let session_id = field_string(request, "session_id")?;
        let lease_id = field_string(request, "lease_id")?;
        let lease_epoch = field_i64(request, "lease_epoch")?;
        let request_generation = field_i64(request, "generation")?;
        let _correlation_id = field_string(request, "correlation_id")?;
        let authority_current =
            self.runtime_authority_current(&instance_id, &lease_id, lease_epoch)?;
        let mut state = self.runtime_session(&session_id)?;
        if state.is_none() {
            if !authority_current {
                return Err(FixtureError::Stale("lease"));
            }
            // A stopped session can retain an UNKNOWN operation.  It is still
            // an instance-wide mutation barrier: do not create a replacement
            // session that could admit a second action before the original
            // effect is authoritatively settled or reconciled.
            if let Some(unresolved) =
                self.unresolved_runtime_operation_for_instance(&instance_id)?
            {
                let historical_state = self
                    .runtime_session(&unresolved.session_id)?
                    .ok_or(FixtureError::HostNotReady)?;
                if kind == "dispatch_action_request" {
                    let operation_id = field_string(request, "operation_id")?;
                    return runtime_rejected_response(
                        request,
                        &historical_state,
                        &operation_id,
                        "active_session",
                    );
                }
                return Err(FixtureError::Conflict);
            }
            if let Some(active_state) = self.active_runtime_session_for_instance(&instance_id)? {
                if kind == "dispatch_action_request" {
                    let operation_id = field_string(request, "operation_id")?;
                    return runtime_rejected_response(
                        request,
                        &active_state,
                        &operation_id,
                        "active_session",
                    );
                }
                return Err(FixtureError::Conflict);
            }
            state = Some(self.create_runtime_session(
                &instance_id,
                &session_id,
                &lease_id,
                lease_epoch,
                request.get("state_id").and_then(Value::as_str),
                request_generation,
            )?);
        }
        let mut state = state.ok_or(FixtureError::HostNotReady)?;
        if !authority_current && kind == "dispatch_action_request" {
            let operation_id = field_string(request, "operation_id")?;
            if self.mark_runtime_operation_unknown_for_context(
                &operation_id,
                &instance_id,
                &session_id,
                &lease_id,
                lease_epoch,
            )? {
                return Ok(runtime_error_response(
                    request,
                    &kind,
                    "stale_lease",
                    state.generation,
                    &state,
                ));
            }
            return runtime_rejected_response(request, &state, &operation_id, "stale_lease");
        }
        // A replacement authority may finish recovery for a historical
        // session, but it must not rewrite that session's lease identity or
        // use its stale credentials for a new mutation. `v3_recover_value`
        // only marks a proved historical operation reconciled and retains the
        // operation/session rows as written under the old authority.
        if authority_current
            && kind == "recover_request"
            && request["recovery"]["kind"].as_str() == Some("reconcile")
            && (state.instance_id != instance_id
                || state.lease_id != lease_id
                || state.lease_epoch != lease_epoch)
        {
            return self.v3_recover_value(request, &mut state);
        }
        if !authority_current
            && (kind == "wait_request"
                || (kind == "recover_request"
                    && matches!(
                        request["recovery"]["kind"].as_str(),
                        Some("release_lease" | "stop_episode" | "reconcile")
                    )))
        {
            if kind == "wait_request" {
                let operation_id = field_string(request, "operation_id")?;
                self.mark_runtime_operation_unknown_for_context(
                    &operation_id,
                    &instance_id,
                    &session_id,
                    &lease_id,
                    lease_epoch,
                )?;
            } else if let Some(operation_id) = request["recovery"]["operation_id"].as_str() {
                self.mark_runtime_operation_unknown_for_context(
                    operation_id,
                    &instance_id,
                    &session_id,
                    &lease_id,
                    lease_epoch,
                )?;
            }
            return Ok(runtime_error_response(
                request,
                &kind,
                "stale_lease",
                state.generation,
                &state,
            ));
        }
        if state.instance_id != instance_id
            || state.lease_id != lease_id
            || state.lease_epoch != lease_epoch
        {
            // The frozen runtime-v3 schema has no error form for read
            // responses.  Reads carry no mutation authority, so return the
            // current bounded observation while all mutating requests remain
            // explicitly unknown and require recovery.
            return match kind.as_str() {
                "state_request" => runtime_observation_response(request, &state),
                "legal_actions_request" => runtime_legal_actions_response(request, &state),
                "reobserve_request" => runtime_reobserve_response(request, &state),
                _ => Ok(runtime_error_response(
                    request,
                    &kind,
                    "stale_lease",
                    state.generation,
                    &state,
                )),
            };
        }
        if state.stopped {
            // The frozen contract has no error form for read responses.  A
            // stopped episode may still be inspected, and an explicit
            // reconcile request must be able to examine durable evidence;
            // only new execution/wait authority is refused.
            return match kind.as_str() {
                "state_request" => runtime_observation_response(request, &state),
                "legal_actions_request" => runtime_legal_actions_response(request, &state),
                "reobserve_request" => runtime_reobserve_response(request, &state),
                "recover_request" => self.v3_recover_value(request, &mut state),
                _ => Ok(runtime_error_response(
                    request,
                    &kind,
                    "episode_stopped",
                    state.generation,
                    &state,
                )),
            };
        }
        match kind.as_str() {
            "state_request" => runtime_observation_response(request, &state),
            "legal_actions_request" => runtime_legal_actions_response(request, &state),
            "reobserve_request" => runtime_reobserve_response(request, &state),
            "dispatch_action_request" => self.v3_dispatch_value(request, &mut state),
            "wait_request" => self.v3_wait_value(request, &mut state),
            "recover_request" => self.v3_recover_value(request, &mut state),
            _ => Err(FixtureError::Invalid(
                "unsupported runtime-v3 kind".to_owned(),
            )),
        }
    }

    pub(crate) fn runtime_authority_current(
        &self,
        instance_id: &str,
        lease_id: &str,
        lease_epoch: i64,
    ) -> Result<bool, FixtureError> {
        // Both transports hold the single DurableHost mutex across this check
        // and admission/execution. Runtime session identifiers are correlation,
        // not an independent source of mutation authority.
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM lease l JOIN fence f
                 ON l.deployment_id=f.deployment_id AND l.instance_id=f.instance_id
                 AND l.boot_id=f.boot_id AND l.instance_incarnation=f.instance_incarnation
                 AND l.host_fence_id=f.host_fence_id
                 WHERE l.singleton=1 AND f.singleton=1 AND l.instance_id=?1
                 AND l.lease_id=?2 AND l.lease_epoch=?3 AND l.revoked=0
                 AND l.expires_tick>?4 AND f.authority_generation BETWEEN 1 AND ?5
                 AND f.fence_generation=f.authority_generation
                 AND f.authority_state='READY')",
                params![
                    instance_id,
                    lease_id,
                    lease_epoch,
                    current_tick(&self.connection)?,
                    MAX_RUNTIME_INTEGER
                ],
                |row| row.get(0),
            )
            .map_err(FixtureError::Sql)
    }

    pub(crate) fn v3_dispatch_value(
        &mut self,
        request: &Value,
        state: &mut RuntimeSession,
    ) -> Result<Value, FixtureError> {
        let requested_generation = field_i64(request, "generation")?;
        let requested_state = field_string(request, "state_id")?;
        let operation_id = field_string(request, "operation_id")?;
        let action = request
            .get("action")
            .ok_or_else(|| FixtureError::Invalid("action missing".to_owned()))?;
        let action_json = bounded_json(action, MAX_ACTION_BYTES)?;
        let action_digest = sha256_hex(action_json.as_bytes());
        if let Some(existing) = self.runtime_operation(&operation_id)? {
            if existing.instance_id != state.instance_id
                || existing.session_id != state.session_id
                || existing.lease_id != state.lease_id
                || existing.lease_epoch != state.lease_epoch
            {
                return runtime_rejected_response(
                    request,
                    state,
                    &operation_id,
                    "operation_conflict",
                );
            }
            if existing.action_digest != action_digest || existing.action_json != action_json {
                return runtime_rejected_response(
                    request,
                    state,
                    &operation_id,
                    "operation_conflict",
                );
            }
            return self.runtime_operation_response(request, state, &existing);
        }

        if requested_generation != state.generation || requested_state != state.state_id {
            return runtime_rejected_response(request, state, &operation_id, "stale_generation");
        }
        let legal_actions = stored_runtime_value(&state.legal_actions_json)?;
        if !legal_actions
            .as_array()
            .is_some_and(|actions| actions.iter().any(|candidate| candidate == action))
        {
            return runtime_rejected_response(request, state, &operation_id, "illegal_action");
        }

        // A session admits at most one unresolved operation.  In particular,
        // a changed action id cannot leapfrog a queued or unknown operation.
        if self
            .active_runtime_operation(&state.session_id, None)?
            .is_some()
        {
            return runtime_rejected_response(request, state, &operation_id, "active_operation");
        }

        // The session-local check above is not sufficient after a stopped
        // session is replaced.  Retain the instance-wide barrier across every
        // session, while allowing an exact operation-id replay to take the
        // idempotent path above.
        if let Some(unresolved) =
            self.unresolved_runtime_operation_for_instance(&state.instance_id)?
            && unresolved.operation_id != operation_id
        {
            return runtime_rejected_response(request, state, &operation_id, "active_session");
        }

        // Runtime history is bounded by admission backpressure rather than
        // archival or eviction. This keeps unresolved operations and every
        // historical operation-id tombstone available for recovery/dedup;
        // archival would require a broader contract than this fixture owns.
        if self.runtime_operation_count()? >= MAX_RUNTIME_OPERATIONS {
            return runtime_rejected_response(request, state, &operation_id, "runtime_capacity");
        }

        let operation = RuntimeOperation {
            operation_id: operation_id.clone(),
            instance_id: state.instance_id.clone(),
            session_id: state.session_id.clone(),
            lease_id: state.lease_id.clone(),
            lease_epoch: state.lease_epoch,
            action_json,
            action_digest,
            pre_state_id: state.state_id.clone(),
            pre_generation: state.generation,
            status: "ADMITTED".to_owned(),
            witness_json: None,
            result_json: None,
        };
        self.insert_runtime_operation(&operation)?;
        runtime_accepted_response(request, state, &operation_id)
    }

    pub(crate) fn v3_wait_value(
        &mut self,
        request: &Value,
        state: &mut RuntimeSession,
    ) -> Result<Value, FixtureError> {
        let operation_id = field_string(request, "operation_id")?;
        let Some(operation) = self.runtime_operation(&operation_id)? else {
            return Ok(runtime_error_response(
                request,
                "wait_request",
                "operation_not_found",
                state.generation,
                state,
            ));
        };
        if operation.instance_id != state.instance_id
            || operation.session_id != state.session_id
            || operation.lease_id != state.lease_id
            || operation.lease_epoch != state.lease_epoch
        {
            return Ok(runtime_error_response(
                request,
                "wait_request",
                "stale_lease",
                state.generation,
                state,
            ));
        }
        let result = self.drain_runtime_operation(request, state, &operation)?;
        let mut response = result;
        response["kind"] = json!("wait_response");
        if response["status"] == "settled" {
            response["wait_outcome"] = json!("successor");
        }
        Ok(response)
    }

    pub(crate) fn v3_recover_value(
        &mut self,
        request: &Value,
        state: &mut RuntimeSession,
    ) -> Result<Value, FixtureError> {
        let recovery = request
            .get("recovery")
            .ok_or_else(|| FixtureError::Invalid("recovery missing".to_owned()))?;
        let recovery_kind = field_string(recovery, "kind")?;
        match recovery_kind.as_str() {
            "reobserve" => {
                // An observation is useful recovery input, but it is not an
                // operation witness and must never settle a pending action.
                let observation = stored_runtime_value(&state.observation_json)?;
                let legal_actions = stored_runtime_value(&state.legal_actions_json)?;
                Ok(runtime_recovery_response(
                    request,
                    state,
                    "accepted",
                    observation,
                    legal_actions,
                    Value::Null,
                    Value::Null,
                ))
            }
            "reconcile" => {
                let operation_id = field_string(recovery, "operation_id")?;
                let Some(operation) = self.runtime_operation(&operation_id)? else {
                    return Ok(runtime_error_response(
                        request,
                        "recover_request",
                        "operation_not_found",
                        state.generation,
                        state,
                    ));
                };
                if operation.instance_id != state.instance_id
                    || operation.session_id != state.session_id
                    || operation.lease_id != state.lease_id
                    || operation.lease_epoch != state.lease_epoch
                {
                    return Ok(runtime_error_response(
                        request,
                        "recover_request",
                        "stale_lease",
                        state.generation,
                        state,
                    ));
                }
                match operation.status.as_str() {
                    "SETTLED" | "RECONCILED" => {
                        self.runtime_operation_response(request, state, &operation)
                    }
                    // A witness is required before a recovery path can claim
                    // settlement.  Reobserve alone only supplies state and is
                    // intentionally not accepted as an effect proof.
                    "UNKNOWN"
                        if operation.witness_json.is_some() && operation.result_json.is_some() =>
                    {
                        self.mark_runtime_reconciled(&operation_id)?;
                        let reconciled = self
                            .runtime_operation(&operation_id)?
                            .ok_or(FixtureError::HostNotReady)?;
                        self.runtime_operation_response(request, state, &reconciled)
                    }
                    _ => Ok(runtime_error_response(
                        request,
                        "recover_request",
                        "effect_witness_missing",
                        state.generation,
                        state,
                    )),
                }
            }
            "release_lease" | "stop_episode" => {
                if recovery_kind == "release_lease" {
                    let transaction = self.connection.transaction().map_err(FixtureError::Sql)?;
                    transaction
                        .execute(
                            "UPDATE lease SET revoked=1 WHERE singleton=1 AND lease_id=?1 AND lease_epoch=?2",
                            params![state.lease_id, state.lease_epoch],
                        )
                        .map_err(FixtureError::Sql)?;
                    transaction
                        .execute(
                            "UPDATE lease_history SET revoked=1 WHERE lease_id=?1 AND lease_epoch=?2",
                            params![state.lease_id, state.lease_epoch],
                        )
                        .map_err(FixtureError::Sql)?;
                    transaction.commit().map_err(FixtureError::Sql)?;
                }
                // Once a dispatch has been admitted, stopping cannot claim it
                // never reached the host.  Retain an unresolved journal row;
                // no later request may dispatch it under a new lease.
                self.mark_active_runtime_operations_unknown(&state.session_id)?;
                state.stopped = true;
                self.persist_runtime_session(state)?;
                let observation = stored_runtime_value(&state.observation_json)?;
                let legal_actions = stored_runtime_value(&state.legal_actions_json)?;
                Ok(runtime_recovery_response(
                    request,
                    state,
                    "cancelled",
                    observation,
                    legal_actions,
                    Value::Null,
                    json!("episode_stopped"),
                ))
            }
            _ => Err(FixtureError::Invalid(
                "unsupported recovery kind".to_owned(),
            )),
        }
    }

    pub(crate) fn runtime_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<RuntimeOperation>, FixtureError> {
        let operation = self
            .connection
            .query_row(
                "SELECT operation_id,instance_id,session_id,lease_id,lease_epoch,action_json,action_digest,pre_state_id,pre_generation,status,witness_json,result_json FROM runtime_operations WHERE operation_id=?1",
                params![operation_id],
                |row| {
                    Ok(RuntimeOperation {
                        operation_id: row.get(0)?,
                        instance_id: row.get(1)?,
                        session_id: row.get(2)?,
                        lease_id: row.get(3)?,
                        lease_epoch: row.get(4)?,
                        action_json: row.get(5)?,
                        action_digest: row.get(6)?,
                        pre_state_id: row.get(7)?,
                        pre_generation: row.get(8)?,
                        status: row.get(9)?,
                        witness_json: row.get(10)?,
                        result_json: row.get(11)?,
                    })
                },
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some(operation) = operation else {
            return Ok(None);
        };
        self.validate_runtime_operation(&operation)?;
        Ok(Some(operation))
    }
}
