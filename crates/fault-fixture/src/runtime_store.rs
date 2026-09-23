//! Durable runtime-v3 operation and session persistence.
//!
//! Owns runtime operation/session rows, transitions (reconciled, unknown,
//! rejected), the operation journal bound and the runtime operation response
//! drain.  Extracted verbatim from `lib.rs` by the runtime-v3-execution-and-
//! persistence split (issue #77); request execution lives in `runtime`.

use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::runtime::{
    RuntimeOperation, RuntimeSession, runtime_accepted_response, runtime_base,
    runtime_error_response, runtime_rejected_response, stored_runtime_value,
    synthetic_legal_actions, synthetic_observation,
};
use crate::server::response_kind;
use crate::wire::parse_value_no_duplicates;
use crate::{
    DurableHost, EFFECT_WITNESS_SOURCE, FIXTURE_TIMESTAMP, FixtureError, MAX_ACTION_BYTES,
    MAX_FRAME_BYTES, MAX_RUNTIME_INTEGER, digest, field_i64, field_string, object_fields,
    sha256_hex, valid_identity, valid_timestamp, validate_digest, validate_runtime_legal_action,
    validate_runtime_legal_actions, validate_runtime_observation, validate_runtime_transition,
    validate_runtime_witness,
};

impl DurableHost {
    #[allow(clippy::too_many_lines, clippy::unused_self)]
    pub(crate) fn validate_runtime_operation(
        &self,
        operation: &RuntimeOperation,
    ) -> Result<(), FixtureError> {
        if !valid_identity(&operation.operation_id)
            || !valid_identity(&operation.instance_id)
            || !valid_identity(&operation.session_id)
            || !valid_identity(&operation.lease_id)
            || !(0..=MAX_RUNTIME_INTEGER).contains(&operation.lease_epoch)
            || !valid_identity(&operation.pre_state_id)
            || !(0..=MAX_RUNTIME_INTEGER).contains(&operation.pre_generation)
            || !matches!(
                operation.status.as_str(),
                "ADMITTED" | "EXECUTING" | "UNKNOWN" | "SETTLED" | "RECONCILED" | "REJECTED"
            )
        {
            return Err(FixtureError::Invalid(
                "runtime operation journal".to_owned(),
            ));
        }
        validate_digest(&operation.action_digest)?;
        if operation.action_json.len() > MAX_ACTION_BYTES {
            return Err(FixtureError::Bounds("runtime action journal"));
        }
        let action = parse_value_no_duplicates(operation.action_json.as_bytes())?;
        validate_runtime_legal_action(&action)?;
        if sha256_hex(operation.action_json.as_bytes()) != operation.action_digest {
            return Err(FixtureError::Conflict);
        }
        if let Some(witness) = operation.witness_json.as_deref() {
            if witness.len() > MAX_FRAME_BYTES {
                return Err(FixtureError::Bounds("runtime witness journal"));
            }
            let witness = parse_value_no_duplicates(witness.as_bytes())?;
            validate_runtime_witness(&witness, &operation.operation_id, &operation.action_digest)?;
        }
        if let Some(result) = operation.result_json.as_deref() {
            if result.len() > MAX_FRAME_BYTES {
                return Err(FixtureError::Bounds("runtime result journal"));
            }
            let result = parse_value_no_duplicates(result.as_bytes())?;
            object_fields(
                &result,
                &[
                    "state_id",
                    "generation",
                    "observation",
                    "legal_actions",
                    "transition",
                ],
                &[
                    "state_id",
                    "generation",
                    "observation",
                    "legal_actions",
                    "transition",
                ],
            )?;
            if !valid_identity(&field_string(&result, "state_id")?)
                || !(0..=MAX_RUNTIME_INTEGER).contains(&field_i64(&result, "generation")?)
            {
                return Err(FixtureError::Invalid("runtime operation result".to_owned()));
            }
            validate_runtime_observation(&result["observation"])?;
            validate_runtime_legal_actions(&result["legal_actions"])?;
            validate_runtime_transition(&result["transition"])?;
            if result["observation"]["state_id"] != result["state_id"]
                || result["observation"]["generation"] != result["generation"]
                || result["transition"]["state_id"] != result["state_id"]
                || result["transition"]["to_generation"] != result["generation"]
                || result["transition"]["from_generation"] != operation.pre_generation
            {
                return Err(FixtureError::Invalid(
                    "runtime operation result relation".to_owned(),
                ));
            }
        }
        if let (Some(witness), Some(result)) = (
            operation.witness_json.as_deref(),
            operation.result_json.as_deref(),
        ) {
            let witness = parse_value_no_duplicates(witness.as_bytes())?;
            let result = parse_value_no_duplicates(result.as_bytes())?;
            if witness["pre_state_id"] != operation.pre_state_id
                || witness["pre_generation"] != operation.pre_generation
                || witness["state_id"] != result["state_id"]
                || witness["generation"] != result["generation"]
            {
                return Err(FixtureError::Invalid(
                    "runtime proof boundary relation".to_owned(),
                ));
            }
        }
        if matches!(operation.status.as_str(), "SETTLED" | "RECONCILED")
            && (operation.witness_json.is_none() || operation.result_json.is_none())
        {
            return Err(FixtureError::Invalid(
                "settled runtime operation lacks proof".to_owned(),
            ));
        }
        if matches!(
            operation.status.as_str(),
            "ADMITTED" | "EXECUTING" | "REJECTED"
        ) && (operation.witness_json.is_some() || operation.result_json.is_some())
        {
            return Err(FixtureError::Invalid(
                "unsettled runtime operation contains proof".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn active_runtime_operation(
        &self,
        session_id: &str,
        excluding: Option<&str>,
    ) -> Result<Option<RuntimeOperation>, FixtureError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT operation_id FROM runtime_operations WHERE session_id=?1 AND status IN ('ADMITTED','EXECUTING','UNKNOWN') ORDER BY created_at,operation_id",
            )
            .map_err(FixtureError::Sql)?;
        let mut rows = statement
            .query(params![session_id])
            .map_err(FixtureError::Sql)?;
        while let Some(row) = rows.next().map_err(FixtureError::Sql)? {
            let operation_id: String = row.get(0).map_err(FixtureError::Sql)?;
            if excluding != Some(operation_id.as_str()) {
                return self.runtime_operation(&operation_id);
            }
        }
        Ok(None)
    }

    pub(crate) fn active_runtime_session_for_instance(
        &self,
        instance_id: &str,
    ) -> Result<Option<RuntimeSession>, FixtureError> {
        let session_id: Option<String> = self
            .connection
            .query_row(
                "SELECT session_id FROM runtime_sessions WHERE instance_id=?1 AND stopped=0 ORDER BY session_id LIMIT 1",
                params![instance_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        session_id
            .as_deref()
            .map_or(Ok(None), |session_id| self.runtime_session(session_id))
    }

    pub(crate) fn unresolved_runtime_operation_for_instance(
        &self,
        instance_id: &str,
    ) -> Result<Option<RuntimeOperation>, FixtureError> {
        let operation_id: Option<String> = self
            .connection
            .query_row(
                "SELECT operation_id FROM runtime_operations WHERE instance_id=?1 AND status IN ('ADMITTED','EXECUTING','UNKNOWN') ORDER BY created_at,operation_id LIMIT 1",
                params![instance_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        operation_id.as_deref().map_or(Ok(None), |operation_id| {
            self.runtime_operation(operation_id)
        })
    }

    pub(crate) fn runtime_operation_count(&self) -> Result<usize, FixtureError> {
        let count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM runtime_operations", [], |row| {
                row.get(0)
            })
            .map_err(FixtureError::Sql)?;
        usize::try_from(count)
            .map_err(|_| FixtureError::Invalid("runtime operation count overflow".to_owned()))
    }

    pub(crate) fn insert_runtime_operation(
        &self,
        operation: &RuntimeOperation,
    ) -> Result<(), FixtureError> {
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "INSERT INTO runtime_operations(operation_id,instance_id,session_id,lease_id,lease_epoch,action_json,action_digest,pre_state_id,pre_generation,status,witness_json,result_json,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,NULL,NULL,?11,?11)",
                params![
                    operation.operation_id,
                    operation.instance_id,
                    operation.session_id,
                    operation.lease_id,
                    operation.lease_epoch,
                    operation.action_json,
                    operation.action_digest,
                    operation.pre_state_id,
                    operation.pre_generation,
                    operation.status,
                    FIXTURE_TIMESTAMP,
                ],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "INSERT INTO runtime_queue(operation_id,enqueued_at) VALUES(?1,?2)",
                params![operation.operation_id, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        transaction.commit().map_err(FixtureError::Sql)
    }

    #[allow(clippy::unused_self)]
    pub(crate) fn runtime_operation_response(
        &self,
        request: &Value,
        state: &RuntimeSession,
        operation: &RuntimeOperation,
    ) -> Result<Value, FixtureError> {
        match operation.status.as_str() {
            "SETTLED" | "RECONCILED" => {
                let result_text = operation.result_json.as_deref().ok_or_else(|| {
                    FixtureError::Invalid("settled runtime result missing".to_owned())
                })?;
                let result = parse_value_no_duplicates(result_text.as_bytes())?;
                let response_kind = response_kind(field_string(request, "kind")?.as_str());
                let mut response = runtime_base(request, &response_kind, state);
                response["generation"] = result["generation"].clone();
                response["state_id"] = result["state_id"].clone();
                response["operation_id"] = json!(operation.operation_id);
                response["observation"] = result["observation"].clone();
                response["legal_actions"] = result["legal_actions"].clone();
                response["status"] = json!("settled");
                response["transition"] = result["transition"].clone();
                if response_kind == "wait_response" {
                    response["wait_outcome"] = json!("successor");
                }
                Ok(response)
            }
            "ADMITTED" => runtime_accepted_response(request, state, &operation.operation_id),
            "REJECTED" if field_string(request, "kind")? == "wait_request" => {
                Ok(runtime_error_response(
                    request,
                    "wait_request",
                    "operation_rejected",
                    state.generation,
                    state,
                ))
            }
            "REJECTED" => runtime_rejected_response(
                request,
                state,
                &operation.operation_id,
                "operation_rejected",
            ),
            "EXECUTING" | "UNKNOWN" => Ok(runtime_error_response(
                request,
                field_string(request, "kind")?.as_str(),
                "operation_unknown",
                state.generation,
                state,
            )),
            _ => Err(FixtureError::Invalid("runtime operation state".to_owned())),
        }
    }

    pub(crate) fn mark_runtime_reconciled(&self, operation_id: &str) -> Result<(), FixtureError> {
        let changed = self
            .connection
            .execute(
                "UPDATE runtime_operations SET status='RECONCILED',updated_at=?2 WHERE operation_id=?1 AND status='UNKNOWN' AND witness_json IS NOT NULL AND result_json IS NOT NULL",
                params![operation_id, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        if changed != 1 {
            return Err(FixtureError::Conflict);
        }
        self.connection
            .execute(
                "DELETE FROM runtime_queue WHERE operation_id=?1",
                params![operation_id],
            )
            .map_err(FixtureError::Sql)?;
        Ok(())
    }

    pub(crate) fn mark_active_runtime_operations_unknown(
        &self,
        session_id: &str,
    ) -> Result<(), FixtureError> {
        self.connection
            .execute(
                "UPDATE runtime_operations SET status='UNKNOWN',updated_at=?2 WHERE session_id=?1 AND status IN ('ADMITTED','EXECUTING')",
                params![session_id, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        self.connection
            .execute(
                "DELETE FROM runtime_queue WHERE operation_id IN (SELECT operation_id FROM runtime_operations WHERE session_id=?1 AND status='UNKNOWN')",
                params![session_id],
            )
            .map_err(FixtureError::Sql)?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn drain_runtime_operation(
        &mut self,
        request: &Value,
        state: &mut RuntimeSession,
        operation: &RuntimeOperation,
    ) -> Result<Value, FixtureError> {
        if operation.status != "ADMITTED" {
            return self.runtime_operation_response(request, state, operation);
        }
        // Revalidate the operation's original durable authority at execution,
        // not merely the caller's session at admission. A fence rotation never
        // authorizes draining queued work from its predecessor.
        if !self.runtime_authority_current(
            &operation.instance_id,
            &operation.lease_id,
            operation.lease_epoch,
        )? {
            self.mark_runtime_operation_unknown(&operation.operation_id)?;
            return Ok(runtime_error_response(
                request,
                "wait_request",
                "stale_lease",
                state.generation,
                state,
            ));
        }
        if operation.pre_state_id != state.state_id || operation.pre_generation != state.generation
        {
            self.mark_runtime_operation_unknown(&operation.operation_id)?;
            return Ok(runtime_error_response(
                request,
                "wait_request",
                "prestate_changed",
                state.generation,
                state,
            ));
        }
        let queued: Option<i64> = self
            .connection
            .query_row(
                "SELECT 1 FROM runtime_queue WHERE operation_id=?1",
                params![operation.operation_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        if queued.is_none() {
            self.mark_runtime_operation_unknown(&operation.operation_id)?;
            return Ok(runtime_error_response(
                request,
                "wait_request",
                "queue_missing",
                state.generation,
                state,
            ));
        }
        let changed = self
            .connection
            .execute(
                "UPDATE runtime_operations SET status='EXECUTING',updated_at=?2 WHERE operation_id=?1 AND status='ADMITTED'",
                params![operation.operation_id, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        if changed != 1 {
            let current = self
                .runtime_operation(&operation.operation_id)?
                .ok_or(FixtureError::HostNotReady)?;
            return self.runtime_operation_response(request, state, &current);
        }
        let action = parse_value_no_duplicates(operation.action_json.as_bytes())?;
        let legal_actions = stored_runtime_value(&state.legal_actions_json)?;
        if !legal_actions
            .as_array()
            .is_some_and(|actions| actions.iter().any(|candidate| candidate == &action))
        {
            self.mark_runtime_operation_rejected(&operation.operation_id)?;
            return runtime_rejected_response(
                request,
                state,
                &operation.operation_id,
                "prestate_changed",
            );
        }
        let action_kind = field_string(
            action
                .get("action")
                .ok_or_else(|| FixtureError::Invalid("action payload missing".to_owned()))?,
            "kind",
        )?;
        let mut observation = stored_runtime_value(&state.observation_json)?;
        let from_generation = state.generation;
        let to_generation = from_generation
            .checked_add(1)
            .ok_or_else(|| FixtureError::Invalid("runtime generation exhausted".to_owned()))?;
        observation["generation"] = json!(to_generation);
        if action_kind == "end_turn" {
            let turn = observation["state"]["turn_index"].as_i64().unwrap_or(1);
            observation["state"]["turn_index"] = json!(turn.saturating_add(1));
        }
        validate_runtime_observation(&observation)?;
        let legal_actions = stored_runtime_value(&state.legal_actions_json)?;
        let transition = json!({
            "from_generation":from_generation,
            "to_generation":to_generation,
            "state_id":state.state_id,
            "effect_kind":format!("synthetic.{action_kind}_settled")
        });
        validate_runtime_transition(&transition)?;
        let result = json!({
            "state_id":state.state_id,
            "generation":to_generation,
            "observation":observation,
            "legal_actions":legal_actions,
            "transition":transition
        });
        let witness = json!({
            "witness_id":Uuid::new_v4().to_string(),
            "operation_id":operation.operation_id,
            "action_digest":operation.action_digest,
            "source":EFFECT_WITNESS_SOURCE,
            "pre_state_id":operation.pre_state_id,
            "pre_generation":operation.pre_generation,
            "state_id":state.state_id,
            "generation":to_generation,
            "effect_digest":digest(&format!("runtime-effect:{}:{}:{}", operation.operation_id, operation.action_digest, to_generation)),
            "observed_at":FIXTURE_TIMESTAMP
        });
        validate_runtime_witness(&witness, &operation.operation_id, &operation.action_digest)?;
        let mut next_state = state.clone();
        next_state.generation = to_generation;
        next_state.observation_json = observation.to_string();
        next_state.last_operation_id = Some(operation.operation_id.clone());
        next_state.last_action_id = Some(field_string(&action, "action_id")?);
        let witness_text = witness.to_string();
        let result_text = result.to_string();
        let transaction = self.connection.transaction().map_err(FixtureError::Sql)?;
        let operation_changed = transaction
            .execute(
                "UPDATE runtime_operations SET status='SETTLED',witness_json=?2,result_json=?3,updated_at=?4 WHERE operation_id=?1 AND status='EXECUTING'",
                params![operation.operation_id, witness_text, result_text, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        if operation_changed != 1 {
            return Err(FixtureError::Conflict);
        }
        let session_changed = transaction
            .execute(
                "UPDATE runtime_sessions SET generation=?2,observation_json=?3,last_operation_id=?4,last_action_id=?5,updated_at=?6 WHERE session_id=?1 AND generation=?7 AND state_id=?8",
                params![
                    next_state.session_id,
                    next_state.generation,
                    next_state.observation_json,
                    next_state.last_operation_id,
                    next_state.last_action_id,
                    FIXTURE_TIMESTAMP,
                    operation.pre_generation,
                    operation.pre_state_id,
                ],
            )
            .map_err(FixtureError::Sql)?;
        if session_changed != 1 {
            return Err(FixtureError::Conflict);
        }
        transaction
            .execute(
                "DELETE FROM runtime_queue WHERE operation_id=?1",
                params![operation.operation_id],
            )
            .map_err(FixtureError::Sql)?;
        transaction.commit().map_err(FixtureError::Sql)?;
        *state = next_state;
        let settled = self
            .runtime_operation(&operation.operation_id)?
            .ok_or(FixtureError::HostNotReady)?;
        self.runtime_operation_response(request, state, &settled)
    }

    pub(crate) fn mark_runtime_operation_unknown(
        &self,
        operation_id: &str,
    ) -> Result<(), FixtureError> {
        let identity: Option<(String, String, String, i64)> = self
            .connection
            .query_row(
                "SELECT instance_id,session_id,lease_id,lease_epoch FROM runtime_operations WHERE operation_id=?1",
                params![operation_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        if let Some((instance_id, session_id, lease_id, lease_epoch)) = identity {
            let _ = self.mark_runtime_operation_unknown_for_context(
                operation_id,
                &instance_id,
                &session_id,
                &lease_id,
                lease_epoch,
            )?;
        }
        Ok(())
    }

    pub(crate) fn mark_runtime_operation_unknown_for_context(
        &self,
        operation_id: &str,
        instance_id: &str,
        session_id: &str,
        lease_id: &str,
        lease_epoch: i64,
    ) -> Result<bool, FixtureError> {
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(FixtureError::Sql)?;
        let changed = transaction
            .execute(
                "UPDATE runtime_operations SET status='UNKNOWN',updated_at=?5 WHERE operation_id=?1 AND instance_id=?2 AND session_id=?3 AND lease_id=?4 AND lease_epoch=?6 AND status IN ('ADMITTED','EXECUTING')",
                params![
                    operation_id,
                    instance_id,
                    session_id,
                    lease_id,
                    FIXTURE_TIMESTAMP,
                    lease_epoch,
                ],
            )
            .map_err(FixtureError::Sql)?;
        if changed == 1 {
            transaction
                .execute(
                    "DELETE FROM runtime_queue WHERE operation_id=?1",
                    params![operation_id],
                )
                .map_err(FixtureError::Sql)?;
        }
        transaction.commit().map_err(FixtureError::Sql)?;
        Ok(changed == 1)
    }

    pub(crate) fn mark_runtime_operation_rejected(
        &self,
        operation_id: &str,
    ) -> Result<(), FixtureError> {
        self.connection
            .execute(
                "UPDATE runtime_operations SET status='REJECTED',updated_at=?2 WHERE operation_id=?1 AND status='EXECUTING'",
                params![operation_id, FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        self.connection
            .execute(
                "DELETE FROM runtime_queue WHERE operation_id=?1",
                params![operation_id],
            )
            .map_err(FixtureError::Sql)?;
        Ok(())
    }

    pub(crate) fn runtime_session(
        &self,
        session_id: &str,
    ) -> Result<Option<RuntimeSession>, FixtureError> {
        let state = self
            .connection
            .query_row(
                "SELECT instance_id,session_id,lease_id,lease_epoch,state_id,generation,observation_json,legal_actions_json,last_operation_id,last_action_id,stopped,updated_at FROM runtime_sessions WHERE session_id=?1",
                params![session_id],
                |row| Ok(RuntimeSession {
                    instance_id: row.get(0)?, session_id: row.get(1)?, lease_id: row.get(2)?,
                    lease_epoch: row.get(3)?, state_id: row.get(4)?, generation: row.get(5)?,
                    observation_json: row.get(6)?, legal_actions_json: row.get(7)?,
                    last_operation_id: row.get(8)?, last_action_id: row.get(9)?,
                    stopped: row.get(10)?, updated_at: row.get(11)?,
                }),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some(state) = state else {
            return Ok(None);
        };
        if !valid_identity(&state.instance_id)
            || !valid_identity(&state.session_id)
            || !valid_identity(&state.lease_id)
            || !valid_identity(&state.state_id)
            || !(0..=MAX_RUNTIME_INTEGER).contains(&state.lease_epoch)
            || !(0..=MAX_RUNTIME_INTEGER).contains(&state.generation)
            || !valid_timestamp(&state.updated_at)
        {
            return Err(FixtureError::Invalid("runtime session identity".to_owned()));
        }
        let observation = stored_runtime_value(&state.observation_json)?;
        validate_runtime_observation(&observation)?;
        let legal_actions = stored_runtime_value(&state.legal_actions_json)?;
        validate_runtime_legal_actions(&legal_actions)?;
        if state
            .last_operation_id
            .as_deref()
            .is_some_and(|value| !valid_identity(value))
            || state
                .last_action_id
                .as_deref()
                .is_some_and(|value| !valid_identity(value))
        {
            return Err(FixtureError::Invalid("runtime session journal".to_owned()));
        }
        if observation["state_id"] != state.state_id
            || observation["generation"] != state.generation
        {
            return Err(FixtureError::Invalid("runtime session boundary".to_owned()));
        }
        Ok(Some(state))
    }

    pub(crate) fn create_runtime_session(
        &self,
        instance_id: &str,
        session_id: &str,
        lease_id: &str,
        lease_epoch: i64,
        requested_state_id: Option<&str>,
        generation: i64,
    ) -> Result<RuntimeSession, FixtureError> {
        let state_id = requested_state_id.unwrap_or("synthetic-state").to_owned();
        let observation = synthetic_observation(&state_id, generation)?;
        let legal_actions = synthetic_legal_actions();
        let state = RuntimeSession {
            instance_id: instance_id.to_owned(),
            session_id: session_id.to_owned(),
            lease_id: lease_id.to_owned(),
            lease_epoch,
            state_id,
            generation,
            observation_json: observation.to_string(),
            legal_actions_json: legal_actions.to_string(),
            last_operation_id: None,
            last_action_id: None,
            stopped: false,
            updated_at: FIXTURE_TIMESTAMP.to_owned(),
        };
        self.persist_runtime_session(&state)?;
        Ok(state)
    }

    pub(crate) fn persist_runtime_session(
        &self,
        state: &RuntimeSession,
    ) -> Result<(), FixtureError> {
        self.connection
            .execute(
                "INSERT OR REPLACE INTO runtime_sessions(instance_id,session_id,lease_id,lease_epoch,state_id,generation,observation_json,legal_actions_json,last_operation_id,last_action_id,stopped,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                params![
                    state.instance_id, state.session_id, state.lease_id, state.lease_epoch,
                    state.state_id, state.generation, state.observation_json, state.legal_actions_json,
                    state.last_operation_id, state.last_action_id, i64::from(state.stopped), state.updated_at,
                ],
            )
            .map_err(FixtureError::Sql)?;
        Ok(())
    }
}
