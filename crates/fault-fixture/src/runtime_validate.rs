//! Runtime-v3 envelope and observation validation for the synthetic fixture.
//!
//! Owns the frozen runtime-v3 envelope checks and every domain validator:
//! action/wait/recover responses, observations, cards, enemies, shop items,
//! legal actions, transitions, witnesses and recovery records.  Extracted
//! verbatim from `lib.rs` by the runtime-v3-envelope-and-observation-validation
//! split (issue #78); the crate root keeps the recovery-contract validators and
//! the runtime-v3 execution methods.

use serde_json::Value;

use crate::{
    EFFECT_WITNESS_SOURCE, FixtureError, MAX_RUNTIME_INTEGER, RUNTIME_V3_SCHEMA_DIGEST, field_i64,
    field_string, object_fields, valid_identity, valid_timestamp, validate_digest,
};

#[allow(clippy::too_many_lines)]
pub(crate) fn validate_runtime_v3_envelope(
    expected_kind: &str,
    value: &Value,
) -> Result<(), FixtureError> {
    const FIELDS: &[&str] = &[
        "protocol_version",
        "schema_digest",
        "provenance",
        "correlation_id",
        "instance_id",
        "session_id",
        "lease_id",
        "lease_epoch",
        "generation",
        "kind",
        "state_id",
        "operation_id",
        "observation",
        "legal_actions",
        "action",
        "status",
        "transition",
        "error_code",
        "wait_for_millis",
        "wait_outcome",
        "recovery",
    ];
    object_fields(value, FIELDS, FIELDS)?;
    if value["protocol_version"] != "runtime-v3-gameplay"
        || value["schema_digest"] != RUNTIME_V3_SCHEMA_DIGEST
        || value["kind"] != expected_kind
    {
        return Err(FixtureError::ContractMismatch);
    }
    object_fields(
        &value["provenance"],
        &["artifact", "source", "generator"],
        &["artifact", "source", "generator"],
    )?;
    if value["provenance"]["artifact"] != "sts2-protocol/runtime-v3-gameplay"
        || value["provenance"]["source"] != "schemas/runtime-v3-gameplay.schema.json"
        || value["provenance"]["generator"] != "hand-authored"
    {
        return Err(FixtureError::ContractMismatch);
    }
    for name in ["correlation_id", "instance_id", "session_id", "lease_id"] {
        if !value[name].as_str().is_some_and(valid_identity) {
            return Err(FixtureError::Invalid("runtime identity".to_owned()));
        }
    }
    for name in ["lease_epoch", "generation"] {
        if value[name]
            .as_i64()
            .is_none_or(|number| !(0..=9_007_199_254_740_991).contains(&number))
        {
            return Err(FixtureError::Invalid("runtime integer".to_owned()));
        }
    }
    let kind = expected_kind;
    if !value["state_id"].is_null() && !value["state_id"].as_str().is_some_and(valid_identity) {
        return Err(FixtureError::Invalid("runtime state identity".to_owned()));
    }
    if !value["operation_id"].is_null()
        && !value["operation_id"].as_str().is_some_and(valid_identity)
    {
        return Err(FixtureError::Invalid(
            "runtime operation identity".to_owned(),
        ));
    }
    if !value["error_code"].is_null() && !value["error_code"].as_str().is_some_and(valid_identity) {
        return Err(FixtureError::Invalid("runtime error identity".to_owned()));
    }
    if !value["wait_for_millis"].is_null()
        && value["wait_for_millis"]
            .as_i64()
            .is_none_or(|number| !(1..=120_000).contains(&number))
    {
        return Err(FixtureError::Invalid("runtime wait bound".to_owned()));
    }
    if !value["status"].is_null()
        && !matches!(
            value["status"].as_str(),
            Some("accepted" | "settled" | "rejected" | "unknown" | "cancelled")
        )
    {
        return Err(FixtureError::Invalid("runtime status".to_owned()));
    }
    if !value["wait_outcome"].is_null()
        && !matches!(
            value["wait_outcome"].as_str(),
            Some("successor" | "same_state_mutation" | "timeout" | "recovery_required")
        )
    {
        return Err(FixtureError::Invalid("runtime wait outcome".to_owned()));
    }
    if !value["observation"].is_null() {
        validate_runtime_observation(&value["observation"])?;
        if value["observation"]["generation"] != value["generation"]
            || value["observation"]["state_id"] != value["state_id"]
        {
            return Err(FixtureError::Invalid(
                "runtime observation/envelope relation".to_owned(),
            ));
        }
    }
    if !value["legal_actions"].is_null() {
        validate_runtime_legal_actions(&value["legal_actions"])?;
    }
    if !value["action"].is_null() {
        validate_runtime_legal_action(&value["action"])?;
    }
    if !value["transition"].is_null() {
        validate_runtime_transition(&value["transition"])?;
        if value["transition"]["to_generation"] != value["generation"]
            || value["transition"]["state_id"] != value["state_id"]
        {
            return Err(FixtureError::Invalid(
                "runtime transition/envelope relation".to_owned(),
            ));
        }
    }
    if !value["recovery"].is_null() {
        validate_runtime_recovery(&value["recovery"])?;
    }

    match kind {
        "state_request" | "reobserve_request" => {
            require_nulls(
                value,
                &[
                    "state_id",
                    "operation_id",
                    "observation",
                    "legal_actions",
                    "action",
                    "status",
                    "transition",
                    "error_code",
                    "wait_for_millis",
                    "wait_outcome",
                    "recovery",
                ],
            )?;
        }
        "state_response" | "reobserve_response" => {
            require_present(value, &["state_id", "observation", "legal_actions"])?;
            require_nulls(
                value,
                &[
                    "operation_id",
                    "action",
                    "status",
                    "transition",
                    "error_code",
                    "wait_for_millis",
                    "wait_outcome",
                    "recovery",
                ],
            )?;
        }
        "legal_actions_request" => {
            require_present(value, &["state_id"])?;
            require_nulls(
                value,
                &[
                    "operation_id",
                    "observation",
                    "legal_actions",
                    "action",
                    "status",
                    "transition",
                    "error_code",
                    "wait_for_millis",
                    "wait_outcome",
                    "recovery",
                ],
            )?;
        }
        "legal_actions_response" => {
            require_present(value, &["state_id", "legal_actions"])?;
            require_nulls(
                value,
                &[
                    "operation_id",
                    "observation",
                    "action",
                    "status",
                    "transition",
                    "error_code",
                    "wait_for_millis",
                    "wait_outcome",
                    "recovery",
                ],
            )?;
        }
        "dispatch_action_request" => {
            require_present(value, &["state_id", "operation_id", "action"])?;
            require_nulls(
                value,
                &[
                    "observation",
                    "legal_actions",
                    "status",
                    "transition",
                    "error_code",
                    "wait_for_millis",
                    "wait_outcome",
                    "recovery",
                ],
            )?;
        }
        "wait_request" => {
            require_present(value, &["operation_id", "wait_for_millis"])?;
            require_nulls(
                value,
                &[
                    "state_id",
                    "observation",
                    "legal_actions",
                    "action",
                    "status",
                    "transition",
                    "error_code",
                    "wait_outcome",
                    "recovery",
                ],
            )?;
        }
        "recover_request" => {
            require_present(value, &["recovery"])?;
            require_nulls(
                value,
                &[
                    "state_id",
                    "operation_id",
                    "observation",
                    "legal_actions",
                    "action",
                    "status",
                    "transition",
                    "error_code",
                    "wait_for_millis",
                    "wait_outcome",
                ],
            )?;
        }
        "dispatch_action_response" => validate_runtime_action_response(value)?,
        "wait_response" => validate_runtime_wait_response(value)?,
        "recover_response" => validate_runtime_recover_response(value)?,
        _ => return Err(FixtureError::Invalid("runtime kind".to_owned())),
    }
    Ok(())
}

pub(crate) fn require_present(value: &Value, fields: &[&str]) -> Result<(), FixtureError> {
    if fields.iter().any(|field| value[*field].is_null()) {
        Err(FixtureError::Invalid("runtime required field".to_owned()))
    } else {
        Ok(())
    }
}

pub(crate) fn require_nulls(value: &Value, fields: &[&str]) -> Result<(), FixtureError> {
    if fields.iter().any(|field| !value[*field].is_null()) {
        Err(FixtureError::Invalid("runtime field relation".to_owned()))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_runtime_action_response(value: &Value) -> Result<(), FixtureError> {
    require_present(value, &["operation_id", "status"])?;
    require_nulls(
        value,
        &["action", "wait_for_millis", "wait_outcome", "recovery"],
    )?;
    match value["status"].as_str() {
        Some("settled") => {
            require_present(
                value,
                &["state_id", "observation", "legal_actions", "transition"],
            )?;
            if !value["error_code"].is_null() {
                return Err(FixtureError::Invalid("settled error".to_owned()));
            }
        }
        Some("accepted") => {
            require_present(value, &["state_id", "observation", "legal_actions"])?;
            require_nulls(value, &["transition", "error_code"])?;
        }
        Some("rejected" | "cancelled") => {
            require_present(
                value,
                &["state_id", "observation", "legal_actions", "error_code"],
            )?;
            require_nulls(value, &["transition"])?;
        }
        Some("unknown") => {
            require_nulls(value, &["observation", "legal_actions", "transition"])?;
            require_present(value, &["error_code"])?;
        }
        _ => return Err(FixtureError::Invalid("runtime action status".to_owned())),
    }
    Ok(())
}

pub(crate) fn validate_runtime_wait_response(value: &Value) -> Result<(), FixtureError> {
    require_present(value, &["operation_id", "status", "wait_outcome"])?;
    require_nulls(value, &["action", "wait_for_millis", "recovery"])?;
    match value["wait_outcome"].as_str() {
        Some("successor" | "same_state_mutation") => {
            if value["status"] != "settled" {
                return Err(FixtureError::Invalid("wait settled relation".to_owned()));
            }
            require_present(
                value,
                &["state_id", "observation", "legal_actions", "transition"],
            )?;
            require_nulls(value, &["error_code"])?;
        }
        Some("timeout" | "recovery_required") => {
            if value["status"] != "unknown" {
                return Err(FixtureError::Invalid("wait unknown relation".to_owned()));
            }
            require_nulls(value, &["observation", "legal_actions", "transition"])?;
            require_present(value, &["error_code"])?;
        }
        _ => return Err(FixtureError::Invalid("wait outcome".to_owned())),
    }
    Ok(())
}

pub(crate) fn validate_runtime_recover_response(value: &Value) -> Result<(), FixtureError> {
    require_present(value, &["operation_id", "status"])?;
    require_nulls(
        value,
        &["action", "wait_for_millis", "wait_outcome", "recovery"],
    )?;
    match value["status"].as_str() {
        Some("settled") => {
            require_present(
                value,
                &["state_id", "observation", "legal_actions", "transition"],
            )?;
            require_nulls(value, &["error_code"])?;
        }
        Some("accepted") => {
            require_present(value, &["state_id", "observation", "legal_actions"])?;
            require_nulls(value, &["transition", "error_code"])?;
        }
        Some("cancelled") => {
            require_present(
                value,
                &["state_id", "observation", "legal_actions", "error_code"],
            )?;
            require_nulls(value, &["transition"])?;
        }
        Some("unknown") => {
            require_nulls(value, &["observation", "legal_actions", "transition"])?;
            require_present(value, &["error_code"])?;
        }
        _ => return Err(FixtureError::Invalid("recover status".to_owned())),
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(crate) fn validate_runtime_observation(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["state_id", "generation", "visible_seed", "player", "state"],
        &["state_id", "generation", "visible_seed", "player", "state"],
    )?;
    if !value["state_id"].as_str().is_some_and(valid_identity)
        || value["generation"]
            .as_i64()
            .is_none_or(|number| !(0..=MAX_RUNTIME_INTEGER).contains(&number))
    {
        return Err(FixtureError::Invalid("runtime observation".to_owned()));
    }
    if !value["visible_seed"].is_null() && !value["visible_seed"].as_str().is_some_and(valid_text) {
        return Err(FixtureError::Invalid("runtime visible seed".to_owned()));
    }
    object_fields(
        &value["player"],
        &[
            "hp", "max_hp", "energy", "gold", "hand", "deck", "discard", "exhaust",
        ],
        &[
            "hp", "max_hp", "energy", "gold", "hand", "deck", "discard", "exhaust",
        ],
    )?;
    for name in ["hp", "max_hp"] {
        if value["player"][name]
            .as_i64()
            .is_none_or(|number| !(0..=65_535).contains(&number))
        {
            return Err(FixtureError::Invalid("runtime player".to_owned()));
        }
    }
    if value["player"]["hp"].as_i64() > value["player"]["max_hp"].as_i64() {
        return Err(FixtureError::Invalid("runtime player health".to_owned()));
    }
    if value["player"]["energy"]
        .as_i64()
        .is_none_or(|number| !(0..=255).contains(&number))
        || value["player"]["gold"]
            .as_u64()
            .is_none_or(|number| number > 4_294_967_295)
    {
        return Err(FixtureError::Invalid("runtime player resources".to_owned()));
    }
    for name in ["hand", "deck", "discard", "exhaust"] {
        let Some(cards) = value["player"][name].as_array() else {
            return Err(FixtureError::Invalid("runtime card list".to_owned()));
        };
        if cards.len() > 256 {
            return Err(FixtureError::Bounds("runtime card list"));
        }
        for card in cards {
            validate_runtime_card(card)?;
        }
    }
    let state = &value["state"];
    let state_name = field_string(state, "state")?;
    match state_name.as_str() {
        "setup" => {
            object_fields(state, &["state", "characters"], &["state", "characters"])?;
            validate_runtime_identity_array(&state["characters"])?;
        }
        "map" => {
            object_fields(
                state,
                &["state", "node_id", "options"],
                &["state", "node_id", "options"],
            )?;
            if !state["node_id"].is_null() && !state["node_id"].as_str().is_some_and(valid_identity)
            {
                return Err(FixtureError::Invalid("runtime map node".to_owned()));
            }
            validate_runtime_identity_array(&state["options"])?;
        }
        "combat" => {
            object_fields(
                state,
                &["state", "turn_index", "enemies"],
                &["state", "turn_index", "enemies"],
            )?;
            if state["turn_index"]
                .as_i64()
                .is_none_or(|number| !(0..=65_535).contains(&number))
            {
                return Err(FixtureError::Invalid("runtime combat".to_owned()));
            }
            let Some(enemies) = state["enemies"].as_array() else {
                return Err(FixtureError::Invalid("runtime combat enemies".to_owned()));
            };
            if enemies.len() > 256 {
                return Err(FixtureError::Bounds("runtime enemies"));
            }
            for enemy in enemies {
                validate_runtime_enemy(enemy)?;
            }
        }
        "reward" | "rest" => {
            object_fields(state, &["state", "options"], &["state", "options"])?;
            validate_runtime_identity_array(&state["options"])?;
        }
        "shop" => {
            object_fields(state, &["state", "items"], &["state", "items"])?;
            let Some(items) = state["items"].as_array() else {
                return Err(FixtureError::Invalid("runtime shop items".to_owned()));
            };
            if items.len() > 256 {
                return Err(FixtureError::Bounds("runtime shop items"));
            }
            for item in items {
                validate_runtime_shop_item(item)?;
            }
        }
        "event" | "selection" => {
            object_fields(state, &["state", "choices"], &["state", "choices"])?;
            validate_runtime_identity_array(&state["choices"])?;
        }
        "victory" => {
            object_fields(state, &["state"], &["state"])?;
        }
        "defeat" => {
            object_fields(state, &["state", "reason"], &["state", "reason"])?;
            if !state["reason"].is_null() && !state["reason"].as_str().is_some_and(valid_text) {
                return Err(FixtureError::Invalid("runtime defeat reason".to_owned()));
            }
        }
        "recovery" => {
            object_fields(state, &["state", "code"], &["state", "code"])?;
            if !state["code"].as_str().is_some_and(valid_identity) {
                return Err(FixtureError::Invalid("runtime recovery code".to_owned()));
            }
        }
        _ => return Err(FixtureError::Invalid("runtime state".to_owned())),
    }
    Ok(())
}

pub(crate) fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

pub(crate) fn validate_runtime_identity_array(value: &Value) -> Result<(), FixtureError> {
    let Some(values) = value.as_array() else {
        return Err(FixtureError::Invalid("runtime identity list".to_owned()));
    };
    if values.len() > 256
        || values
            .iter()
            .any(|item| !item.as_str().is_some_and(valid_identity))
    {
        return Err(FixtureError::Invalid("runtime identity list".to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_runtime_card(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["card_id", "name", "cost", "upgraded"],
        &["card_id", "name", "cost", "upgraded"],
    )?;
    if !valid_identity(&field_string(value, "card_id")?)
        || !valid_text(&field_string(value, "name")?)
        || field_i64(value, "cost")?.is_negative()
        || field_i64(value, "cost")? > 255
        || !value["upgraded"].is_boolean()
    {
        return Err(FixtureError::Invalid("runtime card".to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_runtime_enemy(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["enemy_id", "name", "hp", "max_hp", "intent"],
        &["enemy_id", "name", "hp", "max_hp", "intent"],
    )?;
    if !valid_identity(&field_string(value, "enemy_id")?)
        || !valid_text(&field_string(value, "name")?)
        || field_i64(value, "hp")?.is_negative()
        || field_i64(value, "hp")? > 65_535
        || field_i64(value, "max_hp")?.is_negative()
        || field_i64(value, "max_hp")? > 65_535
        || field_i64(value, "hp")? > field_i64(value, "max_hp")?
    {
        return Err(FixtureError::Invalid("runtime enemy".to_owned()));
    }
    let intent = &value["intent"];
    let kind = field_string(intent, "kind")?;
    match kind.as_str() {
        "attack" => {
            object_fields(
                intent,
                &["kind", "damage", "hits"],
                &["kind", "damage", "hits"],
            )?;
            if field_i64(intent, "damage")?.is_negative()
                || field_i64(intent, "damage")? > 65_535
                || field_i64(intent, "hits")? < 1
                || field_i64(intent, "hits")? > 255
            {
                return Err(FixtureError::Invalid("runtime enemy attack".to_owned()));
            }
        }
        "defend" | "buff" | "debuff" | "unknown" => {
            object_fields(intent, &["kind"], &["kind"])?;
        }
        _ => return Err(FixtureError::Invalid("runtime enemy intent".to_owned())),
    }
    Ok(())
}

pub(crate) fn validate_runtime_shop_item(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["item_id", "name", "price"],
        &["item_id", "name", "price"],
    )?;
    if !valid_identity(&field_string(value, "item_id")?)
        || !valid_text(&field_string(value, "name")?)
        || field_i64(value, "price")?.is_negative()
    {
        return Err(FixtureError::Invalid("runtime shop item".to_owned()));
    }
    // `price` is an unsigned 32-bit JSON integer in the frozen schema.
    if value["price"]
        .as_u64()
        .is_none_or(|price| price > 4_294_967_295)
    {
        return Err(FixtureError::Invalid("runtime shop price".to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_runtime_legal_actions(value: &Value) -> Result<(), FixtureError> {
    let actions = value
        .as_array()
        .ok_or_else(|| FixtureError::Invalid("runtime legal actions".to_owned()))?;
    if actions.len() > 256 {
        return Err(FixtureError::Bounds("runtime legal actions"));
    }
    for (index, action) in actions.iter().enumerate() {
        validate_runtime_legal_action(action)?;
        if actions[..index]
            .iter()
            .any(|previous| previous["action_id"] == action["action_id"])
        {
            return Err(FixtureError::Invalid(
                "duplicate runtime action id".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_runtime_legal_action(value: &Value) -> Result<(), FixtureError> {
    object_fields(value, &["action_id", "action"], &["action_id", "action"])?;
    if !valid_identity(&field_string(value, "action_id")?) {
        return Err(FixtureError::Invalid("runtime action id".to_owned()));
    }
    let action = &value["action"];
    let kind = field_string(action, "kind")?;
    let required: &[&str] = match kind.as_str() {
        "end_turn" | "skip_reward" | "rest" | "confirm_victory" | "save_quit" | "proceed"
        | "confirm_selection" | "cancel_selection" => &[],
        "start_run" => &["character_id"],
        "select_map_node" => &["node_id"],
        "play_card" => &["card_id", "target_id"],
        "choose_reward" => &["reward_id"],
        "shop_purchase" => &["item_id"],
        "shop_remove" | "smith" | "select_card" => &["card_id"],
        "event_choice" => &["choice_id"],
        _ => return Err(FixtureError::Invalid("runtime action kind".to_owned())),
    };
    let mut allowed = vec!["kind"];
    allowed.extend(required.iter().copied());
    object_fields(action, &allowed, &allowed)?;
    for field in required {
        if *field == "target_id" && action[*field].is_null() {
            continue;
        }
        if !action[*field].as_str().is_some_and(valid_identity) {
            return Err(FixtureError::Invalid("runtime action argument".to_owned()));
        }
    }
    Ok(())
}

pub(crate) fn validate_runtime_transition(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "from_generation",
            "to_generation",
            "state_id",
            "effect_kind",
        ],
        &[
            "from_generation",
            "to_generation",
            "state_id",
            "effect_kind",
        ],
    )?;
    let from_generation = field_i64(value, "from_generation")?;
    let to_generation = field_i64(value, "to_generation")?;
    if !(0..=MAX_RUNTIME_INTEGER).contains(&from_generation)
        || !(0..=MAX_RUNTIME_INTEGER).contains(&to_generation)
        || to_generation <= from_generation
        || !valid_identity(&field_string(value, "state_id")?)
        || !valid_identity(&field_string(value, "effect_kind")?)
    {
        return Err(FixtureError::Invalid("runtime transition".to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_runtime_witness(
    value: &Value,
    expected_operation_id: &str,
    expected_action_digest: &str,
) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "witness_id",
            "operation_id",
            "action_digest",
            "source",
            "pre_state_id",
            "pre_generation",
            "state_id",
            "generation",
            "effect_digest",
            "observed_at",
        ],
        &[
            "witness_id",
            "operation_id",
            "action_digest",
            "source",
            "pre_state_id",
            "pre_generation",
            "state_id",
            "generation",
            "effect_digest",
            "observed_at",
        ],
    )?;
    for name in ["witness_id", "operation_id"] {
        if !valid_identity(&field_string(value, name)?) {
            return Err(FixtureError::Invalid("runtime witness identity".to_owned()));
        }
    }
    if field_string(value, "operation_id")? != expected_operation_id
        || field_string(value, "action_digest")? != expected_action_digest
        || field_string(value, "source")? != EFFECT_WITNESS_SOURCE
        || !valid_identity(&field_string(value, "pre_state_id")?)
        || !valid_identity(&field_string(value, "state_id")?)
        || !(0..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "pre_generation")?)
        || !(0..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "generation")?)
        || field_i64(value, "generation")? <= field_i64(value, "pre_generation")?
    {
        return Err(FixtureError::Invalid("runtime witness relation".to_owned()));
    }
    validate_digest(&field_string(value, "action_digest")?)?;
    validate_digest(&field_string(value, "effect_digest")?)?;
    if !valid_timestamp(&field_string(value, "observed_at")?) {
        return Err(FixtureError::Invalid(
            "runtime witness timestamp".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_runtime_recovery(value: &Value) -> Result<(), FixtureError> {
    object_fields(value, &["kind", "operation_id"], &["kind", "operation_id"])?;
    let kind = field_string(value, "kind")?;
    if !matches!(
        kind.as_str(),
        "reobserve" | "reconcile" | "release_lease" | "stop_episode"
    ) {
        return Err(FixtureError::Invalid("runtime recovery kind".to_owned()));
    }
    if kind == "reconcile" {
        if !value["operation_id"].as_str().is_some_and(valid_identity) {
            return Err(FixtureError::Invalid("recovery operation".to_owned()));
        }
    } else if !value["operation_id"].is_null() {
        return Err(FixtureError::Invalid(
            "recovery operation relation".to_owned(),
        ));
    }
    Ok(())
}
