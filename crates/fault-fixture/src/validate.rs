//! Recovery-contract validators for the synthetic fixture.
//!
//! Owns the bounded recovery payload/result checks and the boot, fence, lease,
//! operation, ticket, witness and receipt validators.  Extracted verbatim from
//! `lib.rs` by the recovery-validation, encoding-and-typed-errors split
//! (issue #79); the runtime-v3 validators remain in `lib.rs` (issue #78).

use serde_json::Value;

use crate::encoding::{decode_base64_strict, rcj_action_valid, sha256_hex};
use crate::wire::parse_value_no_duplicates;
use crate::{
    FixtureError, MAX_ACTION_BYTES, MAX_RUNTIME_INTEGER, field_i64, field_string, object_fields,
    valid_timestamp, valid_v4, validate_digest,
};

#[allow(clippy::too_many_lines)]
pub(crate) fn validate_recovery_payload(kind: &str, payload: &Value) -> Result<(), FixtureError> {
    match kind {
        "bootstrap_request" => {
            object_fields(
                payload,
                &[
                    "deployment_id",
                    "instance_id",
                    "instance_incarnation",
                    "release",
                    "lease_policy",
                ],
                &[
                    "deployment_id",
                    "instance_id",
                    "instance_incarnation",
                    "release",
                    "lease_policy",
                ],
            )?;
            let deployment = field_string(payload, "deployment_id")?;
            let instance = field_string(payload, "instance_id")?;
            let incarnation = field_string(payload, "instance_incarnation")?;
            valid_v4(&deployment)?;
            valid_v4(&instance)?;
            valid_v4(&incarnation)?;
            validate_release(
                payload
                    .get("release")
                    .ok_or_else(|| FixtureError::Invalid("release missing".to_owned()))?,
            )?;
            validate_policy(
                payload
                    .get("lease_policy")
                    .ok_or_else(|| FixtureError::Invalid("lease policy missing".to_owned()))?,
            )?;
        }
        "bootstrap_response" => {
            object_fields(
                payload,
                &["result", "boot", "fence"],
                &["result", "boot", "fence"],
            )?;
            validate_result(&payload["result"])?;
            if !payload["boot"].is_null() {
                validate_boot_context(&payload["boot"])?;
            }
            if !payload["fence"].is_null() {
                validate_host_fence(&payload["fence"])?;
            }
        }
        "host_fence_request" => {
            object_fields(payload, &["boot"], &["boot"])?;
            validate_boot_context(&payload["boot"])?;
        }
        "host_fence_response" => {
            object_fields(payload, &["result", "fence"], &["result", "fence"])?;
            validate_result(&payload["result"])?;
            if !payload["fence"].is_null() {
                validate_host_fence(&payload["fence"])?;
            }
        }
        "lease_acquire_request" => {
            object_fields(payload, &["boot", "fence"], &["boot", "fence"])?;
            validate_boot_context(&payload["boot"])?;
            validate_host_fence(&payload["fence"])?;
        }
        "lease_acquire_response" | "lease_renew_response" => {
            object_fields(payload, &["result", "lease"], &["result", "lease"])?;
            validate_result(&payload["result"])?;
            if !payload["lease"].is_null() {
                validate_lease_context(&payload["lease"])?;
            }
        }
        "lease_renew_request" => {
            object_fields(
                payload,
                &["lease", "renew_sequence"],
                &["lease", "renew_sequence"],
            )?;
            validate_lease_context(&payload["lease"])?;
            let sequence = field_i64(payload, "renew_sequence")?;
            if sequence < 1 {
                return Err(FixtureError::Invalid("renew sequence".to_owned()));
            }
        }
        "lease_revoke_request" => {
            object_fields(payload, &["lease", "reason"], &["lease", "reason"])?;
            validate_lease_context(&payload["lease"])?;
            let reason = field_string(payload, "reason")?;
            if !matches!(
                reason.as_str(),
                "operator" | "shutdown" | "incarnation_replaced" | "suspend_ambiguous" | "rekey"
            ) {
                return Err(FixtureError::Invalid("revoke reason".to_owned()));
            }
        }
        "lease_revoke_response" => {
            object_fields(payload, &["result"], &["result"])?;
            validate_result(&payload["result"])?;
        }
        "operation_intent_request" => {
            object_fields(payload, &["lease", "operation"], &["lease", "operation"])?;
            validate_lease_context(&payload["lease"])?;
            validate_operation_full(&payload["operation"])?;
        }
        "operation_intent_response" | "operation_dispatch_response" => {
            object_fields(payload, &["result", "operation"], &["result", "operation"])?;
            validate_result(&payload["result"])?;
            if !payload["operation"].is_null() {
                validate_operation_record(&payload["operation"])?;
            }
        }
        "operation_dispatch_request" => {
            object_fields(payload, &["lease", "operation"], &["lease", "operation"])?;
            validate_lease_context(&payload["lease"])?;
            validate_operation_ref(&payload["operation"])?;
        }
        "operation_lookup_request" => {
            object_fields(
                payload,
                &["operation", "lookup_scope"],
                &["operation", "lookup_scope"],
            )?;
            validate_operation_ref(&payload["operation"])?;
            if payload["lookup_scope"] != "historical_read" {
                return Err(FixtureError::Invalid("lookup scope".to_owned()));
            }
        }
        "operation_lookup_response" => {
            object_fields(
                payload,
                &["result", "operation", "mutation_authorized"],
                &["result", "operation", "mutation_authorized"],
            )?;
            validate_result(&payload["result"])?;
            if payload["mutation_authorized"] != false {
                return Err(FixtureError::Forbidden);
            }
            if !payload["operation"].is_null() {
                validate_operation_record(&payload["operation"])?;
            }
        }
        "operation_reconcile_request" => {
            object_fields(
                payload,
                &["operation", "strategy", "current_fence"],
                &["operation", "strategy", "current_fence"],
            )?;
            validate_operation_ref(&payload["operation"])?;
            validate_host_fence(&payload["current_fence"])?;
            let strategy = field_string(payload, "strategy")?;
            if !matches!(
                strategy.as_str(),
                "reobserve" | "receipt_lookup" | "quarantine"
            ) {
                return Err(FixtureError::Invalid("strategy".to_owned()));
            }
        }
        "operation_reconcile_response" => {
            object_fields(
                payload,
                &["result", "operation", "witness"],
                &["result", "operation", "witness"],
            )?;
            validate_result(&payload["result"])?;
            if !payload["operation"].is_null() {
                validate_operation_record(&payload["operation"])?;
            }
            if !payload["witness"].is_null() {
                validate_effect_witness(&payload["witness"], "", "")?;
            }
        }
        _ => {
            return Err(FixtureError::Invalid(
                "unsupported recovery payload".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_result(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["status", "retryable", "retry_after_seconds"],
        &["status", "retryable", "retry_after_seconds"],
    )?;
    let status = field_string(value, "status")?;
    if !matches!(
        status.as_str(),
        "BOOT_AUTHORITY_CREATED"
            | "BOOT_READY"
            | "BOOT_BLOCKED"
            | "FENCE_ACCEPTED"
            | "FENCE_REJECTED"
            | "LEASE_ACTIVE"
            | "LEASE_RENEWED"
            | "LEASE_REVOKED"
            | "INTENT_RECORDED"
            | "MAY_HAVE_BEEN_DISPATCHED"
            | "ACCEPTED"
            | "SETTLED"
            | "REJECTED"
            | "UNKNOWN"
            | "RECONCILED"
            | "DUPLICATE"
            | "CONFLICT"
            | "NOT_FOUND"
            | "STALE_BOOT"
            | "STALE_INCARNATION"
            | "STALE_LEASE"
            | "LEASE_EXPIRED"
            | "AUTH_REQUIRED"
            | "FORBIDDEN"
            | "CONTRACT_MISMATCH"
            | "PERSISTENCE_UNAVAILABLE"
            | "HOST_NOT_READY"
            | "BOUNDS_EXCEEDED"
            | "INVALID"
            | "BUSY"
    ) {
        return Err(FixtureError::Invalid("response status".to_owned()));
    }
    if !value["retryable"].is_boolean()
        || (!value["retry_after_seconds"].is_null()
            && (value["retry_after_seconds"].as_i64().unwrap_or(0) < 1))
    {
        return Err(FixtureError::Invalid("response retry metadata".to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_release(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "release_digest",
            "config_digest",
            "profile_digest",
            "runtime_v3_schema_digest",
        ],
        &[
            "release_digest",
            "config_digest",
            "profile_digest",
            "runtime_v3_schema_digest",
        ],
    )?;
    for name in [
        "release_digest",
        "config_digest",
        "profile_digest",
        "runtime_v3_schema_digest",
    ] {
        validate_digest(&field_string(value, name)?)?;
    }
    Ok(())
}

pub(crate) fn validate_policy(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["ttl_seconds", "renewal_interval_seconds"],
        &["ttl_seconds", "renewal_interval_seconds"],
    )?;
    let ttl = field_i64(value, "ttl_seconds")?;
    let renewal = field_i64(value, "renewal_interval_seconds")?;
    validate_lease_policy_values(ttl, renewal)
}

pub(crate) fn validate_lease_policy_values(ttl: i64, renewal: i64) -> Result<(), FixtureError> {
    if !(5..=300).contains(&ttl) || !(1..=100).contains(&renewal) || renewal >= ttl {
        return Err(FixtureError::Invalid("lease policy".to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_boot_context(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "deployment_id",
            "instance_id",
            "instance_incarnation",
            "boot_id",
            "authority_generation",
            "release",
            "created_at",
            "state",
        ],
        &[
            "deployment_id",
            "instance_id",
            "instance_incarnation",
            "boot_id",
            "authority_generation",
            "release",
            "created_at",
            "state",
        ],
    )?;
    valid_v4(&field_string(value, "deployment_id")?)?;
    valid_v4(&field_string(value, "instance_id")?)?;
    valid_v4(&field_string(value, "instance_incarnation")?)?;
    valid_v4(&field_string(value, "boot_id")?)?;
    if !(1..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "authority_generation")?)
        || !valid_timestamp(&field_string(value, "created_at")?)
    {
        return Err(FixtureError::Invalid("boot context".to_owned()));
    }
    validate_release(&value["release"])?;
    if !matches!(
        field_string(value, "state")?.as_str(),
        "FENCE_REQUIRED" | "READY" | "BLOCKED" | "REVOKED"
    ) {
        return Err(FixtureError::Invalid("boot state".to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_host_fence(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "host_fence_id",
            "deployment_id",
            "instance_id",
            "instance_incarnation",
            "boot_id",
            "authority_generation",
            "fence_generation",
            "created_at",
        ],
        &[
            "host_fence_id",
            "deployment_id",
            "instance_id",
            "instance_incarnation",
            "boot_id",
            "authority_generation",
            "fence_generation",
            "created_at",
        ],
    )?;
    for name in [
        "host_fence_id",
        "deployment_id",
        "instance_id",
        "instance_incarnation",
        "boot_id",
    ] {
        valid_v4(&field_string(value, name)?)?;
    }
    if !(1..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "authority_generation")?)
        || !(1..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "fence_generation")?)
        || !valid_timestamp(&field_string(value, "created_at")?)
    {
        return Err(FixtureError::Invalid("host fence".to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_lease_context(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "deployment_id",
            "instance_id",
            "instance_incarnation",
            "boot_id",
            "authority_generation",
            "lease_id",
            "lease_epoch",
            "fence_token",
            "issued_at",
            "expires_at",
            "ttl_seconds",
            "renewal_interval_seconds",
        ],
        &[
            "deployment_id",
            "instance_id",
            "instance_incarnation",
            "boot_id",
            "authority_generation",
            "lease_id",
            "lease_epoch",
            "fence_token",
            "issued_at",
            "expires_at",
            "ttl_seconds",
            "renewal_interval_seconds",
        ],
    )?;
    for name in [
        "deployment_id",
        "instance_id",
        "instance_incarnation",
        "boot_id",
        "lease_id",
    ] {
        valid_v4(&field_string(value, name)?)?;
    }
    let token = field_string(value, "fence_token")?;
    if token.len() != 43
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(FixtureError::Invalid("fence token".to_owned()));
    }
    if !(1..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "authority_generation")?)
        || !(1..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "lease_epoch")?)
        || !valid_timestamp(&field_string(value, "issued_at")?)
        || !valid_timestamp(&field_string(value, "expires_at")?)
    {
        return Err(FixtureError::Invalid("lease context".to_owned()));
    }
    let ttl = field_i64(value, "ttl_seconds")?;
    let renewal = field_i64(value, "renewal_interval_seconds")?;
    validate_lease_policy_values(ttl, renewal)
}

pub(crate) fn validate_original_context(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "deployment_id",
            "instance_id",
            "instance_incarnation",
            "boot_id",
            "authority_generation",
            "lease_id",
            "lease_epoch",
        ],
        &[
            "deployment_id",
            "instance_id",
            "instance_incarnation",
            "boot_id",
            "authority_generation",
            "lease_id",
            "lease_epoch",
        ],
    )?;
    for name in [
        "deployment_id",
        "instance_id",
        "instance_incarnation",
        "boot_id",
        "lease_id",
    ] {
        valid_v4(&field_string(value, name)?)?;
    }
    if !(1..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "authority_generation")?)
        || !(1..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "lease_epoch")?)
    {
        return Err(FixtureError::Invalid("original context".to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_expected_boundary(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["state_id", "generation", "catalog_digest"],
        &["state_id", "generation", "catalog_digest"],
    )?;
    valid_v4(&field_string(value, "state_id")?)?;
    if !(0..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "generation")?) {
        return Err(FixtureError::Invalid("boundary generation".to_owned()));
    }
    validate_digest(&field_string(value, "catalog_digest")?)
}

pub(crate) fn validate_operation_full(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "operation_id",
            "payload_digest",
            "original_context",
            "expected_boundary",
            "action",
        ],
        &[
            "operation_id",
            "payload_digest",
            "original_context",
            "expected_boundary",
            "action",
        ],
    )?;
    valid_v4(&field_string(value, "operation_id")?)?;
    let payload_digest = field_string(value, "payload_digest")?;
    validate_digest(&payload_digest)?;
    validate_original_context(&value["original_context"])?;
    validate_expected_boundary(&value["expected_boundary"])?;
    validate_v3_action(&value["action"], Some(&payload_digest))
}

pub(crate) fn validate_operation_ref(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["operation_id", "payload_digest", "original_context"],
        &["operation_id", "payload_digest", "original_context"],
    )?;
    valid_v4(&field_string(value, "operation_id")?)?;
    validate_digest(&field_string(value, "payload_digest")?)?;
    validate_original_context(&value["original_context"])
}

pub(crate) fn validate_operation_context(
    operation: &Value,
    lease: &Value,
) -> Result<(), FixtureError> {
    let context = operation
        .get("original_context")
        .ok_or_else(|| FixtureError::Invalid("original context missing".to_owned()))?;
    for name in [
        "deployment_id",
        "instance_id",
        "instance_incarnation",
        "boot_id",
        "authority_generation",
        "lease_id",
        "lease_epoch",
    ] {
        if context[name] != lease[name] {
            return Err(FixtureError::Stale("lease"));
        }
    }
    Ok(())
}

pub(crate) fn validate_v3_action(
    value: &Value,
    expected_digest: Option<&String>,
) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["schema_digest", "canonical_json_b64", "payload_digest"],
        &["schema_digest", "canonical_json_b64", "payload_digest"],
    )?;
    validate_digest(&field_string(value, "schema_digest")?)?;
    let encoded = field_string(value, "canonical_json_b64")?;
    if encoded.is_empty() || encoded.len() > MAX_ACTION_BYTES {
        return Err(FixtureError::Bounds("canonical action"));
    }
    let bytes = decode_base64_strict(&encoded)
        .ok_or_else(|| FixtureError::Invalid("canonical action base64".to_owned()))?;
    if bytes.len() > MAX_ACTION_BYTES || !rcj_action_valid(&bytes) {
        return Err(FixtureError::Invalid("canonical action".to_owned()));
    }
    let digest_value = field_string(value, "payload_digest")?;
    validate_digest(&digest_value)?;
    if sha256_hex(&bytes) != digest_value
        || expected_digest.is_some_and(|expected| expected != &digest_value)
    {
        return Err(FixtureError::Conflict);
    }
    Ok(())
}

pub(crate) fn validate_operation_record(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "operation_id",
            "state",
            "payload_digest",
            "original_context",
            "expected_boundary",
            "action",
            "ticket",
            "witness",
            "uncertainty_reason",
            "created_at",
            "updated_at",
        ],
        &[
            "operation_id",
            "state",
            "payload_digest",
            "original_context",
            "expected_boundary",
            "action",
            "ticket",
            "witness",
            "uncertainty_reason",
            "created_at",
            "updated_at",
        ],
    )?;
    valid_v4(&field_string(value, "operation_id")?)?;
    let payload_digest = field_string(value, "payload_digest")?;
    validate_digest(&payload_digest)?;
    validate_original_context(&value["original_context"])?;
    validate_expected_boundary(&value["expected_boundary"])?;
    validate_v3_action(&value["action"], Some(&payload_digest))?;
    if !value["ticket"].is_null() {
        validate_ticket_shape(&value["ticket"])?;
    }
    if !value["witness"].is_null() {
        validate_effect_witness(
            &value["witness"],
            &field_string(value, "operation_id")?,
            &payload_digest,
        )?;
    }
    if !value["uncertainty_reason"].is_null()
        && !matches!(
            value["uncertainty_reason"].as_str(),
            Some(
                "transport_lost"
                    | "timeout"
                    | "gateway_crash"
                    | "host_crash"
                    | "receipt_missing"
                    | "authority_rotated"
            )
        )
    {
        return Err(FixtureError::Invalid("uncertainty reason".to_owned()));
    }
    if !valid_timestamp(&field_string(value, "created_at")?)
        || !valid_timestamp(&field_string(value, "updated_at")?)
    {
        return Err(FixtureError::Invalid("operation timestamps".to_owned()));
    }
    if !matches!(
        field_string(value, "state")?.as_str(),
        "INTENT_RECORDED"
            | "MAY_HAVE_BEEN_DISPATCHED"
            | "ACCEPTED"
            | "SETTLED"
            | "REJECTED"
            | "UNKNOWN"
            | "RECONCILED"
    ) {
        return Err(FixtureError::Invalid("operation state".to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_ticket_shape(value: &Value) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "ticket_id",
            "operation_id",
            "payload_digest",
            "boot_id",
            "instance_incarnation",
            "lease_epoch",
            "host_fence_id",
            "state",
            "issued_at",
            "expires_at",
        ],
        &[
            "ticket_id",
            "operation_id",
            "payload_digest",
            "boot_id",
            "instance_incarnation",
            "lease_epoch",
            "host_fence_id",
            "state",
            "issued_at",
            "expires_at",
        ],
    )?;
    for name in [
        "ticket_id",
        "operation_id",
        "boot_id",
        "instance_incarnation",
        "host_fence_id",
    ] {
        valid_v4(&field_string(value, name)?)?;
    }
    validate_digest(&field_string(value, "payload_digest")?)?;
    if !(1..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "lease_epoch")?)
        || !valid_timestamp(&field_string(value, "issued_at")?)
        || !valid_timestamp(&field_string(value, "expires_at")?)
    {
        return Err(FixtureError::Invalid("ticket".to_owned()));
    }
    if !matches!(
        field_string(value, "state")?.as_str(),
        "ISSUED"
            | "ADMITTED"
            | "EXECUTING"
            | "EFFECT_WITNESS_RECORDED"
            | "SETTLED"
            | "REJECTED"
            | "UNKNOWN"
    ) {
        return Err(FixtureError::Invalid("ticket state".to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_ticket(
    value: &Value,
    id: &str,
    payload_digest: &str,
    context_json: &str,
) -> Result<(), FixtureError> {
    validate_ticket_shape(value)?;
    if field_string(value, "operation_id")? != id
        || field_string(value, "payload_digest")? != payload_digest
    {
        return Err(FixtureError::Conflict);
    }
    let context: Value = parse_value_no_duplicates(context_json.as_bytes())?;
    for name in ["instance_incarnation", "boot_id", "lease_epoch"] {
        if value[name] != context[name] {
            return Err(FixtureError::Stale("lease"));
        }
    }
    Ok(())
}

pub(crate) fn validate_effect_witness(
    value: &Value,
    expected_id: &str,
    expected_digest: &str,
) -> Result<(), FixtureError> {
    object_fields(
        value,
        &[
            "witness_id",
            "operation_id",
            "payload_digest",
            "boot_id",
            "instance_incarnation",
            "host_fence_id",
            "source",
            "state_id",
            "generation",
            "effect_digest",
            "observed_at",
        ],
        &[
            "witness_id",
            "operation_id",
            "payload_digest",
            "boot_id",
            "instance_incarnation",
            "host_fence_id",
            "source",
            "state_id",
            "generation",
            "effect_digest",
            "observed_at",
        ],
    )?;
    for name in [
        "witness_id",
        "operation_id",
        "boot_id",
        "instance_incarnation",
        "host_fence_id",
        "state_id",
    ] {
        valid_v4(&field_string(value, name)?)?;
    }
    let payload_digest = field_string(value, "payload_digest")?;
    validate_digest(&payload_digest)?;
    if (!expected_id.is_empty() && field_string(value, "operation_id")? != expected_id)
        || (!expected_digest.is_empty() && payload_digest != expected_digest)
    {
        return Err(FixtureError::Conflict);
    }
    if !matches!(
        field_string(value, "source")?.as_str(),
        "host_game_thread" | "host_receipt" | "authoritative_reobserve"
    ) || !(0..=MAX_RUNTIME_INTEGER).contains(&field_i64(value, "generation")?)
        || !valid_timestamp(&field_string(value, "observed_at")?)
    {
        return Err(FixtureError::Invalid("effect witness".to_owned()));
    }
    validate_digest(&field_string(value, "effect_digest")?)
}

pub(crate) fn validate_receipt(
    value: &Value,
    witness: &Value,
    id: &str,
    payload_digest: &str,
) -> Result<(), FixtureError> {
    object_fields(
        value,
        &["operation_id", "payload_digest", "status", "effect_witness"],
        &["operation_id", "payload_digest", "status", "effect_witness"],
    )?;
    if field_string(value, "operation_id")? != id
        || field_string(value, "payload_digest")? != payload_digest
        || field_string(value, "status")? != "settled"
        || value["effect_witness"] != *witness
    {
        return Err(FixtureError::Conflict);
    }
    Ok(())
}
