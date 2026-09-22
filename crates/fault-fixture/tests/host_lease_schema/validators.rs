//! Closed-shape and semantic validators for grants and acknowledgements.
//!
//! These preserve the exact rejection text and ordering of the original
//! single-file validator chain.

use serde_json::{Map, Value};

use crate::support::{MAX_SAFE_INTEGER, digest, exact_object, object, string, u64_value, uuid};
use crate::time::{timestamp, timestamp_key};

fn validate_release(value: &Value, context: &str) -> Result<(), String> {
    let map = exact_object(
        value,
        &[
            "release_digest",
            "config_digest",
            "profile_digest",
            "runtime_v3_schema_digest",
        ],
        context,
    )?;
    for field in [
        "release_digest",
        "config_digest",
        "profile_digest",
        "runtime_v3_schema_digest",
    ] {
        digest(string(map, field, context)?, &format!("{context}.{field}"))?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_grant(value: &Value) -> Result<(), String> {
    let grant = exact_object(
        value,
        &["boot", "fence", "lease", "release", "gateway"],
        "grant",
    )?;
    let boot = exact_object(
        grant.get("boot").ok_or("grant.boot missing")?,
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
        "grant.boot",
    )?;
    for field in ["deployment_id", "instance_id"] {
        uuid(
            string(boot, field, "grant.boot")?,
            false,
            &format!("grant.boot.{field}"),
        )?;
    }
    for field in ["instance_incarnation", "boot_id"] {
        uuid(
            string(boot, field, "grant.boot")?,
            true,
            &format!("grant.boot.{field}"),
        )?;
    }
    if u64_value(boot, "authority_generation", "grant.boot")? == 0
        || string(boot, "state", "grant.boot")? != "READY"
    {
        return Err("grant.boot is not a current READY authority".to_owned());
    }
    timestamp(
        string(boot, "created_at", "grant.boot")?,
        "grant.boot.created_at",
    )?;
    validate_release(
        boot.get("release").ok_or("grant.boot.release missing")?,
        "grant.boot.release",
    )?;

    let fence = exact_object(
        grant.get("fence").ok_or("grant.fence missing")?,
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
        "grant.fence",
    )?;
    for field in ["host_fence_id", "instance_incarnation", "boot_id"] {
        uuid(
            string(fence, field, "grant.fence")?,
            true,
            &format!("grant.fence.{field}"),
        )?;
    }
    for field in ["deployment_id", "instance_id"] {
        uuid(
            string(fence, field, "grant.fence")?,
            false,
            &format!("grant.fence.{field}"),
        )?;
    }
    for field in ["authority_generation", "fence_generation"] {
        if u64_value(fence, field, "grant.fence")? == 0 {
            return Err(format!("grant.fence.{field} must be positive"));
        }
    }
    timestamp(
        string(fence, "created_at", "grant.fence")?,
        "grant.fence.created_at",
    )?;

    let lease = exact_object(
        grant.get("lease").ok_or("grant.lease missing")?,
        &[
            "deployment_id",
            "instance_id",
            "instance_incarnation",
            "boot_id",
            "authority_generation",
            "host_fence_id",
            "host_fence_generation",
            "lease_id",
            "lease_epoch",
            "fence_token",
            "issued_at",
            "expires_at",
            "ttl_seconds",
            "renewal_interval_seconds",
        ],
        "grant.lease",
    )?;
    for field in ["deployment_id", "instance_id"] {
        uuid(
            string(lease, field, "grant.lease")?,
            false,
            &format!("grant.lease.{field}"),
        )?;
    }
    for field in [
        "instance_incarnation",
        "boot_id",
        "host_fence_id",
        "lease_id",
    ] {
        uuid(
            string(lease, field, "grant.lease")?,
            true,
            &format!("grant.lease.{field}"),
        )?;
    }
    for field in [
        "authority_generation",
        "host_fence_generation",
        "lease_epoch",
    ] {
        if u64_value(lease, field, "grant.lease")? == 0 {
            return Err(format!("grant.lease.{field} must be positive"));
        }
    }
    let token = string(lease, "fence_token", "grant.lease")?;
    if token.len() != 43
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("grant.lease.fence_token is outside its bound".to_owned());
    }
    let issued = timestamp_key(
        string(lease, "issued_at", "grant.lease")?,
        "grant.lease.issued_at",
    )?;
    let expires = timestamp_key(
        string(lease, "expires_at", "grant.lease")?,
        "grant.lease.expires_at",
    )?;
    if expires <= issued {
        return Err("grant.lease.expires_at must be after issued_at".to_owned());
    }
    let ttl = u64_value(lease, "ttl_seconds", "grant.lease")?;
    let renewal = u64_value(lease, "renewal_interval_seconds", "grant.lease")?;
    if !(1..=300).contains(&ttl) || renewal == 0 || renewal >= ttl {
        return Err("grant.lease policy is outside its bound".to_owned());
    }

    let gateway = exact_object(
        grant.get("gateway").ok_or("grant.gateway missing")?,
        &["principal_id", "instance_id", "session_id"],
        "grant.gateway",
    )?;
    uuid(
        string(gateway, "principal_id", "grant.gateway")?,
        false,
        "grant.gateway.principal_id",
    )?;
    uuid(
        string(gateway, "instance_id", "grant.gateway")?,
        false,
        "grant.gateway.instance_id",
    )?;
    uuid(
        string(gateway, "session_id", "grant.gateway")?,
        true,
        "grant.gateway.session_id",
    )?;
    validate_release(
        grant.get("release").ok_or("grant.release missing")?,
        "grant.release",
    )?;

    for field in [
        "deployment_id",
        "instance_id",
        "instance_incarnation",
        "boot_id",
        "authority_generation",
    ] {
        if grant["boot"][field] != grant["fence"][field]
            || grant["boot"][field] != grant["lease"][field]
        {
            return Err(format!("grant authority field mismatch: {field}"));
        }
    }
    for field in ["host_fence_id", "fence_generation"] {
        let lease_field = if field == "fence_generation" {
            "host_fence_generation"
        } else {
            field
        };
        if grant["fence"][field] != grant["lease"][lease_field] {
            return Err(format!("grant fence field mismatch: {field}"));
        }
    }
    if grant["boot"]["release"] != grant["release"]
        || grant["gateway"]["instance_id"] != grant["boot"]["instance_id"]
    {
        return Err("grant release or gateway instance mismatch".to_owned());
    }
    Ok(())
}

pub fn validate_bound_grant(value: &Value, principal: &str) -> Result<(), String> {
    validate_grant(value)?;
    let grant = object(value, "grant")?;
    let gateway = object(
        grant.get("gateway").ok_or("grant.gateway missing")?,
        "grant.gateway",
    )?;
    if string(gateway, "principal_id", "grant.gateway")? != principal {
        return Err("grant gateway principal does not match authenticated actor".to_owned());
    }
    Ok(())
}

fn validate_successful_renew_ack(ack: &Map<String, Value>) -> Result<(), String> {
    if ack["renew_sequence"]
        .as_u64()
        .is_none_or(|sequence| sequence == 0 || sequence > MAX_SAFE_INTEGER)
        || ack["expires_at"].as_str().is_none()
    {
        return Err("renew acknowledgment must echo sequence and expiry".to_owned());
    }
    timestamp(
        ack["expires_at"].as_str().ok_or("renew expiry missing")?,
        "ack.expires_at",
    )
}

pub fn validate_ack(value: &Value, kind: &str) -> Result<(), String> {
    let ack = exact_object(
        value,
        &[
            "result",
            "installation_id",
            "grant_digest",
            "boot_id",
            "instance_incarnation",
            "host_fence_id",
            "fence_generation",
            "lease_id",
            "lease_epoch",
            "host_install_generation",
            "recorded_at",
            "renew_sequence",
            "expires_at",
        ],
        "ack",
    )?;
    let result = exact_object(
        ack.get("result").ok_or("ack.result missing")?,
        &["status", "retryable", "retry_after_seconds"],
        "ack.result",
    )?;
    let status = string(result, "status", "ack.result")?;
    let expected = match kind {
        "lease_install_response" => ["INSTALLED", "DUPLICATE"].as_slice(),
        "lease_renew_response" => ["RENEWED", "RENEW_DUPLICATE"].as_slice(),
        "lease_revoke_response" => ["REVOKED", "REVOKE_DUPLICATE"].as_slice(),
        _ => return Err(format!("unsupported acknowledgment kind {kind}")),
    };
    let error_statuses = [
        "CONFLICT",
        "STALE_BOOT",
        "STALE_FENCE",
        "RELEASE_MISMATCH",
        "LEASE_MISMATCH",
        "EXPIRED",
        "AUTH_REQUIRED",
        "PERSISTENCE_UNAVAILABLE",
        "INVALID",
        "BOUNDS_EXCEEDED",
    ];
    if !expected.contains(&status) && !error_statuses.contains(&status) {
        return Err(format!("unexpected success fixture status {status}"));
    }
    let success = expected.contains(&status);
    if success {
        if result["retryable"] != Value::Bool(false) || !result["retry_after_seconds"].is_null() {
            return Err("successful acknowledgment must not request a retry".to_owned());
        }
    } else if result["retryable"].as_bool().is_none()
        || (!result["retry_after_seconds"].is_null()
            && result["retry_after_seconds"]
                .as_u64()
                .is_none_or(|value| value == 0 || value > MAX_SAFE_INTEGER))
    {
        return Err("error acknowledgment has an invalid retry hint".to_owned());
    }
    uuid(
        string(ack, "installation_id", "ack")?,
        true,
        "ack.installation_id",
    )?;
    digest(string(ack, "grant_digest", "ack")?, "ack.grant_digest")?;
    for field in [
        "boot_id",
        "instance_incarnation",
        "host_fence_id",
        "lease_id",
    ] {
        uuid(string(ack, field, "ack")?, true, &format!("ack.{field}"))?;
    }
    for field in ["fence_generation", "lease_epoch", "host_install_generation"] {
        if u64_value(ack, field, "ack")? == 0 {
            return Err(format!("ack.{field} must be positive"));
        }
    }
    timestamp(string(ack, "recorded_at", "ack")?, "ack.recorded_at")?;
    if kind == "lease_renew_response" && success {
        validate_successful_renew_ack(ack)?;
    } else if success {
        if !ack["renew_sequence"].is_null() {
            return Err("non-renew acknowledgment must not echo a renewal sequence".to_owned());
        }
        if kind == "lease_install_response" && ack["expires_at"].as_str().is_none() {
            return Err("install acknowledgment must echo expiry".to_owned());
        }
        if kind == "lease_revoke_response" && !ack["expires_at"].is_null() {
            return Err("revoke acknowledgment must clear expiry".to_owned());
        }
    }
    Ok(())
}
