//! Executable conformance checks for the additive host lease-control artifact.
//!
//! The workspace intentionally has no JSON-Schema runtime dependency. These
//! tests therefore check the published schema metadata and the bounded closed
//! shapes used by this artifact, then exercise the semantic rules that JSON
//! Schema cannot express (digest and identity binding, time ordering, and
//! duplicate acknowledgment lineage).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as FmtWrite};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::{Uuid, Variant};

const CONTRACT: &str = "watchdog-host-lease-control-v1";
const SCHEMA_DIGEST: &str = "e22faf0f7d3cd313a007b65e52058b3c255153d5778dd8124055c283adf977f9";
const MAX_FRAME_BYTES: usize = 262_144;
const MAX_PROOF_BYTES: usize = 512;

fn artifact_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("schemas/host-lease-control-v1")
}

fn read_json(relative: &str) -> Result<Value, String> {
    let path = artifact_root().join(relative);
    let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))
}

fn read_bytes(relative: &str) -> Result<Vec<u8>, String> {
    let path = artifact_root().join(relative);
    fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))
}

fn object<'a>(value: &'a Value, context: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{context} must be an object"))
}

fn exact_object<'a>(
    value: &'a Value,
    fields: &[&str],
    context: &str,
) -> Result<&'a Map<String, Value>, String> {
    let map = object(value, context)?;
    if map.len() != fields.len() || fields.iter().any(|field| !map.contains_key(*field)) {
        return Err(format!("{context} has an unexpected or missing field"));
    }
    Ok(map)
}

fn string<'a>(map: &'a Map<String, Value>, field: &str, context: &str) -> Result<&'a str, String> {
    map.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{context}.{field} must be a string"))
}

fn u64_value(map: &Map<String, Value>, field: &str, context: &str) -> Result<u64, String> {
    map.get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{context}.{field} must be an unsigned integer"))
}

fn uuid(value: &str, random: bool, context: &str) -> Result<(), String> {
    let parsed = Uuid::parse_str(value).map_err(|_| format!("{context} is not a UUID"))?;
    if parsed.hyphenated().to_string() != value || parsed.get_variant() != Variant::RFC4122 {
        return Err(format!("{context} is not lowercase RFC4122 form"));
    }
    if random && parsed.get_version_num() != 4 {
        return Err(format!("{context} is not UUIDv4"));
    }
    Ok(())
}

fn digest(value: &str, context: &str) -> Result<(), String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{context} is not a lowercase SHA-256 digest"));
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(format!("{context} is not lowercase"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct TimestampKey {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    nanosecond: u32,
}

fn digits(bytes: &[u8], context: &str) -> Result<u32, String> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(format!("{context} contains non-digit timestamp fields"));
    }
    Ok(bytes
        .iter()
        .fold(0_u32, |value, byte| value * 10 + u32::from(byte - b'0')))
}

fn timestamp_key(value: &str, context: &str) -> Result<TimestampKey, String> {
    let bytes = value.as_bytes();
    if !(20..=30).contains(&bytes.len())
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || bytes.last() != Some(&b'Z')
    {
        return Err(format!("{context} is not a UTC timestamp"));
    }
    let year = u16::try_from(digits(&bytes[0..4], context)?)
        .map_err(|_| format!("{context} year is out of range"))?;
    let month = u8::try_from(digits(&bytes[5..7], context)?)
        .map_err(|_| format!("{context} month is out of range"))?;
    let day = u8::try_from(digits(&bytes[8..10], context)?)
        .map_err(|_| format!("{context} day is out of range"))?;
    let hour = u8::try_from(digits(&bytes[11..13], context)?)
        .map_err(|_| format!("{context} hour is out of range"))?;
    let minute = u8::try_from(digits(&bytes[14..16], context)?)
        .map_err(|_| format!("{context} minute is out of range"))?;
    let second = u8::try_from(digits(&bytes[17..19], context)?)
        .map_err(|_| format!("{context} second is out of range"))?;
    if !(1..=12).contains(&month) || !(0..=23).contains(&hour) || minute > 59 || second > 59 {
        return Err(format!(
            "{context} contains an out-of-range timestamp field"
        ));
    }
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days_in_month = match month {
        2 if leap_year => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day == 0 || day > days_in_month {
        return Err(format!("{context} contains an out-of-range calendar day"));
    }
    let nanosecond = if bytes.len() == 20 {
        0
    } else {
        if bytes[19] != b'.' || !(1..=9).contains(&(bytes.len() - 21)) {
            return Err(format!("{context} has an invalid fractional second"));
        }
        let fraction = &bytes[20..bytes.len() - 1];
        if !fraction.iter().all(u8::is_ascii_digit) {
            return Err(format!("{context} has an invalid fractional second"));
        }
        let mut value = digits(fraction, context)?;
        for _ in 0..(9 - fraction.len()) {
            value *= 10;
        }
        value
    };
    Ok(TimestampKey {
        year,
        month,
        day,
        hour,
        minute,
        second,
        nanosecond,
    })
}

fn timestamp(value: &str, context: &str) -> Result<(), String> {
    timestamp_key(value, context).map(|_| ())
}

fn canonical(value: &Value) -> Result<String, String> {
    match value {
        Value::Null => Ok("null".to_owned()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(number) => {
            if number.is_u64() {
                Ok(number.to_string())
            } else {
                Err("HCJ-1 forbids non-u64 numbers".to_owned())
            }
        }
        Value::String(value) => serde_json::to_string(value).map_err(|error| error.to_string()),
        Value::Array(values) => {
            let mut result = String::from("[");
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    result.push(',');
                }
                result.push_str(&canonical(value)?);
            }
            result.push(']');
            Ok(result)
        }
        Value::Object(values) => {
            let mut keys: Vec<&String> = values.keys().collect();
            keys.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            let mut result = String::from("{");
            for (index, key) in keys.iter().enumerate() {
                if index != 0 {
                    result.push(',');
                }
                result.push_str(&serde_json::to_string(key).map_err(|error| error.to_string())?);
                result.push(':');
                result.push_str(&canonical(&values[*key])?);
            }
            result.push('}');
            Ok(result)
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

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

fn validate_bound_grant(value: &Value, principal: &str) -> Result<(), String> {
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

fn validate_ack(value: &Value, kind: &str) -> Result<(), String> {
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
                .is_none_or(|value| value == 0))
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
        if ack["renew_sequence"].as_u64().is_none() || ack["expires_at"].as_str().is_none() {
            return Err("renew acknowledgment must echo sequence and expiry".to_owned());
        }
        timestamp(
            ack["expires_at"].as_str().ok_or("renew expiry missing")?,
            "ack.expires_at",
        )?;
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

#[allow(clippy::too_many_lines)]
fn validate_frame(value: &Value, expected_kind: &str) -> Result<(), String> {
    let frame = exact_object(
        value,
        &[
            "contract",
            "schema_digest",
            "message_id",
            "correlation_id",
            "sent_at",
            "actor",
            "auth",
            "kind",
            "payload",
        ],
        "frame",
    )?;
    if string(frame, "contract", "frame")? != CONTRACT
        || string(frame, "schema_digest", "frame")? != SCHEMA_DIGEST
        || string(frame, "kind", "frame")? != expected_kind
    {
        return Err("frame contract, digest, or kind mismatch".to_owned());
    }
    for field in ["message_id", "correlation_id"] {
        uuid(
            string(frame, field, "frame")?,
            true,
            &format!("frame.{field}"),
        )?;
    }
    timestamp(string(frame, "sent_at", "frame")?, "frame.sent_at")?;
    let actor = exact_object(
        frame.get("actor").ok_or("frame.actor missing")?,
        &["principal_id", "role"],
        "actor",
    )?;
    uuid(
        string(actor, "principal_id", "actor")?,
        false,
        "actor.principal_id",
    )?;
    let auth = exact_object(
        frame.get("auth").ok_or("frame.auth missing")?,
        &["principal_id", "capability", "proof"],
        "auth",
    )?;
    uuid(
        string(auth, "principal_id", "auth")?,
        false,
        "auth.principal_id",
    )?;
    if string(actor, "principal_id", "actor")? != string(auth, "principal_id", "auth")? {
        return Err("actor/auth principal mismatch".to_owned());
    }
    if string(actor, "role", "actor")?
        != if expected_kind.ends_with("_request") {
            "gateway"
        } else {
            "host"
        }
    {
        return Err("unexpected actor role".to_owned());
    }
    let capability = match expected_kind {
        "lease_install_request" | "lease_install_response" => "lease_install",
        "lease_renew_request" | "lease_renew_response" => "lease_renew",
        "lease_revoke_request" | "lease_revoke_response" => "lease_revoke",
        _ => return Err("unknown lease-control kind".to_owned()),
    };
    if string(auth, "capability", "auth")? != capability {
        return Err("capability does not match kind".to_owned());
    }
    let proof = string(auth, "proof", "auth")?;
    if proof.is_empty() || proof.len() > MAX_PROOF_BYTES || !proof.is_ascii() {
        return Err("authentication proof is outside its bound".to_owned());
    }
    let payload = object(
        frame.get("payload").ok_or("frame.payload missing")?,
        "payload",
    )?;
    match expected_kind {
        "lease_install_request" => {
            if payload.len() != 3
                || !["installation_id", "grant", "grant_digest"]
                    .iter()
                    .all(|field| payload.contains_key(*field))
            {
                return Err("install request payload is not closed".to_owned());
            }
            uuid(
                payload["installation_id"]
                    .as_str()
                    .ok_or("installation id missing")?,
                true,
                "installation_id",
            )?;
            digest(
                payload["grant_digest"]
                    .as_str()
                    .ok_or("grant digest missing")?,
                "grant_digest",
            )?;
            validate_bound_grant(&payload["grant"], string(auth, "principal_id", "auth")?)
        }
        "lease_renew_request" => {
            if payload.len() != 4
                || !["installation_id", "grant", "grant_digest", "renew_sequence"]
                    .iter()
                    .all(|field| payload.contains_key(*field))
            {
                return Err("renew request payload is not closed".to_owned());
            }
            uuid(
                payload["installation_id"]
                    .as_str()
                    .ok_or("installation id missing")?,
                true,
                "installation_id",
            )?;
            digest(
                payload["grant_digest"]
                    .as_str()
                    .ok_or("grant digest missing")?,
                "grant_digest",
            )?;
            if payload["renew_sequence"]
                .as_u64()
                .is_none_or(|sequence| sequence == 0)
            {
                return Err("renew sequence must be positive".to_owned());
            }
            validate_bound_grant(&payload["grant"], string(auth, "principal_id", "auth")?)
        }
        "lease_revoke_request" => {
            if payload.len() != 4
                || !["installation_id", "grant", "grant_digest", "reason"]
                    .iter()
                    .all(|field| payload.contains_key(*field))
            {
                return Err("revoke request payload is not closed".to_owned());
            }
            uuid(
                payload["installation_id"]
                    .as_str()
                    .ok_or("installation id missing")?,
                true,
                "installation_id",
            )?;
            digest(
                payload["grant_digest"]
                    .as_str()
                    .ok_or("grant digest missing")?,
                "grant_digest",
            )?;
            if ![
                "operator",
                "shutdown",
                "incarnation_replaced",
                "suspend_ambiguous",
                "rekey",
            ]
            .contains(&payload["reason"].as_str().ok_or("reason missing")?)
            {
                return Err("invalid revoke reason".to_owned());
            }
            validate_bound_grant(&payload["grant"], string(auth, "principal_id", "auth")?)
        }
        kind if kind.ends_with("_response") => {
            if payload.len() != 1 || !payload.contains_key("ack") {
                return Err("response payload is not closed".to_owned());
            }
            validate_ack(&payload["ack"], expected_kind)
        }
        _ => Err("unknown lease-control kind".to_owned()),
    }
}

fn validate_request_semantics(value: &Value, kind: &str) -> Result<(), String> {
    validate_frame(value, kind)?;
    let frame = object(value, "frame")?;
    let payload = object(frame.get("payload").ok_or("payload missing")?, "payload")?;
    let grant = payload.get("grant").ok_or("grant missing")?;
    let digest_value = payload["grant_digest"]
        .as_str()
        .ok_or("grant digest missing")?;
    let canonical = canonical(grant)?;
    if sha256_hex(canonical.as_bytes()) != digest_value {
        return Err("grant digest does not cover canonical grant bytes".to_owned());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReferenceStatus {
    Installed,
    Duplicate,
    Renewed,
    RenewDuplicate,
    Revoked,
    RevokeDuplicate,
    Conflict,
    Missing,
    Expired,
    Invalid,
}

#[derive(Clone, Debug)]
struct PreparedRequest {
    installation_id: String,
    grant_digest: String,
    persisted_grant: Value,
    renewal_identity: Value,
    token_digest: String,
    lease_id: String,
    expires: TimestampKey,
    sequence: Option<u64>,
    reason: Option<String>,
}

#[derive(Clone, Debug)]
struct StoredInstallation {
    initial_grant_digest: String,
    initial_persisted_grant: Value,
    current_grant_digest: String,
    current_persisted_grant: Value,
    current_renewal_identity: Value,
    token_digest: String,
    lease_id: String,
    expires: TimestampKey,
    renewal_sequence: u64,
    active: bool,
    revoked_reason: Option<String>,
    deadline: Option<u64>,
}

#[derive(Default)]
struct ReferenceHost {
    installations: BTreeMap<String, StoredInstallation>,
    lease_installations: BTreeMap<String, String>,
}

fn persisted_grant(value: &Value) -> Result<(Value, String), String> {
    let mut persisted = value.clone();
    let grant = persisted.as_object_mut().ok_or("grant must be an object")?;
    let lease = grant
        .get_mut("lease")
        .and_then(Value::as_object_mut)
        .ok_or("grant.lease must be an object")?;
    let token = lease
        .get("fence_token")
        .and_then(Value::as_str)
        .ok_or("grant.lease.fence_token missing")?
        .to_owned();
    lease.remove("fence_token");
    let token_digest = sha256_hex(token.as_bytes());
    lease.insert(
        "fence_token_digest".to_owned(),
        Value::String(token_digest.clone()),
    );
    Ok((persisted, token_digest))
}

fn renewal_identity(value: &Value) -> Result<Value, String> {
    let (mut persisted, _) = persisted_grant(value)?;
    persisted
        .get_mut("lease")
        .and_then(Value::as_object_mut)
        .ok_or("persisted grant.lease missing")?
        .remove("expires_at");
    Ok(persisted)
}

fn request_parts<'a>(value: &'a Value, kind: &str) -> Result<&'a Map<String, Value>, String> {
    validate_request_semantics(value, kind)?;
    let frame = object(value, "frame")?;
    object(frame.get("payload").ok_or("payload missing")?, "payload")
}

fn prepare_request(value: &Value, kind: &str) -> Result<PreparedRequest, String> {
    let payload = request_parts(value, kind)?;
    let grant = payload.get("grant").ok_or("grant missing")?;
    let (persisted, token_digest) = persisted_grant(grant)?;
    let expires = timestamp_key(
        string(
            object(
                grant.get("lease").ok_or("grant.lease missing")?,
                "grant.lease",
            )?,
            "expires_at",
            "grant.lease",
        )?,
        "grant.lease.expires_at",
    )?;
    let lease = object(
        grant.get("lease").ok_or("grant.lease missing")?,
        "grant.lease",
    )?;
    let sequence = payload.get("renew_sequence").and_then(Value::as_u64);
    let reason = payload
        .get("reason")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    Ok(PreparedRequest {
        installation_id: string(payload, "installation_id", "payload")?.to_owned(),
        grant_digest: string(payload, "grant_digest", "payload")?.to_owned(),
        renewal_identity: renewal_identity(grant)?,
        persisted_grant: persisted,
        token_digest,
        lease_id: string(lease, "lease_id", "grant.lease")?.to_owned(),
        expires,
        sequence,
        reason,
    })
}

fn days_in_month(year: u16, month: u8) -> u8 {
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    match month {
        2 if leap_year => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn wall_seconds(value: TimestampKey) -> i64 {
    let mut days = 0_i64;
    for year in 0..value.year {
        days += if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
            366
        } else {
            365
        };
    }
    for month in 1..value.month {
        days += i64::from(days_in_month(value.year, month));
    }
    days += i64::from(value.day - 1);
    days * 86_400
        + i64::from(value.hour) * 3_600
        + i64::from(value.minute) * 60
        + i64::from(value.second)
}

fn derive_deadline(
    received_at_wall: TimestampKey,
    expires: TimestampKey,
    ttl_seconds: u64,
    received_at_monotonic: u64,
) -> Result<u64, String> {
    let remaining = wall_seconds(expires) - wall_seconds(received_at_wall);
    if remaining <= 0 {
        return Err("grant is expired at receipt".to_owned());
    }
    let remaining = u64::try_from(remaining).map_err(|_| "remaining deadline overflow")?;
    received_at_monotonic
        .checked_add(remaining.min(ttl_seconds))
        .ok_or_else(|| "monotonic deadline overflow".to_owned())
}

impl ReferenceHost {
    fn install(
        &mut self,
        request: &Value,
        received_at: &str,
        received_at_monotonic: u64,
    ) -> ReferenceStatus {
        let Ok(prepared) = prepare_request(request, "lease_install_request") else {
            return ReferenceStatus::Invalid;
        };
        let Ok(received) = timestamp_key(received_at, "received_at") else {
            return ReferenceStatus::Invalid;
        };
        let ttl = request
            .pointer("/payload/grant/lease/ttl_seconds")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let Ok(deadline) = derive_deadline(received, prepared.expires, ttl, received_at_monotonic)
        else {
            return ReferenceStatus::Expired;
        };
        if let Some(existing) = self.installations.get_mut(&prepared.installation_id) {
            if existing.initial_grant_digest == prepared.grant_digest
                && existing.initial_persisted_grant == prepared.persisted_grant
            {
                if !existing.active {
                    existing.active = true;
                    existing.deadline = Some(deadline);
                    return ReferenceStatus::Installed;
                }
                return ReferenceStatus::Duplicate;
            }
            return ReferenceStatus::Conflict;
        }
        if self.lease_installations.contains_key(&prepared.lease_id) {
            return ReferenceStatus::Conflict;
        }
        let stored = StoredInstallation {
            initial_grant_digest: prepared.grant_digest.clone(),
            initial_persisted_grant: prepared.persisted_grant.clone(),
            current_grant_digest: prepared.grant_digest.clone(),
            current_persisted_grant: prepared.persisted_grant,
            current_renewal_identity: prepared.renewal_identity,
            token_digest: prepared.token_digest,
            lease_id: prepared.lease_id.clone(),
            expires: prepared.expires,
            renewal_sequence: 0,
            active: true,
            revoked_reason: None,
            deadline: Some(deadline),
        };
        self.lease_installations
            .insert(prepared.lease_id, prepared.installation_id.clone());
        self.installations.insert(prepared.installation_id, stored);
        ReferenceStatus::Installed
    }

    fn renew(
        &mut self,
        request: &Value,
        received_at: &str,
        received_at_monotonic: u64,
    ) -> ReferenceStatus {
        let Ok(prepared) = prepare_request(request, "lease_renew_request") else {
            return ReferenceStatus::Invalid;
        };
        let Ok(received) = timestamp_key(received_at, "received_at") else {
            return ReferenceStatus::Invalid;
        };
        let ttl = request
            .pointer("/payload/grant/lease/ttl_seconds")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let Ok(deadline) = derive_deadline(received, prepared.expires, ttl, received_at_monotonic)
        else {
            return ReferenceStatus::Expired;
        };
        let Some(existing) = self.installations.get_mut(&prepared.installation_id) else {
            return ReferenceStatus::Missing;
        };
        let Some(sequence) = prepared.sequence else {
            return ReferenceStatus::Invalid;
        };
        if !existing.active {
            return ReferenceStatus::Missing;
        }
        if existing.lease_id != prepared.lease_id
            || existing.token_digest != prepared.token_digest
            || existing.current_renewal_identity != prepared.renewal_identity
        {
            return ReferenceStatus::Conflict;
        }
        if sequence == existing.renewal_sequence
            && existing.current_grant_digest == prepared.grant_digest
            && existing.current_persisted_grant == prepared.persisted_grant
        {
            return ReferenceStatus::RenewDuplicate;
        }
        if sequence <= existing.renewal_sequence || prepared.expires <= existing.expires {
            return ReferenceStatus::Conflict;
        }
        existing.current_grant_digest = prepared.grant_digest;
        existing.current_persisted_grant = prepared.persisted_grant;
        existing.current_renewal_identity = prepared.renewal_identity;
        existing.expires = prepared.expires;
        existing.renewal_sequence = sequence;
        existing.deadline = Some(deadline);
        ReferenceStatus::Renewed
    }

    fn revoke(&mut self, request: &Value) -> ReferenceStatus {
        let Ok(prepared) = prepare_request(request, "lease_revoke_request") else {
            return ReferenceStatus::Invalid;
        };
        let Some(existing) = self.installations.get_mut(&prepared.installation_id) else {
            return ReferenceStatus::Missing;
        };
        if existing.lease_id != prepared.lease_id
            || existing.token_digest != prepared.token_digest
            || existing.current_grant_digest != prepared.grant_digest
            || existing.current_persisted_grant != prepared.persisted_grant
        {
            return ReferenceStatus::Conflict;
        }
        if !existing.active {
            return if existing.revoked_reason == prepared.reason {
                ReferenceStatus::RevokeDuplicate
            } else {
                ReferenceStatus::Conflict
            };
        }
        existing.active = false;
        existing.deadline = None;
        existing.revoked_reason = prepared.reason;
        ReferenceStatus::Revoked
    }

    fn restart(&mut self) {
        for installation in self.installations.values_mut() {
            installation.active = false;
            installation.deadline = None;
        }
    }

    fn deadline(&self, installation_id: &str) -> Option<u64> {
        self.installations
            .get(installation_id)
            .and_then(|installation| installation.deadline)
    }
}

fn set_grant_digest(request: &mut Value) -> Result<(), String> {
    let grant = request
        .pointer("/payload/grant")
        .ok_or("request grant missing")?;
    let digest = sha256_hex(canonical(grant)?.as_bytes());
    *request
        .pointer_mut("/payload/grant_digest")
        .ok_or("request grant digest missing")? = Value::String(digest);
    Ok(())
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value with unique object member names")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(|number| StrictValue(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::String(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::String(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::Null))
            }

            fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = access.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = Map::new();
                while let Some((key, value)) = access.next_entry::<String, StrictValue>()? {
                    if values.insert(key.clone(), value.0).is_some() {
                        return Err(de::Error::custom(format!("duplicate JSON member {key}")));
                    }
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

fn parse_unique_json(bytes: &[u8]) -> Result<Value, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer).map_err(|error| error.to_string())?;
    deserializer
        .end()
        .map_err(|error| format!("trailing JSON data: {error}"))?;
    Ok(value.0)
}

#[allow(clippy::too_many_lines)]
#[test]
fn protected_persistence_and_reference_lifecycle_are_stateful()
-> Result<(), Box<dyn std::error::Error>> {
    let install = read_json("fixtures/valid/lease-install-request.json")?;
    let renew = read_json("fixtures/valid/lease-renew-request.json")?;
    let revoke = read_json("fixtures/valid/lease-revoke-request.json")?;
    let installation_id = install["payload"]["installation_id"]
        .as_str()
        .ok_or("installation id missing")?;

    let mut host = ReferenceHost::default();
    assert_eq!(
        host.install(&install, "2026-09-07T00:00:02Z", 100),
        ReferenceStatus::Installed
    );
    assert_eq!(
        host.install(&install, "2026-09-07T00:00:04Z", 102),
        ReferenceStatus::Duplicate
    );
    assert!(
        host.installations[installation_id]
            .current_persisted_grant
            .pointer("/lease/fence_token")
            .is_none()
    );
    assert!(
        host.installations[installation_id]
            .current_persisted_grant
            .pointer("/lease/fence_token_digest")
            .is_some()
    );
    assert_eq!(
        host.renew(&renew, "2026-09-07T00:00:10Z", 110),
        ReferenceStatus::Renewed
    );
    assert_eq!(
        host.renew(&renew, "2026-09-07T00:00:11Z", 111),
        ReferenceStatus::RenewDuplicate
    );

    let mut renewed_revoke = revoke.clone();
    renewed_revoke["payload"]["grant"] = renew["payload"]["grant"].clone();
    set_grant_digest(&mut renewed_revoke)?;
    assert_eq!(host.revoke(&renewed_revoke), ReferenceStatus::Revoked);
    assert_eq!(
        host.revoke(&renewed_revoke),
        ReferenceStatus::RevokeDuplicate
    );

    let mut conflicting_reason = renewed_revoke.clone();
    conflicting_reason["payload"]["reason"] = Value::String("operator".to_owned());
    assert_eq!(host.revoke(&conflicting_reason), ReferenceStatus::Conflict);

    let mut changed_installation = install.clone();
    changed_installation["payload"]["installation_id"] =
        Value::String("00000000-0000-4000-8000-00000000000a".to_owned());
    assert_eq!(
        host.install(&changed_installation, "2026-09-07T00:00:02Z", 100),
        ReferenceStatus::Conflict
    );

    let mut changed_grant = install.clone();
    changed_grant["payload"]["grant"]["lease"]["expires_at"] =
        Value::String("2026-09-07T00:00:31Z".to_owned());
    set_grant_digest(&mut changed_grant)?;
    assert_eq!(
        host.install(&changed_grant, "2026-09-07T00:00:02Z", 100),
        ReferenceStatus::Conflict
    );

    let mut missing_host = ReferenceHost::default();
    assert_eq!(
        missing_host.renew(&renew, "2026-09-07T00:00:10Z", 110),
        ReferenceStatus::Missing
    );

    let mut nonadvancing = ReferenceHost::default();
    assert_eq!(
        nonadvancing.install(&install, "2026-09-07T00:00:02Z", 100),
        ReferenceStatus::Installed
    );
    assert_eq!(
        nonadvancing.renew(&renew, "2026-09-07T00:00:10Z", 110),
        ReferenceStatus::Renewed
    );
    let mut sequence_conflict = renew.clone();
    sequence_conflict["payload"]["grant"]["lease"]["expires_at"] =
        Value::String("2026-09-07T00:02:00Z".to_owned());
    set_grant_digest(&mut sequence_conflict)?;
    assert_eq!(
        nonadvancing.renew(&sequence_conflict, "2026-09-07T00:00:10Z", 110),
        ReferenceStatus::Conflict
    );

    let mut restarted = ReferenceHost::default();
    assert_eq!(
        restarted.install(&install, "2026-09-07T00:00:02Z", 100),
        ReferenceStatus::Installed
    );
    assert!(restarted.deadline(installation_id).is_some());
    restarted.restart();
    assert!(restarted.deadline(installation_id).is_none());
    assert_eq!(
        restarted.renew(&renew, "2026-09-07T00:00:10Z", 110),
        ReferenceStatus::Missing
    );
    assert_eq!(
        restarted.install(&install, "2026-09-07T00:00:02Z", 100),
        ReferenceStatus::Installed
    );

    let mut expired = install.clone();
    let mut deadline_host = ReferenceHost::default();
    assert_eq!(
        deadline_host.install(&expired, "2026-09-07T00:00:30Z", 130),
        ReferenceStatus::Expired
    );
    expired["payload"]["grant"]["lease"]["expires_at"] =
        Value::String("2026-09-07T00:00:31Z".to_owned());
    set_grant_digest(&mut expired)?;
    assert_eq!(
        deadline_host.install(&expired, "2026-09-07T00:00:30Z", 130),
        ReferenceStatus::Installed
    );
    Ok(())
}

#[test]
fn received_wall_checks_clamp_monotonic_deadlines() -> Result<(), Box<dyn std::error::Error>> {
    let received = timestamp_key("2026-09-07T00:00:10Z", "received")?;
    let short_expiry = timestamp_key("2026-09-07T00:00:15Z", "expiry")?;
    assert_eq!(derive_deadline(received, short_expiry, 30, 100)?, 105);

    let long_expiry = timestamp_key("2026-09-07T00:01:15Z", "expiry")?;
    assert_eq!(derive_deadline(received, long_expiry, 30, 100)?, 130);
    assert!(derive_deadline(received, received, 30, 100).is_err());
    assert!(
        derive_deadline(
            received,
            timestamp_key("2026-09-07T00:00:09Z", "expiry")?,
            30,
            100
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn timestamp_and_semantic_identity_checks_are_strict() -> Result<(), Box<dyn std::error::Error>> {
    assert!(timestamp("2026-09-07T00:00:00.1Z", "fraction").is_ok());
    assert!(timestamp("2026-09-07T00:00:.00Z", "malformed").is_err());
    assert!(timestamp("2026-02-30T00:00:00Z", "calendar").is_err());

    let install = read_json("fixtures/valid/lease-install-request.json")?;
    let mut wrong_principal = install.clone();
    wrong_principal["payload"]["grant"]["gateway"]["principal_id"] =
        Value::String("00000000-0000-4000-8000-000000000009".to_owned());
    set_grant_digest(&mut wrong_principal)?;
    assert!(validate_request_semantics(&wrong_principal, "lease_install_request").is_err());

    let mut wrong_role = install.clone();
    wrong_role["actor"]["role"] = Value::String("host".to_owned());
    assert!(validate_frame(&wrong_role, "lease_install_request").is_err());

    let mut wrong_capability = install.clone();
    wrong_capability["auth"]["capability"] = Value::String("lease_revoke".to_owned());
    assert!(validate_frame(&wrong_capability, "lease_install_request").is_err());

    let mut duplicate_status = read_json("fixtures/valid/lease-install-response.json")?;
    duplicate_status["payload"]["ack"]["result"]["status"] = Value::String("RENEWED".to_owned());
    assert!(validate_frame(&duplicate_status, "lease_install_response").is_err());
    Ok(())
}

#[test]
fn duplicate_json_members_are_rejected_before_semantic_validation()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = read_bytes("fixtures/valid/lease-install-request.json")?;
    assert!(parse_unique_json(&valid).is_ok());
    assert!(parse_unique_json(br#"{"contract":"a","contract":"b"}"#).is_err());
    assert!(parse_unique_json(br#"{"nested":{"id":1,"id":2}}"#).is_err());
    Ok(())
}

#[test]
fn manifest_pins_the_exact_closed_schema_without_self_reference()
-> Result<(), Box<dyn std::error::Error>> {
    let schema_bytes = read_bytes("frame.schema.json")?;
    assert_eq!(sha256_hex(&schema_bytes), SCHEMA_DIGEST);
    let manifest = read_json("manifest.json")?;
    let manifest_object = exact_object(
        &manifest,
        &[
            "$schema",
            "$id",
            "contract",
            "version",
            "schema_file",
            "schema_digest",
            "canonicalization",
            "digest_algorithm",
            "limits",
            "compatibility",
            "publication",
        ],
        "manifest",
    )?;
    assert_eq!(manifest_object["contract"], CONTRACT);
    assert_eq!(manifest_object["schema_digest"], SCHEMA_DIGEST);
    assert_eq!(manifest_object["schema_file"], "frame.schema.json");
    assert_ne!(manifest_object["schema_digest"], manifest_object["$id"]);
    let schema = serde_json::from_slice::<Value>(&schema_bytes)?;
    let alternatives = schema["oneOf"].as_array().ok_or("schema oneOf missing")?;
    assert_eq!(alternatives.len(), 6);
    for definition in [
        "install_request_frame",
        "install_response_frame",
        "renew_request_frame",
        "renew_response_frame",
        "revoke_request_frame",
        "revoke_response_frame",
    ] {
        assert!(
            schema["$defs"][definition].is_object(),
            "missing {definition}"
        );
    }
    assert_eq!(
        schema["$defs"]["common_frame"]["additionalProperties"],
        false
    );
    assert_eq!(schema["$defs"]["grant"]["additionalProperties"], false);
    assert_eq!(schema["$defs"]["ack"]["additionalProperties"], false);
    Ok(())
}

#[test]
fn valid_lifecycle_fixtures_are_closed_bound_and_semantically_coherent()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = [
        ("lease-install-request.json", "lease_install_request"),
        ("lease-install-response.json", "lease_install_response"),
        (
            "lease-install-duplicate-response.json",
            "lease_install_response",
        ),
        ("lease-renew-request.json", "lease_renew_request"),
        ("lease-renew-response.json", "lease_renew_response"),
        (
            "lease-renew-duplicate-response.json",
            "lease_renew_response",
        ),
        ("lease-revoke-request.json", "lease_revoke_request"),
        ("lease-revoke-response.json", "lease_revoke_response"),
        (
            "lease-revoke-duplicate-response.json",
            "lease_revoke_response",
        ),
    ];
    for (file, kind) in valid {
        let bytes = read_bytes(&format!("fixtures/valid/{file}"))?;
        assert!(bytes.len() <= MAX_FRAME_BYTES, "{file} exceeds frame bound");
        let value: Value = serde_json::from_slice(&bytes)?;
        validate_frame(&value, kind).map_err(|error| format!("{file}: {error}"))?;
        if kind.ends_with("_request") {
            validate_request_semantics(&value, kind).map_err(|error| format!("{file}: {error}"))?;
        }
    }
    let install = read_json("fixtures/valid/lease-install-request.json")?;
    let renew = read_json("fixtures/valid/lease-renew-request.json")?;
    let renewed_expiry = renew["payload"]["grant"]["lease"]["expires_at"]
        .as_str()
        .ok_or("renew expiry missing")?;
    let initial_expiry = install["payload"]["grant"]["lease"]["expires_at"]
        .as_str()
        .ok_or("initial expiry missing")?;
    assert!(renewed_expiry > initial_expiry);
    let install_ack = read_json("fixtures/valid/lease-install-response.json")?;
    let duplicate_ack = read_json("fixtures/valid/lease-install-duplicate-response.json")?;
    for field in [
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
        "expires_at",
    ] {
        assert_eq!(
            install_ack["payload"]["ack"][field], duplicate_ack["payload"]["ack"][field],
            "duplicate changed {field}"
        );
    }
    Ok(())
}

#[test]
fn invalid_fixtures_cover_shape_digest_context_and_expiry_failures()
-> Result<(), Box<dyn std::error::Error>> {
    let unknown = read_json("fixtures/invalid/unknown-field.json")?;
    assert!(validate_frame(&unknown, "lease_install_request").is_err());
    let mismatch = read_json("fixtures/semantic-invalid/grant-context-mismatch.json")?;
    assert!(validate_request_semantics(&mismatch, "lease_install_request").is_err());
    let bad_digest = read_json("fixtures/semantic-invalid/grant-digest-mismatch.json")?;
    assert!(validate_request_semantics(&bad_digest, "lease_install_request").is_err());
    let expired = read_json("fixtures/semantic-invalid/expired-renewal.json")?;
    assert!(validate_request_semantics(&expired, "lease_renew_request").is_err());
    Ok(())
}

#[test]
fn schema_and_fixture_field_sets_are_explicitly_closed() -> Result<(), Box<dyn std::error::Error>> {
    let schema = read_json("frame.schema.json")?;
    let definitions = schema["$defs"]
        .as_object()
        .ok_or("schema definitions missing")?;
    let object_definitions: BTreeSet<&str> = [
        "actor",
        "auth",
        "release_set",
        "boot_context",
        "host_fence",
        "lease_context",
        "gateway_identity",
        "grant",
        "result",
        "ack",
        "common_frame",
        "install_request",
        "install_response",
        "renew_request",
        "renew_response",
        "revoke_request",
        "revoke_response",
    ]
    .into_iter()
    .collect();
    for definition in object_definitions {
        assert_eq!(
            definitions[definition]["additionalProperties"], false,
            "{definition} is open"
        );
    }
    let install = read_json("fixtures/valid/lease-install-request.json")?;
    let payload = object(&install["payload"], "payload")?;
    assert_eq!(payload.keys().collect::<Vec<_>>().len(), 3);
    assert!(payload.contains_key("installation_id"));
    assert!(payload.contains_key("grant"));
    assert!(payload.contains_key("grant_digest"));
    Ok(())
}
