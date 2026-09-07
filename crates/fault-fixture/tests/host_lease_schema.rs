//! Executable conformance checks for the additive host lease-control artifact.
//!
//! The workspace intentionally has no JSON-Schema runtime dependency. These
//! tests therefore check the published schema metadata and the bounded closed
//! shapes used by this artifact, then exercise the semantic rules that JSON
//! Schema cannot express (digest and identity binding, time ordering, and
//! duplicate acknowledgment lineage).

use std::collections::BTreeSet;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::{Uuid, Variant};

const CONTRACT: &str = "watchdog-host-lease-control-v1";
const SCHEMA_DIGEST: &str = "80786332a8647b20f1a3c2a822fb200878f0677ea9676b0da3a27cc272ec9385";
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

fn timestamp(value: &str, context: &str) -> Result<(), String> {
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
    let valid = bytes.iter().enumerate().all(|(index, byte)| {
        if matches!(index, 4 | 7 | 10 | 13 | 16) || index == bytes.len() - 1 {
            true
        } else if index == 17 && bytes.len() > 20 {
            *byte == b'.' || byte.is_ascii_digit()
        } else {
            byte.is_ascii_digit()
        }
    });
    if !valid {
        return Err(format!("{context} contains invalid timestamp characters"));
    }
    Ok(())
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
    let issued = string(lease, "issued_at", "grant.lease")?;
    let expires = string(lease, "expires_at", "grant.lease")?;
    timestamp(issued, "grant.lease.issued_at")?;
    timestamp(expires, "grant.lease.expires_at")?;
    if expires <= issued {
        return Err("grant.lease.expires_at must be after issued_at".to_owned());
    }
    let ttl = u64_value(lease, "ttl_seconds", "grant.lease")?;
    let renewal = u64_value(lease, "renewal_interval_seconds", "grant.lease")?;
    if !(5..=300).contains(&ttl) || renewal == 0 || renewal >= ttl {
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
    if !expected.contains(&status) {
        return Err(format!("unexpected success fixture status {status}"));
    }
    if result["retryable"] != Value::Bool(false) || !result["retry_after_seconds"].is_null() {
        return Err("successful acknowledgment must not request a retry".to_owned());
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
    if kind == "lease_renew_response" {
        if ack["renew_sequence"].as_u64().is_none() || ack["expires_at"].as_str().is_none() {
            return Err("renew acknowledgment must echo sequence and expiry".to_owned());
        }
        timestamp(
            ack["expires_at"].as_str().ok_or("renew expiry missing")?,
            "ack.expires_at",
        )?;
    } else {
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
            validate_grant(&payload["grant"])
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
            validate_grant(&payload["grant"])
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
            validate_grant(&payload["grant"])
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
