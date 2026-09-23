//! Lease-control frame validation and canonical grant-digest semantics.
//!
//! `validate_request_semantics` layers the digest check over `validate_frame`;
//! both keep the original closed-object and bounds checks unchanged.

use serde_json::Value;

use crate::support::{
    CONTRACT, MAX_PROOF_BYTES, MAX_SAFE_INTEGER, SCHEMA_DIGEST, canonical, digest, exact_object,
    object, sha256_hex, string, uuid,
};
use crate::time::timestamp;
use crate::validators::{validate_ack, validate_bound_grant};

#[allow(clippy::too_many_lines)]
pub fn validate_frame(value: &Value, expected_kind: &str) -> Result<(), String> {
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
            let sequence = payload["renew_sequence"].as_u64();
            if sequence.is_none_or(|sequence| sequence == 0 || sequence > MAX_SAFE_INTEGER) {
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

pub fn validate_request_semantics(value: &Value, kind: &str) -> Result<(), String> {
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
