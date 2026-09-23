//! Bounded validation helpers and the canonical command fingerprint.

use super::MAX_REASON_BYTES;
use super::commands::AdminCommand;
use super::identity::Capability;
use super::views::ContractVersion;
use crate::admin::{MAX_FRAME_BYTES, MAX_PAYLOAD_BYTES};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub(super) fn validate_identifier(
    value: &str,
    name: &str,
    max_bytes: usize,
) -> std::result::Result<(), String> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value.is_ascii()
        || value.as_bytes().contains(&0)
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"_.:/-".contains(&byte)))
    {
        return Err(format!(
            "{name} is empty, unsafe, or exceeds {max_bytes} bytes"
        ));
    }
    Ok(())
}

pub(super) fn validate_reason(value: &str) -> std::result::Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_REASON_BYTES
        || value.as_bytes().contains(&0)
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "reason exceeds {MAX_REASON_BYTES} bytes or contains controls"
        ));
    }
    Ok(())
}

pub(super) fn validate_uuid_v4(value: &str, name: &str) -> std::result::Result<(), String> {
    let parsed = Uuid::parse_str(value).map_err(|_| format!("{name} must be a UUIDv4"))?;
    if parsed.get_version_num() != 4 {
        return Err(format!("{name} must be a UUIDv4"));
    }
    Ok(())
}

pub(super) fn validate_digest(value: &str) -> std::result::Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("digest must be 64 lowercase hexadecimal characters".to_string());
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Compute the canonical transport fingerprint for a closed command. The
/// reconciliation loop uses the same helper to bind a decoded job payload to
/// the authenticated context before it reaches durable storage.
pub(crate) fn command_fingerprint(capability: Capability, command: &AdminCommand) -> String {
    #[derive(Serialize)]
    struct Fingerprint<'a> {
        contract: ContractVersion,
        capability: Capability,
        command: &'a AdminCommand,
    }
    let bytes = serde_json::to_vec(&Fingerprint {
        contract: ContractVersion::V1,
        capability,
        command,
    })
    .unwrap_or_default();
    sha256_hex(&bytes)
}

/// Keep command payloads below the complete frame bound so framing overhead
/// and authentication fields cannot consume the entire transport budget.
pub(crate) fn payload_within_bound(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_PAYLOAD_BYTES && bytes.len() <= MAX_FRAME_BYTES
}
