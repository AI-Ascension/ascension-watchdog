//! Closed, bounded v1 watchdog-to-harness handoff frames.
//!
//! This is the protocol-only seam. It does not claim a watchdog job, open a
//! store, launch a process, or speak to the harness.

mod json;
mod types;
mod validation;

pub use types::*;

pub const CONTRACT: &str = "ascension-watchdog-worker-handoff-v1";
/// SHA-256 of the exact checked-in `worker-handoff-v1/schema.json` bytes.
pub const SCHEMA_DIGEST: &str = "bb13d15f6c0e4b8d0f58f7391fe4ba319ebc57a0a09effc06d73ea718bbff4cf";
pub const MAX_FRAME_BYTES: usize = 65_536;
pub const MAX_JSON_DEPTH: usize = 16;
pub const MAX_TIMEOUT_MS: u64 = 5_000;
pub const MAX_IDENTITY_BYTES: usize = 128;
pub const MAX_REFERENCE_BYTES: usize = 1_024;
pub const MAX_ATTEMPT_NUMBER: u64 = 9_007_199_254_740_991;
pub const MAX_TERMINAL_BYTES: usize = 16 * 1024;
pub const MAX_OPERATION_BYTES: usize = 64;
pub const OPERATION_RUNTIME_V3_EPISODE: &str = "runtime_v3_episode";
pub const EMPTY_PARAMETERS_DIGEST: &str =
    "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

pub fn decode_frame(bytes: &[u8]) -> Result<Frame, ProtocolError> {
    json::decode_frame(bytes)
}

pub fn decode_request(bytes: &[u8]) -> Result<Frame, ProtocolError> {
    let frame = decode_frame(bytes)?;
    if frame.is_request() {
        Ok(frame)
    } else {
        Err(ProtocolError::InvalidSchema(
            "expected a request frame".to_owned(),
        ))
    }
}

pub fn decode_response(bytes: &[u8]) -> Result<Frame, ProtocolError> {
    let frame = decode_frame(bytes)?;
    if frame.is_response() {
        Ok(frame)
    } else {
        Err(ProtocolError::InvalidSchema(
            "expected a response frame".to_owned(),
        ))
    }
}

pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>, ProtocolError> {
    json::encode_frame(frame)
}

pub fn canonical_parameters(parameters: &serde_json::Value) -> Result<Vec<u8>, ProtocolError> {
    validation::validate_parameters(parameters)?;
    Ok(b"{}".to_vec())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
