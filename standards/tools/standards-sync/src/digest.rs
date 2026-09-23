//! Deterministic SHA-256 digests for bundles and profiles.

use sha2::{Digest, Sha256};

pub(crate) fn sha256_hex(input: &[u8]) -> String {
    Sha256::digest(input)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
