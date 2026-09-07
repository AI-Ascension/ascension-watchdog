// SPDX-License-Identifier: MIT

//! Test-only independent recomputation, not a production proof verifier.
use std::{error::Error, fs, path::Path};

use serde_json::Value;
use sha2::{Digest, Sha256};

fn canonical(value: &Value) -> Result<String, Box<dyn Error>> {
    Ok(match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => {
            let integer = value.as_u64().ok_or("non-unsigned integer")?;
            if integer > 9_007_199_254_740_991 {
                return Err("integer exceeds u53".into());
            }
            integer.to_string()
        }
        Value::String(value) => serde_json::to_string(value)?,
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical)
                .collect::<Result<Vec<_>, _>>()?
                .join(",")
        ),
        Value::Object(values) => {
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            let fields = entries
                .into_iter()
                .map(|(key, value)| {
                    Ok(format!(
                        "{}:{}",
                        serde_json::to_string(key)?,
                        canonical(value)?
                    ))
                })
                .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
            format!("{{{}}}", fields.join(","))
        }
    })
}

fn hash(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(DIGITS[usize::from(byte >> 4)]),
                char::from(DIGITS[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

// Fixed-size public vector key only. Production consumers use their own
// reviewed cryptographic library and constant-time verification.
fn test_hmac(message: &[u8], key_bytes: &[u8; 32]) -> String {
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for (key, (inner, outer)) in key_bytes
        .iter()
        .zip(inner_pad.iter_mut().zip(outer_pad.iter_mut()))
    {
        *inner ^= key;
        *outer ^= key;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner.finalize());
    hex(&outer.finalize())
}

#[test]
fn published_host_lease_proofs_match_independent_recomputation() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/host-lease-control-v1");
    let vectors: Value = serde_json::from_slice(&fs::read(root.join("proof-vectors.json"))?)?;
    assert_eq!(
        vectors["test_key_hex"],
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );
    let canonical_cases = vectors["canonical_cases"]
        .as_array()
        .ok_or("missing cases")?;
    assert_eq!(canonical_cases.len(), 3);
    for case in canonical_cases {
        assert_eq!(
            hash(canonical(&case["input"])?.as_bytes()),
            case["canonical_sha256"]
        );
    }
    let cases = vectors["frame_proof_cases"]
        .as_array()
        .ok_or("missing proofs")?;
    assert_eq!(cases.len(), 9);
    for case in cases {
        let fixture = case["fixture"].as_str().ok_or("missing fixture")?;
        let bytes = fs::read(root.join(fixture))?;
        assert_eq!(hash(&bytes), case["fixture_sha256"], "{fixture}");
        let mut frame: Value = serde_json::from_slice(&bytes)?;
        frame["auth"]
            .as_object_mut()
            .ok_or("missing auth")?
            .remove("proof");
        let body = canonical(&frame)?;
        assert_eq!(hash(body.as_bytes()), case["canonical_sha256"], "{fixture}");
        let domain = match frame["kind"].as_str().ok_or("missing kind")? {
            "lease_install_request" => "host-lease-control/v1/lease-install-request",
            "lease_install_response" => "host-lease-control/v1/lease-install-ack",
            "lease_renew_request" => "host-lease-control/v1/lease-renew-request",
            "lease_renew_response" => "host-lease-control/v1/lease-renew-ack",
            "lease_revoke_request" => "host-lease-control/v1/lease-revoke-request",
            "lease_revoke_response" => "host-lease-control/v1/lease-revoke-ack",
            _ => return Err("unknown frame kind".into()),
        };
        assert_eq!(domain, case["domain"], "domain for {fixture}");
        let mut message = domain.as_bytes().to_vec();
        message.push(0);
        message.extend_from_slice(body.as_bytes());
        assert_eq!(hash(&message), case["signed_message_sha256"], "{fixture}");
        let mut key = [0_u8; 32];
        for (byte, value) in key.iter_mut().zip(0_u8..32) {
            *byte = value;
        }
        assert_eq!(test_hmac(&message, &key), case["proof"], "{fixture}");
        let mut alternate_key = key;
        alternate_key[0] ^= 1;
        assert_ne!(
            test_hmac(&message, &alternate_key),
            case["proof"],
            "alternate key {fixture}"
        );
        message.push(b' ');
        assert_ne!(
            test_hmac(&message, &key),
            case["proof"],
            "tampered {fixture}"
        );
    }
    Ok(())
}
