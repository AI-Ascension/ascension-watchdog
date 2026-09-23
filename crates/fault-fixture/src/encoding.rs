//! Strict encoding, canonical action checks and digest helpers.
//!
//! Owns the canonical RCJ action check, strict base64 decoding and the SHA-256
//! digest helpers.  Extracted verbatim from `lib.rs` by the recovery-validation,
//! encoding-and-typed-errors split (issue #79); callers reach these through the
//! crate root's `use encoding::{...}` import.

use std::fmt::Write as FmtWrite;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::valid_identity;
use crate::wire::parse_value_no_duplicates;

pub(crate) fn rcj_action_valid(bytes: &[u8]) -> bool {
    if bytes.is_empty()
        || bytes.iter().any(|byte| {
            !byte.is_ascii()
                || byte.is_ascii_whitespace()
                || *byte == b'\\'
                || byte.is_ascii_control()
        })
    {
        return false;
    }
    let Ok(value) = parse_value_no_duplicates(bytes) else {
        return false;
    };
    let Ok(canonical) = serde_json::to_vec(&value) else {
        return false;
    };
    if canonical != bytes {
        return false;
    }
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.len() != 2 || !object.contains_key("action") || !object.contains_key("action_id") {
        return false;
    }
    let Some(action_id) = object["action_id"].as_str() else {
        return false;
    };
    if !valid_identity(action_id) {
        return false;
    }
    let Some(action) = object["action"].as_object() else {
        return false;
    };
    let Some(kind) = action.get("kind").and_then(Value::as_str) else {
        return false;
    };
    let required: &[&str] = match kind {
        "end_turn" | "skip_reward" | "rest" | "confirm_victory" | "save_quit" | "proceed"
        | "confirm_selection" | "cancel_selection" => &[],
        "start_run" => &["character_id"],
        "select_map_node" => &["node_id"],
        "play_card" => &["card_id", "target_id"],
        "choose_reward" => &["reward_id"],
        "shop_purchase" => &["item_id"],
        "shop_remove" | "smith" | "select_card" => &["card_id"],
        "event_choice" => &["choice_id"],
        _ => return false,
    };
    action.len() == required.len() + 1
        && required.iter().all(|field| {
            action.get(*field).is_some_and(|entry| {
                (entry.is_null() && *field == "target_id")
                    || entry.as_str().is_some_and(valid_identity)
            })
        })
}

pub(crate) fn decode_base64_strict(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(4) {
        return None;
    }
    let mut output = Vec::with_capacity(value.len() / 4 * 3);
    for (index, chunk) in value.as_bytes().chunks(4).enumerate() {
        let is_last = index + 1 == value.len() / 4;
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c_padding = chunk[2] == b'=';
        let d_padding = chunk[3] == b'=';
        if c_padding {
            if !is_last || !d_padding {
                return None;
            }
            if b & 0x0f != 0 {
                return None;
            }
            output.push((a << 2) | (b >> 4));
        } else {
            let c = base64_value(chunk[2])?;
            if d_padding {
                if !is_last {
                    return None;
                }
                if c & 0x03 != 0 {
                    return None;
                }
                output.push((a << 2) | (b >> 4));
                output.push((b << 4) | (c >> 2));
            } else {
                let d = base64_value(chunk[3])?;
                output.push((a << 2) | (b >> 4));
                output.push((b << 4) | (c >> 2));
                output.push((c << 6) | d);
            }
        }
    }
    Some(output)
}

pub(crate) fn base64_value(value: u8) -> Option<u8> {
    match value {
        b'A'..=b'Z' => Some(value - b'A'),
        b'a'..=b'z' => Some(value - b'a' + 26),
        b'0'..=b'9' => Some(value - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut result = String::with_capacity(64);
    for byte in hasher.finalize() {
        let _ = write!(&mut result, "{byte:02x}");
    }
    result
}

pub(crate) fn digest(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let mut result = String::with_capacity(64);
    for byte in hasher.finalize() {
        let _ = write!(&mut result, "{byte:02x}");
    }
    result
}
