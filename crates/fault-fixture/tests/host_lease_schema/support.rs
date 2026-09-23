//! Artifact loading, bounded JSON accessors and canonical encoding helpers.
//!
//! Every helper here is input-bounded: the artifact root is fixed relative to
//! the crate manifest, object shapes are checked exactly, and the digest/UUID
//! helpers reject any value outside the published closed form.

use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::{Uuid, Variant};

use crate::strict::parse_unique_json;

pub const CONTRACT: &str = "watchdog-host-lease-control-v1";
pub const SCHEMA_DIGEST: &str = "e22faf0f7d3cd313a007b65e52058b3c255153d5778dd8124055c283adf977f9";
pub const MAX_FRAME_BYTES: usize = 262_144;
pub const MAX_PROOF_BYTES: usize = 512;
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn artifact_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("schemas/host-lease-control-v1")
}

pub fn read_json(relative: &str) -> Result<Value, String> {
    let path = artifact_root().join(relative);
    let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    parse_unique_json(&bytes).map_err(|error| format!("{}: {error}", path.display()))
}

pub fn read_bytes(relative: &str) -> Result<Vec<u8>, String> {
    let path = artifact_root().join(relative);
    fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))
}

pub fn object<'a>(value: &'a Value, context: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{context} must be an object"))
}

pub fn exact_object<'a>(
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

pub fn string<'a>(
    map: &'a Map<String, Value>,
    field: &str,
    context: &str,
) -> Result<&'a str, String> {
    map.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{context}.{field} must be a string"))
}

pub fn u64_value(map: &Map<String, Value>, field: &str, context: &str) -> Result<u64, String> {
    let value = map
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{context}.{field} must be an unsigned integer"))?;
    if value > MAX_SAFE_INTEGER {
        return Err(format!("{context}.{field} exceeds the HCJ-1 u53 bound"));
    }
    Ok(value)
}

pub fn uuid(value: &str, random: bool, context: &str) -> Result<(), String> {
    let parsed = Uuid::parse_str(value).map_err(|_| format!("{context} is not a UUID"))?;
    if parsed.hyphenated().to_string() != value || parsed.get_variant() != Variant::RFC4122 {
        return Err(format!("{context} is not lowercase RFC4122 form"));
    }
    if random && parsed.get_version_num() != 4 {
        return Err(format!("{context} is not UUIDv4"));
    }
    Ok(())
}

pub fn digest(value: &str, context: &str) -> Result<(), String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{context} is not a lowercase SHA-256 digest"));
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(format!("{context} is not lowercase"));
    }
    Ok(())
}

pub fn canonical(value: &Value) -> Result<String, String> {
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

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(output, "{byte:02x}");
    }
    output
}
