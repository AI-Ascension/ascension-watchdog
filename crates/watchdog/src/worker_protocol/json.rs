use super::types::{Frame, ProtocolError};
use super::validation;
use super::{MAX_FRAME_BYTES, MAX_JSON_DEPTH};
use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt;

const PROBE_REQUEST: &[&str] = &[
    "contract",
    "schema_digest",
    "direction",
    "command",
    "scope",
    "request_id",
    "timeout_ms",
    "watchdog_boot_id",
];
const PROBE_RESPONSE: &[&str] = &[
    "contract",
    "schema_digest",
    "direction",
    "command",
    "scope",
    "request_id",
    "timeout_ms",
    "watchdog_boot_id",
    "worker_boot_id",
    "deployment_id",
    "worker_owner_id",
    "worker_profile_digest",
    "release_digest",
    "config_digest",
    "ready",
    "admitting",
];
const DISPATCH_REQUEST: &[&str] = &[
    "contract",
    "schema_digest",
    "direction",
    "command",
    "scope",
    "request_id",
    "timeout_ms",
    "watchdog_boot_id",
    "worker_boot_id",
    "handoff_id",
    "deployment_id",
    "job_id",
    "attempt_id",
    "attempt_number",
    "worker_owner_id",
    "worker_profile_digest",
    "run_id",
    "episode_id",
    "trajectory_id",
    "payload_digest",
    "mode_sequence",
    "operation",
    "parameters",
];
const JOB_REQUEST: &[&str] = &[
    "contract",
    "schema_digest",
    "direction",
    "command",
    "scope",
    "request_id",
    "timeout_ms",
    "watchdog_boot_id",
    "worker_boot_id",
    "handoff_id",
    "deployment_id",
    "job_id",
    "attempt_id",
    "attempt_number",
    "worker_owner_id",
    "worker_profile_digest",
    "run_id",
    "episode_id",
    "trajectory_id",
    "payload_digest",
];
const ACK_REQUEST: &[&str] = &[
    "contract",
    "schema_digest",
    "direction",
    "command",
    "scope",
    "request_id",
    "timeout_ms",
    "watchdog_boot_id",
    "worker_boot_id",
    "handoff_id",
    "deployment_id",
    "job_id",
    "attempt_id",
    "attempt_number",
    "worker_owner_id",
    "worker_profile_digest",
    "run_id",
    "episode_id",
    "trajectory_id",
    "payload_digest",
    "terminal_digest",
];
const JOB_RESPONSE: &[&str] = &[
    "contract",
    "schema_digest",
    "direction",
    "command",
    "scope",
    "request_id",
    "timeout_ms",
    "watchdog_boot_id",
    "worker_boot_id",
    "handoff_id",
    "deployment_id",
    "job_id",
    "attempt_id",
    "attempt_number",
    "worker_owner_id",
    "worker_profile_digest",
    "run_id",
    "episode_id",
    "trajectory_id",
    "payload_digest",
    "status",
    "terminal",
];
const ACK_RESPONSE: &[&str] = &[
    "contract",
    "schema_digest",
    "direction",
    "command",
    "scope",
    "request_id",
    "timeout_ms",
    "watchdog_boot_id",
    "worker_boot_id",
    "handoff_id",
    "deployment_id",
    "job_id",
    "attempt_id",
    "attempt_number",
    "worker_owner_id",
    "worker_profile_digest",
    "run_id",
    "episode_id",
    "trajectory_id",
    "payload_digest",
    "status",
];
const CONTROL: &[&str] = &[
    "contract",
    "schema_digest",
    "direction",
    "command",
    "scope",
    "request_id",
    "timeout_ms",
    "watchdog_boot_id",
    "worker_boot_id",
    "deployment_id",
    "worker_owner_id",
    "worker_profile_digest",
    "mode",
    "mode_sequence",
];
const CONTROL_RESPONSE: &[&str] = &[
    "contract",
    "schema_digest",
    "direction",
    "command",
    "scope",
    "request_id",
    "timeout_ms",
    "watchdog_boot_id",
    "worker_boot_id",
    "deployment_id",
    "worker_owner_id",
    "worker_profile_digest",
    "mode",
    "mode_sequence",
    "status",
];

pub fn decode_frame(bytes: &[u8]) -> Result<Frame, ProtocolError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    let value = parse_strict_json(bytes)?;
    let object = value
        .as_object()
        .ok_or_else(|| ProtocolError::InvalidSchema("frame must be a JSON object".to_owned()))?;
    let direction = object
        .get("direction")
        .and_then(Value::as_str)
        .ok_or_else(|| ProtocolError::InvalidSchema("frame direction is required".to_owned()))?;
    let command = object
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| ProtocolError::InvalidSchema("frame command is required".to_owned()))?;
    reject_unknown(
        object,
        allowed_fields(direction, command).ok_or_else(|| {
            ProtocolError::InvalidSchema("unsupported direction or command".to_owned())
        })?,
    )?;
    let frame = match (direction, command) {
        ("request", "probe") => Frame::ProbeRequest(parse_typed(value)?),
        ("response", "probe") => Frame::ProbeResponse(parse_typed(value)?),
        ("request", "dispatch") => Frame::DispatchRequest(parse_typed(value)?),
        ("response", "dispatch") => Frame::DispatchResponse(parse_typed(value)?),
        ("request", "lookup") => Frame::LookupRequest(parse_typed(value)?),
        ("response", "lookup") => Frame::LookupResponse(parse_typed(value)?),
        ("request", "acknowledge") => Frame::AcknowledgeRequest(parse_typed(value)?),
        ("response", "acknowledge") => Frame::AcknowledgeResponse(parse_typed(value)?),
        ("request", "set_control_mode") => Frame::SetControlModeRequest(parse_typed(value)?),
        ("response", "set_control_mode") => Frame::SetControlModeResponse(parse_typed(value)?),
        _ => return Err(ProtocolError::InvalidSchema("unsupported frame".to_owned())),
    };
    validation::validate_frame(&frame)?;
    Ok(frame)
}

pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>, ProtocolError> {
    validation::validate_frame(frame)?;
    let value = match frame {
        Frame::ProbeRequest(value) => serde_json::to_value(value),
        Frame::ProbeResponse(value) => serde_json::to_value(value),
        Frame::DispatchRequest(value) => serde_json::to_value(value),
        Frame::DispatchResponse(value) => serde_json::to_value(value),
        Frame::LookupRequest(value) => serde_json::to_value(value),
        Frame::LookupResponse(value) => serde_json::to_value(value),
        Frame::AcknowledgeRequest(value) => serde_json::to_value(value),
        Frame::AcknowledgeResponse(value) => serde_json::to_value(value),
        Frame::SetControlModeRequest(value) => serde_json::to_value(value),
        Frame::SetControlModeResponse(value) => serde_json::to_value(value),
    }
    .map_err(|error| ProtocolError::InvalidSchema(error.to_string()))?;
    let bytes = serde_json::to_vec(&value)
        .map_err(|error| ProtocolError::InvalidSchema(error.to_string()))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    Ok(bytes)
}

fn allowed_fields(direction: &str, command: &str) -> Option<&'static [&'static str]> {
    match (direction, command) {
        ("request", "probe") => Some(PROBE_REQUEST),
        ("response", "probe") => Some(PROBE_RESPONSE),
        ("request", "dispatch") => Some(DISPATCH_REQUEST),
        ("request", "lookup") => Some(JOB_REQUEST),
        ("request", "acknowledge") => Some(ACK_REQUEST),
        ("response", "dispatch" | "lookup") => Some(JOB_RESPONSE),
        ("response", "acknowledge") => Some(ACK_RESPONSE),
        ("request", "set_control_mode") => Some(CONTROL),
        ("response", "set_control_mode") => Some(CONTROL_RESPONSE),
        _ => None,
    }
}

fn reject_unknown(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
) -> Result<(), ProtocolError> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(ProtocolError::InvalidSchema(format!("unknown field {key}")));
    }
    Ok(())
}

fn parse_typed<T: DeserializeOwned>(value: Value) -> Result<T, ProtocolError> {
    serde_json::from_value(value).map_err(|error| ProtocolError::InvalidSchema(error.to_string()))
}

fn parse_strict_json(bytes: &[u8]) -> Result<Value, ProtocolError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|error| ProtocolError::InvalidJson(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| ProtocolError::InvalidJson(error.to_string()))?;
    Ok(value.into_value())
}

#[derive(Debug)]
enum StrictValue {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Self>),
    Object(serde_json::Map<String, Value>),
}

impl StrictValue {
    fn into_value(self) -> Value {
        match self {
            Self::Null => Value::Null,
            Self::Bool(value) => Value::Bool(value),
            Self::Number(value) => Value::Number(value),
            Self::String(value) => Value::String(value),
            Self::Array(values) => Value::Array(values.into_iter().map(Self::into_value).collect()),
            Self::Object(values) => Value::Object(values),
        }
    }
}

struct StrictSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = StrictValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor { depth: self.depth })
    }
}

struct StrictVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a closed JSON value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(StrictValue::Number)
            .ok_or_else(|| E::custom("JSON number is not finite"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(de::Error::custom("JSON nesting exceeds depth bound"));
        }
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictSeed {
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(StrictValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(de::Error::custom("JSON nesting exceeds depth bound"));
        }
        let mut keys = BTreeSet::new();
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom("duplicate JSON field is not allowed"));
            }
            values.insert(
                key,
                map.next_value_seed(StrictSeed {
                    depth: self.depth + 1,
                })?
                .into_value(),
            );
        }
        Ok(StrictValue::Object(values))
    }
}
