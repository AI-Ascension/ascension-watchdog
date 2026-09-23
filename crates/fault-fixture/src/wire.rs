//! Wire protocol types for the synthetic fixture.
//!
//! Owns the closed recovery sideband envelope (`Frame`, `Actor`, `Auth`), the
//! bounded one-frame-per-connection loopback `Client`, server settings and the
//! strict duplicate-key JSON decoder.  Extracted verbatim from `lib.rs` by the
//! wire-protocol/client/server-transport split (issue #73); the crate root
//! re-exports every previously public name so callers are unchanged.

use std::fmt::Formatter;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Instant;

use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::server::{read_bounded_line, write_raw_response};
use crate::transport::{DeadlineReader, IO_TIMEOUT, connect_bounded};
use crate::{
    FIXTURE_TIMESTAMP, FaultPoint, FixtureError, MAX_FRAME_BYTES, RECOVERY_SCHEMA_DIGEST,
    is_runtime_v3_kind, request_capability, request_role, response_auth, response_auth_checked,
    valid_capability, valid_role, valid_timestamp, valid_v4, validate_recovery_payload,
    validate_runtime_v3_envelope,
};

/// The contract's actor object.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub principal_id: String,
    pub role: String,
}

/// The contract's authentication object.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    pub principal_id: String,
    pub capability: String,
    pub proof: Option<String>,
}

/// Closed recovery sideband envelope.  Payloads are parsed according to
/// `kind`, preserving the contract's top-level identity and capability fields.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub contract: String,
    pub schema_digest: String,
    pub message_id: String,
    pub correlation_id: String,
    pub sent_at: String,
    pub actor: Actor,
    pub auth: Auth,
    pub kind: String,
    pub payload: Value,
}

impl Frame {
    /// Build a valid fixture request with deterministic time and fresh UUIDs.
    #[must_use]
    pub fn request(kind: impl Into<String>, capability: impl Into<String>, payload: Value) -> Self {
        let kind = kind.into();
        let principal = Uuid::new_v4().to_string();
        Self {
            contract: "watchdog-recovery-v1".to_owned(),
            schema_digest: RECOVERY_SCHEMA_DIGEST.to_owned(),
            message_id: Uuid::new_v4().to_string(),
            correlation_id: Uuid::new_v4().to_string(),
            sent_at: FIXTURE_TIMESTAMP.to_owned(),
            actor: Actor {
                principal_id: principal.clone(),
                role: request_role(&kind).to_owned(),
            },
            auth: Auth {
                principal_id: principal,
                capability: capability.into(),
                proof: Some("fixture-proof".to_owned()),
            },
            kind,
            payload,
        }
    }

    pub(crate) fn response(&self, kind: &str, payload: Value) -> Self {
        let principal = Uuid::new_v4().to_string();
        let (role, capability) = response_auth(kind);
        Self {
            contract: "watchdog-recovery-v1".to_owned(),
            schema_digest: RECOVERY_SCHEMA_DIGEST.to_owned(),
            message_id: Uuid::new_v4().to_string(),
            correlation_id: self.correlation_id.clone(),
            sent_at: FIXTURE_TIMESTAMP.to_owned(),
            actor: Actor {
                principal_id: principal.clone(),
                role: role.to_owned(),
            },
            auth: Auth {
                principal_id: principal,
                capability: capability.to_owned(),
                proof: Some("fixture-proof".to_owned()),
            },
            kind: kind.to_owned(),
            payload,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), FixtureError> {
        if self.contract != "watchdog-recovery-v1" || self.schema_digest != RECOVERY_SCHEMA_DIGEST {
            return Err(FixtureError::ContractMismatch);
        }
        valid_v4(&self.message_id)?;
        valid_v4(&self.correlation_id)?;
        valid_v4(&self.actor.principal_id)?;
        valid_v4(&self.auth.principal_id)?;
        valid_role(&self.actor.role)?;
        if self.actor.principal_id != self.auth.principal_id {
            return Err(FixtureError::Invalid(
                "actor/auth principal mismatch".to_owned(),
            ));
        }
        valid_capability(&self.auth.capability)?;
        if self
            .auth
            .proof
            .as_ref()
            .is_none_or(|proof| proof.is_empty() || proof.len() > 512)
        {
            return Err(FixtureError::Bounds("auth proof"));
        }
        if !valid_timestamp(&self.sent_at) {
            return Err(FixtureError::Invalid("timestamp".to_owned()));
        }
        if self.kind.is_empty() || self.payload.is_null() {
            return Err(FixtureError::Invalid("missing kind or payload".to_owned()));
        }
        if let Some(expected) = request_capability(&self.kind) {
            if self.auth.capability != expected {
                return Err(FixtureError::Forbidden);
            }
            if self.actor.role != request_role(&self.kind) {
                return Err(FixtureError::Forbidden);
            }
            validate_recovery_payload(&self.kind, &self.payload)?;
        } else if let Some((expected_role, expected_capability)) = response_auth_checked(&self.kind)
        {
            if self.actor.role != expected_role || self.auth.capability != expected_capability {
                return Err(FixtureError::Forbidden);
            }
            validate_recovery_payload(&self.kind, &self.payload)?;
        } else if is_runtime_v3_kind(&self.kind) {
            validate_runtime_v3_envelope(&self.kind, &self.payload)?;
        } else if matches!(
            self.kind.as_str(),
            "stats"
                | "shutdown"
                | "host_tick"
                | "stats_response"
                | "shutdown_response"
                | "host_tick_response"
        ) {
            // These are test-local control frames, outside the published
            // recovery-v1 18-frame schema. Their payload is validated by the
            // operation handler that owns the control point.
        } else {
            return Err(FixtureError::Invalid("unsupported frame kind".to_owned()));
        }
        Ok(())
    }
}

/// A bounded client for the fixture's one-frame-per-connection loopback wire.
///
/// Each request still opens exactly one connection, but the connect itself is
/// retried on a transient loopback timeout (see [`connect_bounded`]); the
/// one-frame-per-connection contract and the read deadline are unchanged.
#[derive(Clone, Copy, Debug)]
pub struct Client {
    address: SocketAddr,
}

impl Client {
    #[must_use]
    pub const fn new(address: SocketAddr) -> Self {
        Self { address }
    }

    #[must_use]
    pub const fn address(self) -> SocketAddr {
        self.address
    }

    /// Send one closed frame and decode its bounded response.
    ///
    /// # Errors
    ///
    /// Returns a transport, bounds, or JSON error when the peer is unavailable
    /// or does not return a closed response frame.
    pub fn request(&self, frame: &Frame) -> Result<Frame, FixtureError> {
        let bytes =
            serde_json::to_vec(frame).map_err(|error| FixtureError::Json(error.to_string()))?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(FixtureError::Bounds("request frame"));
        }
        let mut stream = connect_bounded(&self.address).map_err(FixtureError::Io)?;
        write_raw_response(&mut stream, &bytes)?;
        let mut reader = BufReader::new(
            DeadlineReader::new(&stream, Instant::now() + IO_TIMEOUT).map_err(FixtureError::Io)?,
        );
        let Some(line) = read_bounded_line(&mut reader)? else {
            return Err(FixtureError::ResponseLost);
        };
        parse_json_no_duplicates::<Frame>(&line)
    }
}

/// Server settings.  `fault` is intentionally only constructible by this
/// test package and is never accepted by a production executable.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub database: PathBuf,
    pub bind: SocketAddr,
    pub fault: FaultPoint,
}

impl ServerConfig {
    #[must_use]
    pub fn loopback(database: impl Into<PathBuf>, fault: FaultPoint) -> Self {
        Self {
            database: database.into(),
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            fault,
        }
    }
}
/// `serde_json::Value` accepts duplicate object members with last-value-wins
/// semantics.  That is unsafe for an authenticated closed envelope: a
/// verifier and a consumer could observe different values.  Build values with
/// a recursive visitor so duplicate keys are rejected at every nesting level.
struct NoDuplicateValue(Value);

impl<'de> Deserialize<'de> for NoDuplicateValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ValueVisitor;

        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = NoDuplicateValue;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON value without duplicate object keys")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NoDuplicateValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NoDuplicateValue(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NoDuplicateValue(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let number = serde_json::Number::from_f64(value)
                    .ok_or_else(|| E::custom("non-finite JSON number"))?;
                Ok(NoDuplicateValue(Value::Number(number)))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NoDuplicateValue(Value::Null))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NoDuplicateValue(Value::String(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NoDuplicateValue(Value::String(value)))
            }

            fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = access.next_element::<NoDuplicateValue>()? {
                    values.push(value.0);
                }
                Ok(NoDuplicateValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = serde_json::Map::new();
                while let Some(key) = access.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom(format!(
                            "duplicate JSON object key: {key}"
                        )));
                    }
                    let value = access.next_value::<NoDuplicateValue>()?;
                    values.insert(key, value.0);
                }
                Ok(NoDuplicateValue(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(ValueVisitor)
    }
}

pub(crate) fn parse_value_no_duplicates(bytes: &[u8]) -> Result<Value, FixtureError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = NoDuplicateValue::deserialize(&mut deserializer)
        .map_err(|error| FixtureError::Json(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| FixtureError::Json(error.to_string()))?;
    Ok(value.0)
}

pub(crate) fn parse_json_no_duplicates<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, FixtureError> {
    let value = parse_value_no_duplicates(bytes)?;
    serde_json::from_value(value).map_err(|error| FixtureError::Json(error.to_string()))
}
