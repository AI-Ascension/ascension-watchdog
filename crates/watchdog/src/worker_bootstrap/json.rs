//! Strict JSON decoding for the worker bootstrap payload.

use super::BootstrapError;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::collections::BTreeSet;
use std::fmt;

/// Parse one complete JSON value while rejecting duplicate object keys.
pub(super) fn parse_strict_json(bytes: &[u8]) -> Result<Value, BootstrapError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|_| BootstrapError::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| BootstrapError::InvalidJson)?;
    Ok(value.into_value())
}

const MAX_JSON_DEPTH: usize = 16;

#[derive(Debug)]
enum StrictValue {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Self>),
    Object(Map<String, Value>),
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
        Number::from_f64(value)
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
            return Err(de::Error::custom(
                "JSON nesting exceeds the bootstrap bound",
            ));
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
            return Err(de::Error::custom(
                "JSON nesting exceeds the bootstrap bound",
            ));
        }
        let mut keys = BTreeSet::new();
        let mut values = Map::new();
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
