//! Structured readers for TOML, JSON, YAML, and UTF-8 text documents.

use crate::Result;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::fs;
use std::path::Path;

pub(crate) fn parse_toml<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let text = read_text(path)?;
    toml::from_str(&text).map_err(|error| format!("{}: invalid TOML: {error}", path.display()))
}

pub(crate) fn parse_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let text = read_text(path)?;
    serde_json::from_str(&text)
        .map_err(|error| format!("{}: invalid JSON: {error}", path.display()))
}

pub(crate) fn parse_json_value(path: &Path) -> Result<Value> {
    parse_json(path)
}

pub(crate) fn parse_yaml<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let text = read_text(path)?;
    serde_yaml::from_str(&text)
        .map_err(|error| format!("{}: invalid YAML: {error}", path.display()))
}

pub(crate) fn read_text(path: &Path) -> Result<String> {
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    String::from_utf8(bytes).map_err(|error| format!("{} is not UTF-8: {error}", path.display()))
}
