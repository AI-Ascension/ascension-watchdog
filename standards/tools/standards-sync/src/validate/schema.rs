//! JSON Schema document validation for the canonical standards schemas.

use crate::Result;
use crate::parsing::parse_json_value;
use crate::paths::{require_directory, require_regular_file};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub(crate) const REQUIRED_SCHEMA_FILES: &[&str] = &[
    "exception.schema.json",
    "lock.schema.json",
    "profile.schema.json",
    "profiles.schema.json",
    "repositories.schema.json",
    "rule.schema.json",
    "rules.schema.json",
];

pub(crate) fn validate_schemas(directory: &Path) -> Result<()> {
    require_directory(directory)?;
    let mut actual = Vec::new();
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot list {}: {error}", directory.display()))?
    {
        let entry =
            entry.map_err(|error| format!("cannot read schema directory entry: {error}"))?;
        actual.push(entry.file_name().to_string_lossy().into_owned());
    }
    actual.sort();
    let mut expected = REQUIRED_SCHEMA_FILES.to_vec();
    expected.sort();
    if actual != expected {
        return Err(format!(
            "{} must contain exactly the canonical schema files",
            directory.display()
        ));
    }

    let mut ids = BTreeSet::new();
    for name in REQUIRED_SCHEMA_FILES {
        let path = directory.join(name);
        require_regular_file(&path)?;
        let value = parse_json_value(&path)?;
        validate_schema_document(&path, &value)?;
        let id = value
            .get("$id")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{} has no string $id", path.display()))?;
        if !ids.insert(id.to_owned()) {
            return Err(format!("duplicate schema $id in {}", path.display()));
        }
        let expected_suffix = format!("/schemas/{name}");
        if !id.ends_with(&expected_suffix) {
            return Err(format!("{} has an unexpected schema $id", path.display()));
        }
    }
    Ok(())
}

pub(crate) fn validate_schema_document(path: &Path, value: &Value) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{} schema root must be a JSON object", path.display()))?;
    let schema = object
        .get("$schema")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{} must have a string $schema", path.display()))?;
    if schema != "https://json-schema.org/draft/2020-12/schema" {
        return Err(format!("{} has unsupported $schema", path.display()));
    }
    if object.get("$id").and_then(Value::as_str).is_none()
        || object.get("title").and_then(Value::as_str).is_none()
        || object.get("type").and_then(Value::as_str) != Some("object")
        || object.get("additionalProperties") != Some(&Value::Bool(false))
    {
        return Err(format!(
            "{} is missing semantic schema metadata",
            path.display()
        ));
    }
    let required = object
        .get("required")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{} required must be an array", path.display()))?;
    let mut required_names = BTreeSet::new();
    for value in required {
        let name = value
            .as_str()
            .ok_or_else(|| format!("{} has a non-string required field", path.display()))?;
        if !required_names.insert(name) {
            return Err(format!(
                "{} has duplicate required field {name}",
                path.display()
            ));
        }
    }
    let properties = object
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{} properties must be an object", path.display()))?;
    for name in &required_names {
        if !properties.contains_key(*name) {
            return Err(format!(
                "{} requires property {name} that is not declared",
                path.display()
            ));
        }
    }
    for (name, schema_value) in properties {
        validate_schema_fragment(path, name, schema_value)?;
    }
    if let Some(defs) = object.get("$defs") {
        let defs = defs
            .as_object()
            .ok_or_else(|| format!("{} $defs must be an object", path.display()))?;
        for (name, schema_value) in defs {
            validate_schema_fragment(path, &format!("$defs.{name}"), schema_value)?;
        }
    }
    let expected_required =
        expected_schema_required(path.file_name().and_then(|name| name.to_str()));
    for name in expected_required {
        if !required_names.contains(name) {
            return Err(format!(
                "{} is missing required semantic field {name}",
                path.display()
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_schema_fragment(path: &Path, name: &str, value: &Value) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{} schema property {name} is not an object", path.display()))?;
    let has_schema_keyword = ["type", "$ref", "const", "enum", "allOf", "oneOf", "anyOf"]
        .iter()
        .any(|key| object.contains_key(*key));
    if !has_schema_keyword {
        return Err(format!(
            "{} schema property {name} has no schema keyword",
            path.display()
        ));
    }
    if let Some(pattern) = object.get("pattern")
        && pattern.as_str().is_none()
    {
        return Err(format!(
            "{} schema property {name} has a non-string pattern",
            path.display()
        ));
    }
    if let Some(reference) = object.get("$ref")
        && reference.as_str().is_none()
    {
        return Err(format!(
            "{} schema property {name} has a non-string $ref",
            path.display()
        ));
    }
    if let Some(enum_values) = object.get("enum")
        && enum_values.as_array().is_none_or(Vec::is_empty)
    {
        return Err(format!(
            "{} schema property {name} has an empty enum",
            path.display()
        ));
    }
    Ok(())
}

pub(crate) fn expected_schema_required(name: Option<&str>) -> &'static [&'static str] {
    match name {
        Some("exception.schema.json") => &[
            "id",
            "rule_ids",
            "paths",
            "owner",
            "rationale",
            "compensating_tests",
            "approval",
            "reviewed_on",
            "expires_on",
            "removal_criteria",
        ],
        Some("lock.schema.json") => &[
            "lock_version",
            "profile_sha256",
            "repository",
            "profile_id",
            "source",
            "files",
            "protected_paths",
            "generated_by",
        ],
        Some("profile.schema.json") => &[
            "schema_version",
            "profile_id",
            "repository",
            "owner",
            "source_bundle",
            "source_commit",
            "source_digest",
            "distribution",
            "scopes",
            "checks",
            "evidence",
            "exceptions",
        ],
        Some("profiles.schema.json") => &["schema_version", "profiles"],
        Some("repositories.schema.json") => {
            &["schema_version", "refreshed", "source", "repositories"]
        }
        Some("rule.schema.json") => &[
            "id",
            "title",
            "purpose",
            "severity",
            "classification",
            "scope",
            "check",
            "verification",
            "command",
            "exception_eligible",
            "failure_behavior",
        ],
        Some("rules.schema.json") => &["schema_version", "rules"],
        _ => &[],
    }
}
