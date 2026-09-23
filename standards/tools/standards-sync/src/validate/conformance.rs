//! Conformance fixture inventory and negative-fixture validation.

use super::{
    validate_exception, validate_lock_bytes, validate_lock_shape, validate_profile,
    validate_schema_document,
};
use crate::Result;
use crate::dates::date_days;
use crate::fixture::create_fixture_directory;
use crate::model::{Exception, LockFile, Profile};
use crate::parsing::{parse_json, parse_json_value, parse_toml, parse_yaml};
use crate::paths::{require_directory, require_regular_file};
use std::fs;
use std::path::Path;

pub(crate) const FIXTURE_AS_OF: &str = "2026-09-07";

pub(crate) const REQUIRED_FIXTURE_FILES: &[&str] = &[
    "README.md",
    "invalid-exception-broad-path.yaml",
    "invalid-exception-pending.yaml",
    "invalid-lock-published.json",
    "invalid-lock-stale-digest.json",
    "invalid-lock-traversal.json",
    "invalid-profile-floating.toml",
    "invalid-profile-missing-source.toml",
    "invalid-schema-missing-required.json",
    "invalid-schema-nonobject.json",
    "valid-exception.yaml",
    "valid-lock.json",
    "valid-profile.toml",
];

pub(crate) fn validate_conformance_inventory(directory: &Path) -> Result<()> {
    require_directory(directory)?;
    let mut actual = Vec::new();
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot list {}: {error}", directory.display()))?
    {
        let entry =
            entry.map_err(|error| format!("cannot read conformance directory entry: {error}"))?;
        actual.push(entry.file_name().to_string_lossy().into_owned());
    }
    actual.sort();
    let mut expected = REQUIRED_FIXTURE_FILES.to_vec();
    expected.sort();
    if actual != expected {
        return Err(format!(
            "{} must contain exactly the conformance fixtures",
            directory.display()
        ));
    }
    for name in REQUIRED_FIXTURE_FILES {
        require_regular_file(&directory.join(name))?;
    }
    Ok(())
}

pub(crate) fn fixture_check(directory: &Path) -> Result<()> {
    validate_conformance_inventory(directory)?;

    let valid_profile = parse_toml::<Profile>(&directory.join("valid-profile.toml"))?;
    validate_profile(&valid_profile)?;
    let valid_lock = parse_json::<LockFile>(&directory.join("valid-lock.json"))?;
    validate_lock_shape(&valid_lock, &valid_profile)?;
    let valid_exception = parse_yaml::<Exception>(&directory.join("valid-exception.yaml"))?;
    validate_exception(&valid_exception, None, date_days(FIXTURE_AS_OF)?, true)?;

    for name in [
        "invalid-profile-floating.toml",
        "invalid-profile-missing-source.toml",
    ] {
        let result = parse_toml::<Profile>(&directory.join(name))
            .and_then(|profile| validate_profile(&profile));
        if result.is_ok() {
            return Err(format!("negative fixture {name} was accepted"));
        }
    }
    for name in ["invalid-lock-traversal.json", "invalid-lock-published.json"] {
        let result = parse_json::<LockFile>(&directory.join(name))
            .and_then(|lock| validate_lock_shape(&lock, &valid_profile));
        if result.is_ok() {
            return Err(format!("negative fixture {name} was accepted"));
        }
    }
    let stale_lock = parse_json::<LockFile>(&directory.join("invalid-lock-stale-digest.json"))?;
    let temp_root = create_fixture_directory()?;
    fs::create_dir(temp_root.join("standards"))
        .map_err(|error| format!("cannot create fixture standards directory: {error}"))?;
    fs::write(temp_root.join("standards/fixture.txt"), b"fixture bytes")
        .map_err(|error| format!("cannot write stale digest fixture: {error}"))?;
    let stale_result = validate_lock_bytes(&temp_root, &stale_lock);
    fs::remove_dir_all(&temp_root)
        .map_err(|error| format!("cannot remove fixture directory: {error}"))?;
    if stale_result.is_ok() {
        return Err("negative fixture invalid-lock-stale-digest.json was accepted".to_owned());
    }
    for name in [
        "invalid-exception-pending.yaml",
        "invalid-exception-broad-path.yaml",
    ] {
        let result = parse_yaml::<Exception>(&directory.join(name)).and_then(|exception| {
            validate_exception(&exception, None, date_days(FIXTURE_AS_OF)?, true)
        });
        if result.is_ok() {
            return Err(format!("negative fixture {name} was accepted"));
        }
    }
    for name in [
        "invalid-schema-missing-required.json",
        "invalid-schema-nonobject.json",
    ] {
        let result = parse_json_value(&directory.join(name))
            .and_then(|value| validate_schema_document(&directory.join(name), &value));
        if result.is_ok() {
            return Err(format!("negative fixture {name} was accepted"));
        }
    }
    println!("fixture-check passed: 3 valid fixtures accepted, 9 negative fixtures rejected");
    Ok(())
}
