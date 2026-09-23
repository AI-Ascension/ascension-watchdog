//! Metadata and conformance validation for a standards bundle.

mod conformance;
mod exception;
mod lock;
mod profile;
mod rules;
mod schema;

pub(crate) use conformance::{fixture_check, validate_conformance_inventory};
pub(crate) use exception::{validate_exception, validate_profile_exception};
pub(crate) use lock::{validate_lock_bytes, validate_lock_shape};
pub(crate) use profile::{validate_check_targets, validate_profile};
pub(crate) use rules::{
    validate_adoption_identity, validate_profile_catalog, validate_repository_map, validate_rules,
};
pub(crate) use schema::{validate_schema_document, validate_schemas};

#[cfg(test)]
pub(crate) use conformance::FIXTURE_AS_OF;
#[cfg(test)]
pub(crate) use profile::validate_check_sets;

use crate::Result;
use crate::dates::as_of_days;
use crate::digest::sha256_hex;
use crate::model::{LockFile, Profile};
use crate::parsing::{parse_json, parse_toml};
use crate::paths::{require_directory, require_regular_file};
use crate::planning::validate_required_checks;
use std::fs;
use std::path::Path;

pub(crate) fn validate_root(root: &Path, as_of: Option<&str>) -> Result<()> {
    let root = root
        .canonicalize()
        .map_err(|error| format!("cannot read root {}: {error}", root.display()))?;
    let standards = root.join("standards");
    let profile_path = root.join("standards-profile.toml");
    let lock_path = root.join("standards.lock.json");

    require_regular_file(&profile_path)?;
    require_regular_file(&lock_path)?;
    require_directory(&standards)?;

    let profile = parse_toml::<Profile>(&profile_path)?;
    validate_profile(&profile)?;
    let lock = parse_json::<LockFile>(&lock_path)?;
    validate_lock_shape(&lock, &profile)?;
    if sha256_hex(&fs::read(&profile_path).map_err(|error| error.to_string())?)
        != lock.profile_sha256
    {
        return Err("profile configuration digest mismatch".to_owned());
    }
    validate_lock_bytes(&root, &lock)?;
    let rule_ids = validate_rules(&standards.join("rules.yaml"))?;
    let profile_ids = validate_profile_catalog(&standards.join("profiles.yaml"))?;
    validate_repository_map(&standards.join("repositories.yaml"), &profile_ids)?;
    validate_adoption_identity(
        &standards.join("repositories.yaml"),
        &profile.repository,
        &profile.owner,
        &profile.profile_id,
    )?;
    validate_check_targets(&root, &profile.checks)?;
    validate_required_checks(&profile)?;
    validate_schemas(&standards.join("schemas"))?;
    validate_conformance_inventory(&standards.join("conformance"))?;
    let as_of = as_of_days(as_of)?;
    validate_profile_exception(&root, &profile, &rule_ids, as_of, false)?;

    println!(
        "validated metadata profile={} repository={} source_commit={} files={} bundle_digest={} (manual semantic review remains separate)",
        profile.profile_id,
        profile.repository,
        profile.source_commit,
        lock.files.len(),
        lock.source.bundle_digest
    );
    Ok(())
}
