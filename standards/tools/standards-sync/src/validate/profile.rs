//! Profile and check-set validation.

use crate::Result;
use crate::identifiers::{
    contains_shell_operator, has_safe_executable, is_upper_identifier, unique, valid_check_name,
    valid_commit, valid_prefixed_digest, valid_profile_id, valid_profile_scope,
    valid_relative_path, valid_repository, valid_target,
};
use crate::model::{CheckSets, Profile};
use crate::paths::require_directory;
use std::collections::BTreeSet;
use std::path::Path;

pub(crate) const EVIDENCE_STATES: &[&str] = &[
    "confirmed",
    "source-derived",
    "proposed",
    "inferred",
    "unverified",
    "unsupported",
];

pub(crate) fn validate_profile(profile: &Profile) -> Result<()> {
    if profile.schema_version != 1 {
        return Err("profile schema_version must be 1".to_owned());
    }
    if !valid_profile_id(&profile.profile_id) {
        return Err(format!("invalid profile_id '{}'", profile.profile_id));
    }
    if !valid_repository(&profile.repository) {
        return Err(format!("invalid repository '{}'", profile.repository));
    }
    if !is_upper_identifier(&profile.owner) {
        return Err(format!("invalid owner '{}'", profile.owner));
    }
    if profile.source_bundle != "AI-Ascension/.github" {
        return Err("source_bundle must be AI-Ascension/.github".to_owned());
    }
    if !valid_commit(&profile.source_commit) {
        return Err("source_commit must be a 40-character lowercase commit".to_owned());
    }
    if !valid_prefixed_digest(&profile.source_digest) {
        return Err("source_digest must be sha256:<64 lowercase hex>".to_owned());
    }
    if profile.distribution != "local" {
        return Err("distribution must be local".to_owned());
    }
    if profile.scopes.is_empty()
        || !unique(&profile.scopes)
        || profile
            .scopes
            .iter()
            .any(|scope| !valid_profile_scope(scope))
    {
        return Err("scopes must be non-empty, unique lowercase identifiers".to_owned());
    }
    validate_check_sets(&profile.checks)?;
    for (name, state) in [
        ("runtime", &profile.evidence.runtime),
        ("deployment", &profile.evidence.deployment),
        ("provider", &profile.evidence.provider),
    ] {
        if !EVIDENCE_STATES.contains(&state.as_str()) {
            return Err(format!("evidence.{name} has unknown state '{state}'"));
        }
    }
    match profile.exceptions.status.as_str() {
        "none" if profile.exceptions.file.is_empty() => {}
        "none" => return Err("exceptions.file must be empty when status is none".to_owned()),
        "pending" | "approved" if valid_relative_path(&profile.exceptions.file) => {}
        "pending" | "approved" => {
            return Err("an exception file must be a safe repository-relative path".to_owned());
        }
        status => return Err(format!("unknown exception status '{status}'")),
    }
    Ok(())
}

pub(crate) fn validate_check_sets(checks: &CheckSets) -> Result<()> {
    if checks.fast.is_empty() && checks.required.is_empty() {
        return Err("profile must declare executable fast or required checks".to_owned());
    }
    let mut names = BTreeSet::new();
    for (tier, values) in [
        ("fast", &checks.fast),
        ("required", &checks.required),
        ("extended", &checks.extended),
    ] {
        if !unique(values) {
            return Err(format!("checks.{tier} contains duplicate check names"));
        }
        for value in values {
            if !valid_check_name(value) {
                return Err(format!("checks.{tier} contains invalid check '{value}'"));
            }
            if !names.insert(value.clone()) {
                return Err(format!("check '{value}' appears in more than one tier"));
            }
        }
    }
    let command_names: BTreeSet<String> = checks.commands.keys().cloned().collect();
    if command_names != names {
        let missing = names
            .difference(&command_names)
            .cloned()
            .collect::<Vec<_>>();
        let extra = command_names
            .difference(&names)
            .cloned()
            .collect::<Vec<_>>();
        return Err(format!(
            "checks.commands must have exactly one command/target for each listed check (missing={missing:?}, extra={extra:?})"
        ));
    }
    for (name, specification) in &checks.commands {
        if specification.command.trim().is_empty()
            || specification
                .command
                .chars()
                .any(|character| character.is_control())
            || contains_shell_operator(&specification.command)
        {
            return Err(format!("check '{name}' has an unsafe or empty command"));
        }
        if !has_safe_executable(&specification.command) {
            return Err(format!("check '{name}' has no executable command token"));
        }
        if !valid_target(&specification.target) {
            return Err(format!("check '{name}' has an unsafe target"));
        }
    }
    Ok(())
}

pub(crate) fn validate_check_targets(root: &Path, checks: &CheckSets) -> Result<()> {
    for (name, specification) in &checks.commands {
        if !valid_target(&specification.target) {
            return Err(format!("check '{name}' has an unsafe target"));
        }
        let mut target = root.to_path_buf();
        require_directory(&target)?;
        if specification.target != "." {
            for component in specification.target.split('/') {
                target.push(component);
                require_directory(&target).map_err(|error| {
                    format!("check '{name}' has an unavailable target: {error}")
                })?;
            }
        }
    }
    Ok(())
}
