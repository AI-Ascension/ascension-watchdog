//! Rule, profile-catalog, and repository-map validation.

use crate::Result;
use crate::dates::valid_date;
use crate::identifiers::{
    contains_shell_operator, has_safe_executable, is_upper_identifier, ordinary_style_rule, unique,
    valid_check_name, valid_commit, valid_language_scope, valid_node_id, valid_profile_id,
    valid_profile_scope, valid_repository, valid_rule_id, valid_rule_scope,
};
use crate::model::{ProfileCatalog, RepositoryMap, RuleDocument};
use crate::parsing::parse_yaml;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(crate) const EXPECTED_REPOSITORIES: &[&str] = &[
    "AI-Ascension/.github",
    "AI-Ascension/AI-Ascension.github.io",
    "AI-Ascension/ai-agent-observability",
    "AI-Ascension/aiascension.tech",
    "AI-Ascension/ascension-brand-overhaul",
    "AI-Ascension/ascension-map-visualizer",
    "AI-Ascension/ascension-watchdog",
    "AI-Ascension/sts2-game-core",
    "AI-Ascension/sts2-game-mod",
    "AI-Ascension/sts2-gateway",
    "AI-Ascension/sts2-harness",
    "AI-Ascension/sts2-mcp-server",
    "AI-Ascension/sts2-protocol",
];

pub(crate) fn validate_rules(path: &Path) -> Result<BTreeMap<String, bool>> {
    let document = parse_yaml::<RuleDocument>(path)?;
    if document.schema_version != 1 {
        return Err(format!("{} schema_version must be 1", path.display()));
    }
    if document.rules.is_empty() {
        return Err(format!("{} must contain at least one rule", path.display()));
    }
    let mut ids = BTreeMap::new();
    for rule in &document.rules {
        if !valid_rule_id(&rule.id)
            || ids
                .insert(rule.id.clone(), rule.exception_eligible)
                .is_some()
        {
            return Err(format!("invalid or duplicate rule id '{}'", rule.id));
        }
        if rule.exception_eligible && !ordinary_style_rule(&rule.id) {
            return Err(format!(
                "rule {} cannot use an ordinary style exception",
                rule.id
            ));
        }
        if rule.id.starts_with("ASC-") {
            let expected = if matches!(rule.id.as_str(), "ASC-SIZE-001" | "ASC-DES-001") {
                "advisory"
            } else {
                "mandatory"
            };
            if rule.severity != expected {
                return Err(format!(
                    "rule {} changes the supplied severity contract",
                    rule.id
                ));
            }
        }
        if rule.title.is_empty() || rule.title.len() > 120 {
            return Err(format!("rule {} has an invalid title", rule.id));
        }
        if rule.purpose.is_empty() || rule.purpose.len() > 500 {
            return Err(format!("rule {} has an invalid purpose", rule.id));
        }
        if rule.scope.is_empty()
            || !unique(&rule.scope)
            || rule.scope.iter().any(|scope| !valid_rule_scope(scope))
        {
            return Err(format!("rule {} has an invalid scope", rule.id));
        }
        if !valid_check_name(&rule.check) {
            return Err(format!("rule {} has an invalid check name", rule.id));
        }
        match rule.verification.as_str() {
            "automated" => {
                let command = rule.command.as_deref().ok_or_else(|| {
                    format!("automated rule {} must name an executable command", rule.id)
                })?;
                if command.is_empty()
                    || command.len() > 240
                    || contains_shell_operator(command)
                    || !has_safe_executable(command)
                {
                    return Err(format!(
                        "rule {} has an invalid executable command",
                        rule.id
                    ));
                }
            }
            "manual" => {
                if rule.command.is_some() {
                    return Err(format!(
                        "manual rule {} must not claim an executable command",
                        rule.id
                    ));
                }
            }
            _ => {
                return Err(format!(
                    "rule {} verification must be automated or manual",
                    rule.id
                ));
            }
        }
        match (
            rule.severity.as_str(),
            rule.classification.as_str(),
            rule.failure_behavior.as_str(),
        ) {
            ("mandatory", "blocking", "reject") | ("advisory", "advisory", "report") => {}
            _ => return Err(format!("rule {} has an invalid severity contract", rule.id)),
        }
    }
    for required in [
        "ASC-OWN-001",
        "ASC-CON-001",
        "ASC-CON-002",
        "ASC-ERR-001",
        "ASC-RES-001",
        "ASC-SEC-001",
        "ASC-SEC-002",
        "ASC-EFX-001",
        "ASC-DEP-001",
        "ASC-FMT-001",
        "ASC-SIZE-001",
        "ASC-SIZE-002",
        "ASC-DES-001",
        "ASC-PROV-001",
        "ASC-EXC-001",
        "ASC-RUS-001",
        "ASC-RUS-002",
        "ASC-RUS-003",
        "ASC-RUS-004",
        "ASC-NET-001",
        "ASC-NET-002",
        "ASC-PHP-001",
        "ASC-PHP-002",
        "ASC-PHP-003",
        "ASC-PHP-004",
        "ASC-WEB-001",
        "ASC-WEB-002",
        "ASC-OPS-001",
        "ASC-OPS-002",
        "ASC-OPS-003",
        "ASC-CI-001",
        "ASC-CI-002",
        "ASC-CI-003",
        "ASC-TST-001",
        "ASC-EVD-001",
        "ASC-REP-001",
        "ASC-PLN-001",
        "X-ID-001",
        "X-VER-001",
        "X-AUTH-001",
        "X-ERR-001",
        "X-LIFE-001",
        "X-TIME-001",
        "X-PRIV-001",
        "X-OWN-001",
    ] {
        if !ids.contains_key(required) {
            return Err(format!("canonical rule {required} is missing"));
        }
    }
    Ok(ids)
}

pub(crate) fn validate_profile_catalog(path: &Path) -> Result<BTreeSet<String>> {
    let document = parse_yaml::<ProfileCatalog>(path)?;
    if document.schema_version != 1 {
        return Err(format!("{} schema_version must be 1", path.display()));
    }
    if document.profiles.is_empty() {
        return Err(format!("{} contains no profiles", path.display()));
    }
    let mut ids = BTreeSet::new();
    for profile in &document.profiles {
        if !valid_profile_id(&profile.id) || !ids.insert(profile.id.clone()) {
            return Err(format!(
                "invalid or duplicate catalog profile '{}'",
                profile.id
            ));
        }
        if profile.purpose.trim().is_empty() {
            return Err(format!("catalog profile {} has no purpose", profile.id));
        }
        if profile.scopes.is_empty()
            || !unique(&profile.scopes)
            || profile
                .scopes
                .iter()
                .any(|scope| !valid_profile_scope(scope))
        {
            return Err(format!("catalog profile {} has invalid scopes", profile.id));
        }
        for (tier, checks) in [
            ("fast", &profile.fast),
            ("required", &profile.required),
            ("extended", &profile.extended),
        ] {
            if !unique(checks) || checks.iter().any(|check| !valid_check_name(check)) {
                return Err(format!(
                    "catalog profile {} has invalid {tier} checks",
                    profile.id
                ));
            }
        }
    }
    Ok(ids)
}

pub(crate) fn validate_repository_map(path: &Path, profile_ids: &BTreeSet<String>) -> Result<()> {
    let document = parse_yaml::<RepositoryMap>(path)?;
    if document.schema_version != 1 {
        return Err(format!("{} schema_version must be 1", path.display()));
    }
    if !valid_date(&document.refreshed) || document.source.trim().is_empty() {
        return Err(format!("{} has invalid refresh metadata", path.display()));
    }
    if document.repositories.len() != EXPECTED_REPOSITORIES.len() {
        return Err(format!(
            "repository map must contain exactly {} records, found {}",
            EXPECTED_REPOSITORIES.len(),
            document.repositories.len()
        ));
    }
    let expected: BTreeSet<&str> = EXPECTED_REPOSITORIES.iter().copied().collect();
    let actual: BTreeSet<&str> = document
        .repositories
        .iter()
        .map(|entry| entry.repository.as_str())
        .collect();
    if actual != expected {
        return Err("repository map does not match the reviewed repositories".to_owned());
    }
    let mut ids = BTreeSet::new();
    for entry in &document.repositories {
        if !valid_repository(&entry.repository)
            || entry.repository_id == 0
            || !ids.insert(entry.repository_id)
            || !valid_node_id(&entry.node_id)
            || entry.default_branch.trim().is_empty()
            || entry.default_branch.chars().any(char::is_whitespace)
            || !valid_commit(&entry.baseline_commit)
            || !is_upper_identifier(&entry.owner)
            || !profile_ids.contains(&entry.profile_id)
            || !matches!(entry.adoption.as_str(), "ready" | "prepared" | "excluded")
        {
            return Err(format!(
                "incomplete repository record for {}",
                entry.repository
            ));
        }
        if entry.language_scopes.is_empty()
            || !unique(&entry.language_scopes)
            || entry
                .language_scopes
                .iter()
                .any(|scope| !valid_language_scope(scope))
        {
            return Err(format!(
                "repository {} has invalid language scopes",
                entry.repository
            ));
        }
        match (entry.adoption.as_str(), entry.exclusion_reason.as_deref()) {
            ("excluded", Some(reason)) if !reason.trim().is_empty() => {}
            ("excluded", _) => {
                return Err(format!(
                    "excluded repository {} needs a reason",
                    entry.repository
                ));
            }
            (_, None) => {}
            (_, Some(_)) => {
                return Err(format!(
                    "non-excluded repository {} has an exclusion reason",
                    entry.repository
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_adoption_identity(
    path: &Path,
    repository: &str,
    owner: &str,
    profile_id: &str,
) -> Result<()> {
    let document = parse_yaml::<RepositoryMap>(path)?;
    let entry = document
        .repositories
        .iter()
        .find(|entry| entry.repository == repository)
        .ok_or_else(|| format!("repository {repository} is not in the reviewed map"))?;
    if entry.owner != owner || entry.profile_id != profile_id {
        return Err(format!(
            "sync identity for {} must use owner={} and profile_id={}",
            repository, entry.owner, entry.profile_id
        ));
    }
    if entry.adoption == "excluded" {
        return Err(format!(
            "repository {} is explicitly excluded: {}",
            repository,
            entry
                .exclusion_reason
                .as_deref()
                .unwrap_or("no reason recorded")
        ));
    }
    Ok(())
}
