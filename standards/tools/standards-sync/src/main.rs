use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::time::{SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, String>;

mod bootstrap;

const EVIDENCE_STATES: &[&str] = &[
    "confirmed",
    "source-derived",
    "proposed",
    "inferred",
    "unverified",
    "unsupported",
];

const FIXTURE_AS_OF: &str = "2026-09-07";

const REQUIRED_SCHEMA_FILES: &[&str] = &[
    "exception.schema.json",
    "lock.schema.json",
    "profile.schema.json",
    "profiles.schema.json",
    "repositories.schema.json",
    "rule.schema.json",
    "rules.schema.json",
];

const REQUIRED_FIXTURE_FILES: &[&str] = &[
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

const EXPECTED_REPOSITORIES: &[&str] = &[
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

#[derive(Debug, Default)]
struct Cli {
    command: String,
    root: PathBuf,
    source_root: PathBuf,
    target_root: PathBuf,
    repository: String,
    profile_id: String,
    owner: String,
    source_commit: String,
    as_of: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    schema_version: u32,
    profile_id: String,
    repository: String,
    owner: String,
    source_bundle: String,
    source_commit: String,
    source_digest: String,
    distribution: String,
    scopes: Vec<String>,
    checks: CheckSets,
    evidence: Evidence,
    exceptions: Exceptions,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckSets {
    fast: Vec<String>,
    required: Vec<String>,
    extended: Vec<String>,
    #[serde(default)]
    commands: BTreeMap<String, CheckCommand>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckCommand {
    command: String,
    target: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    runtime: String,
    deployment: String,
    provider: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Exceptions {
    file: String,
    status: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LockFile {
    lock_version: u32,
    repository: String,
    profile_id: String,
    source: LockSource,
    profile_sha256: String,
    files: Vec<LockEntry>,
    protected_paths: Vec<String>,
    generated_by: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LockSource {
    repository: String,
    commit: String,
    bundle_digest: String,
    distribution: String,
    published: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LockEntry {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDocument {
    schema_version: u32,
    rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    id: String,
    title: String,
    purpose: String,
    severity: String,
    classification: String,
    scope: Vec<String>,
    check: String,
    verification: String,
    command: Option<String>,
    exception_eligible: bool,
    failure_behavior: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileCatalog {
    schema_version: u32,
    profiles: Vec<CatalogProfile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogProfile {
    id: String,
    purpose: String,
    scopes: Vec<String>,
    fast: Vec<String>,
    required: Vec<String>,
    extended: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryMap {
    schema_version: u32,
    refreshed: String,
    source: String,
    repositories: Vec<RepositoryEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryEntry {
    repository: String,
    repository_id: u64,
    node_id: String,
    default_branch: String,
    baseline_commit: String,
    owner: String,
    profile_id: String,
    adoption: String,
    language_scopes: Vec<String>,
    exclusion_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Exception {
    id: String,
    rule_ids: Vec<String>,
    paths: Vec<String>,
    owner: String,
    rationale: String,
    compensating_tests: Vec<String>,
    approval: Approval,
    reviewed_on: String,
    expires_on: String,
    removal_criteria: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    reviewer: String,
    record: String,
    status: String,
}

fn main() {
    let args = match parse_cli() {
        Ok(value) => value,
        Err(error) => fail(&error),
    };

    let result = match args.command.as_str() {
        "validate" => validate_root(&args.root, args.as_of.as_deref()),
        "fixture-check" => fixture_check(&args.root),
        "check-bootstrap" => bootstrap::check(&args.root),
        "sync" => sync_bundle(&args),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        command => Err(format!("unknown command '{command}'; use 'help'")),
    };

    if let Err(error) = result {
        fail(&error);
    }
}

fn fail(error: &str) -> ! {
    eprintln!("standards-sync: error: {error}");
    process::exit(1);
}

fn print_help() {
    println!(
        "standards-sync/1\n\nCommands:\n  validate [--root PATH] [--as-of YYYY-MM-DD]\n  fixture-check --root standards/conformance\n  check-bootstrap [--root PATH]\n  sync --source-root PATH --target-root PATH --repository OWNER/NAME --profile-id ID --owner OWNER --source-commit COMMIT\n\nAll operations are local and read-only except sync's deterministic copy into its target."
    );
}

fn parse_cli() -> Result<Cli> {
    let mut values = env::args().skip(1);
    let command = values.next().unwrap_or_else(|| "help".to_owned());
    let mut cli = Cli {
        command,
        root: PathBuf::from("."),
        ..Cli::default()
    };

    while let Some(flag) = values.next() {
        let mut value = || {
            values
                .next()
                .ok_or_else(|| format!("missing value for {flag}"))
        };
        match flag.as_str() {
            "--root" => cli.root = PathBuf::from(value()?),
            "--source-root" => cli.source_root = PathBuf::from(value()?),
            "--target-root" => cli.target_root = PathBuf::from(value()?),
            "--repository" => cli.repository = value()?,
            "--profile-id" => cli.profile_id = value()?,
            "--owner" => cli.owner = value()?,
            "--source-commit" => cli.source_commit = value()?,
            "--as-of" => cli.as_of = Some(value()?),
            flag => return Err(format!("unknown option '{flag}'")),
        }
    }

    Ok(cli)
}

fn validate_root(root: &Path, as_of: Option<&str>) -> Result<()> {
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

fn validate_profile(profile: &Profile) -> Result<()> {
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

fn validate_check_sets(checks: &CheckSets) -> Result<()> {
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

fn validate_check_targets(root: &Path, checks: &CheckSets) -> Result<()> {
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

fn validate_lock_shape(lock: &LockFile, profile: &Profile) -> Result<()> {
    if !valid_hex_digest(&lock.profile_sha256) {
        return Err("invalid profile configuration digest".to_owned());
    }
    if lock.lock_version != 1 {
        return Err("lock_version must be 1".to_owned());
    }
    if !valid_repository(&lock.repository) || lock.repository != profile.repository {
        return Err("lock repository does not match profile".to_owned());
    }
    if !valid_profile_id(&lock.profile_id) || lock.profile_id != profile.profile_id {
        return Err("lock profile_id does not match profile".to_owned());
    }
    if lock.source.repository != "AI-Ascension/.github" {
        return Err("lock source.repository must be AI-Ascension/.github".to_owned());
    }
    if !valid_commit(&lock.source.commit) || lock.source.commit != profile.source_commit {
        return Err("lock source.commit does not match profile source_commit".to_owned());
    }
    if !valid_prefixed_digest(&lock.source.bundle_digest)
        || lock.source.bundle_digest != profile.source_digest
    {
        return Err("lock bundle_digest does not match profile source_digest".to_owned());
    }
    if lock.source.distribution != "local" {
        return Err("lock source.distribution must be local".to_owned());
    }
    if lock.source.published {
        return Err(
            "local source must keep published=false until remote publication is verified"
                .to_owned(),
        );
    }
    if lock.generated_by != "standards-sync/1" {
        return Err("lock generated_by must be standards-sync/1".to_owned());
    }
    if lock.files.is_empty() {
        return Err("lock files must contain at least one entry".to_owned());
    }
    if lock.protected_paths.is_empty() || !unique(&lock.protected_paths) {
        return Err("protected_paths must be non-empty and unique".to_owned());
    }
    for path in &lock.protected_paths {
        if !path.starts_with("standards/") || !valid_relative_path(path) {
            return Err(format!("unsafe protected path '{path}'"));
        }
    }
    let mut previous: Option<&str> = None;
    for entry in &lock.files {
        if !entry.path.starts_with("standards/")
            || !valid_relative_path(&entry.path)
            || !valid_hex_digest(&entry.sha256)
        {
            return Err(format!("invalid lock entry '{}'", entry.path));
        }
        if previous.is_some_and(|old| old >= entry.path.as_str()) {
            return Err("lock files must be sorted and unique".to_owned());
        }
        previous = Some(&entry.path);
    }
    Ok(())
}

fn validate_lock_bytes(root: &Path, lock: &LockFile) -> Result<()> {
    let mut bundle_input = Vec::new();
    for entry in &lock.files {
        let full = safe_join(root, &entry.path)?;
        require_regular_file(&full)?;
        let bytes =
            fs::read(&full).map_err(|error| format!("cannot read {}: {error}", full.display()))?;
        let actual = sha256_hex(&bytes);
        if actual != entry.sha256 {
            return Err(format!(
                "digest mismatch for {}: expected {}, got {actual}",
                entry.path, entry.sha256
            ));
        }
        append_bundle_record(&mut bundle_input, &entry.path, &bytes);
    }
    let actual_bundle = format!("sha256:{}", sha256_hex(&bundle_input));
    if actual_bundle != lock.source.bundle_digest {
        return Err(format!(
            "bundle digest mismatch: expected {}, got {actual_bundle}",
            lock.source.bundle_digest
        ));
    }

    let standards = root.join("standards");
    let mut actual_files = Vec::new();
    collect_files(&standards, &standards, &mut actual_files)?;
    actual_files.sort();
    let locked: Vec<String> = lock.files.iter().map(|entry| entry.path.clone()).collect();
    if actual_files != locked {
        return Err(format!(
            "lock inventory differs from local standards files: lock has {} entries, local tree has {}",
            locked.len(),
            actual_files.len()
        ));
    }
    Ok(())
}

fn validate_rules(path: &Path) -> Result<BTreeMap<String, bool>> {
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

fn validate_profile_catalog(path: &Path) -> Result<BTreeSet<String>> {
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

fn validate_repository_map(path: &Path, profile_ids: &BTreeSet<String>) -> Result<()> {
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

fn validate_adoption_identity(
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

fn validate_schemas(directory: &Path) -> Result<()> {
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

fn validate_schema_document(path: &Path, value: &Value) -> Result<()> {
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

fn validate_schema_fragment(path: &Path, name: &str, value: &Value) -> Result<()> {
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

fn expected_schema_required(name: Option<&str>) -> &'static [&'static str] {
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

fn validate_conformance_inventory(directory: &Path) -> Result<()> {
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

fn fixture_check(directory: &Path) -> Result<()> {
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

fn validate_profile_exception(
    root: &Path,
    profile: &Profile,
    rule_ids: &BTreeMap<String, bool>,
    as_of: i64,
    allow_fixture_review: bool,
) -> Result<()> {
    if profile.exceptions.status == "none" {
        return Ok(());
    }
    let path = safe_join(root, &profile.exceptions.file)?;
    require_regular_file(&path)?;
    let exception = parse_yaml::<Exception>(&path)?;
    validate_exception(&exception, Some(rule_ids), as_of, allow_fixture_review)
}

fn validate_exception(
    exception: &Exception,
    known_rule_ids: Option<&BTreeMap<String, bool>>,
    as_of: i64,
    allow_fixture_review: bool,
) -> Result<()> {
    if !valid_exception_id(&exception.id)
        || exception.rule_ids.is_empty()
        || !unique(&exception.rule_ids)
        || exception.paths.is_empty()
        || !unique(&exception.paths)
        || exception.owner.trim().is_empty()
        || exception.rationale.trim().len() < 20
        || exception.compensating_tests.is_empty()
        || exception
            .compensating_tests
            .iter()
            .any(|test| test.trim().is_empty())
        || exception.approval.reviewer.trim().is_empty()
        || exception.approval.status != "approved"
        || !valid_date(&exception.reviewed_on)
        || !valid_date(&exception.expires_on)
        || !valid_date_order(&exception.reviewed_on, &exception.expires_on)
        || date_days(&exception.expires_on)? < as_of
        || date_days(&exception.reviewed_on)? > as_of
        || exception.removal_criteria.trim().len() < 10
    {
        return Err("exception is missing required, current approval evidence".to_owned());
    }
    if exception.approval.record == "pending"
        || exception.approval.record == "self"
        || (!exception.approval.record.starts_with("local-review:")
            && !valid_review_url(&exception.approval.record))
    {
        return Err("exception approval record is not a verifiable review reference".to_owned());
    }
    if !allow_fixture_review {
        return Err(
            "exception approval record needs independently validated review evidence; fixture review records are not accepted"
                .to_owned(),
        );
    }
    if exception.approval.record.starts_with("local-review:")
        && !valid_relative_path(
            exception
                .approval
                .record
                .strip_prefix("local-review:")
                .unwrap_or_default(),
        )
    {
        return Err("local exception review record must name a safe review artifact".to_owned());
    }
    for rule in &exception.rule_ids {
        if !valid_rule_id(rule) {
            return Err(format!("invalid exception rule {rule}"));
        }
        if let Some(known) = known_rule_ids
            && !known.contains_key(rule)
        {
            return Err(format!("exception references unknown rule {rule}"));
        }
        if let Some(known) = known_rule_ids
            && !known[rule]
        {
            return Err(format!("rule {rule} is not exception eligible"));
        }
    }
    for path in &exception.paths {
        if !valid_relative_path(path) || path == "." || path.contains('*') {
            return Err(format!("exception path is not exact and relative: {path}"));
        }
    }
    Ok(())
}

fn sync_bundle(args: &Cli) -> Result<()> {
    let source_root = args.source_root.canonicalize().map_err(|error| {
        format!(
            "cannot read source root {}: {error}",
            args.source_root.display()
        )
    })?;
    let target_root = if args.target_root.as_os_str().is_empty() {
        return Err("--target-root is required for sync".to_owned());
    } else {
        args.target_root.clone()
    };
    if !valid_repository(&args.repository)
        || !valid_profile_id(&args.profile_id)
        || !is_upper_identifier(&args.owner)
        || !valid_commit(&args.source_commit)
    {
        return Err("sync repository, profile, owner, or source commit is invalid".to_owned());
    }
    let source_standards = source_root.join("standards");
    require_directory(&source_standards)?;
    let profile_ids = validate_profile_catalog(&source_standards.join("profiles.yaml"))?;
    validate_repository_map(&source_standards.join("repositories.yaml"), &profile_ids)?;
    validate_rules(&source_standards.join("rules.yaml"))?;
    validate_schemas(&source_standards.join("schemas"))?;
    validate_conformance_inventory(&source_standards.join("conformance"))?;
    validate_adoption_identity(
        &source_standards.join("repositories.yaml"),
        &args.repository,
        &args.owner,
        &args.profile_id,
    )?;

    let target_root = if target_root.exists() {
        require_directory(&target_root)?;
        target_root
            .canonicalize()
            .map_err(|error| format!("cannot read target root: {error}"))?
    } else {
        fs::create_dir_all(&target_root)
            .map_err(|error| format!("cannot create target root: {error}"))?;
        target_root
            .canonicalize()
            .map_err(|error| format!("cannot resolve target root: {error}"))?
    };
    if source_root == target_root {
        return Err("source and target roots must differ".to_owned());
    }

    let mut files = Vec::new();
    collect_files(&source_standards, &source_standards, &mut files)?;
    files.sort();
    let mut entries = Vec::new();
    let mut source_bytes = Vec::new();
    let mut bundle_input = Vec::new();
    for path in files {
        let source_path = source_root.join(&path);
        let bytes = fs::read(&source_path)
            .map_err(|error| format!("cannot read {}: {error}", source_path.display()))?;
        append_bundle_record(&mut bundle_input, &path, &bytes);
        entries.push(LockEntry {
            path: path.clone(),
            sha256: sha256_hex(&bytes),
        });
        source_bytes.push((path, bytes));
    }
    verify_source_commit_content(&source_root, &args.source_commit, &source_bytes)?;
    let bundle_digest = format!("sha256:{}", sha256_hex(&bundle_input));
    let profile = generated_profile(
        &args.profile_id,
        &args.repository,
        &args.owner,
        &args.source_commit,
        &bundle_digest,
    )?;
    let profile_text = toml::to_string_pretty(&profile)
        .map_err(|error| format!("cannot encode profile: {error}"))?;
    let lock = LockFile {
        profile_sha256: sha256_hex(profile_text.as_bytes()),
        lock_version: 1,
        repository: args.repository.clone(),
        profile_id: args.profile_id.clone(),
        source: LockSource {
            repository: "AI-Ascension/.github".to_owned(),
            commit: args.source_commit.clone(),
            bundle_digest: bundle_digest.clone(),
            distribution: "local".to_owned(),
            published: false,
        },
        files: entries,
        protected_paths: vec![
            "standards/schemas".to_owned(),
            "standards/conformance".to_owned(),
        ],
        generated_by: "standards-sync/1".to_owned(),
    };
    validate_profile(&profile)?;
    validate_lock_shape(&lock, &profile)?;
    let lock_text = serde_json::to_string_pretty(&lock)
        .map_err(|error| format!("cannot encode lock: {error}"))?
        + "\n";

    // Detect a conflict anywhere in the managed set before writing its first file.
    // This protects a developer's existing copy even when the conflicting entry
    // sorts after many new bundle files.
    for (path, bytes) in &source_bytes {
        inspect_managed_destination(&target_root, path, bytes)?;
    }
    inspect_managed_destination(
        &target_root,
        "standards-profile.toml",
        profile_text.as_bytes(),
    )?;
    inspect_managed_destination(&target_root, "standards.lock.json", lock_text.as_bytes())?;

    for (path, bytes) in source_bytes {
        let target_path = prepare_managed_path(&target_root, &path)?;
        copy_if_absent_or_equal(&target_path, &bytes)?;
    }
    let profile_path = prepare_managed_path(&target_root, "standards-profile.toml")?;
    copy_if_absent_or_equal(&profile_path, profile_text.as_bytes())?;
    let lock_path = prepare_managed_path(&target_root, "standards.lock.json")?;
    copy_if_absent_or_equal(&lock_path, lock_text.as_bytes())?;
    println!(
        "synced {} files to {} bundle_digest={bundle_digest} published=false",
        lock.files.len(),
        target_root.display()
    );
    Ok(())
}

#[derive(Clone, Copy)]
struct CheckSpec {
    name: &'static str,
    command: &'static str,
    target: &'static str,
}

struct ProfilePlan {
    scopes: Vec<&'static str>,
    fast: Vec<CheckSpec>,
    required: Vec<CheckSpec>,
    extended: Vec<CheckSpec>,
}

const STANDARDS_VALIDATE: &str = "cargo +1.97.1 run --locked --manifest-path standards/tools/standards-sync/Cargo.toml -- validate --root .";

fn check(name: &'static str, command: &'static str, target: &'static str) -> CheckSpec {
    CheckSpec {
        name,
        command,
        target,
    }
}

fn git_diff_check() -> CheckSpec {
    check("git-diff-check", "git diff --check", ".")
}

fn standards_check() -> CheckSpec {
    check("standards-validate", STANDARDS_VALIDATE, ".")
}

fn rust_fast(include_metadata: bool) -> Vec<CheckSpec> {
    let mut checks = vec![git_diff_check(), standards_check()];
    if include_metadata {
        checks.push(check(
            "cargo-metadata",
            "cargo metadata --locked --no-deps --format-version 1",
            ".",
        ));
    }
    checks.push(check("cargo-fmt", "cargo fmt --all --check", "."));
    checks
}

fn rust_required() -> Vec<CheckSpec> {
    vec![
        check(
            "repo-policy-strict",
            "cargo run --locked --package repo-policy -- --strict",
            ".",
        ),
        check(
            "cargo-clippy",
            "cargo clippy --workspace --all-targets --all-features --locked -- -D warnings",
            ".",
        ),
        check(
            "cargo-test",
            "cargo test --workspace --all-targets --all-features --locked",
            ".",
        ),
        check(
            "cargo-doc-tests",
            "cargo test --workspace --all-features --doc --locked",
            ".",
        ),
    ]
}

fn artifact_check(name: &'static str, target: &'static str) -> CheckSpec {
    check(name, "sha256sum --check SHA256SUMS", target)
}

fn profile_plan(profile_id: &str, repository: &str) -> Result<ProfilePlan> {
    let plan = match (profile_id, repository) {
        ("org-governance", "AI-Ascension/.github") => ProfilePlan {
            scopes: vec!["markdown", "yaml", "json", "rust"],
            fast: vec![git_diff_check(), standards_check()],
            required: vec![
                check(
                    "standards-fmt",
                    "cargo +1.97.1 fmt --manifest-path standards/tools/standards-sync/Cargo.toml --check",
                    ".",
                ),
                check(
                    "standards-unit-tests",
                    "cargo +1.97.1 test --locked --manifest-path standards/tools/standards-sync/Cargo.toml",
                    ".",
                ),
                check(
                    "standards-clippy",
                    "cargo +1.97.1 clippy --locked --manifest-path standards/tools/standards-sync/Cargo.toml --all-targets -- -D warnings",
                    ".",
                ),
                check(
                    "standards-conformance",
                    "cargo +1.97.1 run --locked --manifest-path standards/tools/standards-sync/Cargo.toml -- fixture-check --root standards/conformance",
                    ".",
                ),
            ],
            extended: vec![check(
                "link-check",
                "bash tests/link-check-template.sh",
                ".",
            )],
        },
        ("rust-pure", "AI-Ascension/sts2-game-core") => ProfilePlan {
            scopes: vec!["rust"],
            fast: rust_fast(false),
            required: rust_required(),
            extended: Vec::new(),
        },
        ("rust-pure", "AI-Ascension/sts2-protocol") => {
            let mut required = rust_required();
            required.extend([
                artifact_check("artifact-runtime-v3", "artifacts/runtime-v3-gameplay"),
                artifact_check("artifact-coop", "artifacts/coop-synchronization-v1"),
                artifact_check("artifact-poc-v1", "artifacts/poc-v1"),
                artifact_check("artifact-runtime-v1", "artifacts/runtime-v1"),
                artifact_check("artifact-runtime-v2", "artifacts/runtime-v2"),
            ]);
            ProfilePlan {
                scopes: vec!["rust", "json", "contracts"],
                fast: rust_fast(true),
                required,
                extended: Vec::new(),
            }
        }
        ("rust-service", "AI-Ascension/sts2-gateway") => {
            let mut required = rust_required();
            required.extend([
                artifact_check("artifact-poc-v1", "protocol-artifact/poc-v1"),
                artifact_check("artifact-runtime-v1", "protocol-artifact/runtime-v1"),
                artifact_check("artifact-runtime-v2", "protocol-artifact/runtime-v2"),
                artifact_check(
                    "artifact-runtime-v3",
                    "protocol-artifact/runtime-v3-gameplay",
                ),
                artifact_check("artifact-coop", "protocol-artifact/coop-synchronization-v1"),
            ]);
            ProfilePlan {
                scopes: vec!["rust", "json", "contracts"],
                fast: rust_fast(false),
                required,
                extended: Vec::new(),
            }
        }
        ("rust-service", "AI-Ascension/sts2-mcp-server") => {
            let mut required = rust_required();
            required.extend([
                artifact_check("artifact-poc-v1", "protocol-artifact/poc-v1"),
                artifact_check("artifact-runtime-v1", "protocol-artifact/runtime-v1"),
                artifact_check("artifact-runtime-v2", "protocol-artifact/runtime-v2"),
                artifact_check(
                    "artifact-runtime-v3",
                    "protocol-artifact/runtime-v3-gameplay",
                ),
                check(
                    "mcp-artifact-test",
                    "cargo test --locked --package sts2-mcp-server --test artifact",
                    ".",
                ),
            ]);
            ProfilePlan {
                scopes: vec!["rust", "json", "contracts"],
                fast: rust_fast(true),
                required,
                extended: Vec::new(),
            }
        }
        ("rust-service", "AI-Ascension/sts2-harness") => {
            let mut required = rust_required();
            required.extend([
                artifact_check("artifact-poc-v1", "protocol-artifact/poc-v1"),
                artifact_check("artifact-runtime-v1", "protocol-artifact/runtime-v1"),
                artifact_check("artifact-runtime-v2", "protocol-artifact/runtime-v2"),
                check(
                    "patch-manifest",
                    "cargo test --package sts2-patch-diff --test patch_manifest --locked",
                    ".",
                ),
            ]);
            ProfilePlan {
                scopes: vec!["rust", "json", "contracts"],
                fast: rust_fast(false),
                required,
                extended: Vec::new(),
            }
        }
        ("rust-managed", "AI-Ascension/sts2-game-mod") => {
            let mut required = rust_required();
            required.extend([
                artifact_check("artifact-poc-v1", "protocol-artifact/poc-v1"),
                artifact_check("artifact-runtime-v1", "protocol-artifact/runtime-v1"),
                artifact_check("artifact-runtime-v2", "protocol-artifact/runtime-v2"),
                artifact_check(
                    "artifact-runtime-v3",
                    "protocol-artifact/runtime-v3-gameplay",
                ),
                check(
                    "managed-format",
                    "bash tools/standards/check-managed.sh format",
                    ".",
                ),
                check(
                    "managed-settings",
                    "bash tools/standards/test-managed-settings.sh",
                    ".",
                ),
                check(
                    "managed-abi",
                    "bash tools/standards/test-managed-abi.sh",
                    ".",
                ),
                check(
                    "managed-build",
                    "dotnet build experiments/managed-rust-interop/managed/ManagedInteropSpike.csproj --configuration Release",
                    ".",
                ),
                check(
                    "managed-workshop",
                    "dotnet run --project experiments/managed-rust-interop/workshop/WorkshopValidationProbe.csproj --configuration Release",
                    ".",
                ),
                check(
                    "managed-settings-probe",
                    "dotnet run --project experiments/managed-rust-interop/settings-tests/SettingsValidationProbe.csproj --configuration Release",
                    ".",
                ),
                check(
                    "managed-queue",
                    "dotnet run --project experiments/managed-rust-interop/queue-tests/RuntimeQueueProbe.csproj --configuration Release",
                    ".",
                ),
                check(
                    "managed-runtime-contract",
                    "dotnet run --project experiments/managed-rust-interop/contract-tests/RuntimeContractProbe.csproj --configuration Release",
                    ".",
                ),
                check(
                    "managed-replay",
                    "dotnet run --project experiments/managed-rust-interop/replay-tests/ReplayValidationProbe.csproj --configuration Release",
                    ".",
                ),
                check(
                    "powershell-syntax",
                    "pwsh -NoProfile -NonInteractive -File tools/standards/check-powershell.ps1",
                    ".",
                ),
                check(
                    "powershell-syntax-negative",
                    "pwsh -NoProfile -NonInteractive -File tools/standards/check-powershell.ps1 -SelfTest",
                    ".",
                ),
                check(
                    "managed-process-bridge",
                    "pwsh -NoProfile -NonInteractive -File experiments/managed-rust-interop/dev-cycle-process-tests.ps1",
                    ".",
                ),
                check(
                    "managed-windows-bridge-build",
                    "dotnet build experiments/managed-rust-interop/session-launcher/windows-bridge/SessionWindowsBridge.csproj --configuration Release -warnaserror",
                    ".",
                ),
                check(
                    "managed-windows-bridge-tests",
                    "dotnet run --project experiments/managed-rust-interop/session-launcher/bridge-tests/SessionWindowsBridgeTests.csproj --configuration Release -warnaserror",
                    ".",
                ),
                check(
                    "managed-host-candidate",
                    "dotnet run --project experiments/managed-rust-interop/host-candidate-tests/HostCandidateProbe.csproj --configuration Release",
                    ".",
                ),
                check(
                    "managed-runtime-v3",
                    "dotnet run --project experiments/managed-rust-interop/gameplay-tests/RuntimeV3ValidationProbe.csproj --configuration Release",
                    ".",
                ),
            ]);
            let extended = vec![
                check(
                    "managed-session-launcher",
                    "bash experiments/managed-rust-interop/session-launcher.test.sh",
                    ".",
                ),
                check(
                    "managed-session-restore",
                    "bash experiments/managed-rust-interop/session-restore.test.sh",
                    ".",
                ),
                check(
                    "managed-session-bridge",
                    "bash experiments/managed-rust-interop/session-bridge.test.sh",
                    ".",
                ),
                check(
                    "managed-provider-build",
                    "bash experiments/managed-rust-interop/provider-build.test.sh",
                    ".",
                ),
                check(
                    "managed-session-install",
                    "bash experiments/managed-rust-interop/session-install.test.sh",
                    ".",
                ),
                check(
                    "managed-live-authorization",
                    "bash experiments/managed-rust-interop/live-authorization.test.sh",
                    ".",
                ),
                check(
                    "managed-runtime-addon",
                    "bash experiments/managed-rust-interop/package-runtime-addon.test.sh",
                    ".",
                ),
                check(
                    "managed-dev-cycle",
                    "bash experiments/managed-rust-interop/dev-cycle.test.sh",
                    ".",
                ),
                check(
                    "managed-session-self-test",
                    "bash experiments/managed-rust-interop/session-launcher.sh --self-test",
                    ".",
                ),
                check(
                    "managed-workshop-package",
                    "bash tools/workshop/test-package-item.sh",
                    ".",
                ),
                check(
                    "managed-runtime-lifecycle",
                    "bash tools/release/test-runtime-lifecycle.sh",
                    ".",
                ),
                check(
                    "managed-gpu-provision",
                    "bash experiments/train-gpu-lifecycle/test-provision.sh",
                    ".",
                ),
                check(
                    "managed-gpu-boot",
                    "bash experiments/train-gpu-lifecycle/test-boot.sh",
                    ".",
                ),
            ];
            ProfilePlan {
                scopes: vec!["rust", "csharp", "shell", "powershell", "json", "contracts"],
                fast: rust_fast(false),
                required,
                extended,
            }
        }
        ("web-php", "AI-Ascension/aiascension.tech") => ProfilePlan {
            scopes: vec!["html", "css", "javascript", "php"],
            fast: vec![
                git_diff_check(),
                standards_check(),
                check("composer-validate", "composer validate --strict", "."),
                check("composer-lint", "composer run lint", "."),
                check("npm-format-check", "npm run format:check", "."),
                check("npm-lint", "npm run lint", "."),
                check("node-tests", "npm test", "."),
            ],
            required: vec![
                check("phpstan", "composer run analyse", "."),
                check("phpunit", "composer run test", "."),
                check("browser-check", "npm run test:browser", "."),
            ],
            extended: vec![check("composer-verify", "composer run verify", ".")],
        },
        ("web-static", "AI-Ascension/AI-Ascension.github.io") => ProfilePlan {
            scopes: vec!["html", "css", "javascript", "rust"],
            fast: vec![
                git_diff_check(),
                standards_check(),
                check("npm-format-check", "npm run format:check", "."),
                check("npm-lint", "npm run lint", "."),
                check("node-tests", "node --test tests/*.test.cjs", "."),
            ],
            required: vec![
                check("browser-check", "npm run test:browser", "."),
                check(
                    "pinned-gateway-recipe",
                    "node ../../scripts/check-recipe.mjs",
                    "recipes/gateway-lease-fence",
                ),
                check(
                    "pinned-mcp-recipe",
                    "node ../../scripts/check-recipe.mjs",
                    "recipes/mcp-seam",
                ),
            ],
            extended: Vec::new(),
        },
        ("operations", "AI-Ascension/ai-agent-observability") => ProfilePlan {
            scopes: vec!["shell", "yaml", "dockerfile", "systemd"],
            fast: vec![
                git_diff_check(),
                standards_check(),
                check("shell-syntax-init", "bash -n deploy/init.sh", "."),
                check(
                    "shell-syntax-key-bootstrap",
                    "bash -n deploy/laminar/bootstrap-project-key.sh",
                    ".",
                ),
                check(
                    "shellcheck",
                    "shellcheck --severity=warning deploy/init.sh deploy/laminar/bootstrap-project-key.sh tests/*.sh tests/fixtures/*",
                    ".",
                ),
            ],
            required: vec![
                check("bootstrap-tests", "bash tests/bootstrap.sh", "."),
                check(
                    "validation-regressions",
                    "bash tests/validation-regressions.sh",
                    ".",
                ),
                check(
                    "compose-policy-regressions",
                    "bash tests/compose-policy-regressions.sh",
                    ".",
                ),
                check(
                    "compose-source-regressions",
                    "bash tests/compose-source-regressions.sh",
                    ".",
                ),
                check(
                    "compose-invariants",
                    "bash tests/compose-invariants.sh",
                    ".",
                ),
                check(
                    "compose-config",
                    "docker compose --env-file deploy/.env.example -f deploy/compose.yaml config --quiet",
                    ".",
                ),
                check(
                    "compose-required-settings",
                    "bash tests/compose-required-settings.sh",
                    ".",
                ),
                check(
                    "compose-structured",
                    "bash tests/compose-structured.sh",
                    ".",
                ),
                check(
                    "dockerfile-mlflow",
                    "docker buildx build --check --file deploy/Dockerfile.mlflow deploy",
                    ".",
                ),
                check(
                    "dockerfile-laminar",
                    "docker buildx build --check --file deploy/Dockerfile.laminar deploy",
                    ".",
                ),
            ],
            extended: Vec::new(),
        },
        ("planning-bootstrap", "AI-Ascension/ascension-watchdog")
        | ("planning-bootstrap", "AI-Ascension/ascension-map-visualizer") => ProfilePlan {
            scopes: vec!["markdown", "configuration", "rust-tooling"],
            fast: vec![git_diff_check(), standards_check()],
            required: vec![check(
                "bootstrap-sources",
                "cargo +1.97.1 run --locked --manifest-path standards/tools/standards-sync/Cargo.toml -- check-bootstrap --root .",
                ".",
            )],
            extended: Vec::new(),
        },
        ("brand-package", "AI-Ascension/ascension-brand-overhaul") => {
            return Err(
                "brand package is explicitly excluded until its source-aware checksum review is complete"
                    .to_owned(),
            );
        }
        _ => {
            return Err(format!(
                "no verified profile command plan for {profile_id} at {repository}"
            ));
        }
    };
    Ok(plan)
}

fn spec_names(specs: &[CheckSpec]) -> Vec<String> {
    specs.iter().map(|spec| spec.name.to_owned()).collect()
}

fn validate_required_checks(profile: &Profile) -> Result<()> {
    let plan = profile_plan(&profile.profile_id, &profile.repository)?;
    if plan
        .scopes
        .iter()
        .any(|scope| !profile.scopes.iter().any(|actual| actual == scope))
    {
        return Err("profile omits a reviewed source scope".to_owned());
    }
    for spec in plan
        .fast
        .iter()
        .chain(plan.required.iter())
        .chain(plan.extended.iter())
    {
        let command = profile
            .checks
            .commands
            .get(spec.name)
            .ok_or_else(|| format!("profile omits reviewed check '{}'", spec.name))?;
        if command.command != spec.command || command.target != spec.target {
            return Err(format!(
                "profile changes reviewed invocation '{}'",
                spec.name
            ));
        }
    }
    for spec in plan.fast.iter().chain(plan.required.iter()) {
        if !profile
            .checks
            .fast
            .iter()
            .chain(profile.checks.required.iter())
            .any(|name| name == spec.name)
        {
            return Err(format!(
                "mandatory check '{}' was moved to an extended lane",
                spec.name
            ));
        }
    }
    Ok(())
}

fn generated_profile(
    profile_id: &str,
    repository: &str,
    owner: &str,
    commit: &str,
    digest: &str,
) -> Result<Profile> {
    let plan = profile_plan(profile_id, repository)?;
    let all_specs = plan
        .fast
        .iter()
        .chain(plan.required.iter())
        .chain(plan.extended.iter())
        .copied()
        .collect::<Vec<_>>();
    let mut commands = BTreeMap::new();
    for spec in all_specs {
        commands.insert(
            spec.name.to_owned(),
            CheckCommand {
                command: spec.command.to_owned(),
                target: spec.target.to_owned(),
            },
        );
    }
    Ok(Profile {
        schema_version: 1,
        profile_id: profile_id.to_owned(),
        repository: repository.to_owned(),
        owner: owner.to_owned(),
        source_bundle: "AI-Ascension/.github".to_owned(),
        source_commit: commit.to_owned(),
        source_digest: digest.to_owned(),
        distribution: "local".to_owned(),
        scopes: plan.scopes.into_iter().map(str::to_owned).collect(),
        checks: CheckSets {
            fast: spec_names(&plan.fast),
            required: spec_names(&plan.required),
            extended: spec_names(&plan.extended),
            commands,
        },
        evidence: Evidence {
            runtime: "unverified".to_owned(),
            deployment: "unverified".to_owned(),
            provider: "unverified".to_owned(),
        },
        exceptions: Exceptions {
            file: String::new(),
            status: "none".to_owned(),
        },
    })
}

fn verify_source_commit_content(
    source_root: &Path,
    commit: &str,
    source_bytes: &[(String, Vec<u8>)],
) -> Result<()> {
    let top_level = git_output(
        source_root,
        &["rev-parse".to_owned(), "--show-toplevel".to_owned()],
    )?;
    let top_level = String::from_utf8(top_level)
        .map_err(|error| format!("git returned a non-UTF-8 repository path: {error}"))?;
    let top_level = PathBuf::from(top_level.trim());
    if top_level != source_root {
        return Err(format!(
            "source root {} is not the Git worktree root {}",
            source_root.display(),
            top_level.display()
        ));
    }
    git_output(
        source_root,
        &[
            "cat-file".to_owned(),
            "-e".to_owned(),
            format!("{commit}^{{commit}}"),
        ],
    )?;
    let tree = git_output(
        source_root,
        &[
            "ls-tree".to_owned(),
            "-r".to_owned(),
            "--name-only".to_owned(),
            commit.to_owned(),
            "--".to_owned(),
            "standards".to_owned(),
        ],
    )?;
    let mut committed = String::from_utf8(tree)
        .map_err(|error| format!("source commit tree is not UTF-8: {error}"))?
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    committed.sort();
    let mut expected = source_bytes
        .iter()
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    expected.sort();
    if committed != expected {
        return Err(
            "source commit standards tree differs from the source checkout inventory; commit the exact source bundle first"
                .to_owned(),
        );
    }
    for (path, expected_bytes) in source_bytes {
        let object = format!("{commit}:{path}");
        let actual = git_output(source_root, &["show".to_owned(), object])?;
        if &actual != expected_bytes {
            return Err(format!(
                "source commit content differs from checkout for {path}; refusing sync"
            ));
        }
    }
    Ok(())
}

fn git_output(root: &Path, args: &[String]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| format!("cannot execute git for {}: {error}", root.display()))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(format!(
            "git {} failed{}",
            args.join(" "),
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        ));
    }
    Ok(output.stdout)
}

fn append_bundle_record(input: &mut Vec<u8>, path: &str, bytes: &[u8]) {
    input.extend_from_slice(path.as_bytes());
    input.push(0);
    input.extend_from_slice(bytes);
    input.push(0);
}

fn prepare_managed_path(root: &Path, relative: &str) -> Result<PathBuf> {
    if !valid_relative_path(relative) {
        return Err(format!("unsafe managed path '{relative}'"));
    }
    let components = relative.split('/').collect::<Vec<_>>();
    let mut current = root.to_path_buf();
    for component in &components[..components.len() - 1] {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "managed path traverses symlink {}",
                    current.display()
                ));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(format!(
                    "managed path component is not a directory {}",
                    current.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(&current)
                .map_err(|create_error| {
                    format!(
                        "cannot create managed directory {}: {create_error}",
                        current.display()
                    )
                })?,
            Err(error) => {
                return Err(format!(
                    "cannot inspect managed path {}: {error}",
                    current.display()
                ));
            }
        }
    }
    let path = root.join(relative);
    if let Ok(metadata) = fs::symlink_metadata(&path)
        && metadata.file_type().is_symlink()
    {
        return Err(format!("managed path is a symlink {}", path.display()));
    }
    Ok(path)
}

fn copy_if_absent_or_equal(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        require_regular_file(path)?;
        let existing =
            fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if existing != bytes {
            return Err(format!(
                "refusing to overwrite differing managed file {}",
                path.display()
            ));
        }
        return Ok(());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))
}

fn inspect_managed_destination(root: &Path, relative: &str, bytes: &[u8]) -> Result<()> {
    if !valid_relative_path(relative) {
        return Err(format!("unsafe managed path '{relative}'"));
    }
    let mut path = root.to_path_buf();
    let components: Vec<_> = relative.split('/').collect();
    for (index, component) in components.iter().enumerate() {
        path.push(component);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(format!("cannot inspect {}: {error}", path.display())),
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("managed path traverses symlink {}", path.display()));
            }
            Ok(metadata) if index + 1 == components.len() => {
                if !metadata.is_file()
                    || fs::read(&path).map_err(|error| error.to_string())? != bytes
                {
                    return Err(format!(
                        "refusing to overwrite differing managed file {}",
                        path.display()
                    ));
                }
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(format!(
                    "managed path component is not a directory {}",
                    path.display()
                ));
            }
            Ok(_) => {}
        }
    }
    Ok(())
}

fn collect_files(root: &Path, directory: &Path, output: &mut Vec<String>) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot list {}: {error}", directory.display()))?
        .collect::<io::Result<Vec<_>>>()
        .map_err(|error| format!("cannot read directory {}: {error}", directory.display()))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "symlink is not allowed in standards bundle: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            if path.strip_prefix(root).ok() == Some(Path::new("tools/standards-sync/target")) {
                continue;
            }
            collect_files(root, &path, output)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|error| format!("cannot relativize {}: {error}", path.display()))?;
            output.push(format!(
                "standards/{}",
                relative.to_string_lossy().replace('\\', "/")
            ));
        } else {
            return Err(format!("unsupported standards entry {}", path.display()));
        }
    }
    Ok(())
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    if !valid_relative_path(relative) {
        return Err(format!("unsafe path '{relative}'"));
    }
    let path = root.join(relative);
    let parent = path
        .parent()
        .ok_or_else(|| format!("path has no parent: {relative}"))?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|error| format!("cannot resolve {}: {error}", parent.display()))?;
    let canonical_root = root
        .canonicalize()
        .map_err(|error| format!("cannot resolve {}: {error}", root.display()))?;
    if !canonical_parent.starts_with(&canonical_root) {
        return Err(format!("path escapes root: {relative}"));
    }
    Ok(path)
}

fn require_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("missing directory {}: {error}", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("{} is not a real directory", path.display()));
    }
    Ok(())
}

fn require_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("missing file {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    Ok(())
}

fn parse_toml<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let text = read_text(path)?;
    toml::from_str(&text).map_err(|error| format!("{}: invalid TOML: {error}", path.display()))
}

fn parse_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let text = read_text(path)?;
    serde_json::from_str(&text)
        .map_err(|error| format!("{}: invalid JSON: {error}", path.display()))
}

fn parse_json_value(path: &Path) -> Result<Value> {
    parse_json(path)
}

fn parse_yaml<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let text = read_text(path)?;
    serde_yaml::from_str(&text)
        .map_err(|error| format!("{}: invalid YAML: {error}", path.display()))
}

fn read_text(path: &Path) -> Result<String> {
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    String::from_utf8(bytes).map_err(|error| format!("{} is not UTF-8: {error}", path.display()))
}

fn unique(values: &[String]) -> bool {
    let mut set = BTreeSet::new();
    values.iter().all(|value| set.insert(value))
}

fn valid_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_prefixed_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_hex_digest)
}

fn valid_repository(value: &str) -> bool {
    let Some(name) = value.strip_prefix("AI-Ascension/") else {
        return false;
    };
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_profile_id(value: &str) -> bool {
    (3..=49).contains(&value.len())
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_profile_scope(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
}

fn valid_rule_scope(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_language_scope(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_check_name(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
}

fn is_upper_identifier(value: &str) -> bool {
    (2..=16).contains(&value.len())
        && value.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_rule_id(value: &str) -> bool {
    let parts = value.split('-').collect::<Vec<_>>();
    parts.len() == 3
        && matches!(parts[0], "X" | "RUST" | "MANAGED" | "WEB" | "OPS" | "DOC")
        && !parts[1].is_empty()
        && parts[1]
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        && parts[2].len() == 3
        && parts[2].bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_exception_id(value: &str) -> bool {
    let parts = value.split('-').collect::<Vec<_>>();
    parts.len() == 3
        && parts[0] == "EXC"
        && !parts[1].is_empty()
        && parts[1]
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        && parts[2].len() == 3
        && parts[2].bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains('\\')
        && !value.contains('*')
        && !value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
}

fn valid_target(value: &str) -> bool {
    valid_relative_path(value) || value == "."
}

fn contains_shell_operator(value: &str) -> bool {
    value.contains(';')
        || value.contains('|')
        || value.contains('&')
        || value.contains(char::from(96))
        || value.contains("$(")
        || value.contains('>')
        || value.contains('<')
}

fn has_safe_executable(value: &str) -> bool {
    value.split_whitespace().next().is_some_and(|executable| {
        executable
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
    })
}

fn valid_node_id(value: &str) -> bool {
    value.starts_with("R_kg")
        && value.len() > 4
        && value
            .bytes()
            .skip(4)
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn valid_review_url(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://github.com/AI-Ascension/") else {
        return false;
    };
    let mut parts = rest.split('/');
    let Some(repository) = parts.next() else {
        return false;
    };
    let Some(kind) = parts.next() else {
        return false;
    };
    let Some(number) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && valid_repository(&format!("AI-Ascension/{repository}"))
        && matches!(kind, "issues" | "pull")
        && !number.is_empty()
        && number.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_date(value: &str) -> bool {
    date_parts(value).is_some()
}

fn valid_date_order(start: &str, end: &str) -> bool {
    match (date_days(start), date_days(end)) {
        (Ok(start), Ok(end)) => start <= end,
        _ => false,
    }
}

fn date_parts(value: &str) -> Option<(i32, u32, u32)> {
    let mut parts = value.split('-');
    let year = parts.next()?.parse::<i32>().ok()?;
    let month = parts.next()?.parse::<u32>().ok()?;
    let day = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some()
        || value.len() != 10
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
    {
        return None;
    }
    Some((year, month, day))
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn date_days(value: &str) -> Result<i64> {
    let (year, month, day) = date_parts(value).ok_or_else(|| format!("invalid date '{value}'"))?;
    let adjusted_year = year - i32::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year / 400
    } else {
        (adjusted_year - 399) / 400
    };
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month as i32 + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day as i32 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Ok(i64::from(era * 146097 + day_of_era - 719468))
}

fn as_of_days(as_of: Option<&str>) -> Result<i64> {
    match as_of {
        Some(value) => date_days(value),
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| (duration.as_secs() / 86_400) as i64)
            .map_err(|error| format!("cannot determine current UTC date: {error}")),
    }
}

fn create_fixture_directory() -> Result<PathBuf> {
    let base = std::env::temp_dir();
    let pid = std::process::id();
    for attempt in 0..1000u32 {
        let root = base.join(format!("standards-sync-fixture-{pid}-{attempt}"));
        let marker = root.with_extension("creating");
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker)
        {
            Ok(file) => {
                drop(file);
                let result = fs::create_dir(&root);
                let _ = fs::remove_file(&marker);
                match result {
                    Ok(()) => return Ok(root),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        return Err(format!(
                            "cannot create unique fixture directory {}: {error}",
                            root.display()
                        ));
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "cannot reserve unique fixture directory {}: {error}",
                    marker.display()
                ));
            }
        }
    }
    Err("cannot reserve a unique fixture directory after 1000 attempts".to_owned())
}

fn sha256_hex(input: &[u8]) -> String {
    Sha256::digest(input)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod conformance_tests;

#[cfg(test)]
mod tests {
    use super::{
        date_days, sha256_hex, valid_commit, valid_relative_path, valid_target, validate_schemas,
    };

    #[test]
    fn sha256_matches_published_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn path_and_commit_guards_reject_ambiguous_inputs() {
        assert!(valid_commit("0123456789abcdef0123456789abcdef01234567"));
        assert!(!valid_commit("main"));
        assert!(valid_relative_path("standards/schemas/profile.schema.json"));
        assert!(!valid_relative_path("standards/../secret"));
        assert!(!valid_relative_path("/absolute"));
        assert!(valid_target("."));
        assert!(!valid_target("a/../secret"));
    }

    #[test]
    fn date_order_uses_calendar_days() {
        assert!(
            date_days("2026-02-28")
                .ok()
                .zip(date_days("2026-03-01").ok())
                .is_some_and(|(start, end)| start < end)
        );
        assert!(
            date_days("2024-02-29")
                .ok()
                .zip(date_days("2024-03-01").ok())
                .is_some_and(|(start, end)| start < end)
        );
    }

    #[test]
    fn canonical_schema_documents_have_semantic_metadata() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join("standards/schemas");
        assert!(validate_schemas(&root).is_ok());
    }
}
