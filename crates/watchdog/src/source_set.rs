//! Read-only verification of an exact cross-repository source and contract set.
//!
//! This is deliberately a gate, not a release publisher. It checks the
//! immutable inputs that can be inspected from a collection of already
//! fetched worktrees: full commit pins, clean working trees, repository
//! remotes, checksum manifests, and the serialized consumer contract. It
//! does not fetch, build, install, activate, or run any companion service.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, symlink_metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

const MAX_SOURCE_SET_MANIFEST_BYTES: usize = 1_048_576;
const MAX_CHECKSUMS_BYTES: usize = 4 * 1_048_576;
const MAX_CONTRACT_JSON_BYTES: usize = 4 * 1_048_576;
const EXPECTED_CONSUMERS: [&str; 3] = ["sts2-gateway", "sts2-mcp-server", "sts2-harness"];
const REQUIRED_SOURCE_REPOSITORIES: [&str; 7] = [
    "ascension-watchdog",
    "sts2-gateway",
    "sts2-harness",
    "sts2-mcp-server",
    "sts2-game-mod",
    "sts2-protocol",
    "sts2-game-core",
];
const DEFAULT_ARTIFACTS: [(&str, &str); 4] = [
    ("sts2-protocol", "artifacts/coop-native-v1"),
    ("sts2-gateway", "protocol-artifact/coop-native-v1"),
    ("sts2-harness", "protocol-artifact/coop-native-v1"),
    ("sts2-mcp-server", "protocol-artifact/coop-native-v1"),
];
const REQUIRED_ARTIFACT_FILES: [&str; 5] = [
    "SHA256SUMS",
    "manifest.json",
    "schema.json",
    "conformance.json",
    "consumer-conformance.json",
];
const CONTRACT_FILES: [&str; 4] = [
    "manifest.json",
    "schema.json",
    "conformance.json",
    "consumer-conformance.json",
];

#[derive(Debug, Deserialize)]
struct SourceSetManifest {
    schema_version: u32,
    classification: String,
    repositories: BTreeMap<String, RepositoryPin>,
}

#[derive(Debug, Deserialize)]
struct RepositoryPin {
    revision: String,
    #[serde(rename = "ref")]
    reference: String,
    remote: String,
    #[serde(flatten)]
    _additional: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceSetReport {
    pub verifier_version: u32,
    pub manifest_sha256: String,
    pub classification: String,
    pub repository_count: usize,
    pub artifact_count: usize,
    pub admitted: bool,
    pub repositories: BTreeMap<String, RepositoryReport>,
    pub artifacts: BTreeMap<String, ArtifactReport>,
    pub contract_comparison: ContractComparisonReport,
    pub issues: Vec<String>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Serialize)]
pub struct RepositoryReport {
    pub expected_revision: String,
    pub actual_revision: Option<String>,
    pub expected_ref: String,
    pub observed_ref: Option<String>,
    pub expected_remote: String,
    pub observed_remote: Option<String>,
    pub clean: bool,
    pub revision_match: bool,
    pub remote_match: bool,
    pub passed: bool,
    pub issues: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ArtifactReport {
    pub repository: String,
    pub relative_path: String,
    pub present: bool,
    pub checksums_checked: bool,
    pub checksum_entries: usize,
    pub required_files: BTreeMap<String, String>,
    pub contract_files: BTreeMap<String, String>,
    pub consumer_status: Option<String>,
    pub consumer_boundary: Option<String>,
    pub consumer_commits: BTreeMap<String, String>,
    pub passed: bool,
    pub issues: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ContractComparisonReport {
    pub files: BTreeMap<String, BTreeMap<String, String>>,
    pub contract_files_identical: bool,
    pub issues: Vec<String>,
}

/// Verify a candidate manifest against explicitly supplied local worktrees.
///
/// The returned report is complete even when admission fails. Callers should
/// preserve the report and use its admitted field as the gate; an absent
/// repository, dirty worktree, stale consumer binding, missing artifact, or
/// checksum failure never becomes a warning-only result.
pub fn verify_document(
    manifest_path: &Path,
    repository_paths: &BTreeMap<String, PathBuf>,
    artifact_paths: &BTreeMap<String, PathBuf>,
) -> Result<SourceSetReport, String> {
    let manifest_bytes = read_bounded(manifest_path, MAX_SOURCE_SET_MANIFEST_BYTES)?;
    let manifest_sha256 = digest_hex(&Sha256::digest(&manifest_bytes));
    let manifest: SourceSetManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("invalid source-set manifest: {error}"))?;
    validate_manifest(&manifest)?;

    let mut issues = Vec::new();
    let expected_names = manifest
        .repositories
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    for name in repository_paths.keys() {
        if !expected_names.contains(name) {
            issues.push(format!(
                "repository path supplied for unknown manifest entry {name}"
            ));
        }
    }

    let mut repositories = BTreeMap::new();
    let mut canonical_repositories = BTreeMap::new();
    for (name, pin) in &manifest.repositories {
        let Some(path) = repository_paths.get(name) else {
            repositories.insert(name.clone(), missing_repository_report(pin));
            issues.push(format!("repository path missing for {name}"));
            continue;
        };
        let (report, canonical) = inspect_repository(pin, path);
        if let Some(canonical) = canonical {
            canonical_repositories.insert(name.clone(), canonical);
        }
        if !report.passed {
            issues.extend(report.issues.iter().map(|issue| format!("{name}: {issue}")));
        }
        repositories.insert(name.clone(), report);
    }

    for required in REQUIRED_SOURCE_REPOSITORIES {
        if !manifest.repositories.contains_key(required) {
            issues.push(format!(
                "manifest omits required source repository {required}"
            ));
        }
    }

    let expected_artifacts = DEFAULT_ARTIFACTS
        .into_iter()
        .map(|(name, relative)| (name.to_owned(), relative.to_owned()))
        .collect::<BTreeMap<_, _>>();
    for name in artifact_paths.keys() {
        if !expected_artifacts.contains_key(name) {
            issues.push(format!(
                "artifact path supplied for unknown contract repository {name}"
            ));
        }
    }

    let mut artifacts = BTreeMap::new();
    for (repository, relative_path) in expected_artifacts {
        let path = artifact_paths.get(&repository).cloned().or_else(|| {
            canonical_repositories
                .get(&repository)
                .map(|root| root.join(&relative_path))
        });
        let report = match path {
            Some(path) => inspect_artifact(
                &repository,
                &relative_path,
                &path,
                canonical_repositories.get(&repository),
                &manifest.repositories,
            ),
            None => missing_artifact_report(&repository, &relative_path),
        };
        if !report.passed {
            issues.extend(
                report
                    .issues
                    .iter()
                    .map(|issue| format!("{repository} artifact: {issue}")),
            );
        }
        artifacts.insert(repository, report);
    }

    let contract_comparison = compare_contract_files(&artifacts);
    if !contract_comparison.contract_files_identical {
        issues.extend(
            contract_comparison
                .issues
                .iter()
                .map(|issue| format!("contract: {issue}")),
        );
    }

    let repositories_pass = repositories.values().all(|report| report.passed)
        && repositories.len() == manifest.repositories.len()
        && repository_paths.len() == manifest.repositories.len();
    let artifacts_pass = artifacts.values().all(|report| report.passed);
    let admitted = issues.is_empty() && repositories_pass && artifacts_pass;

    Ok(SourceSetReport {
        verifier_version: 1,
        manifest_sha256,
        classification: manifest.classification,
        repository_count: repositories.len(),
        artifact_count: artifacts.len(),
        admitted,
        repositories,
        artifacts,
        contract_comparison,
        issues,
    })
}

fn validate_manifest(manifest: &SourceSetManifest) -> Result<(), String> {
    if manifest.schema_version != 1 {
        return Err(format!(
            "unsupported source-set manifest schema version {}",
            manifest.schema_version
        ));
    }
    if manifest.classification.trim().is_empty() {
        return Err("source-set manifest classification is empty".to_owned());
    }
    if manifest.repositories.is_empty() {
        return Err("source-set manifest has no repositories".to_owned());
    }
    for (name, pin) in &manifest.repositories {
        if name.is_empty() || name.contains('/') || name.contains('\\') {
            return Err(format!("invalid source repository name {name:?}"));
        }
        if !valid_revision(&pin.revision) {
            return Err(format!(
                "source repository {name} does not use a full commit pin"
            ));
        }
        if pin.reference.trim().is_empty() {
            return Err(format!("source repository {name} has an empty ref"));
        }
        if normalize_remote(&pin.remote).is_none() {
            return Err(format!(
                "source repository {name} has an unsupported remote"
            ));
        }
    }
    Ok(())
}

fn inspect_repository(pin: &RepositoryPin, path: &Path) -> (RepositoryReport, Option<PathBuf>) {
    let mut report = RepositoryReport {
        expected_revision: pin.revision.clone(),
        actual_revision: None,
        expected_ref: pin.reference.clone(),
        observed_ref: None,
        expected_remote: pin.remote.clone(),
        observed_remote: None,
        clean: false,
        revision_match: false,
        remote_match: false,
        passed: false,
        issues: Vec::new(),
    };

    let Ok(canonical) = path.canonicalize() else {
        report
            .issues
            .push("worktree path is unavailable".to_owned());
        return (report, None);
    };
    if !canonical.is_dir() {
        report
            .issues
            .push("worktree path is not a directory".to_owned());
        return (report, None);
    }

    let root_output = match git(&canonical, &["rev-parse", "--show-toplevel"]) {
        Ok(output) => output,
        Err(issue) => {
            report.issues.push(issue);
            return (report, None);
        }
    };
    let Ok(git_root) = PathBuf::from(root_output.trim()).canonicalize() else {
        report
            .issues
            .push("Git did not report a usable worktree root".to_owned());
        return (report, None);
    };
    if git_root != canonical {
        report
            .issues
            .push("supplied path is not the Git worktree root".to_owned());
        return (report, Some(git_root));
    }

    match git(&canonical, &["rev-parse", "HEAD"]) {
        Ok(actual) => {
            let actual = actual.trim().to_owned();
            report.revision_match = actual == pin.revision;
            report.actual_revision = Some(actual);
            if !report.revision_match {
                report
                    .issues
                    .push("HEAD differs from the manifest pin".to_owned());
            }
        }
        Err(issue) => report.issues.push(issue),
    }

    match git(
        &canonical,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
    ) {
        Ok(status) => {
            report.clean = status.trim().is_empty();
            if !report.clean {
                report.issues.push("working tree is dirty".to_owned());
            }
        }
        Err(issue) => report.issues.push(issue),
    }

    match git(&canonical, &["branch", "--show-current"]) {
        Ok(reference) => {
            let reference = reference.trim().to_owned();
            if !reference.is_empty() {
                if reference != pin.reference {
                    report
                        .issues
                        .push("checked-out branch differs from the manifest ref".to_owned());
                }
                report.observed_ref = Some(reference);
            }
        }
        Err(issue) => report.issues.push(issue),
    }

    match git(&canonical, &["remote", "get-url", "origin"]) {
        Ok(remote) => {
            let remote = remote.trim().to_owned();
            report.remote_match = normalize_remote(&remote)
                .zip(normalize_remote(&pin.remote))
                .is_some_and(|(actual, expected)| actual.eq_ignore_ascii_case(&expected));
            report.observed_remote = Some(remote);
            if !report.remote_match {
                report
                    .issues
                    .push("origin remote differs from the manifest".to_owned());
            }
        }
        Err(issue) => report.issues.push(issue),
    }

    report.passed =
        report.issues.is_empty() && report.clean && report.revision_match && report.remote_match;
    (report, Some(canonical))
}

fn missing_repository_report(pin: &RepositoryPin) -> RepositoryReport {
    RepositoryReport {
        expected_revision: pin.revision.clone(),
        actual_revision: None,
        expected_ref: pin.reference.clone(),
        observed_ref: None,
        expected_remote: pin.remote.clone(),
        observed_remote: None,
        clean: false,
        revision_match: false,
        remote_match: false,
        passed: false,
        issues: vec!["worktree path was not supplied".to_owned()],
    }
}

fn inspect_artifact(
    repository: &str,
    relative_path: &str,
    path: &Path,
    repository_root: Option<&PathBuf>,
    repositories: &BTreeMap<String, RepositoryPin>,
) -> ArtifactReport {
    let mut report = ArtifactReport {
        repository: repository.to_owned(),
        relative_path: relative_path.to_owned(),
        present: false,
        checksums_checked: false,
        checksum_entries: 0,
        required_files: BTreeMap::new(),
        contract_files: BTreeMap::new(),
        consumer_status: None,
        consumer_boundary: None,
        consumer_commits: BTreeMap::new(),
        passed: false,
        issues: Vec::new(),
    };

    let Some(repository_root) = repository_root else {
        report
            .issues
            .push("repository worktree was not admitted".to_owned());
        return report;
    };
    if !symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_dir())
        .unwrap_or(false)
    {
        report
            .issues
            .push("artifact path is not a real directory".to_owned());
        return report;
    }
    let Ok(artifact_root) = path.canonicalize() else {
        report
            .issues
            .push("artifact directory is unavailable".to_owned());
        return report;
    };
    if !artifact_root.is_dir() {
        report
            .issues
            .push("artifact path is not a directory".to_owned());
        return report;
    }
    if !artifact_root.starts_with(repository_root) {
        report
            .issues
            .push("artifact directory escapes its repository worktree".to_owned());
        return report;
    }
    report.present = true;

    for file_name in REQUIRED_ARTIFACT_FILES {
        let file_path = artifact_root.join(file_name);
        if !regular_file(&file_path) {
            report
                .issues
                .push(format!("required artifact file {file_name} is missing"));
            continue;
        }
        match hash_file(&file_path) {
            Ok(digest) => {
                report.required_files.insert(file_name.to_owned(), digest);
            }
            Err(_) => report.issues.push(format!(
                "required artifact file {file_name} could not be hashed"
            )),
        }
    }

    for file_name in CONTRACT_FILES {
        let file_path = artifact_root.join(file_name);
        if regular_file(&file_path) {
            match hash_file(&file_path) {
                Ok(digest) => {
                    report.contract_files.insert(file_name.to_owned(), digest);
                }
                Err(_) => report
                    .issues
                    .push(format!("contract file {file_name} could not be hashed")),
            }
        }
    }
    for golden in golden_files(&artifact_root) {
        let relative = golden
            .strip_prefix(&artifact_root)
            .ok()
            .and_then(Path::to_str)
            .map(str::to_owned);
        let Some(relative) = relative else {
            report
                .issues
                .push("golden contract path is not UTF-8".to_owned());
            continue;
        };
        match hash_file(&golden) {
            Ok(digest) => {
                report.contract_files.insert(relative, digest);
            }
            Err(_) => report
                .issues
                .push("golden contract file could not be hashed".to_owned()),
        }
    }

    match validate_checksums(&artifact_root, repository_root) {
        Ok(entries) => {
            report.checksums_checked = true;
            report.checksum_entries = entries.len();
            for required in REQUIRED_ARTIFACT_FILES.iter().skip(1) {
                if !entries.contains(*required) {
                    report
                        .issues
                        .push(format!("SHA256SUMS does not cover {required}"));
                }
            }
        }
        Err(issue) => report.issues.push(issue),
    }

    let consumer_path = artifact_root.join("consumer-conformance.json");
    if regular_file(&consumer_path) {
        match read_bounded(&consumer_path, MAX_CONTRACT_JSON_BYTES)
            .and_then(|bytes| inspect_consumer_conformance(&bytes, repositories))
        {
            Ok(summary) => {
                report.consumer_status = summary.status;
                report.consumer_boundary = summary.boundary;
                report.consumer_commits = summary.commits;
                report.issues.extend(summary.issues);
            }
            Err(issue) => report.issues.push(issue),
        }
    }

    report.passed = report.present
        && report.checksums_checked
        && REQUIRED_ARTIFACT_FILES
            .iter()
            .all(|file| report.required_files.contains_key(*file))
        && report.issues.is_empty();
    report
}

fn missing_artifact_report(repository: &str, relative_path: &str) -> ArtifactReport {
    ArtifactReport {
        repository: repository.to_owned(),
        relative_path: relative_path.to_owned(),
        present: false,
        checksums_checked: false,
        checksum_entries: 0,
        required_files: BTreeMap::new(),
        contract_files: BTreeMap::new(),
        consumer_status: None,
        consumer_boundary: None,
        consumer_commits: BTreeMap::new(),
        passed: false,
        issues: vec!["artifact cannot be resolved without an admitted repository".to_owned()],
    }
}

fn inspect_consumer_conformance(
    bytes: &[u8],
    repositories: &BTreeMap<String, RepositoryPin>,
) -> Result<ConsumerSummary, String> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("consumer-conformance.json is invalid JSON: {error}"))?;
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let boundary = value
        .get("cross_boundary")
        .and_then(|value| value.get("source_to_consumer"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut issues = Vec::new();
    if status.as_deref().is_none_or(str::is_empty) {
        issues.push("consumer conformance has no status".to_owned());
    }
    if boundary.as_deref() != Some("pass") {
        issues.push("consumer boundary is not settled as pass".to_owned());
    }
    if contains_pending(&value) {
        issues.push("consumer conformance contains a pending marker".to_owned());
    }

    let mut commits = BTreeMap::new();
    let Some(consumers) = value.get("consumers").and_then(Value::as_array) else {
        issues.push("consumer conformance has no consumer array".to_owned());
        return Ok(ConsumerSummary {
            status,
            boundary,
            commits,
            issues,
        });
    };
    let mut seen = BTreeSet::new();
    for consumer in consumers {
        let Some(repository) = consumer.get("repository").and_then(Value::as_str) else {
            issues.push("consumer entry has no repository".to_owned());
            continue;
        };
        if !seen.insert(repository.to_owned()) {
            issues.push(format!("consumer {repository} appears more than once"));
        }
        let commit = consumer
            .get("commit")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        commits.insert(repository.to_owned(), commit.clone());
        let Some(pin) = repositories.get(repository) else {
            issues.push(format!(
                "consumer {repository} is absent from the source manifest"
            ));
            continue;
        };
        if commit != pin.revision {
            issues.push(format!(
                "consumer {repository} is not bound to the manifest revision"
            ));
        }
        if consumer.get("result").and_then(Value::as_str) != Some("pass") {
            issues.push(format!("consumer {repository} does not report pass"));
        }
    }
    let expected = EXPECTED_CONSUMERS
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    if seen != expected {
        issues.push("consumer set differs from the required gateway/MCP/harness set".to_owned());
    }

    Ok(ConsumerSummary {
        status,
        boundary,
        commits,
        issues,
    })
}

struct ConsumerSummary {
    status: Option<String>,
    boundary: Option<String>,
    commits: BTreeMap<String, String>,
    issues: Vec<String>,
}

fn contains_pending(value: &Value) -> bool {
    match value {
        Value::String(value) => value == "pending" || value.starts_with("pending-"),
        Value::Array(values) => values.iter().any(contains_pending),
        Value::Object(values) => values.values().any(contains_pending),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn compare_contract_files(
    artifacts: &BTreeMap<String, ArtifactReport>,
) -> ContractComparisonReport {
    let mut files = BTreeMap::<String, BTreeMap<String, String>>::new();
    for (repository, artifact) in artifacts {
        for (file, digest) in &artifact.contract_files {
            files
                .entry(file.clone())
                .or_default()
                .insert(repository.clone(), digest.clone());
        }
    }

    let mut issues = Vec::new();
    let repository_names = artifacts.keys().cloned().collect::<Vec<_>>();
    for file in files.keys().cloned().collect::<Vec<_>>() {
        let Some(observed) = files.get(&file) else {
            issues.push(format!("{file} disappeared during contract comparison"));
            continue;
        };
        if observed.len() != repository_names.len() {
            issues.push(format!(
                "{file} is missing from one or more contract artifacts"
            ));
            continue;
        }
        let unique = observed.values().collect::<BTreeSet<_>>();
        if unique.len() != 1 {
            issues.push(format!("{file} differs across contract artifacts"));
        }
    }
    for file in CONTRACT_FILES {
        if !files.contains_key(file) {
            issues.push(format!("{file} is absent from every contract artifact"));
        }
    }
    ContractComparisonReport {
        files,
        contract_files_identical: issues.is_empty(),
        issues,
    }
}

fn validate_checksums(
    artifact_root: &Path,
    repository_root: &Path,
) -> Result<BTreeSet<String>, String> {
    let repository_root = repository_root
        .canonicalize()
        .map_err(|_| "repository root is unavailable".to_owned())?;
    let checksums = read_bounded(&artifact_root.join("SHA256SUMS"), MAX_CHECKSUMS_BYTES)?;
    let text = std::str::from_utf8(&checksums).map_err(|_| "SHA256SUMS is not UTF-8".to_owned())?;
    let mut seen = BTreeSet::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Some((digest, relative)) = line.split_once("  ") else {
            return Err("SHA256SUMS contains a malformed row".to_owned());
        };
        let relative = relative.strip_prefix('*').unwrap_or(relative);
        if !valid_digest(digest) || relative.is_empty() || Path::new(relative).is_absolute() {
            return Err("SHA256SUMS contains an invalid digest or path".to_owned());
        }
        if !seen.insert(relative.to_owned()) {
            return Err("SHA256SUMS contains a duplicate path".to_owned());
        }
        let path = artifact_root.join(relative);
        let canonical = path
            .canonicalize()
            .map_err(|_| "SHA256SUMS names a missing file".to_owned())?;
        if !regular_file(&path) || !canonical.starts_with(&repository_root) {
            return Err("SHA256SUMS names a path outside the repository".to_owned());
        }
        let actual = hash_file(&canonical)
            .map_err(|_| "SHA256SUMS names a file that could not be hashed".to_owned())?;
        if actual != digest {
            return Err("SHA256SUMS contains a digest mismatch".to_owned());
        }
    }
    if seen.is_empty() {
        return Err("SHA256SUMS contains no entries".to_owned());
    }
    Ok(seen)
}

fn golden_files(root: &Path) -> Vec<PathBuf> {
    let golden = root.join("golden");
    let Ok(entries) = fs::read_dir(golden) else {
        return Vec::new();
    };
    let mut files = entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| regular_file(path))
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn git(path: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(arguments)
        .output()
        .map_err(|_| "Git is unavailable".to_owned())?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.trim();
        if detail.is_empty() {
            return Err(format!("git {} failed", arguments.join(" ")));
        }
        return Err(format!("git {} failed: {detail}", arguments.join(" ")));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let metadata = symlink_metadata(path).map_err(|_| "required file is unavailable".to_owned())?;
    if !metadata.file_type().is_file() {
        return Err("required path is not a regular file".to_owned());
    }
    let length = usize::try_from(metadata.len()).map_err(|_| "file length overflows".to_owned())?;
    if length > maximum {
        return Err("file exceeds the verifier byte bound".to_owned());
    }
    let mut file = File::open(path).map_err(|_| "required file cannot be opened".to_owned())?;
    let mut bytes = Vec::with_capacity(length);
    file.read_to_end(&mut bytes)
        .map_err(|_| "required file cannot be read".to_owned())?;
    Ok(bytes)
}

fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|_| "file cannot be opened".to_owned())?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 65_536];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| "file cannot be read".to_owned())?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest_hex(&digest.finalize()))
}

fn regular_file(path: &Path) -> bool {
    symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

fn normalize_remote(remote: &str) -> Option<String> {
    let remote = remote.trim().trim_end_matches('/').trim_end_matches(".git");
    let repository = if let Some(repository) = remote.strip_prefix("git@github.com:") {
        repository
    } else if let Some(repository) = remote.strip_prefix("https://github.com/") {
        repository
    } else if let Some(repository) = remote.strip_prefix("ssh://git@github.com/") {
        repository
    } else if !remote.contains("://") && !remote.contains(':') {
        remote
    } else {
        return None;
    };
    let repository = repository.trim_matches('/');
    (repository.split('/').count() == 2 && !repository.contains(char::is_whitespace))
        .then(|| repository.to_owned())
}

fn valid_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(DIGITS[usize::from(byte >> 4)]),
                char::from(DIGITS[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    #[test]
    fn remote_normalization_accepts_https_and_ssh_only_for_github() {
        assert_eq!(
            normalize_remote("https://github.com/AI-Ascension/ascension-watchdog.git"),
            Some("AI-Ascension/ascension-watchdog".to_owned())
        );
        assert_eq!(
            normalize_remote("git@github.com:AI-Ascension/ascension-watchdog.git"),
            Some("AI-Ascension/ascension-watchdog".to_owned())
        );
        assert_eq!(
            normalize_remote("AI-Ascension/ascension-watchdog"),
            Some("AI-Ascension/ascension-watchdog".to_owned())
        );
        assert!(normalize_remote("https://example.invalid/AI-Ascension/watchdog").is_none());
    }

    #[test]
    fn checksum_reader_rejects_traversal_and_accepts_bounded_parent_paths() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let repository = temporary.path().join("repo");
        let artifact = repository.join("nested/artifact");
        fs::create_dir_all(repository.join("schemas")).expect("schemas");
        fs::create_dir_all(&artifact).expect("artifact");
        fs::write(repository.join("schemas/schema.json"), b"schema").expect("schema");
        let digest = digest_hex(&Sha256::digest(b"schema"));
        fs::write(
            artifact.join("SHA256SUMS"),
            format!("{digest}  ../../schemas/schema.json\n"),
        )
        .expect("checksums");
        assert_eq!(
            validate_checksums(&artifact, &repository).map(|entries| entries.len()),
            Ok(1)
        );
        fs::write(
            artifact.join("SHA256SUMS"),
            format!("{digest}  ../../../outside.json\n"),
        )
        .expect("checksums");
        assert!(validate_checksums(&artifact, &repository).is_err());
    }

    #[test]
    fn consumer_conformance_requires_current_pins_and_settled_boundary() {
        let repositories = EXPECTED_CONSUMERS
            .into_iter()
            .map(|name| {
                (
                    name.to_owned(),
                    RepositoryPin {
                        revision: "a".repeat(40),
                        reference: "main".to_owned(),
                        remote: format!("AI-Ascension/{name}"),
                        _additional: BTreeMap::new(),
                    },
                )
            })
            .collect();
        let value = serde_json::json!({
            "status": "accepted_component",
            "consumers": EXPECTED_CONSUMERS.into_iter().map(|name| serde_json::json!({
                "repository": name,
                "commit": "b".repeat(40),
                "result": "pass"
            })).collect::<Vec<_>>(),
            "cross_boundary": {"source_to_consumer": "pending-final-adapter-conformance"}
        });
        let summary =
            inspect_consumer_conformance(&serde_json::to_vec(&value).expect("JSON"), &repositories)
                .expect("conformance parses");
        assert!(
            summary
                .issues
                .iter()
                .any(|issue| issue.contains("manifest revision"))
        );
        assert!(
            summary
                .issues
                .iter()
                .any(|issue| issue.contains("pending marker"))
        );
        assert!(
            summary
                .issues
                .iter()
                .any(|issue| issue.contains("settled as pass"))
        );
    }

    #[test]
    fn git_fixture_report_is_clean_and_exact() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        run_git(temporary.path(), &["init", "--quiet"]);
        run_git(temporary.path(), &["config", "user.name", "fixture"]);
        run_git(
            temporary.path(),
            &["config", "user.email", "fixture@example.invalid"],
        );
        fs::write(temporary.path().join("file"), b"fixture").expect("file");
        run_git(temporary.path(), &["add", "file"]);
        run_git(temporary.path(), &["commit", "--quiet", "-m", "fixture"]);
        let revision = git(temporary.path(), &["rev-parse", "HEAD"])
            .expect("revision")
            .trim()
            .to_owned();
        run_git(
            temporary.path(),
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/AI-Ascension/fixture.git",
            ],
        );
        let pin = RepositoryPin {
            revision,
            reference: "master".to_owned(),
            remote: "AI-Ascension/fixture".to_owned(),
            _additional: BTreeMap::new(),
        };
        let (report, root) = inspect_repository(&pin, temporary.path());
        assert!(report.passed, "{report:?}");
        assert_eq!(root, Some(temporary.path().canonicalize().expect("root")));
    }

    fn run_git(path: &Path, arguments: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(arguments)
            .stdin(Stdio::null())
            .status()
            .expect("git fixture command");
        assert!(
            status.success(),
            "git fixture command failed: {arguments:?}"
        );
    }
}
