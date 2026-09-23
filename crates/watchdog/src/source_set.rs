//! Read-only verification of an exact cross-repository source and contract set.
//!
//! This is deliberately a gate, not a release publisher. It checks the
//! immutable inputs that can be inspected from a collection of already
//! fetched worktrees: full commit pins, clean working trees, repository
//! remotes, checksum manifests, and the serialized consumer contract. An
//! artifact-only delivery revision may additionally identify the exact source
//! revision/tree that consumer records bind to; the verifier requires that
//! source to be an ancestor and rejects any diff outside the declared artifact
//! directory. It does not fetch, build, install, activate, or run any
//! companion service.
//!
//! The verifier is split into cohesive child modules; this file stays the
//! `source_set` coordinator so every existing path into the module keeps
//! working:
//!
//! - `validation` owns manifest schema admission plus the shared revision,
//!   remote and digest primitives.
//! - `io` owns the bounded file reads and the Git process probe.
//! - `repository` owns repository pin and worktree identity verification.
//! - `artifact` owns artifact checksum, required-file and golden-contract
//!   verification.
//! - `conformance` owns consumer-conformance parsing and the cross-artifact
//!   contract comparison.
//!
//! Every resulting module is below the 1,000-line target, so no exception has
//! to be documented. The unit tests move to `source_set/tests.rs` but stay a
//! direct `tests` child of this coordinator, so their discovered names and the
//! cross-module integration coverage are unchanged.

#[path = "source_set/artifact.rs"]
mod artifact;
#[path = "source_set/conformance.rs"]
mod conformance;
#[path = "source_set/io.rs"]
mod io;
#[path = "source_set/repository.rs"]
mod repository;
#[path = "source_set/validation.rs"]
mod validation;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use artifact::{inspect_artifact, missing_artifact_report};
use conformance::compare_contract_files;
use io::read_bounded;
use repository::{inspect_repository, missing_repository_report};
pub(crate) use validation::digest_hex;
use validation::validate_manifest;

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
    #[serde(default)]
    source_revision: Option<String>,
    #[serde(default)]
    source_tree: Option<String>,
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
    pub expected_source_revision: Option<String>,
    pub expected_source_tree: Option<String>,
    pub source_revision_match: bool,
    pub source_tree_match: bool,
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
///
/// The revision field always identifies the exact checked-out worktree. When a
/// metadata-only delivery commit is used, source_revision and source_tree
/// identify the source bytes represented by consumer-conformance records.
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
        let artifact_relative_path = DEFAULT_ARTIFACTS
            .iter()
            .find(|(repository, _)| *repository == name)
            .map(|(_, relative_path)| *relative_path);
        let (report, canonical) = inspect_repository(pin, path, artifact_relative_path);
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

#[cfg(test)]
#[path = "source_set/tests.rs"]
mod tests;
