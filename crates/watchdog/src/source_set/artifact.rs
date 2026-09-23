//! Artifact checksum, required-file and golden-contract verification.

use super::conformance::inspect_consumer_conformance;
use super::io::{hash_file, read_bounded, regular_file};
use super::validation::valid_digest;
use super::{
    ArtifactReport, CONTRACT_FILES, MAX_CHECKSUMS_BYTES, MAX_CONTRACT_JSON_BYTES,
    REQUIRED_ARTIFACT_FILES, RepositoryPin,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, symlink_metadata};
use std::path::{Path, PathBuf};

pub(super) fn inspect_artifact(
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

pub(super) fn missing_artifact_report(repository: &str, relative_path: &str) -> ArtifactReport {
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

pub(super) fn validate_checksums(
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
