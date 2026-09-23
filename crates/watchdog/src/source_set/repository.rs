//! Repository pin verification against an already-fetched local worktree.

use super::io::git;
use super::validation::normalize_remote;
use super::{RepositoryPin, RepositoryReport};
use std::path::{Path, PathBuf};

pub(super) fn inspect_repository(
    pin: &RepositoryPin,
    path: &Path,
    artifact_relative_path: Option<&str>,
) -> (RepositoryReport, Option<PathBuf>) {
    let mut report = RepositoryReport {
        expected_revision: pin.revision.clone(),
        actual_revision: None,
        expected_source_revision: pin.source_revision.clone(),
        expected_source_tree: pin.source_tree.clone(),
        source_revision_match: pin.source_revision.is_none(),
        source_tree_match: pin.source_tree.is_none(),
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

    if let (Some(source_revision), Some(source_tree)) =
        (pin.source_revision.as_deref(), pin.source_tree.as_deref())
    {
        let source_object = format!("{source_revision}^{{commit}}");
        if git(&canonical, &["cat-file", "-e", &source_object]).is_err() {
            report
                .issues
                .push("source revision is not present in the worktree object database".to_owned());
        } else if git(
            &canonical,
            &[
                "merge-base",
                "--is-ancestor",
                source_revision,
                &pin.revision,
            ],
        )
        .is_err()
        {
            report
                .issues
                .push("source revision is not an ancestor of the artifact revision".to_owned());
        } else {
            report.source_revision_match = true;
            let source_tree_object = format!("{source_revision}^{{tree}}");
            match git(&canonical, &["rev-parse", &source_tree_object]) {
                Ok(actual_tree) if actual_tree.trim() == source_tree => {
                    report.source_tree_match = true;
                }
                Ok(_) => report
                    .issues
                    .push("source tree differs from the pinned source revision".to_owned()),
                Err(issue) => report.issues.push(issue),
            }

            match artifact_relative_path {
                Some(artifact_relative_path) => {
                    match git(
                        &canonical,
                        &["diff", "--name-only", source_revision, &pin.revision],
                    ) {
                        Ok(changed_files) => {
                            let artifact_prefix = format!("{artifact_relative_path}/");
                            let unexpected = changed_files
                                .lines()
                                .map(str::trim)
                                .filter(|file| {
                                    !file.is_empty()
                                        && *file != artifact_relative_path
                                        && !file.starts_with(&artifact_prefix)
                                })
                                .collect::<Vec<_>>();
                            if !unexpected.is_empty() {
                                report.issues.push(format!(
                                    "source-to-artifact revision diff escapes the declared artifact path: {}",
                                    unexpected.join(", ")
                                ));
                            }
                        }
                        Err(issue) => report.issues.push(issue),
                    }
                }
                None => report.issues.push(
                    "source revision pin requires a repository with a declared artifact path"
                        .to_owned(),
                ),
            }
        }
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

    report.passed = report.issues.is_empty()
        && report.clean
        && report.revision_match
        && report.remote_match
        && report.source_revision_match
        && report.source_tree_match;
    (report, Some(canonical))
}

pub(super) fn missing_repository_report(pin: &RepositoryPin) -> RepositoryReport {
    RepositoryReport {
        expected_revision: pin.revision.clone(),
        actual_revision: None,
        expected_source_revision: pin.source_revision.clone(),
        expected_source_tree: pin.source_tree.clone(),
        source_revision_match: false,
        source_tree_match: false,
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
