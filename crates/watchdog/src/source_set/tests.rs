use super::artifact::validate_checksums;
use super::conformance::inspect_consumer_conformance;
use super::io::git;
use super::repository::inspect_repository;
use super::validation::{digest_hex, normalize_remote};
use super::*;
use std::fs;
use std::process::{Command, Stdio};

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
                    source_revision: None,
                    source_tree: None,
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
        source_revision: None,
        source_tree: None,
        _additional: BTreeMap::new(),
    };
    let (report, root) = inspect_repository(&pin, temporary.path(), None);
    assert!(report.passed, "{report:?}");
    assert_eq!(root, Some(temporary.path().canonicalize().expect("root")));
}

#[test]
fn artifact_refresh_revision_must_be_ancestor_and_artifact_only() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    run_git(temporary.path(), &["init", "--quiet"]);
    run_git(temporary.path(), &["config", "user.name", "fixture"]);
    run_git(
        temporary.path(),
        &["config", "user.email", "fixture@example.invalid"],
    );
    run_git(
        temporary.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/AI-Ascension/fixture.git",
        ],
    );
    fs::write(temporary.path().join("source"), b"source").expect("source");
    run_git(temporary.path(), &["add", "source"]);
    run_git(temporary.path(), &["commit", "--quiet", "-m", "source"]);
    let source_revision = git(temporary.path(), &["rev-parse", "HEAD"])
        .expect("source revision")
        .trim()
        .to_owned();
    let source_tree = git(temporary.path(), &["rev-parse", "HEAD^{tree}"])
        .expect("source tree")
        .trim()
        .to_owned();

    let artifact = temporary.path().join("artifact");
    fs::create_dir_all(&artifact).expect("artifact");
    fs::write(artifact.join("metadata"), b"metadata").expect("metadata");
    run_git(temporary.path(), &["add", "artifact/metadata"]);
    run_git(
        temporary.path(),
        &["commit", "--quiet", "-m", "artifact refresh"],
    );
    let artifact_revision = git(temporary.path(), &["rev-parse", "HEAD"])
        .expect("artifact revision")
        .trim()
        .to_owned();
    run_git(temporary.path(), &["branch", "--move", "artifact-refresh"]);

    let mut pin = RepositoryPin {
        revision: artifact_revision.clone(),
        reference: "artifact-refresh".to_owned(),
        remote: "AI-Ascension/fixture".to_owned(),
        source_revision: Some(source_revision.clone()),
        source_tree: Some(source_tree),
        _additional: BTreeMap::new(),
    };
    let (report, _) = inspect_repository(&pin, temporary.path(), Some("artifact"));
    assert!(report.passed, "{report:?}");

    fs::write(temporary.path().join("unexpected"), b"unexpected").expect("unexpected");
    run_git(temporary.path(), &["add", "unexpected"]);
    run_git(
        temporary.path(),
        &["commit", "--quiet", "-m", "unexpected source change"],
    );
    pin.revision = git(temporary.path(), &["rev-parse", "HEAD"])
        .expect("unexpected revision")
        .trim()
        .to_owned();
    let (report, _) = inspect_repository(&pin, temporary.path(), Some("artifact"));
    assert!(!report.passed);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| { issue.contains("source-to-artifact revision diff escapes") })
    );
}

#[test]
fn consumer_conformance_can_bind_to_source_revision_and_tree() {
    let source_revision = "a".repeat(40);
    let source_tree = "b".repeat(40);
    let repositories = EXPECTED_CONSUMERS
        .into_iter()
        .map(|name| {
            (
                name.to_owned(),
                RepositoryPin {
                    revision: format!("artifact-{name}"),
                    reference: "artifact-refresh".to_owned(),
                    remote: format!("AI-Ascension/{name}"),
                    source_revision: Some(source_revision.clone()),
                    source_tree: Some(source_tree.clone()),
                    _additional: BTreeMap::new(),
                },
            )
        })
        .collect();
    let value = serde_json::json!({
        "status": "component_serialized_conformance",
        "consumers": EXPECTED_CONSUMERS.into_iter().map(|name| serde_json::json!({
            "repository": name,
            "commit": source_revision,
            "tree": source_tree,
            "result": "pass"
        })).collect::<Vec<_>>(),
        "cross_boundary": {"source_to_consumer": "pass"}
    });
    let summary =
        inspect_consumer_conformance(&serde_json::to_vec(&value).expect("JSON"), &repositories)
            .expect("conformance parses");
    assert!(summary.issues.is_empty(), "{:?}", summary.issues);
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
