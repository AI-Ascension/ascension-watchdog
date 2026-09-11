//! Reproducible cross-repository build-set orchestration.
//!
//! This is the executable counterpart to the read-only source-set gate.  It
//! first verifies that the candidate manifest is admitted against explicitly
//! supplied local worktrees, then runs each repository's declared, bounded
//! locked build in that repository's own worktree.  It never imports a sibling
//! crate by path, never fetches, and never mutates a companion worktree: the
//! only writable location it creates is a caller-supplied scratch directory.
//!
//! A build is evidence about the exact inputs that were compiled.  A passing
//! build is not a service installation, activation, live-host, reboot, or soak
//! result, and this module makes no such claim.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::map_err_ignore,
    clippy::similar_names
)]

use crate::source_set;
use crate::source_set::digest_hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, symlink_metadata};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MAX_PLAN_BYTES: usize = 262_144;
const MAX_TAIL_BYTES: u64 = 16_384;
const DEFAULT_TIMEOUT_SECONDS: u64 = 3_600;
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const TOOLCHAIN_PLACEHOLDER: &str = "{toolchain}";
const ROOT_PLACEHOLDER: &str = "{root}";
const SCRATCH_PLACEHOLDER: &str = "{scratch}";

/// Declarative build plan: an exact command per repository plus an optional
/// fallback.  The plan never carries a worktree path; paths are supplied at
/// invocation time so a stale absolute path cannot be committed.
#[derive(Clone, Debug, Deserialize)]
struct BuildPlan {
    schema_version: u32,
    classification: String,
    #[serde(default)]
    toolchain: Option<String>,
    #[serde(default)]
    default: Option<BuildStep>,
    #[serde(default)]
    repositories: BTreeMap<String, Option<BuildStep>>,
}

#[derive(Clone, Debug, Deserialize)]
struct BuildStep {
    program: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

/// Machine-readable build-set result.  `built` is true only when every
/// requested repository produced a zero exit status.
#[derive(Clone, Debug, Serialize)]
pub struct BuildSetReport {
    pub orchestrator_version: u32,
    pub plan_sha256: String,
    pub manifest_sha256: String,
    pub classification: String,
    pub admitted: bool,
    pub built: bool,
    pub toolchain: Option<String>,
    pub repository_count: usize,
    pub repositories: BTreeMap<String, BuildStepReport>,
    pub issues: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BuildStepReport {
    pub status: String,
    pub program: String,
    pub args: Vec<String>,
    pub working_directory: Option<PathBuf>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_millis: u64,
    pub stdout_tail: String,
    pub stderr_tail: String,
    pub issues: Vec<String>,
}

struct StepOutcome {
    status: Option<std::process::ExitStatus>,
    timed_out: bool,
    duration: Duration,
    stdout: String,
    stderr: String,
}

/// Verify the admitted source set, then run every declared build in sequence.
///
/// Admission failure short-circuits with `admitted = false` and no command
/// execution, so a build can never be reported against an unverified source
/// set.  The returned report is complete on both success and failure; callers
/// gate on `admitted && built && issues.is_empty()`.
pub fn run_build_set(
    manifest_path: &Path,
    plan_path: &Path,
    repository_paths: &BTreeMap<String, PathBuf>,
    artifact_paths: &BTreeMap<String, PathBuf>,
    scratch_root: &Path,
) -> Result<BuildSetReport, String> {
    let plan_bytes = read_bounded(plan_path, MAX_PLAN_BYTES)?;
    let plan_sha256 = digest_hex(&Sha256::digest(&plan_bytes));
    let plan: BuildPlan = serde_json::from_slice(&plan_bytes)
        .map_err(|error| format!("invalid build plan: {error}"))?;
    validate_plan(&plan)?;

    let verification = source_set::verify_document(manifest_path, repository_paths, artifact_paths);
    let (manifest_sha256, admitted, verification_issues, admitted_repositories) = match verification
    {
        Ok(report) => (
            report.manifest_sha256,
            report.admitted,
            report.issues,
            report.repositories.keys().cloned().collect::<BTreeSet<_>>(),
        ),
        Err(error) => (String::new(), false, vec![error], BTreeSet::new()),
    };

    let mut report = BuildSetReport {
        orchestrator_version: 1,
        plan_sha256,
        manifest_sha256,
        classification: plan.classification.clone(),
        admitted,
        built: false,
        toolchain: plan.toolchain.clone(),
        repository_count: plan.repositories.len(),
        repositories: BTreeMap::new(),
        issues: verification_issues,
    };
    if !admitted {
        report
            .issues
            .push("build set refused: source-set admission failed".to_owned());
        return Ok(report);
    }

    let scratch = scratch_root.join(format!("build-set-{}", uuid::Uuid::new_v4()));
    if let Err(error) = fs::create_dir_all(&scratch) {
        report
            .issues
            .push(format!("build scratch directory is unavailable: {error}"));
        return Ok(report);
    }

    let mut all_passed = true;
    for name in plan.repositories.keys() {
        if !admitted_repositories.contains(name) {
            all_passed = false;
            report.repositories.insert(
                name.clone(),
                refused(
                    format!("{name} is not part of the admitted source set"),
                    step_hint(&plan, name),
                ),
            );
            continue;
        }
        let step = plan
            .repositories
            .get(name)
            .and_then(Option::as_ref)
            .or(plan.default.as_ref())
            .ok_or_else(|| format!("build plan has no command for {name}"))?;
        let entry = execute_repository(name, step, &plan, repository_paths, &scratch);
        if entry.status != "pass" {
            all_passed = false;
        }
        report.repositories.insert(name.clone(), entry);
    }
    let _ = fs::remove_dir_all(&scratch);

    report.built = all_passed;
    if !all_passed {
        report
            .issues
            .push("one or more repository builds failed".to_owned());
    }
    Ok(report)
}

fn execute_repository(
    name: &str,
    step: &BuildStep,
    plan: &BuildPlan,
    repository_paths: &BTreeMap<String, PathBuf>,
    scratch: &Path,
) -> BuildStepReport {
    let mut report = BuildStepReport {
        status: "fail".to_owned(),
        program: step.program.clone(),
        args: step.args.clone(),
        working_directory: None,
        exit_code: None,
        timed_out: false,
        duration_millis: 0,
        stdout_tail: String::new(),
        stderr_tail: String::new(),
        issues: Vec::new(),
    };

    let Some(root) = repository_paths
        .get(name)
        .and_then(|path| path.canonicalize().ok())
    else {
        report
            .issues
            .push("repository worktree path is missing or unusable".to_owned());
        return report;
    };
    if !root.is_dir() {
        report
            .issues
            .push("repository worktree path is not a directory".to_owned());
        return report;
    }
    report.working_directory = Some(root.clone());

    let step_scratch = scratch.join(sanitized(name));

    let program = match substitute(&step.program, plan, Some(&root), Some(&step_scratch)) {
        Ok(program) => program,
        Err(issue) => {
            report.issues.push(issue);
            return report;
        }
    };
    report.program.clone_from(&program);

    let mut args = Vec::with_capacity(step.args.len());
    for argument in &step.args {
        match substitute(argument, plan, Some(&root), Some(&step_scratch)) {
            Ok(value) => args.push(value),
            Err(issue) => {
                report.issues.push(issue);
                return report;
            }
        }
    }
    report.args.clone_from(&args);

    let mut env = BTreeMap::new();
    for (key, value) in &step.env {
        match substitute(value, plan, Some(&root), Some(&step_scratch)) {
            Ok(value) => {
                env.insert(key.clone(), value);
            }
            Err(issue) => {
                report.issues.push(issue);
                return report;
            }
        }
    }

    let timeout = Duration::from_secs(step.timeout_seconds.unwrap_or(DEFAULT_TIMEOUT_SECONDS));
    let outcome = match execute_step(&program, &args, &env, &root, &step_scratch, timeout) {
        Ok(outcome) => outcome,
        Err(issue) => {
            report.issues.push(issue);
            return report;
        }
    };

    report.exit_code = outcome.status.and_then(|status| status.code());
    report.timed_out = outcome.timed_out;
    report.duration_millis = u64::try_from(outcome.duration.as_millis()).unwrap_or(u64::MAX);
    report.stdout_tail = outcome.stdout;
    report.stderr_tail = outcome.stderr;
    if outcome.timed_out {
        report
            .issues
            .push(format!("build exceeded the {timeout:?} wall-clock bound"));
    } else if !outcome.status.is_some_and(|status| status.success()) {
        report
            .issues
            .push("build command exited non-zero".to_owned());
    } else {
        "pass".clone_into(&mut report.status);
    }
    report
}

fn step_hint(plan: &BuildPlan, name: &str) -> BuildStep {
    plan.repositories
        .get(name)
        .and_then(Option::as_ref)
        .or(plan.default.as_ref())
        .cloned()
        .unwrap_or_else(|| BuildStep {
            program: String::new(),
            args: Vec::new(),
            env: BTreeMap::new(),
            timeout_seconds: None,
        })
}

fn refused(issue: String, step: BuildStep) -> BuildStepReport {
    BuildStepReport {
        status: "fail".to_owned(),
        program: step.program,
        args: step.args,
        working_directory: None,
        exit_code: None,
        timed_out: false,
        duration_millis: 0,
        stdout_tail: String::new(),
        stderr_tail: String::new(),
        issues: vec![issue],
    }
}

fn execute_step(
    program: &str,
    args: &[String],
    env: &BTreeMap<String, String>,
    working_directory: &Path,
    scratch: &Path,
    timeout: Duration,
) -> Result<StepOutcome, String> {
    if let Err(error) = fs::create_dir_all(scratch) {
        return Err(format!("build scratch directory is unavailable: {error}"));
    }
    let stdout_path = scratch.join("stdout");
    let stderr_path = scratch.join("stderr");
    let stdout_file = File::create(&stdout_path)
        .map_err(|error| format!("build stdout sink is unavailable: {error}"))?;
    let stderr_file = File::create(&stderr_path)
        .map_err(|error| format!("build stderr sink is unavailable: {error}"))?;

    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));
    for (key, value) in env {
        command.env(key, value);
    }

    let started = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| format!("build command {program} could not start: {error}"))?;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break None;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return Err(format!("build command wait failed: {error}")),
        }
    };
    let duration = started.elapsed();

    Ok(StepOutcome {
        status,
        timed_out,
        duration,
        stdout: read_tail(&stdout_path, MAX_TAIL_BYTES),
        stderr: read_tail(&stderr_path, MAX_TAIL_BYTES),
    })
}

fn validate_plan(plan: &BuildPlan) -> Result<(), String> {
    if plan.schema_version != 1 {
        return Err(format!(
            "unsupported build plan schema version {}",
            plan.schema_version
        ));
    }
    if plan.classification.trim().is_empty() {
        return Err("build plan classification is empty".to_owned());
    }
    if plan.repositories.is_empty() {
        return Err("build plan declares no repositories".to_owned());
    }
    for (name, step) in &plan.repositories {
        if name.is_empty() || name.contains('/') || name.contains('\\') {
            return Err(format!("invalid build plan repository name {name:?}"));
        }
        match step {
            Some(step) => validate_step(name, step)?,
            None if plan.default.is_some() => {}
            None => {
                return Err(format!(
                    "build plan {name} has no command and no default step"
                ));
            }
        }
    }
    if let Some(step) = &plan.default {
        validate_step("<default>", step)?;
    }
    Ok(())
}

fn validate_step(name: &str, step: &BuildStep) -> Result<(), String> {
    if step.program.trim().is_empty() {
        return Err(format!("build plan {name} has an empty program"));
    }
    if step.program.contains('/') || step.program.contains('\\') {
        return Err(format!(
            "build plan {name} must name a program on PATH, not a path"
        ));
    }
    if step.timeout_seconds == Some(0) {
        return Err(format!("build plan {name} has a zero timeout"));
    }
    Ok(())
}

fn substitute(
    value: &str,
    plan: &BuildPlan,
    root: Option<&Path>,
    scratch: Option<&Path>,
) -> Result<String, String> {
    let mut value = value.to_owned();
    if value.contains(TOOLCHAIN_PLACEHOLDER) {
        let toolchain = plan.toolchain.as_deref().ok_or_else(|| {
            "build plan uses {toolchain} without declaring a toolchain".to_owned()
        })?;
        value = value.replace(TOOLCHAIN_PLACEHOLDER, toolchain);
    }
    if value.contains(ROOT_PLACEHOLDER) {
        let root =
            root.ok_or_else(|| "build plan uses {root} without a resolved repository".to_owned())?;
        let root = root
            .to_str()
            .ok_or_else(|| "repository worktree path is not valid UTF-8".to_owned())?;
        value = value.replace(ROOT_PLACEHOLDER, root);
    }
    if value.contains(SCRATCH_PLACEHOLDER) {
        let scratch = scratch
            .ok_or_else(|| "build plan uses {scratch} without a scratch directory".to_owned())?;
        let scratch = scratch
            .to_str()
            .ok_or_else(|| "build scratch path is not valid UTF-8".to_owned())?;
        value = value.replace(SCRATCH_PLACEHOLDER, scratch);
    }
    Ok(value)
}

fn sanitized(name: &str) -> String {
    name.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn read_tail(path: &Path, limit: u64) -> String {
    let Ok(mut file) = File::open(path) else {
        return String::new();
    };
    let length = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
    if file
        .seek(SeekFrom::Start(length.saturating_sub(limit)))
        .is_err()
    {
        return String::new();
    }
    let mut buffer = Vec::new();
    if (&mut file).take(limit).read_to_end(&mut buffer).is_err() {
        return String::new();
    }
    String::from_utf8_lossy(&buffer).into_owned()
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let metadata = symlink_metadata(path).map_err(|_| "build plan is unavailable".to_owned())?;
    if !metadata.file_type().is_file() {
        return Err("build plan path is not a regular file".to_owned());
    }
    let length =
        usize::try_from(metadata.len()).map_err(|_| "build plan length overflows".to_owned())?;
    if length > maximum {
        return Err("build plan exceeds the orchestrator byte bound".to_owned());
    }
    let mut file = File::open(path).map_err(|_| "build plan cannot be opened".to_owned())?;
    let mut bytes = Vec::with_capacity(length);
    file.read_to_end(&mut bytes)
        .map_err(|_| "build plan cannot be read".to_owned())?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_from(value: serde_json::Value) -> BuildPlan {
        serde_json::from_value(value).expect("plan fixture parses")
    }

    #[test]
    fn plan_validation_rejects_invalid_shapes() {
        assert!(
            validate_plan(&plan_from(serde_json::json!({
                "schema_version": 2,
                "classification": "test",
                "repositories": {"a": {"program": "cargo"}}
            })))
            .is_err()
        );
        assert!(
            validate_plan(&plan_from(serde_json::json!({
                "schema_version": 1,
                "classification": "",
                "repositories": {"a": {"program": "cargo"}}
            })))
            .is_err()
        );
        assert!(
            validate_plan(&plan_from(serde_json::json!({
                "schema_version": 1,
                "classification": "test",
                "repositories": {}
            })))
            .is_err()
        );
        assert!(
            validate_plan(&plan_from(serde_json::json!({
                "schema_version": 1,
                "classification": "test",
                "repositories": {"a": {"program": "/usr/bin/cargo"}}
            })))
            .is_err()
        );
        assert!(
            validate_plan(&plan_from(serde_json::json!({
                "schema_version": 1,
                "classification": "test",
                "repositories": {"a": {"program": "cargo", "timeout_seconds": 0}}
            })))
            .is_err()
        );
        assert!(
            validate_plan(&plan_from(serde_json::json!({
                "schema_version": 1,
                "classification": "test",
                "repositories": {"a": null}
            })))
            .is_err()
        );
        assert!(
            validate_plan(&plan_from(serde_json::json!({
                "schema_version": 1,
                "classification": "test",
                "default": {"program": "cargo", "args": ["build"]},
                "repositories": {"a": null}
            })))
            .is_ok()
        );
    }

    #[test]
    fn substitution_requires_every_placeholder_to_resolve() {
        let plan = plan_from(serde_json::json!({
            "schema_version": 1,
            "classification": "test",
            "toolchain": "1.97.1",
            "repositories": {"a": {"program": "cargo", "args": ["+{toolchain}", "build"]}}
        }));
        let root = Path::new("/tmp/worktree");
        assert_eq!(
            substitute("+{toolchain}", &plan, Some(root), None).expect("toolchain resolves"),
            "+1.97.1"
        );
        assert_eq!(
            substitute("--manifest-path={root}/Cargo.toml", &plan, Some(root), None)
                .expect("root resolves"),
            "--manifest-path=/tmp/worktree/Cargo.toml"
        );
        assert_eq!(
            substitute(
                "{scratch}/target",
                &plan,
                Some(root),
                Some(Path::new("/tmp/scratch"))
            )
            .expect("scratch resolves"),
            "/tmp/scratch/target"
        );
        assert!(substitute("{root}", &plan, None, None).is_err());
        assert!(substitute("{scratch}", &plan, Some(root), None).is_err());
        let no_toolchain = plan_from(serde_json::json!({
            "schema_version": 1,
            "classification": "test",
            "repositories": {"a": {"program": "cargo"}}
        }));
        assert!(substitute("+{toolchain}", &no_toolchain, Some(root), None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn step_captures_bounded_output_and_exit_status() {
        let scratch = tempfile::tempdir().expect("scratch");
        let ok = execute_step(
            "sh",
            &["-c".to_owned(), "printf hello".to_owned()],
            &BTreeMap::new(),
            scratch.path(),
            &scratch.path().join("ok"),
            Duration::from_secs(30),
        )
        .expect("step runs");
        assert!(ok.status.is_some_and(|status| status.success()));
        assert_eq!(ok.stdout, "hello");
        assert!(!ok.timed_out);

        let bad = execute_step(
            "sh",
            &["-c".to_owned(), "exit 7".to_owned()],
            &BTreeMap::new(),
            scratch.path(),
            &scratch.path().join("bad"),
            Duration::from_secs(30),
        )
        .expect("step runs");
        assert_eq!(bad.status.and_then(|status| status.code()), Some(7));
    }

    #[cfg(unix)]
    #[test]
    fn step_is_killed_at_the_wall_clock_bound() {
        let scratch = tempfile::tempdir().expect("scratch");
        let outcome = execute_step(
            "sleep",
            &["30".to_owned()],
            &BTreeMap::new(),
            scratch.path(),
            &scratch.path().join("slow"),
            Duration::from_millis(250),
        )
        .expect("step runs");
        assert!(outcome.timed_out);
        assert!(outcome.status.is_none());
        assert!(outcome.duration < Duration::from_secs(10));
    }

    #[test]
    fn admission_failure_never_runs_a_build_command() {
        let scratch = tempfile::tempdir().expect("scratch");
        let manifest = scratch.path().join("manifest.json");
        fs::write(
            &manifest,
            serde_json::json!({
                "schema_version": 1,
                "classification": "test",
                "repositories": {
                    "ascension-watchdog": {
                        "revision": "0".repeat(40),
                        "ref": "bootstrap",
                        "remote": "AI-Ascension/ascension-watchdog"
                    }
                }
            })
            .to_string(),
        )
        .expect("manifest writes");
        let plan = scratch.path().join("plan.json");
        fs::write(
            &plan,
            serde_json::json!({
                "schema_version": 1,
                "classification": "test",
                "repositories": {
                    "ascension-watchdog": {
                        "program": "sh",
                        "args": ["-c", "touch ran-marker"]
                    }
                }
            })
            .to_string(),
        )
        .expect("plan writes");

        let report = run_build_set(
            &manifest,
            &plan,
            &BTreeMap::new(),
            &BTreeMap::new(),
            scratch.path(),
        )
        .expect("report");
        assert!(!report.admitted);
        assert!(!report.built);
        assert!(report.repositories.is_empty());
        assert!(!scratch.path().join("ran-marker").exists());
    }
}
