//! Reviewed per-repository check plans and deterministic profile generation.

mod managed;
mod plan;

pub(crate) use plan::profile_plan;

use crate::Result;
use crate::model::{CheckCommand, CheckSets, Evidence, Exceptions, Profile};
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
pub(crate) struct CheckSpec {
    name: &'static str,
    command: &'static str,
    target: &'static str,
}

pub(crate) struct ProfilePlan {
    scopes: Vec<&'static str>,
    fast: Vec<CheckSpec>,
    required: Vec<CheckSpec>,
    extended: Vec<CheckSpec>,
}

pub(crate) const STANDARDS_VALIDATE: &str = "cargo +1.97.1 run --locked --manifest-path standards/tools/standards-sync/Cargo.toml -- validate --root .";

pub(crate) fn check(name: &'static str, command: &'static str, target: &'static str) -> CheckSpec {
    CheckSpec {
        name,
        command,
        target,
    }
}

pub(crate) fn git_diff_check() -> CheckSpec {
    check("git-diff-check", "git diff --check", ".")
}

pub(crate) fn standards_check() -> CheckSpec {
    check("standards-validate", STANDARDS_VALIDATE, ".")
}

pub(crate) fn rust_fast(include_metadata: bool) -> Vec<CheckSpec> {
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

pub(crate) fn rust_required() -> Vec<CheckSpec> {
    vec![
        check(
            "repo-policy-strict",
            "cargo run --locked --package repo-policy -- --strict",
            ".",
        ),
        check(
            "cargo-clippy-production",
            "cargo clippy --workspace --lib --bins --all-features --locked -- -D warnings -F clippy::unwrap_used -F clippy::expect_used -F clippy::panic -F clippy::todo -F clippy::unimplemented",
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

pub(crate) fn artifact_check(name: &'static str, target: &'static str) -> CheckSpec {
    check(name, "sha256sum --check SHA256SUMS", target)
}

pub(crate) fn spec_names(specs: &[CheckSpec]) -> Vec<String> {
    specs.iter().map(|spec| spec.name.to_owned()).collect()
}

pub(crate) fn validate_required_checks(profile: &Profile) -> Result<()> {
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

pub(crate) fn generated_profile(
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
