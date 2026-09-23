//! Consumer-conformance parsing and cross-artifact contract comparison.

use super::{
    ArtifactReport, CONTRACT_FILES, ContractComparisonReport, EXPECTED_CONSUMERS, RepositoryPin,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn inspect_consumer_conformance(
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
        let expected_revision = pin.source_revision.as_deref().unwrap_or(&pin.revision);
        let binding_label = if pin.source_revision.is_some() {
            "source revision"
        } else {
            "manifest revision"
        };
        if commit != expected_revision {
            issues.push(format!(
                "consumer {repository} is not bound to the {binding_label}"
            ));
        }
        if let Some(expected_tree) = pin.source_tree.as_deref() {
            if consumer.get("tree").and_then(Value::as_str) != Some(expected_tree) {
                issues.push(format!(
                    "consumer {repository} is not bound to the pinned source tree"
                ));
            }
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

pub(super) struct ConsumerSummary {
    pub(super) status: Option<String>,
    pub(super) boundary: Option<String>,
    pub(super) commits: BTreeMap<String, String>,
    pub(super) issues: Vec<String>,
}

fn contains_pending(value: &Value) -> bool {
    match value {
        Value::String(value) => value == "pending" || value.starts_with("pending-"),
        Value::Array(values) => values.iter().any(contains_pending),
        Value::Object(values) => values.values().any(contains_pending),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

pub(super) fn compare_contract_files(
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
