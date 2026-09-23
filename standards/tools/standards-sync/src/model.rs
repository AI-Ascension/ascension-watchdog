//! Serialized configuration and document data models.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Profile {
    pub(crate) schema_version: u32,
    pub(crate) profile_id: String,
    pub(crate) repository: String,
    pub(crate) owner: String,
    pub(crate) source_bundle: String,
    pub(crate) source_commit: String,
    pub(crate) source_digest: String,
    pub(crate) distribution: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) checks: CheckSets,
    pub(crate) evidence: Evidence,
    pub(crate) exceptions: Exceptions,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckSets {
    pub(crate) fast: Vec<String>,
    pub(crate) required: Vec<String>,
    pub(crate) extended: Vec<String>,
    #[serde(default)]
    pub(crate) commands: BTreeMap<String, CheckCommand>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckCommand {
    pub(crate) command: String,
    pub(crate) target: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Evidence {
    pub(crate) runtime: String,
    pub(crate) deployment: String,
    pub(crate) provider: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Exceptions {
    pub(crate) file: String,
    pub(crate) status: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LockFile {
    pub(crate) lock_version: u32,
    pub(crate) repository: String,
    pub(crate) profile_id: String,
    pub(crate) source: LockSource,
    pub(crate) profile_sha256: String,
    pub(crate) files: Vec<LockEntry>,
    pub(crate) protected_paths: Vec<String>,
    pub(crate) generated_by: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LockSource {
    pub(crate) repository: String,
    pub(crate) commit: String,
    pub(crate) bundle_digest: String,
    pub(crate) distribution: String,
    pub(crate) published: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LockEntry {
    pub(crate) path: String,
    pub(crate) sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleDocument {
    pub(crate) schema_version: u32,
    pub(crate) rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rule {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) purpose: String,
    pub(crate) severity: String,
    pub(crate) classification: String,
    pub(crate) scope: Vec<String>,
    pub(crate) check: String,
    pub(crate) verification: String,
    pub(crate) command: Option<String>,
    pub(crate) exception_eligible: bool,
    pub(crate) failure_behavior: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileCatalog {
    pub(crate) schema_version: u32,
    pub(crate) profiles: Vec<CatalogProfile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CatalogProfile {
    pub(crate) id: String,
    pub(crate) purpose: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) fast: Vec<String>,
    pub(crate) required: Vec<String>,
    pub(crate) extended: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepositoryMap {
    pub(crate) schema_version: u32,
    pub(crate) refreshed: String,
    pub(crate) source: String,
    pub(crate) repositories: Vec<RepositoryEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepositoryEntry {
    pub(crate) repository: String,
    pub(crate) repository_id: u64,
    pub(crate) node_id: String,
    pub(crate) default_branch: String,
    pub(crate) baseline_commit: String,
    pub(crate) owner: String,
    pub(crate) profile_id: String,
    pub(crate) adoption: String,
    pub(crate) language_scopes: Vec<String>,
    pub(crate) exclusion_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Exception {
    pub(crate) id: String,
    pub(crate) rule_ids: Vec<String>,
    pub(crate) paths: Vec<String>,
    pub(crate) owner: String,
    pub(crate) rationale: String,
    pub(crate) compensating_tests: Vec<String>,
    pub(crate) approval: Approval,
    pub(crate) reviewed_on: String,
    pub(crate) expires_on: String,
    pub(crate) removal_criteria: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Approval {
    pub(crate) reviewer: String,
    pub(crate) record: String,
    pub(crate) status: String,
}
