//! Fail-closed evidence checks for the Windows session-0 native boundary.
//!
//! This module deliberately validates an evidence document, rather than
//! inferring native admission from a build, a synthetic test, or a runner OS.
//! It has no release activation capability.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

const REQUIRED_NATIVE_CHECKS: [&str; 2] = [
    "native_worker_runtime_delivers_controller_bound_bootstrap_and_stops_exact_child",
    "native_worker_launch_rejects_durable_stop_before_resume_and_cleans_exact_job",
];
const MAX_EVIDENCE_BYTES: u64 = 64 * 1024;
const MAX_RECEIPT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationEvidence {
    schema_version: u8,
    repository: String,
    evidence_kind: String,
    result: String,
    source_revision: String,
    runner: RunnerEvidence,
    checks: Vec<CheckEvidence>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnerEvidence {
    os: String,
    session_id: Option<u32>,
    service_session_zero: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckEvidence {
    name: String,
    outcome: String,
    receipt_sha256: String,
}

/// Stable, machine-readable result of the native qualification gate.
#[derive(Clone, Debug, Serialize)]
pub struct NativeQualificationReport {
    pub schema_version: u8,
    pub qualified_native: bool,
    pub source_revision: String,
    pub evidence_kind: String,
    pub result: String,
    pub issues: Vec<String>,
}

/// Verify native evidence for one immutable source revision.
///
/// The report is intentionally complete on semantic failures. Callers must use
/// `qualified_native`, not a successful JSON parse, as the release gate.
pub fn verify_native_document(
    evidence_path: &Path,
    receipt_path: &Path,
    expected_source_revision: &str,
) -> Result<NativeQualificationReport, String> {
    if !is_revision(expected_source_revision) {
        return Err(
            "expected source revision must be exactly 40 lowercase hexadecimal characters"
                .to_owned(),
        );
    }
    let bytes = read_bounded(evidence_path, MAX_EVIDENCE_BYTES, "evidence")?;
    let evidence: QualificationEvidence = serde_json::from_slice(&bytes)
        .map_err(|error| format!("native qualification evidence is malformed: {error}"))?;
    let receipt = read_bounded(receipt_path, MAX_RECEIPT_BYTES, "receipt")?;
    let receipt_digest = crate::source_set::digest_hex(&Sha256::digest(receipt));
    let mut issues = Vec::new();
    if evidence.schema_version != 1 {
        issues.push("unsupported qualification evidence schema version".to_owned());
    }
    if evidence.repository != "AI-Ascension/ascension-watchdog" {
        issues.push("evidence repository is not AI-Ascension/ascension-watchdog".to_owned());
    }
    if evidence.evidence_kind != "native-session0" {
        issues.push("evidence kind is not native-session0; synthetic evidence never qualifies a native release".to_owned());
    }
    if evidence.result != "passed" {
        issues.push("native qualification result is not passed".to_owned());
    }
    if !is_revision(&evidence.source_revision) {
        issues.push("evidence source revision is not an immutable revision".to_owned());
    } else if evidence.source_revision != expected_source_revision {
        issues.push("evidence source revision does not match the candidate".to_owned());
    }
    if evidence.runner.os != "windows" {
        issues.push("native qualification runner OS is not windows".to_owned());
    }
    if evidence.runner.session_id != Some(0) || !evidence.runner.service_session_zero {
        issues.push("native qualification was not executed in service session 0".to_owned());
    }
    if evidence.checks.len() != REQUIRED_NATIVE_CHECKS.len() {
        issues.push("native evidence must contain exactly the required check receipts".to_owned());
    }
    for required in REQUIRED_NATIVE_CHECKS {
        let matching = evidence
            .checks
            .iter()
            .filter(|check| check.name == required)
            .collect::<Vec<_>>();
        if matching.len() != 1
            || matching[0].outcome != "passed"
            || !is_digest(&matching[0].receipt_sha256)
            || matching[0].receipt_sha256 != receipt_digest
        {
            issues.push(format!("required native check did not pass: {required}"));
        }
    }
    Ok(NativeQualificationReport {
        schema_version: 1,
        qualified_native: issues.is_empty(),
        source_revision: evidence.source_revision,
        evidence_kind: evidence.evidence_kind,
        result: evidence.result,
        issues,
    })
}

/// Create explicitly non-native synthetic evidence for ordinary CI artifacts.
pub fn synthetic_evidence(
    source_revision: &str,
    os: &str,
    receipt_sha256: &str,
) -> Result<String, String> {
    if !is_revision(source_revision) {
        return Err(
            "source revision must be exactly 40 lowercase hexadecimal characters".to_owned(),
        );
    }
    if os.is_empty()
        || os.len() > 32
        || !os
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
    {
        return Err("synthetic evidence OS must be a short lowercase identifier".to_owned());
    }
    if !is_digest(receipt_sha256) {
        return Err(
            "synthetic evidence receipt digest must be 64 lowercase hexadecimal characters"
                .to_owned(),
        );
    }
    serde_json::to_string(&serde_json::json!({
        "schema_version": 1,
        "repository": "AI-Ascension/ascension-watchdog",
        "evidence_kind": "synthetic",
        "result": "passed",
        "source_revision": source_revision,
        "runner": {"os": os, "session_id": null, "service_session_zero": false},
        "checks": [{"name": "workspace-synthetic-tests", "outcome": "passed", "receipt_sha256": receipt_sha256}]
    }))
    .map_err(|error| format!("synthetic evidence serialization failed: {error}"))
}

fn is_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn read_bounded(path: &Path, limit: u64, kind: &str) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path)
        .map_err(|error| format!("native qualification {kind} is unavailable: {error}"))?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("native qualification {kind} cannot be read: {error}"))?;
    if bytes.len() as u64 > limit {
        return Err(format!(
            "native qualification {kind} exceeds its byte bound"
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{synthetic_evidence, verify_native_document};
    use sha2::Digest;
    use std::fs;

    const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn evidence(contents: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), contents).unwrap();
        file
    }

    fn receipt() -> (tempfile::NamedTempFile, String) {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), b"native receipt fixture").unwrap();
        let digest =
            crate::source_set::digest_hex(&sha2::Sha256::digest(b"native receipt fixture"));
        (file, digest)
    }

    #[test]
    fn native_session_zero_evidence_qualifies_only_when_all_requirements_pass() {
        let (receipt, digest) = receipt();
        let file = evidence(&format!(
            r#"{{"schema_version":1,"repository":"AI-Ascension/ascension-watchdog","evidence_kind":"native-session0","result":"passed","source_revision":"{REVISION}","runner":{{"os":"windows","session_id":0,"service_session_zero":true}},"checks":[{{"name":"native_worker_runtime_delivers_controller_bound_bootstrap_and_stops_exact_child","outcome":"passed","receipt_sha256":"{DIGEST}"}},{{"name":"native_worker_launch_rejects_durable_stop_before_resume_and_cleans_exact_job","outcome":"passed","receipt_sha256":"{DIGEST}"}}]}}"#
        ).replace(DIGEST, &digest));
        assert!(
            verify_native_document(file.path(), receipt.path(), REVISION)
                .unwrap()
                .qualified_native
        );
    }

    #[test]
    fn synthetic_success_is_not_native_qualified() {
        let (receipt, digest) = receipt();
        let file = evidence(&synthetic_evidence(REVISION, "linux", &digest).unwrap());
        let report = verify_native_document(file.path(), receipt.path(), REVISION).unwrap();
        assert!(!report.qualified_native);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.contains("synthetic evidence"))
        );
    }

    #[test]
    fn forged_receipt_digest_or_duplicate_check_fails_closed() {
        let (receipt, _) = receipt();
        let file = evidence(&format!(
            r#"{{"schema_version":1,"repository":"AI-Ascension/ascension-watchdog","evidence_kind":"native-session0","result":"passed","source_revision":"{REVISION}","runner":{{"os":"windows","session_id":0,"service_session_zero":true}},"checks":[{{"name":"native_worker_runtime_delivers_controller_bound_bootstrap_and_stops_exact_child","outcome":"passed","receipt_sha256":"{DIGEST}"}},{{"name":"native_worker_runtime_delivers_controller_bound_bootstrap_and_stops_exact_child","outcome":"passed","receipt_sha256":"{DIGEST}"}},{{"name":"native_worker_launch_rejects_durable_stop_before_resume_and_cleans_exact_job","outcome":"passed","receipt_sha256":"{DIGEST}"}}]}}"#
        ));
        let report = verify_native_document(file.path(), receipt.path(), REVISION).unwrap();
        assert!(!report.qualified_native);
        assert!(report.issues.iter().any(|issue| issue.contains("exactly")));
    }

    #[test]
    fn wrong_session_or_revision_fails_closed() {
        let (receipt, _) = receipt();
        let file = evidence(&format!(
            r#"{{"schema_version":1,"repository":"AI-Ascension/ascension-watchdog","evidence_kind":"native-session0","result":"passed","source_revision":"{REVISION}","runner":{{"os":"windows","session_id":1,"service_session_zero":false}},"checks":[]}}"#
        ));
        let report = verify_native_document(
            file.path(),
            receipt.path(),
            "fedcba9876543210fedcba9876543210fedcba98",
        )
        .unwrap();
        assert!(!report.qualified_native);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.contains("does not match"))
        );
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.contains("session 0"))
        );
    }
}
