use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn candidate_manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("workspace-manifest.candidate.json")
}

#[test]
fn source_set_failure_is_json_and_nonzero() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_watchdog"))
        .args(["release", "source-set", "verify", "--manifest"])
        .arg(candidate_manifest())
        .output()?;
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["admitted"], false);
    assert_eq!(report["manifest_sha256"].as_str().map(str::len), Some(64));
    assert!(
        report["issues"]
            .as_array()
            .is_some_and(|issues| issues.iter().any(|issue| {
                issue
                    .as_str()
                    .is_some_and(|issue| issue.contains("repository path missing"))
            }))
    );
    Ok(())
}
