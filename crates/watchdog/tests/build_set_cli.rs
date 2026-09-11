use serde_json::Value;
use std::process::Command;

#[test]
fn build_set_refuses_to_build_an_unadmitted_source_set() -> Result<(), Box<dyn std::error::Error>> {
    let scratch = tempfile::tempdir()?;
    let marker = scratch.path().join("ran-marker");
    let manifest = scratch.path().join("manifest.json");
    std::fs::write(
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
    )?;
    let plan = scratch.path().join("plan.json");
    std::fs::write(
        &plan,
        serde_json::json!({
            "schema_version": 1,
            "classification": "test",
            "repositories": {
                "ascension-watchdog": {
                    "program": "sh",
                    "args": ["-c", format!("touch {}", marker.display())]
                }
            }
        })
        .to_string(),
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_watchdog"))
        .args(["release", "build-set", "--manifest"])
        .arg(&manifest)
        .arg("--plan")
        .arg(&plan)
        .arg("--scratch")
        .arg(scratch.path())
        .output()?;
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["admitted"], false);
    assert_eq!(report["built"], false);
    assert_eq!(
        report["repositories"].as_object().map(serde_json::Map::len),
        Some(0)
    );
    assert!(!marker.exists());
    Ok(())
}
