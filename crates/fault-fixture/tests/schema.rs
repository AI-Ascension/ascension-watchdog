//! Exact artifact and Draft 2020-12 conformance checks for the fixture inputs.

use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::PathBuf;

use fault_fixture::{RECOVERY_SCHEMA_JSON, RUNTIME_V3_SCHEMA_JSON};
use jsonschema::{Draft, PatternOptions, Validator};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn artifact_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("artifacts")
        .join(relative)
}

fn validator(schema: &str) -> Result<Validator, Box<dyn std::error::Error>> {
    let schema: Value = serde_json::from_str(schema)?;
    Ok(jsonschema::options()
        .with_draft(Draft::Draft202012)
        .with_pattern_options(PatternOptions::fancy_regex().size_limit(1_000_000_000))
        .build(&schema)?)
}

fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut result = String::with_capacity(64);
    for byte in hasher.finalize() {
        let _ = write!(&mut result, "{byte:02x}");
    }
    result
}

#[test]
fn recovery_artifact_valid_and_invalid_fixtures_use_draft_2020_12()
-> Result<(), Box<dyn std::error::Error>> {
    let validator = validator(RECOVERY_SCHEMA_JSON)?;
    let valid = [
        "watchdog-recovery-v1/fixtures/valid/bootstrap-request.json",
        "watchdog-recovery-v1/fixtures/valid/bootstrap-response.json",
        "watchdog-recovery-v1/fixtures/valid/host-fence-request.json",
        "watchdog-recovery-v1/fixtures/valid/host-fence-response.json",
        "watchdog-recovery-v1/fixtures/valid/lease-acquire-request.json",
        "watchdog-recovery-v1/fixtures/valid/lease-acquire-response.json",
        "watchdog-recovery-v1/fixtures/valid/lease-renew-request.json",
        "watchdog-recovery-v1/fixtures/valid/lease-renew-response.json",
        "watchdog-recovery-v1/fixtures/valid/lease-revoke-request.json",
        "watchdog-recovery-v1/fixtures/valid/lease-revoke-response.json",
        "watchdog-recovery-v1/fixtures/valid/operation-intent-request.json",
        "watchdog-recovery-v1/fixtures/valid/operation-intent-response.json",
        "watchdog-recovery-v1/fixtures/valid/operation-dispatch-request.json",
        "watchdog-recovery-v1/fixtures/valid/operation-dispatch-response.json",
        "watchdog-recovery-v1/fixtures/valid/operation-lookup-request.json",
        "watchdog-recovery-v1/fixtures/valid/operation-lookup-response.json",
        "watchdog-recovery-v1/fixtures/valid/operation-reconcile-request.json",
        "watchdog-recovery-v1/fixtures/valid/operation-reconcile-response.json",
    ];
    for relative in valid {
        let path = artifact_path(relative);
        let value: Value = serde_json::from_slice(&fs::read(&path)?)?;
        validator
            .validate(&value)
            .map_err(|error| format!("{relative}: {error}"))?;
    }
    let invalid = [
        "watchdog-recovery-v1/fixtures/invalid/oversized-action.json",
        "watchdog-recovery-v1/fixtures/invalid/stale-contract.json",
        "watchdog-recovery-v1/fixtures/invalid/unknown-field.json",
    ];
    for relative in invalid {
        let path = artifact_path(relative);
        let value: Value = serde_json::from_slice(&fs::read(&path)?)?;
        assert!(
            !validator.is_valid(&value),
            "invalid fixture accepted: {relative}"
        );
    }
    Ok(())
}

#[test]
fn runtime_artifact_compiles_as_draft_2020_12() -> Result<(), Box<dyn std::error::Error>> {
    let _validator = validator(RUNTIME_V3_SCHEMA_JSON)?;
    for (relative, schema) in [
        ("watchdog-recovery-v1", RECOVERY_SCHEMA_JSON),
        ("runtime-v3-gameplay", RUNTIME_V3_SCHEMA_JSON),
    ] {
        let manifest: Value = serde_json::from_slice(&fs::read(artifact_path(&format!(
            "{relative}/manifest.json"
        )))?)?;
        assert_eq!(
            manifest["schema_digest"],
            digest(schema.as_bytes()),
            "artifact schema digest drifted: {relative}"
        );
    }
    Ok(())
}
