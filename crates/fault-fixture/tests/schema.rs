//! Exact artifact and Draft 2020-12 conformance checks for the fixture inputs.

use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::{Component, Path, PathBuf};

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

fn resolve_checksum_path(
    artifact_root: &Path,
    package_root: &Path,
    relative: &Path,
) -> Result<PathBuf, String> {
    if relative.is_absolute() {
        return Err(format!("checksum path is absolute: {}", relative.display()));
    }

    let package_root = fs::canonicalize(package_root)
        .map_err(|error| format!("canonicalize package root: {error}"))?;
    let artifact_root = fs::canonicalize(artifact_root)
        .map_err(|error| format!("canonicalize artifact root: {error}"))?;
    if !artifact_root.starts_with(&package_root) {
        return Err(format!(
            "artifact root escapes package boundary: {}",
            artifact_root.display()
        ));
    }

    let mut resolved = artifact_root;
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(component) => resolved.push(component),
            Component::ParentDir => {
                resolved.pop();
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "checksum path has a rooted component: {}",
                    relative.display()
                ));
            }
        }
    }
    if !resolved.starts_with(&package_root) {
        return Err(format!(
            "checksum path escapes package boundary: {}",
            relative.display()
        ));
    }

    // A lexical check is enough for missing paths. For an existing entry also
    // resolve symlinks so a manifest cannot reach outside the package through
    // a path that looks lexically safe.
    if resolved.exists() {
        let canonical = fs::canonicalize(&resolved)
            .map_err(|error| format!("canonicalize {}: {error}", relative.display()))?;
        if !canonical.starts_with(&package_root) {
            return Err(format!(
                "checksum path escapes package boundary through symlink: {}",
                relative.display()
            ));
        }
    }
    Ok(resolved)
}

fn verify_checksum_manifest(artifact_root: &Path, package_root: &Path) -> Result<(), String> {
    let checksum_path = artifact_root.join("SHA256SUMS");
    let contents = fs::read_to_string(&checksum_path)
        .map_err(|error| format!("read {}: {error}", checksum_path.display()))?;
    let mut entries = 0usize;
    for (line_number, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Some((expected, relative)) = line.split_once("  ") else {
            return Err(format!("malformed checksum line {}", line_number + 1));
        };
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("invalid checksum on line {}", line_number + 1));
        }
        let relative = Path::new(relative);
        let path = resolve_checksum_path(artifact_root, package_root, relative)?;
        let bytes = fs::read(&path)
            .map_err(|error| format!("missing checksum path {}: {error}", relative.display()))?;
        let actual = digest(&bytes);
        if actual != expected {
            return Err(format!(
                "checksum mismatch for {}: expected {expected}, got {actual}",
                relative.display()
            ));
        }
        entries += 1;
    }
    if entries == 0 {
        return Err("checksum manifest has no entries".to_owned());
    }
    Ok(())
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

#[test]
fn checksum_manifests_bind_paths_to_artifact_root_and_package_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let package_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for relative in ["runtime-v3-gameplay", "watchdog-recovery-v1"] {
        let artifact_root = package_root.join("artifacts").join(relative);
        verify_checksum_manifest(&artifact_root, &package_root)
            .map_err(|error| format!("{relative}: {error}"))?;
    }

    let scratch = std::env::temp_dir().join(format!(
        "watchdog-fault-fixture-checksum-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    fs::create_dir_all(scratch.join("artifacts/package"))?;
    fs::create_dir_all(scratch.join("fixtures"))?;
    fs::write(
        scratch.join("fixtures/source.json"),
        b"{\"fixture\":true}\n",
    )?;
    let source_digest = digest(&fs::read(scratch.join("fixtures/source.json"))?);
    let checksum_path = scratch.join("artifacts/package/SHA256SUMS");

    // `../../fixtures` is intentionally outside the artifact directory but
    // remains inside the crate/package boundary.
    fs::write(
        &checksum_path,
        format!("{source_digest}  ../../fixtures/source.json\n"),
    )?;
    verify_checksum_manifest(&scratch.join("artifacts/package"), &scratch)?;

    fs::write(
        &checksum_path,
        format!("{}  ../../fixtures/source.json\n", "0".repeat(64)),
    )?;
    let mismatch = verify_checksum_manifest(&scratch.join("artifacts/package"), &scratch)
        .expect_err("mismatched checksum was accepted");
    assert!(mismatch.contains("checksum mismatch"), "{mismatch}");

    fs::write(
        &checksum_path,
        format!("{source_digest}  ../../fixtures/missing.json\n"),
    )?;
    let missing = verify_checksum_manifest(&scratch.join("artifacts/package"), &scratch)
        .expect_err("missing checksum path was accepted");
    assert!(missing.contains("missing checksum path"), "{missing}");

    fs::write(
        &checksum_path,
        format!("{source_digest}  ../../../outside.json\n"),
    )?;
    let escape = verify_checksum_manifest(&scratch.join("artifacts/package"), &scratch)
        .expect_err("checksum path escaped package boundary");
    assert!(escape.contains("escapes package boundary"), "{escape}");

    fs::remove_dir_all(scratch)?;
    Ok(())
}
