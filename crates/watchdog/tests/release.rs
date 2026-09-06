// SPDX-License-Identifier: MIT

use std::fs;
use std::io::Cursor;

use ascension_watchdog::release::{
    Artifact, ArtifactRole, Compatibility, ReleaseManifest, Revision, StoreCompatibility,
};
use sha2::{Digest, Sha256};

fn manifest() -> ReleaseManifest {
    let bytes = b"synthetic approved executable bytes";
    ReleaseManifest {
        schema_version: 1,
        release_id: "synthetic-release-1".to_owned(),
        revisions: [
            "ascension-watchdog",
            "sts2-gateway",
            "sts2-harness",
            "sts2-mcp-server",
            "sts2-game-mod",
            "sts2-protocol",
        ]
        .into_iter()
        .map(|repository| Revision {
            repository: repository.to_owned(),
            commit: "a".repeat(40),
        })
        .collect(),
        artifacts: [
            (ArtifactRole::Watchdog, "watchdog"),
            (ArtifactRole::Gateway, "gateway"),
            (ArtifactRole::Harness, "harness"),
            (ArtifactRole::Mcp, "mcp"),
            (ArtifactRole::Mod, "mod"),
            (ArtifactRole::HostBroker, "broker"),
        ]
        .into_iter()
        .map(|(role, path)| Artifact {
            role,
            path: path.into(),
            sha256: hex_digest(bytes),
            bytes: bytes.len() as u64,
        })
        .collect(),
        compatibility: Compatibility {
            game_build: "synthetic-1".to_owned(),
            runtime_profile: "runtime-v3-gameplay".to_owned(),
            runtime_profile_sha256: "a".repeat(64),
            recovery_profile: "watchdog-recovery-v1".to_owned(),
            recovery_profile_sha256: "b".repeat(64),
            configuration_sha256: "c".repeat(64),
            provider_adapter: "synthetic-provider".to_owned(),
            provider_adapter_sha256: "d".repeat(64),
            stores: ["watchdog", "gateway", "harness"]
                .into_iter()
                .map(|owner| StoreCompatibility {
                    owner: owner.to_owned(),
                    minimum_schema: 1,
                    maximum_schema: 1,
                })
                .collect(),
        },
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    Sha256::digest(bytes)
        .iter()
        .flat_map(|byte| {
            [
                char::from(DIGITS[usize::from(byte >> 4)]),
                char::from(DIGITS[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

fn stage(root: &std::path::Path, release: &ReleaseManifest) -> std::io::Result<()> {
    for artifact in &release.artifacts {
        fs::write(
            root.join(&artifact.path),
            b"synthetic approved executable bytes",
        )?;
    }
    Ok(())
}

#[test]
fn exact_release_bytes_pass_and_single_byte_tampering_fails()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let release = manifest();
    stage(temporary.path(), &release)?;
    let inspection = release.inspect(temporary.path())?;
    assert_eq!(inspection.artifact_count, 6);
    assert_eq!(inspection.manifest_sha256.len(), 64);
    fs::write(
        temporary.path().join("gateway"),
        b"Synthetic approved executable bytes",
    )?;
    assert!(release.inspect(temporary.path()).is_err());
    Ok(())
}

#[test]
fn original_manifest_digest_preserves_exact_approved_artifact_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let release = manifest();
    stage(temporary.path(), &release)?;
    let compact = serde_json::to_vec(&release)?;
    let pretty = serde_json::to_vec_pretty(&release)?;
    let compact_inspection =
        ReleaseManifest::inspect_document(compact.as_slice(), temporary.path())?;
    let pretty_inspection = ReleaseManifest::inspect_document(pretty.as_slice(), temporary.path())?;
    assert_eq!(compact_inspection.manifest_sha256, hex_digest(&compact));
    assert_eq!(pretty_inspection.manifest_sha256, hex_digest(&pretty));
    assert_ne!(
        compact_inspection.manifest_sha256,
        pretty_inspection.manifest_sha256
    );
    Ok(())
}

#[test]
fn closed_manifest_rejects_unknown_duplicate_and_oversized_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let bytes = serde_json::to_vec(&manifest())?;
    assert!(ReleaseManifest::read(Cursor::new(&bytes)).is_ok());
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
    value["launch_arbitrary_command"] = serde_json::json!(true);
    assert!(ReleaseManifest::read(Cursor::new(serde_json::to_vec(&value)?)).is_err());
    let text = String::from_utf8(bytes)?;
    let duplicate = text.replacen('{', "{\"schema_version\":1,", 1);
    assert!(ReleaseManifest::read(Cursor::new(duplicate)).is_err());
    assert!(ReleaseManifest::read(Cursor::new(vec![b' '; 65_537])).is_err());
    Ok(())
}

#[test]
fn source_role_path_and_migration_duplicates_fail_closed() {
    let mut release = manifest();
    release.revisions.push(release.revisions[0].clone());
    assert!(release.validate().is_err());
    release = manifest();
    release.artifacts[1].role = ArtifactRole::Watchdog;
    assert!(release.validate().is_err());
    release = manifest();
    release.artifacts[1].path = release.artifacts[0].path.clone();
    assert!(release.validate().is_err());
    release = manifest();
    release.artifacts[1].path = "WATCHDOG".into();
    assert!(release.validate().is_err());
    release = manifest();
    release.compatibility.stores[1].owner = "watchdog".to_owned();
    assert!(release.validate().is_err());
    release = manifest();
    release.compatibility.stores[1].minimum_schema = 2;
    assert!(release.validate().is_err());
}

#[test]
fn portable_path_escape_variants_are_rejected() {
    for path in [
        "../gateway",
        "/gateway",
        "C:\\gateway.exe",
        "bin/../../gateway",
        "bin\\gateway",
        "gateway:stream",
        "./gateway",
        "bin//gateway",
        "gateway/",
        "gateway.",
        "NUL.exe",
        "COM1",
        "",
    ] {
        let mut release = manifest();
        release.artifacts[1].path = path.into();
        assert!(release.validate().is_err(), "accepted path {path}");
    }
}

#[test]
fn relative_release_ids_and_unapproved_repository_extensions_are_rejected() {
    for id in [".", "..", "release."] {
        let mut release = manifest();
        release.release_id = id.to_owned();
        assert!(release.validate().is_err());
    }
    let mut release = manifest();
    release.revisions.push(Revision {
        repository: "unapproved-companion".to_owned(),
        commit: "a".repeat(40),
    });
    assert!(release.validate().is_err());
    release.revisions.pop();
    release.revisions.push(Revision {
        repository: "ai-agent-observability".to_owned(),
        commit: "b".repeat(40),
    });
    assert!(release.validate().is_ok());
}

#[test]
fn missing_source_and_mixed_profile_metadata_fail() {
    let mut release = manifest();
    release
        .revisions
        .retain(|revision| revision.repository != "sts2-game-mod");
    assert!(release.validate().is_err());
    release = manifest();
    release.compatibility.recovery_profile = "runtime-v3-gameplay".to_owned();
    assert!(release.validate().is_err());
    release = manifest();
    release.compatibility.recovery_profile_sha256 = "b".repeat(63);
    assert!(release.validate().is_err());
}

#[cfg(unix)]
#[test]
fn symlinked_artifacts_and_intermediate_directories_are_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;
    let temporary = tempfile::tempdir()?;
    let source = temporary.path().join("source");
    let indirect = temporary.path().join("indirect");
    fs::create_dir(&source)?;
    symlink(&source, &indirect)?;
    let nested = source.join("release");
    fs::create_dir(&nested)?;
    let mut release = manifest();
    stage(&source, &release)?;
    stage(&nested, &release)?;
    assert!(release.inspect(&indirect).is_err());
    assert!(release.inspect(&indirect.join("release")).is_err());
    symlink(source.join("gateway"), source.join("gateway-link"))?;
    release.artifacts[1].path = "gateway-link".into();
    assert!(release.inspect(&source).is_err());
    release = manifest();
    symlink(&source, source.join("bin"))?;
    release.artifacts[1].path = "bin/gateway".into();
    assert!(release.inspect(&source).is_err());
    Ok(())
}

#[test]
fn inspection_does_not_create_missing_state_or_directories()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let missing = temporary.path().join("absent");
    assert!(manifest().inspect(&missing).is_err());
    assert!(!missing.exists());
    Ok(())
}
