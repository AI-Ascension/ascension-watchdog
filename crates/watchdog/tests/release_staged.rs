use ascension_watchdog::config::{ComponentConfig, WatchdogConfig, hex_digest};
use ascension_watchdog::release::{
    Artifact, ArtifactRole, Compatibility, ReleaseManifest, Revision, StoreCompatibility,
};
#[cfg(target_os = "linux")]
use ascension_watchdog::release_staged::ReleaseProtection;
#[cfg(target_os = "linux")]
use ascension_watchdog::release_staged::{
    CatalogOwnerPolicy, CatalogOwnerPolicyOrigin, CatalogOwnerProof,
};
use ascension_watchdog::release_staged::{ProtectedReleaseCatalog, ReleaseStagedCapability};
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const ARTIFACT_BYTES: &[u8] = b"immutable release role bytes";

struct Fixture {
    temp: TempDir,
    catalog_root: PathBuf,
    release_root: PathBuf,
    config: WatchdogConfig,
    compatibility: Compatibility,
    manifest_bytes: Vec<u8>,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().expect("release fixture tempdir");
    let catalog_root = temp.path().join("releases");
    let release_root = catalog_root.join("release-1");
    fs::create_dir(&catalog_root).expect("catalog root");
    fs::create_dir(&release_root).expect("release root");

    let digest = hex_digest(ARTIFACT_BYTES);
    let config = WatchdogConfig {
        database: temp.path().join("watchdog.sqlite3"),
        deployment_id: "staged-release-test".to_owned(),
        allow_synthetic_children: true,
        components: vec![
            component("gateway", &release_root.join("gateway"), &digest),
            component("harness", &release_root.join("harness"), &digest),
        ],
        ..WatchdogConfig::default()
    };
    let compatibility = Compatibility {
        game_build: "game-build-1".to_owned(),
        runtime_profile: "runtime-v3-gameplay".to_owned(),
        runtime_profile_sha256: "a".repeat(64),
        recovery_profile: "watchdog-recovery-v1".to_owned(),
        recovery_profile_sha256: "b".repeat(64),
        configuration_sha256: config.digest().expect("config digest"),
        provider_adapter: "provider-one".to_owned(),
        provider_adapter_sha256: "c".repeat(64),
        stores: ["watchdog", "gateway", "harness"]
            .into_iter()
            .map(|owner| StoreCompatibility {
                owner: owner.to_owned(),
                minimum_schema: 1,
                maximum_schema: 1,
            })
            .collect(),
    };
    let manifest = ReleaseManifest {
        schema_version: 1,
        release_id: "release-1".to_owned(),
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
            path: PathBuf::from(path),
            sha256: digest.clone(),
            bytes: ARTIFACT_BYTES.len() as u64,
        })
        .collect(),
        compatibility: compatibility.clone(),
    };
    for artifact in &manifest.artifacts {
        fs::write(release_root.join(&artifact.path), ARTIFACT_BYTES).expect("release artifact");
    }
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).expect("manifest bytes");
    fs::write(release_root.join("manifest.json"), &manifest_bytes).expect("manifest");
    protect_tree(&catalog_root, &release_root, &manifest);
    Fixture {
        temp,
        catalog_root,
        release_root,
        config,
        compatibility,
        manifest_bytes,
    }
}

fn component(id: &str, executable: &Path, digest: &str) -> ComponentConfig {
    ComponentConfig {
        id: id.to_owned(),
        executable: executable.to_owned(),
        args: Vec::new(),
        cwd: None,
        environment: std::collections::BTreeMap::new(),
        executable_sha256: Some(digest.to_owned()),
        restart: true,
    }
}

#[cfg(unix)]
fn protect_tree(catalog_root: &Path, release_root: &Path, manifest: &ReleaseManifest) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(catalog_root, fs::Permissions::from_mode(0o555))
        .expect("catalog permissions");
    fs::set_permissions(release_root, fs::Permissions::from_mode(0o555))
        .expect("release permissions");
    for artifact in &manifest.artifacts {
        fs::set_permissions(
            release_root.join(&artifact.path),
            fs::Permissions::from_mode(0o444),
        )
        .expect("artifact permissions");
    }
    fs::set_permissions(
        release_root.join("manifest.json"),
        fs::Permissions::from_mode(0o444),
    )
    .expect("manifest permissions");
}

#[cfg(not(unix))]
fn protect_tree(_catalog_root: &Path, _release_root: &Path, _manifest: &ReleaseManifest) {}

fn schemas() -> [(&'static str, u32); 3] {
    [("watchdog", 1), ("gateway", 1), ("harness", 1)]
}

fn stage(fixture: &Fixture) -> Result<ReleaseStagedCapability, String> {
    ProtectedReleaseCatalog::new(&fixture.catalog_root)?.stage(
        "release-1",
        &hex_digest(&fixture.manifest_bytes),
        &fixture.compatibility,
        &schemas(),
        &fixture.config,
    )
}

#[cfg(target_os = "linux")]
fn approved_owner(fixture: &Fixture) -> CatalogOwnerPolicy {
    use std::os::unix::fs::MetadataExt;
    CatalogOwnerPolicy::approved_unix_uid(
        fs::metadata(&fixture.catalog_root)
            .expect("catalog metadata")
            .uid()
            .into(),
    )
}

#[cfg(target_os = "linux")]
#[test]
fn caller_approved_catalog_owner_policy_is_recorded_and_bound() {
    let fixture = fixture();
    let policy = approved_owner(&fixture);
    let catalog = ProtectedReleaseCatalog::new_with_owner_policy(&fixture.catalog_root, policy)
        .expect("approved owner catalog");
    assert_eq!(
        catalog.owner_proof(),
        CatalogOwnerProof::ApprovedCatalogOwner {
            policy,
            observed_unix_uid: policy.expected_unix_uid(),
        }
    );
    let capability = catalog
        .stage(
            "release-1",
            &hex_digest(&fixture.manifest_bytes),
            &fixture.compatibility,
            &schemas(),
            &fixture.config,
        )
        .expect("approved owner stage");
    assert_eq!(capability.owner_proof(), catalog.owner_proof());
    assert!(capability.owner_proof().is_approved());
    assert_eq!(
        capability
            .owner_proof()
            .policy()
            .expect("approved policy")
            .origin(),
        CatalogOwnerPolicyOrigin::CallerSuppliedUnixUid
    );
}

#[cfg(target_os = "linux")]
#[test]
fn caller_approved_catalog_owner_policy_rejects_wrong_uid() {
    let fixture = fixture();
    let observed = fs::metadata(&fixture.catalog_root)
        .expect("catalog metadata")
        .uid();
    let wrong = u64::from(observed == 0);
    let error = ProtectedReleaseCatalog::new_with_owner_policy(
        &fixture.catalog_root,
        CatalogOwnerPolicy::approved_unix_uid(wrong),
    )
    .expect_err("wrong approved owner must not open catalog");
    assert!(error.contains("owner"), "unexpected owner error: {error}");
}

#[cfg(target_os = "linux")]
#[test]
fn approved_policy_detects_replaced_above_catalog_ancestor() {
    let fixture = fixture();
    let policy = approved_owner(&fixture);
    let capability = ReleaseStagedCapability::stage_with_owner_policy(
        &fixture.catalog_root,
        policy,
        "release-1",
        &hex_digest(&fixture.manifest_bytes),
        &fixture.compatibility,
        &schemas(),
        &fixture.config,
    )
    .expect("approved owner stage");

    let original_parent = fixture
        .catalog_root
        .parent()
        .expect("catalog parent")
        .to_owned();
    let moved_parent = original_parent.with_extension("moved");
    fs::rename(&original_parent, &moved_parent).expect("move original catalog ancestor");
    fs::create_dir(&original_parent).expect("replace catalog ancestor");
    assert!(
        capability.verify_held().is_err(),
        "ancestor replacement must invalidate retained proof"
    );
    fs::remove_dir(&original_parent).expect("remove replacement ancestor");
    fs::rename(moved_parent, original_parent).expect("restore original catalog ancestor");
}

#[cfg(target_os = "linux")]
#[test]
fn stages_exact_manifest_digest_six_roles_and_checked_component_bindings() {
    let fixture = fixture();
    let capability = stage(&fixture).expect("stage protected release");
    assert_eq!(
        capability.manifest_digest(),
        hex_digest(&fixture.manifest_bytes)
    );
    assert_eq!(capability.release_id(), "release-1");
    assert_eq!(capability.role_bindings().len(), 6);
    assert_eq!(
        capability
            .role_binding(ArtifactRole::Gateway)
            .expect("gateway role")
            .path(),
        fixture.release_root.join("gateway")
    );
    assert_eq!(
        capability.protection(),
        ReleaseProtection::LinuxSecureDescriptors
    );
    assert!(capability.protection().secure_path_open());
    assert!(capability.protection().limitations().contains("chmod"));
    assert!(capability.protection().limitations().contains("pre-opened"));
    assert!(
        capability
            .protection()
            .limitations()
            .contains("never launch authority")
    );
    assert!(!capability.owner_proof().is_approved());
    assert!(matches!(
        capability.owner_proof(),
        CatalogOwnerProof::ObservedCatalogOwner { .. }
    ));
    capability.verify_held().expect("held proof");
    let mut handle = capability
        .role_handle(ArtifactRole::Gateway)
        .expect("gateway handle");
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut handle, &mut bytes).expect("read gateway");
    assert_eq!(bytes, ARTIFACT_BYTES);
}

#[cfg(target_os = "linux")]
#[test]
fn exact_original_manifest_bytes_are_the_release_identity() {
    let fixture = fixture();
    let capability = stage(&fixture).expect("stage protected release");
    let generated = serde_json::to_vec(capability.manifest()).expect("generated manifest");
    assert_ne!(generated, fixture.manifest_bytes);
    assert_ne!(capability.manifest_digest(), hex_digest(&generated));
    assert_eq!(
        capability.manifest_digest(),
        hex_digest(&fixture.manifest_bytes)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn held_verification_is_safe_for_concurrent_readers() {
    let fixture = fixture();
    let capability = stage(&fixture).expect("stage protected release");
    std::thread::scope(|scope| {
        let checks = (0..8)
            .map(|_| scope.spawn(|| capability.verify_held()))
            .collect::<Vec<_>>();
        for check in checks {
            check
                .join()
                .expect("verification thread")
                .expect("concurrent held verification");
        }
    });
}

#[cfg(target_os = "linux")]
#[test]
fn independently_approved_manifest_digest_is_required() {
    let fixture = fixture();
    let wrong_digest = "0".repeat(64);
    let error = ProtectedReleaseCatalog::new(&fixture.catalog_root)
        .and_then(|catalog| {
            catalog.stage(
                "release-1",
                &wrong_digest,
                &fixture.compatibility,
                &schemas(),
                &fixture.config,
            )
        })
        .expect_err("computed but unapproved manifest digest must not stage");
    assert!(error.contains("independently approved digest"));

    let malformed = "A".repeat(64);
    let error = ProtectedReleaseCatalog::new(&fixture.catalog_root)
        .and_then(|catalog| {
            catalog.stage(
                "release-1",
                &malformed,
                &fixture.compatibility,
                &schemas(),
                &fixture.config,
            )
        })
        .expect_err("noncanonical manifest digest must be rejected");
    assert!(error.contains("lowercase SHA-256"));
}

#[cfg(target_os = "linux")]
#[test]
fn held_capability_detects_in_place_artifact_tampering() {
    let fixture = fixture();
    let capability = stage(&fixture).expect("stage protected release");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = fixture.release_root.join("gateway");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("make writable");
        fs::write(&path, b"tampered release bytes").expect("tamper artifact");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).expect("restore mode");
        assert!(capability.verify_held().is_err());
    }
    #[cfg(not(unix))]
    {
        let _ = capability;
    }
}

#[cfg(target_os = "linux")]
#[test]
fn hardlinked_fixed_roles_are_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = fixture();
    fs::set_permissions(&fixture.release_root, fs::Permissions::from_mode(0o755))
        .expect("reopen release directory for hard-link setup");
    fs::remove_file(fixture.release_root.join("gateway")).expect("remove gateway");
    fs::hard_link(
        fixture.release_root.join("harness"),
        fixture.release_root.join("gateway"),
    )
    .expect("hard-link harness as gateway");
    fs::set_permissions(&fixture.release_root, fs::Permissions::from_mode(0o555))
        .expect("restore release permissions");

    let error = stage(&fixture).expect_err("hard-linked roles must not stage");
    assert!(
        error.contains("hard links") || error.contains("share one device/inode identity"),
        "unexpected hard-link rejection: {error}"
    );
}

#[test]
fn writable_catalog_and_mixed_profile_digest_are_rejected() {
    let fixture = fixture();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&fixture.catalog_root, fs::Permissions::from_mode(0o755))
            .expect("make catalog writable");
        assert!(ProtectedReleaseCatalog::new(&fixture.catalog_root).is_err());
        fs::set_permissions(&fixture.catalog_root, fs::Permissions::from_mode(0o555))
            .expect("restore catalog permissions");
    }

    let mut approved = fixture.compatibility.clone();
    approved.runtime_profile_sha256 = "f".repeat(64);
    assert!(
        ProtectedReleaseCatalog::new(&fixture.catalog_root)
            .and_then(|catalog| {
                catalog.stage(
                    "release-1",
                    &hex_digest(&fixture.manifest_bytes),
                    &approved,
                    &schemas(),
                    &fixture.config,
                )
            })
            .is_err()
    );
}

#[test]
fn duplicate_fixed_manifest_names_and_unlisted_ids_fail_closed() {
    let fixture = fixture();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // The fixture is intentionally protected before staging.  Temporarily
        // reopen the directory for this adversarial setup, then restore the
        // protected mode before exercising selection.
        fs::set_permissions(&fixture.release_root, fs::Permissions::from_mode(0o755))
            .expect("reopen release directory for duplicate");
    }
    fs::copy(
        fixture.release_root.join("manifest.json"),
        fixture.release_root.join("release-manifest.json"),
    )
    .expect("duplicate manifest");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            fixture.release_root.join("release-manifest.json"),
            fs::Permissions::from_mode(0o444),
        )
        .expect("duplicate manifest permissions");
        fs::set_permissions(&fixture.release_root, fs::Permissions::from_mode(0o555))
            .expect("restore release permissions");
    }
    assert!(stage(&fixture).is_err());
    assert!(
        ProtectedReleaseCatalog::new(&fixture.catalog_root)
            .and_then(|catalog| catalog.stage(
                "../release-1",
                &hex_digest(&fixture.manifest_bytes),
                &fixture.compatibility,
                &schemas(),
                &fixture.config
            ))
            .is_err()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn fifo_paths_fail_closed_without_blocking() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const CASE_ENV: &str = "ASCENSION_RELEASE_STAGED_FIFO_CASE";
    if let Ok(case) = std::env::var(CASE_ENV) {
        let fixture = fixture();
        fs::set_permissions(&fixture.release_root, fs::Permissions::from_mode(0o755))
            .expect("reopen release directory for FIFO");
        let fifo_path = if case == "manifest" {
            let path = fixture.release_root.join("manifest.json");
            fs::remove_file(&path).expect("remove manifest for FIFO");
            path
        } else if case == "artifact" {
            let path = fixture.release_root.join("gateway");
            fs::remove_file(&path).expect("remove artifact for FIFO");
            path
        } else {
            return Err(format!("unknown FIFO child case: {case}").into());
        };
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo_path,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .expect("create FIFO");
        fs::set_permissions(&fifo_path, fs::Permissions::from_mode(0o444))
            .expect("FIFO permissions");
        fs::set_permissions(&fixture.release_root, fs::Permissions::from_mode(0o555))
            .expect("restore release permissions");
        assert!(stage(&fixture).is_err(), "FIFO path must not stage");
        return Ok(());
    }

    for case in ["manifest", "artifact"] {
        let mut child = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "fifo_paths_fail_closed_without_blocking",
                "--nocapture",
            ])
            .env(CASE_ENV, case)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    assert!(
                        status.success(),
                        "FIFO {case} child rejected with status {status}"
                    );
                    break;
                }
                Ok(None) => {}
                Err(error) => {
                    let cleanup = kill_and_reap_bounded(&mut child, Duration::from_secs(1));
                    return Err(format!(
                        "FIFO {case} child status probe failed: {error}; cleanup: {cleanup:?}"
                    )
                    .into());
                }
            }
            if Instant::now() >= deadline {
                let cleanup = kill_and_reap_bounded(&mut child, Duration::from_secs(1));
                return Err(
                    format!("FIFO {case} staging child blocked; cleanup: {cleanup:?}").into(),
                );
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn kill_and_reap_bounded(
    child: &mut std::process::Child,
    budget: std::time::Duration,
) -> Result<(), String> {
    if let Err(error) = child.kill() {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return Ok(());
        }
        return Err(format!("uncertain cleanup after kill failed: {error}"));
    }
    let deadline = std::time::Instant::now() + budget;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            Ok(None) => return Err("uncertain cleanup: child did not reap by deadline".to_owned()),
            Err(error) => return Err(format!("uncertain cleanup: bounded reap failed: {error}")),
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn convenience_staging_does_not_change_configuration_or_selector_state() {
    let fixture = fixture();
    let before = fixture.config.clone();
    let capability = ReleaseStagedCapability::stage(
        &fixture.catalog_root,
        "release-1",
        &hex_digest(&fixture.manifest_bytes),
        &fixture.compatibility,
        &schemas(),
        &fixture.config,
    )
    .expect("stage release");
    assert_eq!(fixture.config, before);
    assert_eq!(capability.release_id(), "release-1");
    assert!(!fixture.temp.path().join("watchdog.sqlite3").exists());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platforms_fail_closed_before_minting_a_capability() {
    let fixture = fixture();
    let error = ProtectedReleaseCatalog::new(&fixture.catalog_root)
        .expect_err("non-Linux platform must not mint a staged capability");
    assert!(error.contains("fail-closed"));
}
