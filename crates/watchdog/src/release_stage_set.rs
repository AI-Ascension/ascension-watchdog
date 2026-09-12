//! Reproducible assembly of an immutable six-role release set.
//!
//! This is release *staging*, not activation.  It verifies the admitted source
//! set, copies the six fixed role artifacts into a new catalog release
//! directory, binds each artifact's exact bytes and the deployment
//! configuration digest into a closed release manifest, and returns a
//! machine-readable report.  It never activates, launches, or mutates an
//! existing release, and it does not set ownership: the caller stages under a
//! catalog whose owner policy it controls (root for a production catalog).
#![allow(clippy::missing_errors_doc, clippy::map_err_ignore)]

use crate::config::WatchdogConfig;
use crate::release::{
    Artifact, ArtifactRole, Compatibility, ReleaseManifest, Revision, StoreCompatibility,
};
use crate::source_set;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAX_SOURCE_SET_MANIFEST_BYTES: usize = 1_048_576;
const MAX_COMPATIBILITY_BYTES: usize = 65_536;
const MAX_ARTIFACT_BYTES: u64 = 1_073_741_824;
const MANIFEST_NAME: &str = "release-manifest.json";
const ROLES: [(&str, ArtifactRole); 6] = [
    ("watchdog", ArtifactRole::Watchdog),
    ("gateway", ArtifactRole::Gateway),
    ("harness", ArtifactRole::Harness),
    ("mcp", ArtifactRole::Mcp),
    ("mod", ArtifactRole::Mod),
    ("host_broker", ArtifactRole::HostBroker),
];

#[derive(Debug, Deserialize)]
struct SourceSetDocument {
    repositories: BTreeMap<String, SourceSetPin>,
}

#[derive(Debug, Deserialize)]
struct SourceSetPin {
    revision: String,
}

/// Deployment compatibility inputs the caller supplies explicitly.  The
/// profile names are fixed by the release contract and are not taken from the
/// file, so a caller cannot invent a profile identity.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompatibilityProfile {
    game_build: String,
    runtime_profile_sha256: String,
    recovery_profile_sha256: String,
    provider_adapter: String,
    provider_adapter_sha256: String,
    stores: Vec<StoreCompatibility>,
}

#[derive(Clone, Debug, Serialize)]
pub struct StagedArtifact {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct StageSetReport {
    pub stager_version: u32,
    pub release_id: String,
    pub catalog: PathBuf,
    pub manifest: PathBuf,
    pub manifest_sha256: String,
    pub revision_count: usize,
    pub artifact_count: usize,
    pub config_digest: String,
    pub artifacts: BTreeMap<String, StagedArtifact>,
}

/// Verify admission, then assemble a new release directory from the six role
/// artifacts.  An existing release directory is never overwritten.
pub fn stage_release_set(
    manifest_path: &Path,
    catalog_root: &Path,
    release_id: &str,
    config_path: &Path,
    compatibility_path: &Path,
    role_sources: &BTreeMap<String, PathBuf>,
    repository_paths: &BTreeMap<String, PathBuf>,
    artifact_paths: &BTreeMap<String, PathBuf>,
) -> Result<StageSetReport, String> {
    let verification =
        source_set::verify_document(manifest_path, repository_paths, artifact_paths)?;
    if !verification.admitted {
        return Err(format!(
            "release staging refused: source-set admission failed: {}",
            verification.issues.join("; ")
        ));
    }
    let manifest_bytes = read_bounded(manifest_path, MAX_SOURCE_SET_MANIFEST_BYTES)?;
    let document: SourceSetDocument = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("invalid source-set manifest: {error}"))?;
    let mut revisions = Vec::with_capacity(document.repositories.len());
    for (repository, pin) in &document.repositories {
        if pin.revision.len() != 40 || !pin.revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!(
                "source repository {repository} does not carry a 40-hex release commit"
            ));
        }
        revisions.push(Revision {
            repository: repository.clone(),
            commit: pin.revision.clone(),
        });
    }

    let compatibility = read_compatibility(compatibility_path)?;
    let config = WatchdogConfig::from_file(config_path)
        .map_err(|error| format!("deployment configuration is unreadable: {error}"))?;
    let config_digest = config
        .digest()
        .map_err(|error| format!("deployment configuration digest failed: {error}"))?;

    assemble_release_set(
        catalog_root,
        release_id,
        revisions,
        compatibility,
        config_digest,
        role_sources,
    )
}

/// Assemble the release directory from already-validated inputs.  Separated so
/// the deterministic file and manifest behavior is unit-testable without git.
pub(crate) fn assemble_release_set(
    catalog_root: &Path,
    release_id: &str,
    revisions: Vec<Revision>,
    profile: CompatibilityProfile,
    config_digest: String,
    role_sources: &BTreeMap<String, PathBuf>,
) -> Result<StageSetReport, String> {
    let expected = ROLES
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    let supplied = role_sources.keys().cloned().collect::<BTreeSet<_>>();
    if supplied != expected {
        let missing = expected.difference(&supplied).cloned().collect::<Vec<_>>();
        let unknown = supplied.difference(&expected).cloned().collect::<Vec<_>>();
        return Err(format!(
            "release staging requires exactly the six fixed roles; missing [{}], unknown [{}]",
            missing.join(", "),
            unknown.join(", ")
        ));
    }

    let root = catalog_root
        .canonicalize()
        .map_err(|_| "catalog root is unavailable".to_owned())?;
    if !root.is_dir() {
        return Err("catalog root is not a directory".to_owned());
    }
    let release_dir = root.join(release_id);
    if release_dir.exists() {
        return Err(format!(
            "release {release_id} already exists in the catalog"
        ));
    }

    let mut artifacts = BTreeMap::new();
    let mut staged = Vec::new();
    for (name, role) in ROLES {
        let source = role_sources
            .get(name)
            .ok_or_else(|| format!("role {name} has no source"))?;
        let (sha256, bytes) = hash_file_bounded(source, MAX_ARTIFACT_BYTES)?;
        staged.push((name, role, source.clone(), sha256, bytes));
    }

    let validation_manifest = ReleaseManifest {
        schema_version: 1,
        release_id: release_id.to_owned(),
        revisions,
        artifacts: staged
            .iter()
            .map(|(name, role, _source, sha256, bytes)| Artifact {
                role: *role,
                path: PathBuf::from(name),
                sha256: sha256.clone(),
                bytes: *bytes,
            })
            .collect(),
        compatibility: Compatibility {
            game_build: profile.game_build,
            runtime_profile: "runtime-v3-gameplay".to_owned(),
            runtime_profile_sha256: profile.runtime_profile_sha256,
            recovery_profile: "watchdog-recovery-v1".to_owned(),
            recovery_profile_sha256: profile.recovery_profile_sha256,
            configuration_sha256: config_digest.clone(),
            provider_adapter: profile.provider_adapter,
            provider_adapter_sha256: profile.provider_adapter_sha256,
            stores: profile.stores,
        },
    };
    validation_manifest
        .validate()
        .map_err(|error| format!("assembled release manifest is invalid: {error}"))?;

    fs::create_dir(&release_dir)
        .map_err(|error| format!("release directory was not created: {error}"))?;
    for (name, _role, source, sha256, bytes) in &staged {
        let destination = release_dir.join(name);
        copy_bounded(source, &destination, *bytes)?;
        artifacts.insert(
            (*name).to_owned(),
            StagedArtifact {
                path: (*name).to_owned(),
                sha256: sha256.clone(),
                bytes: *bytes,
            },
        );
    }

    let manifest_bytes = serde_json::to_vec_pretty(&validation_manifest)
        .map_err(|error| format!("release manifest serialization failed: {error}"))?;
    let manifest_sha256 = digest_hex(&Sha256::digest(&manifest_bytes));
    let manifest_path = release_dir.join(MANIFEST_NAME);
    write_new(&manifest_path, &manifest_bytes)?;

    Ok(StageSetReport {
        stager_version: 1,
        release_id: release_id.to_owned(),
        catalog: root,
        manifest: manifest_path,
        manifest_sha256,
        revision_count: validation_manifest.revisions.len(),
        artifact_count: validation_manifest.artifacts.len(),
        config_digest,
        artifacts,
    })
}

fn read_compatibility(path: &Path) -> Result<CompatibilityProfile, String> {
    let bytes = read_bounded(path, MAX_COMPATIBILITY_BYTES)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid compatibility profile: {error}"))
}

fn hash_file_bounded(path: &Path, maximum: u64) -> Result<(String, u64), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "role artifact is unavailable".to_owned())?;
    if !metadata.file_type().is_file() {
        return Err("role artifact is not a regular file".to_owned());
    }
    if metadata.len() == 0 || metadata.len() > maximum {
        return Err("role artifact size is outside bounds".to_owned());
    }
    let mut file = File::open(path).map_err(|_| "role artifact cannot be opened".to_owned())?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 65_536];
    let mut total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| "role artifact cannot be read".to_owned())?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(
                u64::try_from(read).map_err(|_| "role artifact length overflows".to_owned())?,
            )
            .ok_or_else(|| "role artifact length overflows".to_owned())?;
        hasher.update(&buffer[..read]);
    }
    if total != metadata.len() {
        return Err("role artifact changed while hashing".to_owned());
    }
    Ok((digest_hex(&hasher.finalize()), total))
}

fn copy_bounded(source: &Path, destination: &Path, expected: u64) -> Result<(), String> {
    let mut reader =
        File::open(source).map_err(|_| "role artifact cannot be reopened".to_owned())?;
    let mut writer = File::options()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|_| "staged role cannot be created".to_owned())?;
    let mut remaining = expected;
    let mut buffer = vec![0_u8; 65_536];
    while remaining > 0 {
        let want = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = reader
            .read(&mut buffer[..want])
            .map_err(|_| "role artifact cannot be read".to_owned())?;
        if read == 0 {
            return Err("role artifact ended before its recorded length".to_owned());
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|_| "staged role cannot be written".to_owned())?;
        remaining -= u64::try_from(read).unwrap_or(0);
    }
    writer
        .sync_all()
        .map_err(|_| "staged role cannot be flushed".to_owned())?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "release manifest cannot be created".to_owned())?;
    file.write_all(bytes)
        .map_err(|_| "release manifest cannot be written".to_owned())?;
    file.sync_all()
        .map_err(|_| "release manifest cannot be flushed".to_owned())?;
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "required file is unavailable".to_owned())?;
    if !metadata.file_type().is_file() {
        return Err("required path is not a regular file".to_owned());
    }
    let length = usize::try_from(metadata.len()).map_err(|_| "file length overflows".to_owned())?;
    if length > maximum {
        return Err("file exceeds the stager byte bound".to_owned());
    }
    let mut file = File::open(path).map_err(|_| "required file cannot be opened".to_owned())?;
    let mut bytes = Vec::with_capacity(length);
    file.read_to_end(&mut bytes)
        .map_err(|_| "required file cannot be read".to_owned())?;
    Ok(bytes)
}

fn digest_hex(bytes: &[u8]) -> String {
    crate::source_set::digest_hex(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex64(fill: char) -> String {
        fill.to_string().repeat(64)
    }

    fn profile() -> CompatibilityProfile {
        CompatibilityProfile {
            game_build: "sts2-2-minimum".to_owned(),
            runtime_profile_sha256: hex64('a'),
            recovery_profile_sha256: hex64('b'),
            provider_adapter: "codex-local".to_owned(),
            provider_adapter_sha256: hex64('c'),
            stores: vec![
                StoreCompatibility {
                    owner: "watchdog".to_owned(),
                    minimum_schema: 1,
                    maximum_schema: 2,
                },
                StoreCompatibility {
                    owner: "gateway".to_owned(),
                    minimum_schema: 1,
                    maximum_schema: 1,
                },
                StoreCompatibility {
                    owner: "harness".to_owned(),
                    minimum_schema: 1,
                    maximum_schema: 1,
                },
            ],
        }
    }

    fn revisions() -> Vec<Revision> {
        [
            "ascension-watchdog",
            "sts2-gateway",
            "sts2-harness",
            "sts2-mcp-server",
            "sts2-game-mod",
            "sts2-protocol",
        ]
        .iter()
        .map(|repository| Revision {
            repository: (*repository).to_owned(),
            commit: "0".repeat(40),
        })
        .collect()
    }

    fn role_sources(directory: &Path) -> BTreeMap<String, PathBuf> {
        let mut sources = BTreeMap::new();
        for (name, _role) in ROLES {
            let path = directory.join(format!("{name}.src"));
            fs::write(&path, format!("artifact-{name}")).expect("role fixture");
            sources.insert(name.to_owned(), path);
        }
        sources
    }

    #[test]
    fn staging_requires_every_fixed_role() {
        let catalog = tempfile::tempdir().expect("catalog");
        let sources = tempfile::tempdir().expect("sources");
        let mut roles = role_sources(sources.path());
        roles.remove("mod");
        let error = assemble_release_set(
            catalog.path(),
            "release-x",
            revisions(),
            profile(),
            hex64('d'),
            &roles,
        )
        .expect_err("missing role must fail");
        assert!(error.contains("six fixed roles"), "{error}");
    }

    #[test]
    fn staging_writes_a_manifest_bound_to_the_config_digest() {
        let catalog = tempfile::tempdir().expect("catalog");
        let sources = tempfile::tempdir().expect("sources");
        let roles = role_sources(sources.path());
        let config_digest = hex64('d');
        let report = assemble_release_set(
            catalog.path(),
            "release-a",
            revisions(),
            profile(),
            config_digest.clone(),
            &roles,
        )
        .expect("staging succeeds");
        assert_eq!(report.artifact_count, 6);
        assert_eq!(report.revision_count, 6);
        assert_eq!(report.config_digest, config_digest);

        let bytes = fs::read(&report.manifest).expect("manifest exists");
        assert_eq!(
            report.manifest_sha256,
            digest_hex(&Sha256::digest(&bytes)),
            "reported digest must match the exact manifest bytes"
        );
        let manifest = ReleaseManifest::read(bytes.as_slice()).expect("manifest validates");
        assert_eq!(manifest.release_id, "release-a");
        assert_eq!(manifest.compatibility.configuration_sha256, config_digest);
        assert_eq!(
            manifest.compatibility.runtime_profile,
            "runtime-v3-gameplay"
        );
        assert_eq!(manifest.artifacts.len(), 6);
    }

    #[test]
    fn staging_never_overwrites_an_existing_release() {
        let catalog = tempfile::tempdir().expect("catalog");
        let sources = tempfile::tempdir().expect("sources");
        let roles = role_sources(sources.path());
        assemble_release_set(
            catalog.path(),
            "release-a",
            revisions(),
            profile(),
            hex64('d'),
            &roles,
        )
        .expect("first staging");
        let error = assemble_release_set(
            catalog.path(),
            "release-a",
            revisions(),
            profile(),
            hex64('d'),
            &roles,
        )
        .expect_err("second staging must be refused");
        assert!(error.contains("already exists"), "{error}");
    }

    #[test]
    fn invalid_compatibility_is_rejected() {
        let catalog = tempfile::tempdir().expect("catalog");
        let sources = tempfile::tempdir().expect("sources");
        let roles = role_sources(sources.path());
        let mut invalid = profile();
        invalid.game_build = String::new();
        let error = assemble_release_set(
            catalog.path(),
            "release-a",
            revisions(),
            invalid,
            hex64('d'),
            &roles,
        )
        .expect_err("empty game build must fail");
        assert!(error.contains("invalid"), "{error}");
    }
}
