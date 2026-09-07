// SPDX-License-Identifier: MIT
//! Bounded release-set inspection. Inspection is evidence about bytes read, not
//! authorization to launch them; activation must also enforce immutable storage.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_MANIFEST_BYTES: usize = 65_536;
const MAX_ARTIFACT_BYTES: u64 = 1_073_741_824;
const REQUIRED_REPOSITORIES: [&str; 6] = [
    "ascension-watchdog",
    "sts2-gateway",
    "sts2-harness",
    "sts2-mcp-server",
    "sts2-game-mod",
    "sts2-protocol",
];
const OPTIONAL_REPOSITORIES: [&str; 4] = [
    "sts2-game-core",
    "ai-agent-observability",
    ".github",
    "AI-Ascension.github.io",
];
const WINDOWS_SERVICE_EXECUTABLE: &str = "watchdog.exe";

/// Exact original-source revision, independently of artifact byte identity.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    pub repository: String,
    pub commit: String,
}

/// An artifact path is relative to its immutable release directory.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub role: ArtifactRole,
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
}

/// Fixed launch roles; no arbitrary executable or generic proxy role exists.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRole {
    Watchdog,
    Gateway,
    Harness,
    Mcp,
    Mod,
    HostBroker,
}

/// Accepted schema interval for one owner's database. Binary rollback must not
/// restore database bytes or authority generations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoreCompatibility {
    pub owner: String,
    pub minimum_schema: u32,
    pub maximum_schema: u32,
}

/// Immutable identities used to reject mixed builds and identical profile names
/// whose bytes differ. Provider identity is approved deployment input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Compatibility {
    pub game_build: String,
    pub runtime_profile: String,
    pub runtime_profile_sha256: String,
    pub recovery_profile: String,
    pub recovery_profile_sha256: String,
    pub configuration_sha256: String,
    pub provider_adapter: String,
    pub provider_adapter_sha256: String,
    pub stores: Vec<StoreCompatibility>,
}

/// Closed version-one release manifest. A parsed manifest is not an activated
/// release and does not confer lifecycle authority.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub release_id: String,
    pub revisions: Vec<Revision>,
    pub artifacts: Vec<Artifact>,
    pub compatibility: Compatibility,
}

/// Evidence of a bounded byte inspection. It intentionally contains no launch
/// capability and cannot replace protected-directory activation checks.
#[derive(Clone, Debug, Serialize)]
pub struct ReleaseInspection {
    pub release_id: String,
    pub artifact_count: usize,
    pub total_bytes: u64,
    pub manifest_sha256: String,
}

impl ReleaseManifest {
    /// Check a candidate against independently approved deployment identities and
    /// current owner-reported schemas. This does not migrate or restore a store,
    /// approve the candidate, or establish runtime mutation authority.
    ///
    /// # Errors
    /// Rejects mixed profile/configuration/provider/build identities and missing,
    /// duplicated, unknown or incompatible current database schemas.
    pub fn check_deployment_compatibility(
        &self,
        approved: &Compatibility,
        current_schemas: &[(&str, u32)],
    ) -> Result<(), String> {
        self.validate()?;
        approved.validate()?;
        let candidate = &self.compatibility;
        if candidate.game_build != approved.game_build
            || candidate.runtime_profile != approved.runtime_profile
            || candidate.runtime_profile_sha256 != approved.runtime_profile_sha256
            || candidate.recovery_profile != approved.recovery_profile
            || candidate.recovery_profile_sha256 != approved.recovery_profile_sha256
            || candidate.configuration_sha256 != approved.configuration_sha256
            || candidate.provider_adapter != approved.provider_adapter
            || candidate.provider_adapter_sha256 != approved.provider_adapter_sha256
        {
            return Err("candidate differs from approved deployment identities".to_owned());
        }
        if current_schemas.len() != 3 {
            return Err("current owner schema inventory must contain three stores".to_owned());
        }
        let mut owners = BTreeSet::new();
        for &(owner, current) in current_schemas {
            if !owners.insert(owner) {
                return Err("duplicate current schema owner".to_owned());
            }
            for compatibility in [candidate, approved] {
                let supported = compatibility.stores.iter().any(|store| {
                    store.owner == owner
                        && (store.minimum_schema..=store.maximum_schema).contains(&current)
                });
                if !supported {
                    return Err(
                        "current store schema is not compatible with approved release".to_owned(),
                    );
                }
            }
        }
        Ok(())
    }

    /// Inspect artifacts and retain the digest of the exact input manifest bytes,
    /// including its original whitespace. This is the release-contract entrypoint.
    ///
    /// # Errors
    /// Rejects invalid or oversized documents, missing or mismatched artifacts
    /// and indirect filesystem paths. It never activates a release.
    pub fn inspect_document(reader: impl Read, root: &Path) -> Result<ReleaseInspection, String> {
        let bytes = bounded_document(reader)?;
        let manifest = Self::read(bytes.as_slice())?;
        let mut inspection = manifest.inspect(root)?;
        inspection.manifest_sha256 = digest_hex(&Sha256::digest(&bytes));
        Ok(inspection)
    }

    /// Read and validate at most 64 KiB without allocating from an input length.
    /// Duplicate struct fields and unknown fields are rejected by deserialization.
    ///
    /// # Errors
    /// Rejects I/O failures, oversized or malformed JSON and invalid manifests.
    pub fn read(reader: impl Read) -> Result<Self, String> {
        let bytes = bounded_document(reader)?;
        let manifest: Self = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid release manifest: {error}"))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validate exact revisions, closed role sets, digest syntax and migration
    /// bounds before filesystem or process actions.
    ///
    /// # Errors
    /// Rejects unsupported versions, missing or duplicate identities, unsafe
    /// artifact paths and incompatible profile or migration metadata.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 || !identity(&self.release_id) {
            return Err("unsupported release version or invalid identity".to_owned());
        }
        self.validate_revisions()?;
        self.validate_artifacts()?;
        self.compatibility.validate()
    }

    fn validate_revisions(&self) -> Result<(), String> {
        if self.revisions.len() < REQUIRED_REPOSITORIES.len() || self.revisions.len() > 16 {
            return Err("release revision count is outside bounds".to_owned());
        }
        let mut repositories = BTreeSet::new();
        for revision in &self.revisions {
            if !identity(&revision.repository)
                || !(REQUIRED_REPOSITORIES.contains(&revision.repository.as_str())
                    || OPTIONAL_REPOSITORIES.contains(&revision.repository.as_str()))
                || !hex(&revision.commit, 40)
                || !repositories.insert(revision.repository.as_str())
            {
                return Err("invalid or duplicate source revision".to_owned());
            }
        }
        if REQUIRED_REPOSITORIES
            .iter()
            .any(|repository| !repositories.contains(repository))
        {
            return Err("release omits a required companion revision".to_owned());
        }
        Ok(())
    }

    fn validate_artifacts(&self) -> Result<(), String> {
        if self.artifacts.len() != 6 {
            return Err("release requires exactly six executable roles".to_owned());
        }
        let mut roles = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for artifact in &self.artifacts {
            if !relative_path(&artifact.path)
                || !hex(&artifact.sha256, 64)
                || artifact.bytes == 0
                || artifact.bytes > MAX_ARTIFACT_BYTES
                || !roles.insert(artifact.role)
                || !paths.insert(artifact.path.to_string_lossy().to_ascii_lowercase())
            {
                return Err("invalid or duplicate release artifact".to_owned());
            }
        }
        Ok(())
    }

    /// Inspect current bytes without changing release or runtime state. Symlinks
    /// and reparse points are rejected. This check is not a TOCTOU guarantee:
    /// callers must enforce protected immutable directories during activation.
    /// The manifest digest here covers this struct's generated JSON encoding.
    /// Use `inspect_document` when inspecting an existing manifest artifact.
    ///
    /// # Errors
    /// Rejects invalid manifests, missing or indirect paths, mismatched artifact
    /// bytes and filesystem errors without changing release selection.
    pub fn inspect(&self, root: &Path) -> Result<ReleaseInspection, String> {
        self.validate()?;
        require_real_root(root)?;
        self.validate_windows_service_candidate(root)?;
        let mut total_bytes = 0_u64;
        for artifact in &self.artifacts {
            inspect_artifact(root, artifact)?;
            total_bytes = total_bytes
                .checked_add(artifact.bytes)
                .ok_or_else(|| "release byte count overflow".to_owned())?;
        }
        let canonical = serde_json::to_vec(self)
            .map_err(|error| format!("release serialization failed: {error}"))?;
        Ok(ReleaseInspection {
            release_id: self.release_id.clone(),
            artifact_count: self.artifacts.len(),
            total_bytes,
            manifest_sha256: digest_hex(&Sha256::digest(canonical)),
        })
    }

    /// Bind the fixed Windows service executable to the manifest's watchdog
    /// artifact whenever an installer candidate is present.  The generic
    /// inspector is also used for release-like fixtures that do not contain a
    /// Windows executable, so absence of this exact candidate preserves that
    /// portable use while its presence cannot be an unlisted extra file.
    fn validate_windows_service_candidate(&self, root: &Path) -> Result<(), String> {
        let candidate = root.join(WINDOWS_SERVICE_EXECUTABLE);
        match fs::symlink_metadata(&candidate) {
            Ok(_) => {
                let watchdog = self
                    .artifacts
                    .iter()
                    .find(|artifact| artifact.role == ArtifactRole::Watchdog)
                    .ok_or_else(|| "release has no watchdog artifact".to_owned())?;
                if watchdog.path != Path::new(WINDOWS_SERVICE_EXECUTABLE) {
                    return Err(
                        "Windows service candidate watchdog.exe must be the manifest watchdog artifact"
                            .to_owned(),
                    );
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "Windows service candidate watchdog.exe is unavailable: {error}"
            )),
        }
    }
}

fn bounded_document(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_MANIFEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("release manifest read failed: {error}"))?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err("release manifest exceeds byte bound".to_owned());
    }
    Ok(bytes)
}

impl Compatibility {
    fn validate(&self) -> Result<(), String> {
        if !identity(&self.game_build)
            || self.runtime_profile != "runtime-v3-gameplay"
            || self.recovery_profile != "watchdog-recovery-v1"
            || !identity(&self.provider_adapter)
        {
            return Err("unsupported release compatibility identity".to_owned());
        }
        for digest in [
            &self.runtime_profile_sha256,
            &self.recovery_profile_sha256,
            &self.configuration_sha256,
            &self.provider_adapter_sha256,
        ] {
            if !hex(digest, 64) {
                return Err("invalid release compatibility digest".to_owned());
            }
        }
        let mut owners = BTreeSet::new();
        for store in &self.stores {
            if !["watchdog", "gateway", "harness"].contains(&store.owner.as_str())
                || store.minimum_schema == 0
                || store.minimum_schema > store.maximum_schema
                || !owners.insert(store.owner.as_str())
            {
                return Err("invalid or duplicate store compatibility".to_owned());
            }
        }
        if owners.len() != 3 {
            return Err("release requires all three owner-local store ranges".to_owned());
        }
        Ok(())
    }
}

fn identity(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && !value.ends_with('.')
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(DIGITS[usize::from(byte >> 4)]),
                char::from(DIGITS[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

fn relative_path(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    !value.is_empty() && value.len() <= 240 && value.split('/').all(portable_component)
}

fn portable_component(value: &str) -> bool {
    if !identity(value) {
        return false;
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    !matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

pub(crate) fn require_real_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err("release root must be absolute".to_owned());
    }
    let mut ancestor = PathBuf::new();
    for component in root.components() {
        if matches!(component, Component::ParentDir | Component::CurDir) {
            return Err("release root contains a relative component".to_owned());
        }
        ancestor.push(component.as_os_str());
        // A Windows drive prefix alone is not an absolute filesystem root.
        if !matches!(component, Component::Prefix(_)) {
            require_real_directory(&ancestor)?;
        }
    }
    Ok(())
}

fn require_real_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("release directory unavailable: {error}"))?;
    if !metadata.is_dir() || indirect(&metadata) {
        return Err("release directory must not be a link or reparse point".to_owned());
    }
    Ok(())
}

fn indirect(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn inspect_artifact(root: &Path, artifact: &Artifact) -> Result<(), String> {
    let mut path = root.to_path_buf();
    let mut components = artifact.path.components().peekable();
    while let Some(component) = components.next() {
        path.push(component.as_os_str());
        if components.peek().is_some() {
            require_real_directory(&path)?;
        }
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("release artifact unavailable: {error}"))?;
    if !metadata.is_file() || indirect(&metadata) || metadata.len() != artifact.bytes {
        return Err("release artifact type or size mismatch".to_owned());
    }
    let mut file =
        File::open(path).map_err(|error| format!("release artifact open failed: {error}"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 8_192];
    let mut remaining = artifact.bytes;
    while remaining != 0 {
        let capacity = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| "release read bound overflow".to_owned())?;
        let count = file
            .read(&mut buffer[..capacity])
            .map_err(|error| format!("release artifact read failed: {error}"))?;
        if count == 0 {
            return Err("release artifact truncated during inspection".to_owned());
        }
        digest.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let count = file
        .read(&mut buffer[..1])
        .map_err(|error| format!("release artifact final read failed: {error}"))?;
    if count != 0 || digest_hex(&digest.finalize()) != artifact.sha256 {
        return Err("release artifact digest or size changed".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BYTES: &[u8] = b"synthetic watchdog release artifact";

    fn manifest(watchdog_path: &str) -> ReleaseManifest {
        ReleaseManifest {
            schema_version: 1,
            release_id: "installer-candidate".to_owned(),
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
                (ArtifactRole::Watchdog, watchdog_path),
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
                sha256: digest_hex(&Sha256::digest(BYTES)),
                bytes: BYTES.len() as u64,
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

    fn stage(root: &Path, release: &ReleaseManifest) {
        for artifact in &release.artifacts {
            fs::write(root.join(&artifact.path), BYTES).expect("stage artifact");
        }
    }

    #[test]
    fn windows_candidate_cannot_be_an_unlisted_extra_file() {
        let temporary = tempfile::tempdir().expect("temporary release root");
        let release = manifest("watchdog");
        stage(temporary.path(), &release);
        fs::write(temporary.path().join(WINDOWS_SERVICE_EXECUTABLE), BYTES)
            .expect("stage unlisted candidate");

        let error = release
            .inspect(temporary.path())
            .expect_err("unlisted Windows candidate must be rejected");
        assert!(error.contains("must be the manifest watchdog artifact"));
    }

    #[test]
    fn windows_candidate_is_bound_to_manifest_digest() {
        let temporary = tempfile::tempdir().expect("temporary release root");
        let release = manifest(WINDOWS_SERVICE_EXECUTABLE);
        stage(temporary.path(), &release);
        assert_eq!(release.inspect(temporary.path()).unwrap().artifact_count, 6);

        fs::write(
            temporary.path().join(WINDOWS_SERVICE_EXECUTABLE),
            b"tampered watchdog release artifact",
        )
        .expect("tamper candidate");
        assert!(release.inspect(temporary.path()).is_err());
    }
}
