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
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoreCompatibility {
    pub owner: String,
    pub minimum_schema: u32,
    pub maximum_schema: u32,
}

/// Immutable identities used to reject mixed builds and identical profile names
/// whose bytes differ. Provider identity is approved deployment input.
#[derive(Clone, Debug, Deserialize, Serialize)]
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
    /// Read and validate at most 64 KiB without allocating from an input length.
    /// Duplicate struct fields and unknown fields are rejected by deserialization.
    ///
    /// # Errors
    /// Rejects I/O failures, oversized or malformed JSON and invalid manifests.
    pub fn read(reader: impl Read) -> Result<Self, String> {
        let mut bytes = Vec::new();
        reader
            .take((MAX_MANIFEST_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("release manifest read failed: {error}"))?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err("release manifest exceeds byte bound".to_owned());
        }
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
                || !paths.insert(&artifact.path)
            {
                return Err("invalid or duplicate release artifact".to_owned());
            }
        }
        Ok(())
    }

    /// Inspect current bytes without changing release or runtime state. Symlinks
    /// and reparse points are rejected. This check is not a TOCTOU guarantee:
    /// callers must enforce protected immutable directories during activation.
    ///
    /// # Errors
    /// Rejects invalid manifests, missing or indirect paths, mismatched artifact
    /// bytes and filesystem errors without changing release selection.
    pub fn inspect(&self, root: &Path) -> Result<ReleaseInspection, String> {
        self.validate()?;
        require_real_directory(root)?;
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
    !value.is_empty()
        && value.len() <= 240
        && !value.contains(['\\', ':', '\0'])
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
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
