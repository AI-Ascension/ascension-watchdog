//! Owner-local, descriptor-bound validation of one complete release set.
//!
//! A [`ReleaseStagedCapability`] is deliberately narrower than activation.  It
//! selects a release only by a bounded logical ID below a protected catalog
//! root, verifies the exact original manifest bytes and all six fixed roles,
//! and retains read-only handles for the selected objects.  It does not change
//! a selector, launch a process, rewrite configuration, or alter durable
//! release-selection state.

use crate::config::WatchdogConfig;
use crate::release::{ArtifactRole, Compatibility, ReleaseManifest};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Cursor;
use std::path::{Component, Path, PathBuf};

#[path = "release_staged_hash.rs"]
mod release_staged_hash;
use release_staged_hash::{MAX_MANIFEST_BYTES, digest_hex, read_bounded, validate_digest};
#[path = "release_staged_proof.rs"]
mod release_staged_proof;
use release_staged_proof::{
    FileIdentity, HeldArtifact, HeldDirectory, clone_directory, open_directory_child,
    open_directory_path, open_manifest, open_relative_file, platform_protection,
    validate_directory_handle, validate_directory_identity, validate_file_handle,
};

const MAX_RELEASE_ID_BYTES: usize = 128;
const MANIFEST_NAMES: [&str; 2] = ["release-manifest.json", "manifest.json"];

/// The proof retained by a staged capability.  A capability is never created
/// on platforms where no bounded protected-handle strategy is available.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseProtection {
    /// Linux opened every directory and file through an `O_NOFOLLOW` descriptor
    /// walk and retains those descriptors for the capability lifetime.
    LinuxSecureDescriptors,
}

impl ReleaseProtection {
    /// Whether path traversal itself was performed with an OS no-follow open.
    #[must_use]
    pub const fn secure_path_open(self) -> bool {
        matches!(self, Self::LinuxSecureDescriptors)
    }

    /// A bounded explanation of what this proof does not establish.
    #[must_use]
    pub const fn limitations(self) -> &'static str {
        match self {
            Self::LinuxSecureDescriptors => {
                "descriptor identity, regular-file link count, owner, and read-only mode are checked; this is not an immutable handoff because the catalog owner can still chmod and a pre-opened or privileged writer can still write through another handle, so activation must enforce its independently trusted-owner policy and consume or seal the held handles immediately after final verification; returned paths are informational and never launch authority"
            }
        }
    }
}

/// One fixed role bound to the exact bytes read from its retained handle; this
/// binding is not, by itself, an immutable handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseRoleBinding {
    /// The closed manifest role.
    pub role: ArtifactRole,
    /// The path from the selected release directory, copied from the manifest.
    pub relative_path: PathBuf,
    /// Informational normalized absolute path observed while opening the role;
    /// this path is never launch authority.  Consumers must use the retained
    /// role handle and an approved protected handoff instead.
    pub absolute_path: PathBuf,
    /// SHA-256 of the exact bytes read from the retained handle.
    pub sha256: String,
    /// Exact byte length read from the retained handle.
    pub bytes: u64,
}

impl ReleaseRoleBinding {
    /// Return the informational checked absolute path for diagnostics and
    /// adapters.  This is not launch authority; use the retained role handle
    /// for an approved protected handoff.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.absolute_path
    }
}

/// A protected release catalog.  The catalog root is a trusted deployment
/// configuration input; callers select within it using only a logical release
/// ID.  The root handle is retained so a later path replacement cannot turn a
/// staged capability into an arbitrary directory.
/// The catalog owner is observed, not independently authorized by this API;
/// parent directories above the catalog are not retained. Activation needs a
/// separate trusted-owner and ancestor policy plus a protected byte handoff.
#[derive(Debug)]
pub struct ProtectedReleaseCatalog {
    root: HeldDirectory,
    protection: ReleaseProtection,
}

impl ProtectedReleaseCatalog {
    /// Open an existing protected release catalog without creating directories
    /// or selecting a release.
    ///
    /// # Errors
    /// Rejects relative/dot/traversal roots, links/reparse points, writable
    /// catalog roots, and platforms without a protected-handle implementation.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, String> {
        let root = normalized_absolute_directory(root.as_ref())?;
        crate::release::require_real_root(&root)?;
        let protection = platform_protection()?;
        let file = open_directory_path(&root)?;
        let identity = validate_directory_handle(&file, &root, None, "release catalog root")?;
        Ok(Self {
            root: HeldDirectory {
                path: root,
                file,
                identity,
            },
            protection,
        })
    }

    /// Return the trusted catalog root used for logical release selection.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root.path
    }

    /// Return the platform protection strategy and its explicit limitations.
    #[must_use]
    pub const fn protection(&self) -> ReleaseProtection {
        self.protection
    }

    /// Validate and stage one release selected by its logical ID.
    ///
    /// `approved` and `current_schemas` are independent owner inputs.  The
    /// supplied configuration is checked for an exact digest and every
    /// configured fixed-role component is bound to the selected path and
    /// digest; it is never rewritten.
    ///
    /// # Errors
    /// Rejects malformed IDs/manifests, ambiguous or indirect manifest paths,
    /// writable/replaced files or ancestors within the catalog, incomplete role sets, mixed
    /// compatibility identities, and component paths or hashes that do not
    /// equal the selected release bindings.
    pub fn stage(
        &self,
        release_id: &str,
        expected_manifest_sha256: &str,
        approved: &Compatibility,
        current_schemas: &[(&str, u32)],
        config: &WatchdogConfig,
    ) -> Result<ReleaseStagedCapability, String> {
        validate_release_id(release_id)?;
        validate_digest(expected_manifest_sha256, "approved manifest digest")?;
        config
            .validate()
            .map_err(|error| format!("deployment configuration is invalid: {error}"))?;

        let release_path = self.root.path.join(release_id);
        let release_file = open_directory_child(&self.root.file, &release_path, release_id)?;
        let release_identity = validate_directory_handle(
            &release_file,
            &release_path,
            Some(self.root.identity.owner),
            "selected release directory",
        )?;
        let release = HeldDirectory {
            path: release_path,
            file: release_file,
            identity: release_identity,
        };

        let (manifest_name, manifest_file) = open_manifest(&release)?;
        let manifest_path = release.path.join(manifest_name);
        let manifest_identity = validate_file_handle(
            &manifest_file,
            &manifest_path,
            None,
            None,
            Some(self.root.identity.owner),
            "release manifest",
        )?;
        let manifest_bytes = read_bounded(&manifest_file, MAX_MANIFEST_BYTES)?;
        let manifest_digest = digest_hex(&manifest_bytes);
        if manifest_digest != expected_manifest_sha256 {
            return Err(
                "release manifest bytes differ from the independently approved digest".to_owned(),
            );
        }
        let manifest = ReleaseManifest::read(Cursor::new(&manifest_bytes))?;
        if manifest.release_id != release_id {
            return Err("manifest release id differs from selected release id".to_owned());
        }
        manifest.check_deployment_compatibility(approved, current_schemas)?;
        let config_digest = config
            .digest()
            .map_err(|error| format!("deployment configuration digest failed: {error}"))?;
        if config_digest != manifest.compatibility.configuration_sha256 {
            return Err(
                "deployment configuration digest differs from the selected release".to_owned(),
            );
        }

        let mut artifacts = manifest.artifacts.clone();
        artifacts.sort_by_key(|artifact| artifact.role);
        let mut bindings = Vec::with_capacity(artifacts.len());
        let mut held_directories = Vec::new();
        let mut held_artifacts = Vec::with_capacity(artifacts.len());
        #[cfg(unix)]
        let mut artifact_identities = BTreeSet::new();
        for artifact in artifacts {
            let opened = open_relative_file(&release, &artifact.path)?;
            let absolute_path = release.path.join(&artifact.path);
            let identity = validate_file_handle(
                &opened.file,
                &absolute_path,
                Some(artifact.bytes),
                Some(&artifact.sha256),
                Some(self.root.identity.owner),
                "release artifact",
            )?;
            #[cfg(unix)]
            if !artifact_identities.insert((identity.device, identity.inode)) {
                return Err(
                    "selected release roles share one device/inode identity and cannot be staged"
                        .to_owned(),
                );
            }
            held_directories.extend(opened.ancestors);
            let binding = ReleaseRoleBinding {
                role: artifact.role,
                relative_path: artifact.path,
                absolute_path,
                sha256: artifact.sha256,
                bytes: artifact.bytes,
            };
            held_artifacts.push(HeldArtifact {
                binding: binding.clone(),
                file: opened.file,
                identity,
            });
            bindings.push(binding);
        }
        if bindings.len() != 6 {
            return Err("selected release did not produce exactly six role bindings".to_owned());
        }
        validate_config_bindings(config, &bindings)?;

        let capability = ReleaseStagedCapability {
            release_id: release_id.to_owned(),
            manifest_digest,
            manifest,
            release,
            manifest_path,
            manifest_file,
            manifest_identity,
            held_directories,
            held_artifacts,
            catalog_root: clone_directory(&self.root)?,
            protection: self.protection,
        };
        capability.verify_held()?;
        Ok(capability)
    }
}

/// Concrete verified bytes and retained handles for one complete release.
/// Dropping this value releases the handles; it never changes a selector or
/// process state.
#[derive(Debug)]
pub struct ReleaseStagedCapability {
    release_id: String,
    manifest_digest: String,
    manifest: ReleaseManifest,
    release: HeldDirectory,
    manifest_path: PathBuf,
    manifest_file: File,
    manifest_identity: FileIdentity,
    held_directories: Vec<HeldDirectory>,
    held_artifacts: Vec<HeldArtifact>,
    catalog_root: HeldDirectory,
    protection: ReleaseProtection,
}

impl ReleaseStagedCapability {
    /// Convenience constructor that opens a protected catalog and stages one
    /// logical release ID.  The catalog is retained by the returned handles.
    pub fn stage(
        root: impl AsRef<Path>,
        release_id: &str,
        expected_manifest_sha256: &str,
        approved: &Compatibility,
        current_schemas: &[(&str, u32)],
        config: &WatchdogConfig,
    ) -> Result<Self, String> {
        let catalog = ProtectedReleaseCatalog::new(root)?;
        catalog.stage(
            release_id,
            expected_manifest_sha256,
            approved,
            current_schemas,
            config,
        )
    }

    /// Exact logical release identity selected by the manifest and request.
    #[must_use]
    pub fn release_id(&self) -> &str {
        &self.release_id
    }

    /// SHA-256 of the original manifest bytes, including whitespace.
    #[must_use]
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    /// The parsed manifest whose bytes were retained and hashed.
    #[must_use]
    pub fn manifest(&self) -> &ReleaseManifest {
        &self.manifest
    }

    /// Absolute selected release directory.
    #[must_use]
    pub fn release_root(&self) -> &Path {
        &self.release.path
    }

    /// Absolute fixed manifest path selected below the release directory.
    #[must_use]
    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    /// Deterministic role bindings in `ArtifactRole` order.
    #[must_use]
    pub fn role_bindings(&self) -> Vec<ReleaseRoleBinding> {
        self.held_artifacts
            .iter()
            .map(|artifact| artifact.binding.clone())
            .collect()
    }

    /// Return one checked role binding without exposing arbitrary paths.
    #[must_use]
    pub fn role_binding(&self, role: ArtifactRole) -> Option<&ReleaseRoleBinding> {
        self.held_artifacts
            .iter()
            .find(|artifact| artifact.binding.role == role)
            .map(|artifact| &artifact.binding)
    }

    /// Return the retained read-only file handle for a fixed role after
    /// revalidating all held identities and protected paths.
    pub fn role_handle(&self, role: ArtifactRole) -> Result<File, String> {
        self.verify_held()?;
        let artifact = self
            .held_artifacts
            .iter()
            .find(|artifact| artifact.binding.role == role)
            .ok_or_else(|| "requested role is not present in the staged release".to_owned())?;
        artifact
            .file
            .try_clone()
            .map_err(|error| format!("release role handle clone failed: {error}"))
    }

    /// Return the proof class and its explicit platform limitations.
    #[must_use]
    pub const fn protection(&self) -> ReleaseProtection {
        self.protection
    }

    /// Recheck every retained directory, manifest handle, role handle, exact
    /// digest and path identity.  This is the handoff gate for a future
    /// selector/runtime adapter; this module itself performs no handoff.
    pub fn verify_held(&self) -> Result<(), String> {
        validate_directory_identity(&self.catalog_root, None, "release catalog root")?;
        validate_directory_identity(
            &self.release,
            Some(self.catalog_root.identity.owner),
            "selected release directory",
        )?;
        for directory in &self.held_directories {
            validate_directory_identity(
                directory,
                Some(self.catalog_root.identity.owner),
                "release artifact ancestor",
            )?;
        }
        let manifest_identity = validate_file_handle(
            &self.manifest_file,
            &self.manifest_path,
            None,
            None,
            Some(self.catalog_root.identity.owner),
            "release manifest",
        )?;
        if manifest_identity != self.manifest_identity {
            return Err("release manifest identity changed while staged".to_owned());
        }
        let manifest_bytes = read_bounded(&self.manifest_file, MAX_MANIFEST_BYTES)?;
        if digest_hex(&manifest_bytes) != self.manifest_digest {
            return Err("release manifest bytes changed while staged".to_owned());
        }
        for artifact in &self.held_artifacts {
            let identity = validate_file_handle(
                &artifact.file,
                &artifact.binding.absolute_path,
                Some(artifact.binding.bytes),
                Some(&artifact.binding.sha256),
                Some(self.catalog_root.identity.owner),
                "release artifact",
            )?;
            if identity != artifact.identity {
                return Err(format!(
                    "release role {:?} identity changed while staged",
                    artifact.binding.role
                ));
            }
        }
        Ok(())
    }
}

fn normalized_absolute_directory(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() || path.as_os_str().is_empty() {
        return Err("release catalog root must be an absolute path".to_owned());
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir | Component::ParentDir => {
                return Err("release catalog root contains dot or traversal components".to_owned());
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    if normalized != path || normalized.file_name().is_none() {
        return Err("release catalog root is not a normalized directory path".to_owned());
    }
    Ok(normalized)
}

fn validate_release_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_RELEASE_ID_BYTES
        || matches!(value, "." | "..")
        || value.ends_with('.')
        || value.contains(['/', '\\', '\0'])
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("release id is outside the bounded logical identity format".to_owned());
    }
    Ok(())
}

fn validate_relative_artifact(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() || !path.is_relative() {
        return Err("release artifact path must be relative".to_owned());
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err("release artifact path contains a non-normal component".to_owned());
        }
        if component
            .as_os_str()
            .to_string_lossy()
            .contains(['/', '\\', '\0'])
        {
            return Err("release artifact path contains a separator or NUL".to_owned());
        }
    }
    Ok(())
}

fn validate_config_bindings(
    config: &WatchdogConfig,
    bindings: &[ReleaseRoleBinding],
) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for component in &config.components {
        let role = component_role(&component.id).ok_or_else(|| {
            format!(
                "deployment component {} is not one of the fixed release roles",
                component.id
            )
        })?;
        if !seen.insert(role) {
            return Err(format!(
                "deployment role {role:?} is configured more than once"
            ));
        }
        let digest = component.executable_sha256.as_deref().ok_or_else(|| {
            format!(
                "deployment component {} has no immutable executable hash",
                component.id
            )
        })?;
        let binding = bindings
            .iter()
            .find(|binding| binding.role == role)
            .ok_or_else(|| format!("release role {role:?} is missing from the manifest"))?;
        let configured_path = normalized_absolute_path(&component.executable)?;
        if !same_path(&configured_path, &binding.absolute_path) {
            return Err(format!(
                "deployment component {} path differs from selected release role",
                component.id
            ));
        }
        if digest != binding.sha256 {
            return Err(format!(
                "deployment component {} hash differs from selected release role",
                component.id
            ));
        }
    }
    Ok(())
}

fn component_role(id: &str) -> Option<ArtifactRole> {
    match id {
        "watchdog" => Some(ArtifactRole::Watchdog),
        "gateway" => Some(ArtifactRole::Gateway),
        "harness" => Some(ArtifactRole::Harness),
        "mcp" | "mcp-server" | "sts2-mcp-server" => Some(ArtifactRole::Mcp),
        "mod" | "game-mod" | "sts2-game-mod" => Some(ArtifactRole::Mod),
        "host-broker" | "host_broker" | "hostbroker" => Some(ArtifactRole::HostBroker),
        _ => None,
    }
}

fn normalized_absolute_path(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() || path.as_os_str().is_empty() {
        return Err("component executable must be an absolute path".to_owned());
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                return Err("component executable contains traversal".to_owned());
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    Ok(normalized)
}

fn same_path(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}
