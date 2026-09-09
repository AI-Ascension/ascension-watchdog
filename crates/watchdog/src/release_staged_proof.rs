//! Protected-handle and filesystem identity proof for staged releases.

use super::release_staged_hash::digest_bounded;
use super::{ReleaseProtection, ReleaseRoleBinding, validate_relative_artifact};
#[cfg(test)]
use std::cell::RefCell;
use std::fs::{self, File, Metadata};
#[cfg(target_os = "linux")]
use std::path::Component;
use std::path::{Path, PathBuf};

#[cfg(test)]
thread_local! {
    static AFTER_HASH_HOOK: RefCell<Option<fn(&Path) -> Result<(), String>>> =
        const { RefCell::new(None) };
}

#[cfg(test)]
fn run_after_hash_hook(path: &Path) -> Result<(), String> {
    AFTER_HASH_HOOK.with(|hook| {
        hook.borrow()
            .as_ref()
            .map_or(Ok(()), |callback| callback(path))
    })
}

#[derive(Debug)]
pub(super) struct HeldDirectory {
    pub(super) path: PathBuf,
    pub(super) file: File,
    pub(super) identity: FileIdentity,
}

#[derive(Debug)]
pub(super) struct HeldArtifact {
    pub(super) binding: ReleaseRoleBinding,
    pub(super) file: File,
    pub(super) identity: FileIdentity,
}

#[derive(Debug)]
pub(super) struct OpenedFile {
    pub(super) file: File,
    pub(super) ancestors: Vec<HeldDirectory>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FileIdentity {
    pub(super) owner: u64,
    #[cfg(unix)]
    pub(super) device: u64,
    #[cfg(unix)]
    pub(super) inode: u64,
}

pub(super) fn platform_protection() -> Result<ReleaseProtection, String> {
    if cfg!(target_os = "linux") {
        Ok(ReleaseProtection::LinuxSecureDescriptors)
    } else {
        Err(
            "protected release handles require the Linux descriptor proof; this platform is fail-closed"
                .to_owned(),
        )
    }
}

pub(super) fn clone_directory(directory: &HeldDirectory) -> Result<HeldDirectory, String> {
    Ok(HeldDirectory {
        path: directory.path.clone(),
        file: directory
            .file
            .try_clone()
            .map_err(|error| format!("release directory handle clone failed: {error}"))?,
        identity: directory.identity,
    })
}

pub(super) fn validate_directory_identity(
    directory: &HeldDirectory,
    owner: Option<u64>,
    name: &str,
) -> Result<(), String> {
    let identity = validate_directory_handle(&directory.file, &directory.path, owner, name)?;
    if identity != directory.identity {
        return Err(format!("{name} identity changed while staged"));
    }
    Ok(())
}

pub(super) fn validate_directory_handle(
    file: &File,
    path: &Path,
    owner: Option<u64>,
    name: &str,
) -> Result<FileIdentity, String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("{name} handle metadata unavailable: {error}"))?;
    if !metadata.is_dir() || indirect(&metadata) {
        return Err(format!("{name} must be a real directory"));
    }
    validate_protection(&metadata, owner, false, name)?;
    let path_metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{name} path unavailable: {error}"))?;
    if !path_metadata.is_dir() || indirect(&path_metadata) {
        return Err(format!("{name} path is not a real directory"));
    }
    if file_identity(&path_metadata) != file_identity(&metadata) {
        return Err(format!("{name} path changed while opening"));
    }
    Ok(file_identity(&metadata))
}

pub(super) fn validate_file_handle(
    file: &File,
    path: &Path,
    expected_bytes: Option<u64>,
    expected_digest: Option<&str>,
    owner: Option<u64>,
    name: &str,
) -> Result<FileIdentity, String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("{name} handle metadata unavailable: {error}"))?;
    if !metadata.is_file() || indirect(&metadata) {
        return Err(format!("{name} must be a real regular file"));
    }
    validate_protection(&metadata, owner, true, name)?;
    if let Some(expected_bytes) = expected_bytes
        && metadata.len() != expected_bytes
    {
        return Err(format!("{name} byte length differs from its manifest"));
    }
    let identity = file_identity(&metadata);
    let path_metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{name} path unavailable: {error}"))?;
    if !path_metadata.is_file() || indirect(&path_metadata) {
        return Err(format!("{name} path is not a real regular file"));
    }
    if file_identity(&path_metadata) != identity {
        return Err(format!("{name} path changed while opening"));
    }
    let digest = if let Some(expected_digest) = expected_digest {
        let expected_bytes = expected_bytes
            .ok_or_else(|| format!("{name} digest validation requires an expected byte length"))?;
        let digest = digest_bounded(file, expected_bytes, name)?;
        #[cfg(test)]
        run_after_hash_hook(path)?;
        Some((expected_digest, expected_bytes, digest))
    } else {
        None
    };
    let after = file
        .metadata()
        .map_err(|error| format!("{name} handle metadata changed: {error}"))?;
    if file_identity(&after) != identity || after.len() != metadata.len() {
        return Err(format!("{name} changed while hashing"));
    }
    validate_protection(&after, owner, true, name)?;
    let after_path_metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{name} path unavailable: {error}"))?;
    if !after_path_metadata.is_file() || indirect(&after_path_metadata) {
        return Err(format!("{name} path is not a real regular file"));
    }
    if file_identity(&after_path_metadata) != file_identity(&after) {
        return Err(format!("{name} path changed while hashing"));
    }
    if let Some((expected_digest, expected_bytes, (digest, bytes_read))) = digest {
        if bytes_read != expected_bytes {
            return Err(format!("{name} was truncated while hashing"));
        }
        if expected_digest != digest {
            return Err(format!("{name} digest differs from its manifest"));
        }
    }
    Ok(identity)
}

fn validate_protection(
    metadata: &Metadata,
    owner: Option<u64>,
    regular_file: bool,
    name: &str,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o222 != 0 {
            return Err(format!("{name} is writable and cannot be staged"));
        }
        if regular_file && metadata.nlink() != 1 {
            return Err(format!("{name} has hard links and cannot be staged"));
        }
        if let Some(expected_owner) = owner
            && u64::from(metadata.uid()) != expected_owner
        {
            return Err(format!("{name} owner differs from the protected catalog"));
        }
        let _ = regular_file;
    }
    #[cfg(not(unix))]
    {
        let _ = (metadata, owner, regular_file);
        Err(format!("{name} protected filesystem proof is unavailable"))
    }
    #[cfg(unix)]
    Ok(())
}

fn file_identity(metadata: &Metadata) -> FileIdentity {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        FileIdentity {
            owner: u64::from(metadata.uid()),
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        FileIdentity { owner: 0 }
    }
}

fn indirect(metadata: &Metadata) -> bool {
    #[cfg(unix)]
    {
        metadata.file_type().is_symlink()
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

#[cfg(target_os = "linux")]
pub(super) fn open_directory_path(path: &Path) -> Result<File, String> {
    use rustix::fs::{Mode, OFlags, open, openat};
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY;
    let mut directory = File::from(
        open("/", flags, Mode::empty())
            .map_err(|error| format!("release root open failed: {error}"))?,
    );
    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let descriptor = openat(&directory, name, flags, Mode::empty())
            .map_err(|error| format!("release root component open failed: {error}"))?;
        directory = File::from(descriptor);
    }
    Ok(directory)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn open_directory_path(_path: &Path) -> Result<File, String> {
    Err("protected release directory handles are unavailable on this platform".to_owned())
}

#[cfg(target_os = "linux")]
pub(super) fn open_directory_child(parent: &File, path: &Path, name: &str) -> Result<File, String> {
    use rustix::fs::{Mode, OFlags, openat};
    let descriptor = openat(
        parent,
        std::ffi::OsStr::new(name),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|error| format!("release {name} directory open failed: {error}"))?;
    let file = File::from(descriptor);
    let _ = path;
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn open_directory_child(
    _parent: &File,
    _path: &Path,
    _name: &str,
) -> Result<File, String> {
    Err("protected release directory handles are unavailable on this platform".to_owned())
}

pub(super) fn open_manifest(release: &HeldDirectory) -> Result<(&'static str, File), String> {
    let mut found: Option<(&'static str, File)> = None;
    for name in super::MANIFEST_NAMES {
        match open_named_file(&release.file, &release.path.join(name), name) {
            Ok(file) => {
                if found.is_some() {
                    return Err(
                        "selected release contains more than one fixed manifest name".to_owned(),
                    );
                }
                found = Some((name, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!("release manifest open failed: {error}"));
            }
        }
    }
    found.ok_or_else(|| "selected release has no fixed manifest".to_owned())
}

pub(super) fn open_relative_file(
    release: &HeldDirectory,
    path: &Path,
) -> Result<OpenedFile, String> {
    validate_relative_artifact(path)?;
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{Mode, OFlags, openat};
        let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY;
        let mut directory = release
            .file
            .try_clone()
            .map_err(|error| format!("release directory handle clone failed: {error}"))?;
        let mut current_path = release.path.clone();
        let mut ancestors = Vec::new();
        let components = path.components().collect::<Vec<_>>();
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(name) = component else {
                return Err("release artifact path contains an invalid component".to_owned());
            };
            let final_component = index + 1 == components.len();
            current_path.push(name);
            if final_component {
                let descriptor = openat(
                    &directory,
                    *name,
                    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                    Mode::empty(),
                )
                .map_err(|error| format!("release artifact open failed: {error}"))?;
                return Ok(OpenedFile {
                    file: File::from(descriptor),
                    ancestors,
                });
            }
            let descriptor = openat(&directory, *name, flags, Mode::empty())
                .map_err(|error| format!("release artifact ancestor open failed: {error}"))?;
            let file = File::from(descriptor);
            let identity = validate_directory_handle(
                &file,
                &current_path,
                Some(release.identity.owner),
                "release artifact ancestor",
            )?;
            ancestors.push(HeldDirectory {
                path: current_path.clone(),
                file: file.try_clone().map_err(|error| {
                    format!("release artifact ancestor handle clone failed: {error}")
                })?,
                identity,
            });
            directory = file;
        }
        Err("release artifact path must name a file".to_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = release;
        Err("protected release file handles are unavailable on this platform".to_owned())
    }
}

fn open_named_file(parent: &File, path: &Path, name: &str) -> std::io::Result<File> {
    #[cfg(target_os = "linux")]
    let _ = path;
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{Mode, OFlags, openat};
        let descriptor = openat(
            parent,
            std::ffi::OsStr::new(name),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        Ok(File::from(descriptor))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (parent, path, name);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "protected release file handles are unavailable on this platform",
        ))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::super::release_staged_hash::digest_hex;
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn make_writable(path: &Path) -> Result<(), String> {
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))
            .map_err(|error| format!("test writable-mode change failed: {error}"))
    }

    #[test]
    fn protection_change_after_hash_is_rejected() {
        let directory = tempfile::tempdir().expect("test directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private test directory");
        let path = directory.path().join("role");
        let bytes = b"private role fixture";
        fs::write(&path, bytes).expect("test role");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).expect("private test role");
        let file = File::open(&path).expect("open test role");
        let owner = file.metadata().expect("test role metadata").uid();
        let digest = digest_hex(bytes);

        AFTER_HASH_HOOK.with(|hook| *hook.borrow_mut() = Some(make_writable));
        let result = validate_file_handle(
            &file,
            &path,
            Some(bytes.len() as u64),
            Some(&digest),
            Some(u64::from(owner)),
            "test role",
        );
        AFTER_HASH_HOOK.with(|hook| *hook.borrow_mut() = None);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444))
            .expect("restore private test role");

        assert!(
            result
                .as_ref()
                .is_err_and(|error| error.contains("writable")),
            "post-hash protection change was accepted: {result:?}"
        );
    }
}
