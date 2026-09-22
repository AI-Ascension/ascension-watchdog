//! Worker credential loading and protection checks.
//!
//! This module validates the configured credential reference and opens the
//! exact owner-protected object before reading it.  No new API path exposes
//! credential bytes: the only accessor is [`ProtectedCredential::bytes`], and
//! the Linux path walks held, non-following directory descriptors so a replaced
//! path cannot re-point the read at another object.

use super::MAX_PATH_BYTES;
use super::ensure_deadline;
use crate::error::{Result, WatchdogError};
use std::fs;
#[cfg(not(windows))]
use std::fs::File;
#[cfg(not(windows))]
use std::io::{ErrorKind, Read};
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::path::Component;
use std::path::Path;
use std::time::Instant;
use zeroize::Zeroizing;

const MAX_CREDENTIAL_BYTES: usize = 4 * 1024;

pub(crate) fn validate_credential_reference(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || path.as_os_str().to_string_lossy().len() > MAX_PATH_BYTES
        || path.as_os_str().to_string_lossy().contains('\0')
    {
        return Err(WatchdogError::InvalidInput(
            "worker credential path must be an absolute bounded path".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| WatchdogError::Unauthorized("worker credential is unavailable".to_owned()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(WatchdogError::Unauthorized(
            "worker credential is not a protected regular file".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(WatchdogError::Unauthorized(
                "worker credential is not owner-only".to_owned(),
            ));
        }
    }
    #[cfg(windows)]
    ascension_platform_windows::validate_protected_credential_file(path).map_err(|_| {
        WatchdogError::Unauthorized("worker credential is not owner-protected".to_owned())
    })?;
    Ok(())
}

pub(crate) struct ProtectedCredential {
    #[cfg(target_os = "linux")]
    _ancestors: Vec<OwnedFd>,
    #[cfg(target_os = "linux")]
    _file: File,
    bytes: Zeroizing<Vec<u8>>,
}

impl ProtectedCredential {
    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

pub(crate) fn read_credential(path: &Path, deadline: Instant) -> Result<ProtectedCredential> {
    ensure_deadline(deadline, "worker credential read")?;
    // Open and validate the exact object before reading it.  The Unix Linux
    // path walks held, non-following directory descriptors and opens the final
    // descriptor with O_NONBLOCK before validating its type.  Windows uses the
    // platform's held-handle ancestor walk for the same reason.  This function
    // is called only after worker-peer authentication.
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let _ = (path, deadline);
        return Err(WatchdogError::Unsupported(
            "worker credential transport is unsupported on this platform".to_owned(),
        ));
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, deadline);
        return Err(WatchdogError::Unsupported(
            "worker credential transport is unsupported on this platform".to_owned(),
        ));
    }
    #[cfg(any(target_os = "linux", windows))]
    {
        #[cfg(target_os = "linux")]
        let mut file = open_linux_credential(path, deadline)?;
        #[cfg(windows)]
        let bytes = Zeroizing::new(
            ascension_platform_windows::read_protected_payload_file(path, MAX_CREDENTIAL_BYTES)
                .map_err(|_| {
                    WatchdogError::Unauthorized("worker credential is unavailable".to_owned())
                })?,
        );
        #[cfg(target_os = "linux")]
        let bytes = read_bounded_credential(&mut file.file, deadline)?;
        ensure_deadline(deadline, "worker credential read")?;
        if bytes.is_empty()
            || bytes.len() > MAX_CREDENTIAL_BYTES
            || bytes.contains(&0)
            || !bytes.is_ascii()
            || bytes.iter().any(u8::is_ascii_whitespace)
        {
            return Err(WatchdogError::Unauthorized(
                "worker credential is empty, oversized, or malformed".to_owned(),
            ));
        }
        #[cfg(target_os = "linux")]
        {
            Ok(ProtectedCredential {
                _ancestors: file.ancestors,
                _file: file.file,
                bytes,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(ProtectedCredential { bytes })
        }
    }
}

#[cfg(target_os = "linux")]
struct OpenCredential {
    ancestors: Vec<OwnedFd>,
    file: File,
}

#[cfg(target_os = "linux")]
fn open_linux_credential(path: &Path, deadline: Instant) -> Result<OpenCredential> {
    use rustix::fs::{Mode, OFlags, fstatfs, open, openat};

    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(value) => components.push(value),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(WatchdogError::InvalidInput(
                    "worker credential path contains traversal".to_owned(),
                ));
            }
        }
    }
    if !path.is_absolute() || components.is_empty() {
        return Err(WatchdogError::InvalidInput(
            "worker credential path must be an absolute local file".to_owned(),
        ));
    }
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let root = open("/", flags | OFlags::DIRECTORY, Mode::empty())
        .map_err(|_| WatchdogError::Unauthorized("worker credential is unavailable".to_owned()))?;
    validate_linux_credential_directory(&root)?;
    ensure_local_protected_filesystem(
        fstatfs(&root)
            .map_err(|_| {
                WatchdogError::Unauthorized(
                    "worker credential filesystem is unavailable".to_owned(),
                )
            })?
            .f_type
            .cast_unsigned(),
    )?;
    let mut ancestors = vec![root];
    for (index, name) in components.iter().enumerate() {
        ensure_deadline(deadline, "worker credential open")?;
        let final_component = index + 1 == components.len();
        let directory = ancestors.last().ok_or_else(|| {
            WatchdogError::Unauthorized("worker credential path is unavailable".to_owned())
        })?;
        let descriptor = openat(
            directory,
            *name,
            if final_component {
                flags
            } else {
                flags | OFlags::DIRECTORY
            },
            Mode::empty(),
        )
        .map_err(|_| WatchdogError::Unauthorized("worker credential is unavailable".to_owned()))?;
        if final_component {
            let file: File = descriptor.into();
            return Ok(OpenCredential {
                ancestors,
                file: validate_linux_credential_file(file, deadline)?,
            });
        }
        validate_linux_credential_directory(&descriptor)?;
        ensure_local_protected_filesystem(
            fstatfs(&descriptor)
                .map_err(|_| {
                    WatchdogError::Unauthorized(
                        "worker credential filesystem is unavailable".to_owned(),
                    )
                })?
                .f_type
                .cast_unsigned(),
        )?;
        ancestors.push(descriptor);
    }
    Err(WatchdogError::Unauthorized(
        "worker credential is unavailable".to_owned(),
    ))
}

#[cfg(target_os = "linux")]
fn validate_linux_credential_directory(directory: &OwnedFd) -> Result<()> {
    use rustix::fs::fstat;

    let metadata = fstat(directory).map_err(|_| {
        WatchdogError::Unauthorized("worker credential directory is unavailable".to_owned())
    })?;
    let mode = metadata.st_mode;
    let directory_type = (mode & 0o170_000) == 0o040_000;
    // A sticky, root-owned system temporary directory is safe as an outer
    // ancestor: unprivileged users cannot rename another user's directory.
    // Every non-sticky ancestor must be free of group/world write access.
    let sticky_root = metadata.st_uid == 0 && mode & 0o1000 != 0;
    if !directory_type || (mode & 0o022 != 0 && !sticky_root) {
        return Err(WatchdogError::Unauthorized(
            "worker credential ancestor is not protected".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_linux_credential_file(file: File, deadline: Instant) -> Result<File> {
    use rustix::fs::{fstat, fstatfs};

    ensure_deadline(deadline, "worker credential validation")?;
    // fstat is intentionally performed on the held descriptor rather than on
    // the requested path.  `File::metadata` is equivalent but fstat makes the
    // descriptor authority explicit in this security-sensitive path.
    let metadata = fstat(&file)
        .map_err(|_| WatchdogError::Unauthorized("worker credential is unavailable".to_owned()))?;
    let mode = metadata.st_mode;
    let regular = (mode & 0o170_000) == 0o100_000;
    if !regular || metadata.st_uid != rustix::process::geteuid().as_raw() || mode & 0o077 != 0 {
        return Err(WatchdogError::Unauthorized(
            "worker credential is not an owner-only regular file".to_owned(),
        ));
    }
    // A synchronous read cannot be cancelled portably once a regular-file
    // filesystem blocks in the kernel.  Fail closed for filesystems outside
    // the explicitly supported local set instead of claiming the transport
    // deadline covers an unbounded remote/pseudo filesystem read.
    let filesystem = fstatfs(&file).map_err(|_| {
        WatchdogError::Unauthorized("worker credential filesystem is unavailable".to_owned())
    })?;
    ensure_local_protected_filesystem(filesystem.f_type.cast_unsigned())?;
    ensure_deadline(deadline, "worker credential validation")?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn ensure_local_protected_filesystem(filesystem_type: u64) -> Result<()> {
    if !matches!(
        filesystem_type,
        0x0000_ef53 // ext2/ext3/ext4
            | 0x0102_1994 // tmpfs
            | 0x794c_7630 // overlayfs
            | 0x5846_5342 // xfs
            | 0x9123_683e // btrfs
            | 0xf2f5_2010 // f2fs
    ) {
        return Err(WatchdogError::Unauthorized(
            "worker credential filesystem is not an approved local protected filesystem".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_bounded_credential(file: &mut File, deadline: Instant) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_CREDENTIAL_BYTES + 1));
    let mut buffer = Zeroizing::new([0_u8; 256]);
    loop {
        ensure_deadline(deadline, "worker credential read")?;
        let count = file.read(&mut buffer[..]).map_err(|error| {
            if error.kind() == ErrorKind::WouldBlock {
                WatchdogError::Timeout("worker credential read timed out".to_owned())
            } else {
                WatchdogError::Unauthorized("worker credential is unavailable".to_owned())
            }
        })?;
        if count == 0 {
            break;
        }
        if bytes.len().saturating_add(count) > MAX_CREDENTIAL_BYTES {
            return Err(WatchdogError::Unauthorized(
                "worker credential is empty, oversized, or malformed".to_owned(),
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}
