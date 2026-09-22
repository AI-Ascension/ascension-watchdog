//! Owner-local singleton controller lock and protected owner-path validation.
//!
//! Extracted verbatim from `storage.rs` (issue #95) without behavior change.
//! This module owns the exclusive mutating-controller lock, its same-process
//! registry, and the canonical owner-path/link/reparse/handle checks that
//! reject path substitution and mismatched owner locks before owner-local
//! storage is opened.  Callers keep the `crate::storage::SingletonLock` path
//! through the re-export in the storage facade.

use super::validate_local_storage_path;
use crate::error::{Result, WatchdogError};
use fs2::FileExt;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

/// Acquire the single mutating controller lock for one owner-local store.
/// The advisory lock is held by an open file descriptor and never relies on a
/// stale PID or executable name for ownership.
#[derive(Debug)]
pub struct SingletonLock {
    inner: Arc<LockInner>,
}

#[derive(Debug)]
struct LockInner {
    path: PathBuf,
    file: File,
    // On Windows this handle is opened with directory backup semantics and
    // without delete sharing.  Holding it keeps the owner directory from
    // being replaced while the lock file is authoritative.  The standard
    // library does not expose a stable Windows file-id accessor on the pinned
    // toolchain, so this protected-directory/handle boundary is the identity
    // check rather than an unstable MetadataExt method.
    #[cfg(windows)]
    #[allow(dead_code)]
    protected_parent: ascension_platform_windows::ProtectedDirectoryHandle,
}

impl Drop for LockInner {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl SingletonLock {
    /// Acquire `<database>.lock` without deleting another owner's lock file.
    #[allow(clippy::suspicious_open_options)]
    pub fn acquire(database: impl AsRef<Path>) -> Result<Self> {
        let database = canonical_owner_path(database.as_ref(), "database")?;
        let path = lock_path(&database);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        // Parent creation is itself a filesystem boundary.  Re-resolve the
        // path after it exists and reject any link/reparse substitution before
        // opening the lock file.  The owner directory must still be protected
        // from untrusted writers; path checks alone cannot close a TOCTOU race.
        let stable_database = canonical_owner_path(&database, "database")?;
        if stable_database != database {
            return Err(WatchdogError::Conflict(
                "database path changed while preparing owner lock".to_string(),
            ));
        }
        let stable_lock = canonical_owner_path(&path, "lock")?;
        if stable_lock != path {
            return Err(WatchdogError::Conflict(
                "lock path changed while preparing owner lock".to_string(),
            ));
        }
        #[cfg(windows)]
        let protected_parent = open_protected_owner_directory(database.parent())?;
        let file = open_lock_file(&path)?;
        validate_opened_lock_handle(&path, &file)?;
        file.try_lock_exclusive().map_err(|error| {
            if is_lock_contention(&error) {
                WatchdogError::Busy(path.clone())
            } else {
                WatchdogError::Io(error)
            }
        })?;
        let inner = Arc::new(LockInner {
            path: path.clone(),
            file,
            #[cfg(windows)]
            protected_parent,
        });
        if let Ok(mut registry) = lock_registry().lock() {
            registry.retain(|_, weak| weak.strong_count() > 0);
            registry.insert(path, Arc::downgrade(&inner));
        }
        Ok(Self { inner })
    }

    /// Path of the lock file for diagnostics.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// Write non-authoritative diagnostic metadata.  It is never used to
    /// decide whether a process may be terminated.
    pub fn write_owner_hint(&self, hint: &str) -> Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        if hint.len() > 512 || hint.as_bytes().contains(&0) {
            return Err(WatchdogError::InvalidInput(
                "owner hint is oversized".to_string(),
            ));
        }
        let mut file = &self.inner.file;
        file.seek(SeekFrom::Start(0))?;
        file.set_len(0)?;
        file.write_all(hint.as_bytes())?;
        file.sync_data()?;
        Ok(())
    }

    /// Reuse an already held same-process lock for a nested store bootstrap.
    /// This is private to the storage owner path; public `acquire` remains
    /// non-reentrant so a second controller still receives `Busy`.
    pub(super) fn current_for_path(database: &Path) -> Option<Self> {
        let database = canonical_owner_path(database, "database").ok()?;
        let path = lock_path(&database);
        let registry = lock_registry().lock().ok()?;
        let inner = registry.get(&path)?.upgrade()?;
        Some(Self { inner })
    }
}

fn lock_registry() -> &'static Mutex<HashMap<PathBuf, Weak<LockInner>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, Weak<LockInner>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn is_lock_contention(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::WouldBlock
        || (error.raw_os_error().is_some()
            && error.raw_os_error() == fs2::lock_contended_error().raw_os_error())
}

fn lock_path(database: &Path) -> PathBuf {
    let mut value = database.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

/// Open the lock file with no delete sharing on Windows.  This is the stable
/// standard-library equivalent of the native platform wrapper's protected
/// file boundary: another process may still open the file and receive normal
/// fs2 lock contention, but it cannot unlink, rename, or replace the file
/// underneath the authoritative handle.
#[allow(clippy::suspicious_open_options)]
fn open_lock_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    Ok(options.open(path)?)
}

#[cfg(windows)]
fn open_protected_owner_directory(
    path: Option<&Path>,
) -> Result<ascension_platform_windows::ProtectedDirectoryHandle> {
    let path = path.ok_or_else(|| {
        WatchdogError::InvalidInput("database path has no owner-local parent".to_string())
    })?;
    ascension_platform_windows::open_protected_directory(path)
        .map_err(|error| WatchdogError::Io(std::io::Error::other(error)))
}

pub(super) fn ensure_owner_lock(database: &Path, owner: &SingletonLock) -> Result<()> {
    let database = canonical_owner_path(database, "database")?;
    if owner.path() != lock_path(&database) {
        return Err(WatchdogError::Unauthorized(
            "singleton lock does not match the requested database".to_string(),
        ));
    }
    Ok(())
}

/// Resolve an owner-local database path without following a link/reparse
/// component.  The final database may be absent during initialization; all
/// existing ancestors and the existing leaf are still inspected.  A missing
/// suffix is joined to the canonical nearest existing parent so equivalent
/// relative/absolute spellings use one lock identity.
pub(super) fn canonical_owner_path(path: &Path, name: &str) -> Result<PathBuf> {
    validate_local_storage_path(path, name)?;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let Some(file_name) = absolute.file_name() else {
        return Err(WatchdogError::InvalidInput(format!(
            "{name} path must name a file"
        )));
    };
    reject_existing_link_components(&absolute, name)?;

    let parent = absolute.parent().ok_or_else(|| {
        WatchdogError::InvalidInput(format!("{name} path has no owner-local parent"))
    })?;
    let mut existing = parent.to_path_buf();
    let mut missing = Vec::new();
    while !existing.exists() {
        let Some(component) = existing.file_name() else {
            return Err(WatchdogError::InvalidInput(format!(
                "{name} path has no existing owner-local ancestor"
            )));
        };
        missing.push(component.to_os_string());
        if !existing.pop() {
            return Err(WatchdogError::InvalidInput(format!(
                "{name} path has no existing owner-local ancestor"
            )));
        }
    }
    let metadata = fs::symlink_metadata(&existing)?;
    reject_link_or_reparse(&metadata, name)?;
    if !metadata.is_dir() {
        return Err(WatchdogError::InvalidInput(format!(
            "{name} owner-local parent is not a directory"
        )));
    }
    let mut canonical = fs::canonicalize(&existing)?;
    for component in missing.iter().rev() {
        canonical.push(component);
    }
    canonical.push(file_name);
    // If the leaf appeared between the first inspection and canonical path
    // construction, inspect it too.  An absent leaf remains valid for init.
    if let Ok(metadata) = fs::symlink_metadata(&canonical) {
        reject_link_or_reparse(&metadata, name)?;
    }
    Ok(canonical)
}

fn reject_existing_link_components(path: &Path, name: &str) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        // A Windows verbatim path reports its prefix (`\\?\C:`) and root as
        // separate components.  Querying metadata for the prefix alone is an
        // invalid Win32 operation; defer the first filesystem check until a
        // complete root/normal path has been assembled.
        if matches!(
            component,
            std::path::Component::Prefix(_) | std::path::Component::RootDir
        ) {
            current.push(component.as_os_str());
            continue;
        }
        current.push(component.as_os_str());
        // A Windows drive/verbatim prefix alone is not a rooted directory.
        // Inspect it only after RootDir has completed the volume root.
        if matches!(component, std::path::Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => reject_link_or_reparse(&metadata, name)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(WatchdogError::Io(error)),
        }
    }
    Ok(())
}

pub(super) fn reject_link_or_reparse(metadata: &fs::Metadata, name: &str) -> Result<()> {
    if metadata.file_type().is_symlink() || is_reparse_point(metadata) {
        return Err(WatchdogError::InvalidInput(format!(
            "{name} path contains a symbolic link or reparse point"
        )));
    }
    Ok(())
}

/// Validate the path again after opening the lock and compare its stable file
/// identity with the opened handle where the platform exposes one.  This does
/// not replace protected owner-directory permissions, but it prevents a
/// path-swap from silently turning the descriptor into a different regular
/// file between validation and lock acquisition.
fn validate_opened_lock_handle(path: &Path, file: &File) -> Result<()> {
    let path_metadata = fs::symlink_metadata(path)?;
    reject_link_or_reparse(&path_metadata, "lock")?;
    if !path_metadata.is_file() {
        return Err(WatchdogError::InvalidInput(
            "lock path is not a regular file".to_string(),
        ));
    }
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        return Err(WatchdogError::Conflict(
            "opened lock handle is no longer a regular file".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != opened_metadata.dev()
            || path_metadata.ino() != opened_metadata.ino()
        {
            return Err(WatchdogError::Conflict(
                "lock path changed after its handle was opened".to_string(),
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // `file_index`/volume identity is still unstable in Rust 1.97.1.
        // Compare the stable metadata exposed by the pinned toolchain as a
        // post-open sanity check; the no-delete sharing on both the lock file
        // and its protected parent is the stronger anti-replacement guard.
        let path_fingerprint = (
            path_metadata.file_size(),
            path_metadata.creation_time(),
            path_metadata.last_write_time(),
            path_metadata.file_attributes(),
        );
        let opened_fingerprint = (
            opened_metadata.file_size(),
            opened_metadata.creation_time(),
            opened_metadata.last_write_time(),
            opened_metadata.file_attributes(),
        );
        if path_fingerprint != opened_fingerprint {
            return Err(WatchdogError::Conflict(
                "lock path changed after its handle was opened".to_string(),
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}
