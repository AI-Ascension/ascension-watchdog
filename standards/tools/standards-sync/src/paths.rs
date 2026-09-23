//! Safe filesystem helpers for managed bundle destinations.

use crate::Result;
use crate::identifiers::valid_relative_path;
use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};

pub(crate) fn prepare_managed_path(root: &Path, relative: &str) -> Result<PathBuf> {
    if !valid_relative_path(relative) {
        return Err(format!("unsafe managed path '{relative}'"));
    }
    let components = relative.split('/').collect::<Vec<_>>();
    let mut current = root.to_path_buf();
    for component in &components[..components.len() - 1] {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "managed path traverses symlink {}",
                    current.display()
                ));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(format!(
                    "managed path component is not a directory {}",
                    current.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(&current)
                .map_err(|create_error| {
                    format!(
                        "cannot create managed directory {}: {create_error}",
                        current.display()
                    )
                })?,
            Err(error) => {
                return Err(format!(
                    "cannot inspect managed path {}: {error}",
                    current.display()
                ));
            }
        }
    }
    let path = root.join(relative);
    if let Ok(metadata) = fs::symlink_metadata(&path)
        && metadata.file_type().is_symlink()
    {
        return Err(format!("managed path is a symlink {}", path.display()));
    }
    Ok(path)
}

pub(crate) fn copy_if_absent_or_equal(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        require_regular_file(path)?;
        let existing =
            fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if existing != bytes {
            return Err(format!(
                "refusing to overwrite differing managed file {}",
                path.display()
            ));
        }
        return Ok(());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))
}

pub(crate) fn inspect_managed_destination(root: &Path, relative: &str, bytes: &[u8]) -> Result<()> {
    if !valid_relative_path(relative) {
        return Err(format!("unsafe managed path '{relative}'"));
    }
    let mut path = root.to_path_buf();
    let components: Vec<_> = relative.split('/').collect();
    for (index, component) in components.iter().enumerate() {
        path.push(component);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(format!("cannot inspect {}: {error}", path.display())),
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("managed path traverses symlink {}", path.display()));
            }
            Ok(metadata) if index + 1 == components.len() => {
                if !metadata.is_file()
                    || fs::read(&path).map_err(|error| error.to_string())? != bytes
                {
                    return Err(format!(
                        "refusing to overwrite differing managed file {}",
                        path.display()
                    ));
                }
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(format!(
                    "managed path component is not a directory {}",
                    path.display()
                ));
            }
            Ok(_) => {}
        }
    }
    Ok(())
}

pub(crate) fn collect_files(root: &Path, directory: &Path, output: &mut Vec<String>) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot list {}: {error}", directory.display()))?
        .collect::<io::Result<Vec<_>>>()
        .map_err(|error| format!("cannot read directory {}: {error}", directory.display()))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "symlink is not allowed in standards bundle: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            if path.strip_prefix(root).ok() == Some(Path::new("tools/standards-sync/target")) {
                continue;
            }
            collect_files(root, &path, output)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|error| format!("cannot relativize {}: {error}", path.display()))?;
            output.push(format!(
                "standards/{}",
                relative.to_string_lossy().replace('\\', "/")
            ));
        } else {
            return Err(format!("unsupported standards entry {}", path.display()));
        }
    }
    Ok(())
}

pub(crate) fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    if !valid_relative_path(relative) {
        return Err(format!("unsafe path '{relative}'"));
    }
    let path = root.join(relative);
    let parent = path
        .parent()
        .ok_or_else(|| format!("path has no parent: {relative}"))?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|error| format!("cannot resolve {}: {error}", parent.display()))?;
    let canonical_root = root
        .canonicalize()
        .map_err(|error| format!("cannot resolve {}: {error}", root.display()))?;
    if !canonical_parent.starts_with(&canonical_root) {
        return Err(format!("path escapes root: {relative}"));
    }
    Ok(path)
}

pub(crate) fn require_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("missing directory {}: {error}", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("{} is not a real directory", path.display()));
    }
    Ok(())
}

pub(crate) fn require_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("missing file {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    Ok(())
}
