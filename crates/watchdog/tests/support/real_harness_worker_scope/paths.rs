//! Canonical file identity and bounded content digests.

use super::MAX_IMAGE_BYTES;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub(crate) fn canonical_regular(
    path: &Path,
    label: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(io::Error::other(format!("{label} is not a regular non-symlink file")).into());
    }
    let canonical = fs::canonicalize(path)?;
    let canonical_metadata = fs::metadata(&canonical)?;
    if !canonical_metadata.file_type().is_file()
        || canonical_metadata.permissions().mode() & 0o111 == 0
    {
        return Err(io::Error::other(format!("{label} is not an executable regular file")).into());
    }
    Ok(canonical)
}

pub(crate) fn canonical_config(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(io::Error::other("watchdog config is not a regular non-symlink file").into());
    }
    Ok(fs::canonicalize(path)?)
}

pub(crate) fn sha256_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_IMAGE_BYTES {
        return Err(io::Error::other("daemon image exceeds bounded hash size").into());
    }
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read)?)
            .ok_or_else(|| io::Error::other("daemon image hash length overflow"))?;
        if total > MAX_IMAGE_BYTES {
            return Err(io::Error::other("daemon image grew beyond bounded hash size").into());
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        let _ = write!(&mut output, "{byte:02x}");
    }
    Ok(output)
}
