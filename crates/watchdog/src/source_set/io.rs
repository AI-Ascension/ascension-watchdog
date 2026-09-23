//! Bounded filesystem and Git process helpers shared by the verifier.

use super::validation::digest_hex;
use sha2::{Digest, Sha256};
use std::fs::{File, symlink_metadata};
use std::io::Read;
use std::path::Path;
use std::process::Command;

pub(super) fn git(path: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(arguments)
        .output()
        .map_err(|_| "Git is unavailable".to_owned())?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.trim();
        if detail.is_empty() {
            return Err(format!("git {} failed", arguments.join(" ")));
        }
        return Err(format!("git {} failed: {detail}", arguments.join(" ")));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub(super) fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let metadata = symlink_metadata(path).map_err(|_| "required file is unavailable".to_owned())?;
    if !metadata.file_type().is_file() {
        return Err("required path is not a regular file".to_owned());
    }
    let length = usize::try_from(metadata.len()).map_err(|_| "file length overflows".to_owned())?;
    if length > maximum {
        return Err("file exceeds the verifier byte bound".to_owned());
    }
    let mut file = File::open(path).map_err(|_| "required file cannot be opened".to_owned())?;
    let mut bytes = Vec::with_capacity(length);
    file.read_to_end(&mut bytes)
        .map_err(|_| "required file cannot be read".to_owned())?;
    Ok(bytes)
}

pub(super) fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|_| "file cannot be opened".to_owned())?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 65_536];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| "file cannot be read".to_owned())?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest_hex(&digest.finalize()))
}

pub(super) fn regular_file(path: &Path) -> bool {
    symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}
