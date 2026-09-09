//! Bounded, offset-independent hashing for staged release handles.

use sha2::{Digest, Sha256};
use std::fs::File;

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

pub(super) const MAX_MANIFEST_BYTES: u64 = 65_536;

pub(super) fn digest_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
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

pub(super) fn validate_digest(value: &str, name: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} must be a lowercase SHA-256 digest"));
    }
    Ok(())
}

const READ_CHUNK_BYTES: usize = 16 * 1024;

/// Read at fixed offsets so concurrent verification cannot race on a shared
/// open-file cursor.  The one-byte bound probe is included in the same loop.
pub(super) fn read_bounded(file: &File, maximum: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let bound = maximum
        .checked_add(1)
        .ok_or_else(|| "release read bound overflows".to_owned())?;
    let mut offset = 0_u64;
    let mut buffer = [0_u8; READ_CHUNK_BYTES];
    while offset < bound {
        let count = usize::try_from((bound - offset).min(READ_CHUNK_BYTES as u64))
            .map_err(|_| "release read chunk size overflows".to_owned())?;
        let read = read_at(file, &mut buffer[..count], offset)
            .map_err(|error| format!("release handle positional read failed: {error}"))?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(|| "release read offset overflows".to_owned())?;
        if bytes.len() as u64 > maximum {
            return Err("release manifest exceeds its bounded byte limit".to_owned());
        }
    }
    Ok(bytes)
}

/// Hash at fixed offsets without materializing the file.  The one-byte bound
/// probe is included in the same loop so a file that grows after metadata
/// validation is rejected rather than partially hashed.
pub(super) fn digest_bounded(
    file: &File,
    maximum: u64,
    name: &str,
) -> Result<(String, u64), String> {
    let mut hasher = Sha256::new();
    let bound = maximum
        .checked_add(1)
        .ok_or_else(|| "release digest bound overflows".to_owned())?;
    let mut offset = 0_u64;
    let mut bytes_read = 0_u64;
    let mut buffer = [0_u8; READ_CHUNK_BYTES];
    while offset < bound {
        let count = usize::try_from((bound - offset).min(READ_CHUNK_BYTES as u64))
            .map_err(|_| "release digest chunk size overflows".to_owned())?;
        let read = read_at(file, &mut buffer[..count], offset)
            .map_err(|error| format!("{name} positional digest read failed: {error}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes_read = bytes_read
            .checked_add(read as u64)
            .ok_or_else(|| "release digest byte count overflows".to_owned())?;
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(|| "release digest offset overflows".to_owned())?;
        if bytes_read > maximum {
            return Err(format!("{name} exceeds its bounded byte limit"));
        }
    }
    let digest = hasher.finalize();
    Ok((hex_encode(&digest), bytes_read))
}

#[cfg(unix)]
fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    file.read_at(buffer, offset)
}

#[cfg(windows)]
fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    file.seek_read(buffer, offset)
}

#[cfg(not(any(unix, windows)))]
fn read_at(_file: &File, _buffer: &mut [u8], _offset: u64) -> std::io::Result<usize> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "positional release reads are unavailable on this platform",
    ))
}
