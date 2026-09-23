//! Executable snapshot creation and integrity hashing.

use super::MAX_HASH_BYTES;
use crate::platform::contract::AdapterError;
use rustix::fs::MemfdFlags;
use rustix::fs::SealFlags;
use rustix::fs::fcntl_add_seals;
use rustix::fs::memfd_create;
use sha2::Digest;
use sha2::Sha256;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;

/// Open an approved executable once, copy the verified bytes into a sealed
/// executable memfd, and return its `/proc/self/fd` path.  The source handle
/// is opened nonblocking and all metadata checks are made on that handle, so
/// a FIFO or device cannot make verification hang.  The sealed snapshot makes
/// an in-place source mutation after verification irrelevant to the exec.
pub(super) fn open_verified_executable(
    path: &Path,
    expected_digest: &str,
) -> Result<(File, PathBuf), AdapterError> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        AdapterError::Invalid(format!("Linux executable cannot be resolved: {error}"))
    })?;
    let mut source = open_nonblocking_read(&canonical)?;
    let metadata = source.metadata().map_err(|error| {
        AdapterError::Unavailable(format!("Linux executable metadata failed: {error}"))
    })?;
    if !metadata.is_file() {
        return Err(AdapterError::Invalid(
            "Linux executable is not a regular file".to_owned(),
        ));
    }
    if metadata.len() > MAX_HASH_BYTES {
        return Err(AdapterError::Invalid(
            "Linux executable exceeds the hash size bound".to_owned(),
        ));
    }
    let snapshot_fd = create_executable_snapshot()?;
    let mut snapshot = File::from(snapshot_fd);
    let digest = hash_and_copy(&mut source, &mut snapshot)?;
    if digest != expected_digest {
        return Err(AdapterError::IdentityMismatch(
            "Linux executable bytes changed before descriptor-bound exec".to_owned(),
        ));
    }
    fcntl_add_seals(
        &snapshot,
        SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL,
    )
    .map_err(|error| {
        AdapterError::Unavailable(format!(
            "Linux executable snapshot cannot be sealed: {error}"
        ))
    })?;
    let fd = snapshot.as_raw_fd();
    if fd < 0 {
        return Err(AdapterError::Io(
            "Linux executable descriptor has an invalid number".to_owned(),
        ));
    }
    let fd_path = PathBuf::from(format!("/proc/self/fd/{fd}"));
    Ok((snapshot, fd_path))
}

pub(super) fn create_executable_snapshot() -> Result<rustix::fd::OwnedFd, AdapterError> {
    let base_flags = MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING;
    match memfd_create(
        "ascension-verified-executable",
        base_flags | MemfdFlags::EXEC,
    ) {
        Ok(fd) => Ok(fd),
        Err(error) if error == rustix::io::Errno::INVAL => {
            // MFD_EXEC was added in Linux 6.3.  Older kernels either permit
            // executable memfds by default or reject them through a host
            // memfd_noexec policy; retain the latter error below.
            memfd_create("ascension-verified-executable", base_flags).map_err(|fallback| {
                AdapterError::Unavailable(format!(
                    "Linux executable snapshot cannot be created: {fallback}"
                ))
            })
        }
        Err(error) => Err(AdapterError::Unavailable(format!(
            "Linux executable snapshot cannot be created: {error}"
        ))),
    }
}

pub(super) fn hash_file(path: &Path) -> Result<String, AdapterError> {
    let file = open_nonblocking_read(path)?;
    let metadata = file.metadata().map_err(|error| {
        AdapterError::Unavailable(format!("cannot inspect Linux executable bytes: {error}"))
    })?;
    if !metadata.is_file() {
        return Err(AdapterError::Invalid(
            "Linux executable is not a regular file".to_owned(),
        ));
    }
    if metadata.len() > MAX_HASH_BYTES {
        return Err(AdapterError::Invalid(
            "Linux executable exceeds the hash size bound".to_owned(),
        ));
    }
    hash_reader(file)
}

pub(super) fn open_nonblocking_read(path: &Path) -> Result<File, AdapterError> {
    let flags = rustix::fs::OFlags::NONBLOCK
        .bits()
        .try_into()
        .map_err(|_| AdapterError::Invalid("Linux nonblocking flag is out of range".to_owned()))?;
    OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|error| {
            AdapterError::Unavailable(format!("cannot open Linux executable bytes: {error}"))
        })
}

pub(super) fn hash_reader(reader: impl Read) -> Result<String, AdapterError> {
    hash_stream(reader, None)
}

pub(super) fn hash_and_copy(
    reader: impl Read,
    writer: &mut impl Write,
) -> Result<String, AdapterError> {
    hash_stream(reader, Some(writer))
}

pub(super) fn hash_stream(
    mut reader: impl Read,
    mut writer: Option<&mut dyn Write>,
) -> Result<String, AdapterError> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total_read = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| AdapterError::Io(format!("cannot hash Linux executable: {error}")))?;
        if read == 0 {
            break;
        }
        total_read = total_read
            .checked_add(u64::try_from(read).map_err(|_| {
                AdapterError::Invalid("Linux executable read size exceeds bounds".to_owned())
            })?)
            .ok_or_else(|| {
                AdapterError::Invalid("Linux executable exceeds the hash size bound".to_owned())
            })?;
        if total_read > MAX_HASH_BYTES {
            return Err(AdapterError::Invalid(
                "Linux executable exceeds the hash size bound".to_owned(),
            ));
        }
        if let Some(writer) = writer.as_deref_mut() {
            writer.write_all(&buffer[..read]).map_err(|error| {
                AdapterError::Io(format!("cannot create Linux executable snapshot: {error}"))
            })?;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
