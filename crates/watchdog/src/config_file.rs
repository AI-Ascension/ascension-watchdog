// SPDX-License-Identifier: MIT

//! Bounded configuration reads through non-link file handles. The returned
//! path is a normalized bootstrap reference, not authority to execute a file.
//! Platform launch admission still revalidates its protected configuration.

use crate::error::{Result, WatchdogError};
use std::path::{Component, Path, PathBuf};

const MAX_CONFIG_BYTES: usize = 65_536;

pub(super) fn read(path: &Path) -> Result<(Vec<u8>, PathBuf)> {
    let path = normalized_path(path)?;
    Ok((read_bytes(&path)?, path))
}

fn normalized_path(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(WatchdogError::InvalidInput(
            "configuration path is empty".to_owned(),
        ));
    }
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                return Err(WatchdogError::InvalidInput(
                    "configuration path must not contain parent traversal".to_owned(),
                ));
            }
            Component::CurDir => {}
            _ => normalized.push(component.as_os_str()),
        }
    }
    if !normalized.is_absolute()
        || normalized.file_name().is_none()
        || normalized.as_os_str().to_string_lossy().len() > 4096
    {
        return Err(WatchdogError::InvalidInput(
            "configuration path must name a bounded local file".to_owned(),
        ));
    }
    Ok(normalized)
}

#[cfg(unix)]
fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags, open, openat};
    use std::fs::File;
    use std::io::{Error, Read};

    if ["/proc", "/sys", "/dev"]
        .iter()
        .any(|root| path.starts_with(root))
    {
        return Err(WatchdogError::InvalidInput(
            "configuration must not use an operating-system pseudo-file".to_owned(),
        ));
    }
    let components = path
        .components()
        .filter_map(|part| match part {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect::<Vec<_>>();
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let mut directory = open("/", flags | OFlags::DIRECTORY, Mode::empty()).map_err(Error::from)?;
    for (index, name) in components.iter().enumerate() {
        let final_component = index + 1 == components.len();
        let descriptor = openat(
            &directory,
            *name,
            if final_component {
                flags
            } else {
                flags | OFlags::DIRECTORY
            },
            Mode::empty(),
        )
        .map_err(Error::from)?;
        if !final_component {
            directory = descriptor;
            continue;
        }
        let file = File::from(descriptor);
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(WatchdogError::InvalidInput(
                "configuration must be a regular file".to_owned(),
            ));
        }
        if metadata.len() > MAX_CONFIG_BYTES as u64 {
            return Err(WatchdogError::InvalidInput(
                "configuration exceeds 65536-byte limit".to_owned(),
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_CONFIG_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(WatchdogError::InvalidInput(
                "configuration exceeds 65536-byte limit".to_owned(),
            ));
        }
        return Ok(bytes);
    }
    Err(WatchdogError::InvalidInput(
        "configuration must name a file".to_owned(),
    ))
}

#[cfg(windows)]
fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    // Do not use a path metadata size shortcut here. The native reader opens
    // and retains every ancestor and the exact file handle, validates either
    // the owner-only development ACL or the SYSTEM/Administrators/virtual-
    // service packaged ACL, and enforces the byte bound while reading.
    ascension_platform_windows::read_protected_service_config_file(path, MAX_CONFIG_BYTES).map_err(
        |error| {
            WatchdogError::InvalidInput(format!("protected configuration read failed: {error}"))
        },
    )
}

#[cfg(not(any(unix, windows)))]
fn read_bytes(_path: &Path) -> Result<Vec<u8>> {
    Err(WatchdogError::Unsupported(
        "protected configuration reading is unavailable on this platform".to_owned(),
    ))
}
