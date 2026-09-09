//! State-level descriptor-store evidence, not a per-notification receipt.
//!
//! The caller must authenticate PID 1 and keep the source directory open from
//! submission through verification. This prevents inode reuse from satisfying
//! the match. A previous copy of the same object is an idempotent success.

use super::super::{BrokerError, BrokerResult, MAX_RECEIPTS};
use super::DescriptorName;
use rustix::fs::{OFlags, fcntl_getfl, major, minor};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::File;
use std::os::unix::fs::MetadataExt;

pub(crate) const MAX_SNAPSHOT_BYTES: usize = MAX_RECEIPTS * 8192;

/// systemd >=254 `a(suuutuusu)`, in documented wire order. The path is only
/// diagnostic; it is never opened or treated as authority.
#[derive(Clone, Debug, Deserialize, Serialize, zbus::zvariant::Type)]
pub(crate) struct StoreEntry {
    name: String,
    mode: u32,
    device_major: u32,
    device_minor: u32,
    inode: u64,
    rdevice_major: u32,
    rdevice_minor: u32,
    path: String,
    flags: u32,
}

pub(crate) fn decode(message: &zbus::Message) -> BrokerResult<Vec<StoreEntry>> {
    let body = message.body();
    if body.len() > MAX_SNAPSHOT_BYTES {
        return Err(BrokerError::Conflict(
            "manager descriptor snapshot exceeds byte bound".to_owned(),
        ));
    }
    let entries: Vec<StoreEntry> = body.deserialize().map_err(|error| {
        BrokerError::Unavailable(format!("manager descriptor snapshot type failed: {error}"))
    })?;
    validate_entries(&entries)?;
    Ok(entries)
}

fn validate_entries(entries: &[StoreEntry]) -> BrokerResult<()> {
    if entries.len() > MAX_RECEIPTS {
        return Err(BrokerError::Conflict(
            "manager descriptor snapshot exceeds entry bound".to_owned(),
        ));
    }
    let mut names = BTreeSet::new();
    for entry in entries {
        let name = DescriptorName::parse(&entry.name)?;
        if !names.insert(name) || entry.path.len() > 4096 || entry.path.contains('\0') {
            return Err(BrokerError::Conflict(
                "manager descriptor snapshot is ambiguous or oversized".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn verify_directory(
    entries: &[StoreEntry],
    name: &DescriptorName,
    directory: &File,
) -> BrokerResult<()> {
    validate_entries(entries)?;
    let metadata = directory.metadata().map_err(super::super::io_error)?;
    if !metadata.is_dir() {
        return Err(BrokerError::Conflict(
            "descriptor-store source is not a held directory".to_owned(),
        ));
    }
    // systemd deliberately masks the architecture's raw O_LARGEFILE bit from
    // F_GETFL in this method. CLOEXEC is an fd flag, not a status flag.
    let flags = (fcntl_getfl(directory).map_err(|error| super::super::io_error(error.into()))?
        & !OFlags::LARGEFILE)
        .bits();
    let entry = entries.iter().find(|entry| entry.name == name.as_str());
    if !entry.is_some_and(|entry| {
        entry.mode == metadata.mode()
            && entry.device_major == major(metadata.dev())
            && entry.device_minor == minor(metadata.dev())
            && entry.inode == metadata.ino()
            && entry.rdevice_major == major(metadata.rdev())
            && entry.rdevice_minor == minor(metadata.rdev())
            && entry.flags == flags
    }) {
        return Err(BrokerError::Conflict(
            "manager does not retain the exact named directory object".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn verify_absent(entries: &[StoreEntry], name: &DescriptorName) -> BrokerResult<()> {
    validate_entries(entries)?;
    if entries.iter().any(|entry| entry.name == name.as_str()) {
        return Err(BrokerError::Conflict(
            "retired descriptor remains in the manager store".to_owned(),
        ));
    }
    Ok(())
}

/// Removal is idempotent when absent. A present same-name entry must match the
/// original held object before any removal notification may be emitted.
pub(crate) fn require_removal_binding(
    entries: &[StoreEntry],
    name: &DescriptorName,
    directory: Option<&File>,
) -> BrokerResult<bool> {
    validate_entries(entries)?;
    if !entries.iter().any(|entry| entry.name == name.as_str()) {
        return Ok(false);
    }
    let directory = directory.ok_or_else(|| {
        BrokerError::Conflict(
            "stored descriptor cannot be removed without original-object proof".to_owned(),
        )
    })?;
    verify_directory(entries, name, directory)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(file: &File) -> Result<StoreEntry, Box<dyn std::error::Error>> {
        let metadata = file.metadata()?;
        Ok(StoreEntry {
            name: format!("cg-{}", "a".repeat(64)),
            mode: metadata.mode(),
            device_major: major(metadata.dev()),
            device_minor: minor(metadata.dev()),
            inode: metadata.ino(),
            rdevice_major: major(metadata.rdev()),
            rdevice_minor: minor(metadata.rdev()),
            path: "/diagnostic-only".to_owned(),
            flags: (fcntl_getfl(file)? & !OFlags::LARGEFILE).bits(),
        })
    }

    #[test]
    fn snapshot_matches_original_object_not_submission_or_path()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let directory = File::open(root.path())?;
        let entry = fixture(&directory)?;
        let name = DescriptorName::parse(&entry.name)?;
        let another_open_of_same_object = File::open(root.path())?;
        verify_directory(
            std::slice::from_ref(&entry),
            &name,
            &another_open_of_same_object,
        )?;
        let moved = root.path().join("moved");
        std::fs::create_dir(&moved)?;
        let replacement = File::open(&moved)?;
        assert!(verify_directory(&[entry], &name, &replacement).is_err());
        Ok(())
    }

    #[test]
    fn absent_duplicate_or_any_changed_identity_field_rejects()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let directory = File::open(root.path())?;
        let entry = fixture(&directory)?;
        let name = DescriptorName::parse(&entry.name)?;
        assert!(verify_directory(&[], &name, &directory).is_err());
        assert!(verify_directory(&[entry.clone(), entry.clone()], &name, &directory).is_err());
        for field in 0..8 {
            let mut changed = entry.clone();
            match field {
                0 => changed.name = format!("cg-{}", "b".repeat(64)),
                1 => changed.mode ^= 0o020,
                2 => changed.device_major ^= 1,
                3 => changed.device_minor ^= 1,
                4 => changed.inode ^= 1,
                5 => changed.rdevice_major ^= 1,
                6 => changed.rdevice_minor ^= 1,
                _ => changed.flags ^= OFlags::NONBLOCK.bits(),
            }
            assert!(verify_directory(&[changed], &name, &directory).is_err());
        }
        let regular = tempfile::tempfile()?;
        assert!(verify_directory(&[entry], &name, &regular).is_err());
        Ok(())
    }

    #[test]
    fn descriptor_removal_requires_exact_absence_and_rejects_ambiguous_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let directory = File::open(root.path())?;
        let entry = fixture(&directory)?;
        let name = DescriptorName::parse(&entry.name)?;
        assert!(!require_removal_binding(&[], &name, None)?);
        assert!(require_removal_binding(
            std::slice::from_ref(&entry),
            &name,
            Some(&directory)
        )?);
        assert!(require_removal_binding(std::slice::from_ref(&entry), &name, None).is_err());
        let foreign_root = tempfile::tempdir()?;
        let foreign = File::open(foreign_root.path())?;
        assert!(
            require_removal_binding(std::slice::from_ref(&entry), &name, Some(&foreign)).is_err()
        );
        assert!(verify_absent(std::slice::from_ref(&entry), &name).is_err());
        verify_absent(&[], &name)?;
        let other = DescriptorName::parse(&format!("cg-{}", "b".repeat(64)))?;
        verify_absent(std::slice::from_ref(&entry), &other)?;
        assert!(verify_absent(&[entry.clone(), entry], &other).is_err());
        Ok(())
    }

    #[test]
    fn wire_signature_and_snapshot_limits_are_checked() -> Result<(), Box<dyn std::error::Error>> {
        use zbus::zvariant::Type;
        assert_eq!(StoreEntry::SIGNATURE.to_string(), "(suuutuusu)");
        let root = tempfile::tempdir()?;
        let directory = File::open(root.path())?;
        let entry = fixture(&directory)?;
        let message =
            zbus::Message::method_call("/fixture", "Snapshot")?.build(&vec![entry.clone()])?;
        let decoded = decode(&message)?;
        verify_directory(&decoded, &DescriptorName::parse(&entry.name)?, &directory)?;
        let oversized =
            zbus::Message::method_call("/fixture", "Snapshot")?
                .build(&vec![entry.clone(); MAX_RECEIPTS + 1])?;
        assert!(decode(&oversized).is_err());
        let mut long_path = entry;
        long_path.path = "x".repeat(MAX_SNAPSHOT_BYTES + 1);
        let oversized =
            zbus::Message::method_call("/fixture", "Snapshot")?.build(&vec![long_path])?;
        assert!(decode(&oversized).is_err());
        Ok(())
    }
}
