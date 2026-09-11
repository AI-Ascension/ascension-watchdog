//! A narrow Linux FFI boundary for inherited descriptor intake.
//!
//! No inherited descriptor is converted to a Rust borrow or owner. `fcntl`
//! receives only an integer and may reject invalid descriptors with EBADF.
//! Only its newly allocated duplicate becomes an `OwnedFd`. The originals
//! remain open, marked CLOEXEC, until process exit; their protocol-level count
//! is bounded by the broker to 128. Intake must precede threads and other file
//! opens so descriptor-number reuse cannot change the activation mapping.
//!
//! This module grants no process or cgroup authority. The broker separately
//! authenticates the service manager and matches every duplicated directory to
//! its exact stored descriptor and durable launch receipt.

#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

pub const FIRST_ACTIVATION_FD: i32 = 3;
pub const MAX_ACTIVATION_FDS: i32 = 128;
#[cfg(target_os = "linux")]
const DUPLICATE_FLOOR: i32 = FIRST_ACTIVATION_FD + MAX_ACTIVATION_FDS;

/// Duplicate an activation descriptor without taking ownership of the original.
/// Both original and copy are close-on-exec on success. The new descriptor is
/// above the entire activation range, so intake cannot fill a missing slot and
/// accidentally make a later invalid activation descriptor look valid.
///
/// This is memory-safe even for an invalid raw number: no borrowed Rust fd is
/// manufactured from it. Protocol correctness requires early, single-threaded
/// intake with independently validated activation metadata.
///
/// # Errors
/// Returns an error for a descriptor outside the bounded activation range, a
/// closed source, descriptor exhaustion, or a native fcntl failure. On failure,
/// any successfully allocated copy is dropped; the original is never closed.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn duplicate_activation_descriptor(source: RawFd) -> io::Result<OwnedFd> {
    if !(FIRST_ACTIVATION_FD..DUPLICATE_FLOOR).contains(&source) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "descriptor is outside the bounded activation range",
        ));
    }
    // SAFETY: fcntl's F_DUPFD_CLOEXEC ABI consumes two integer arguments and
    // dereferences no user pointer. An invalid source is a kernel error. On
    // success it allocates a distinct open descriptor owned only by this call.
    let duplicate = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, DUPLICATE_FLOOR) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful duplication above is open and uniquely owned;
    // it has not been exposed elsewhere and is never converted a second time.
    let owned = unsafe { OwnedFd::from_raw_fd(duplicate) };
    // SAFETY: F_GETFD and F_SETFD operate on integer descriptors/flags only.
    // No Rust ownership is created for the source, and it is never closed here.
    let flags = unsafe { libc::fcntl(source, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the third variadic argument has the native integer flag type.
    let result = unsafe { libc::fcntl(source, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Seek, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn duplication_preserves_exact_deleted_directory_and_never_owns_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("original");
        std::fs::create_dir(&path)?;
        let original = File::open(&path)?;
        let metadata = original.metadata()?;
        let duplicate = File::from(duplicate_activation_descriptor(original.as_raw_fd())?);
        assert!(duplicate.as_raw_fd() >= DUPLICATE_FLOOR);
        std::fs::remove_dir(&path)?;
        std::fs::create_dir(&path)?;
        let replacement = File::open(&path)?;
        assert_ne!(replacement.metadata()?.ino(), metadata.ino());
        assert_eq!(duplicate.metadata()?.ino(), metadata.ino());
        drop(duplicate);
        assert_eq!(original.metadata()?.ino(), metadata.ino());
        Ok(())
    }

    #[test]
    fn owned_copy_shares_open_description_and_survives_source_drop()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut original = tempfile::tempfile()?;
        original.write_all(b"abc")?;
        original.rewind()?;
        let mut duplicate = File::from(duplicate_activation_descriptor(original.as_raw_fd())?);
        let mut byte = [0_u8; 1];
        duplicate.read_exact(&mut byte)?;
        assert_eq!(byte, *b"a");
        original.read_exact(&mut byte)?;
        assert_eq!(byte, *b"b");
        drop(original);
        duplicate.read_exact(&mut byte)?;
        assert_eq!(byte, *b"c");
        Ok(())
    }

    #[test]
    fn both_original_and_copy_are_close_on_exec() -> io::Result<()> {
        use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
        let original = tempfile::tempfile()?;
        fcntl_setfd(&original, FdFlags::empty())?;
        let duplicate = duplicate_activation_descriptor(original.as_raw_fd())?;
        assert!(fcntl_getfd(&original)?.contains(FdFlags::CLOEXEC));
        assert!(fcntl_getfd(&duplicate)?.contains(FdFlags::CLOEXEC));
        Ok(())
    }

    #[test]
    fn invalid_range_cannot_duplicate_stdio_or_fill_activation_slots() {
        for descriptor in [-1, 0, 1, 2, DUPLICATE_FLOOR, i32::MAX] {
            assert!(duplicate_activation_descriptor(descriptor).is_err());
        }
    }
}
