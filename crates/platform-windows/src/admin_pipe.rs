//! Bounded Windows named-pipe transport for watchdog administration.
//!
//! This module is separate from the lifecycle pipe in native.rs.  The
//! lifecycle channel has a different protocol and is deliberately not reused
//! for JSON admin requests.  The wrappers below keep all Win32 calls and
//! unsafe code in the platform boundary; the portable watchdog only sees
//! bounded byte frames and authenticated connection results.
//!
//! The transport is split into cohesive child modules: `win32` holds the
//! shared Win32 transport primitives (the unique-ownership handle and
//! security-descriptor wrappers, frame, timeout and endpoint-name validation,
//! the polling read/write helpers with their pending-I/O classification, the
//! pipe-local-information query and the SID, token, process-image and
//! creation-time identity queries); `server` holds the fixed admin pipe
//! server; `client` holds the admin and worker pipe clients; and `protected`
//! holds the protected credential, payload and service-config readers with
//! their local-path traversal and `ProtectedFileAcl` policy.  This file keeps
//! the child module declarations and the re-exports so every existing import
//! path keeps working.

#![cfg(windows)]

mod client;
mod protected;
mod server;
mod win32;

pub use client::AdminPipeClient;
pub use protected::{
    read_protected_payload_file, read_protected_service_config_file,
    validate_protected_credential_file,
};
pub use server::{AdminPipePeer, AdminPipeServer};
pub use win32::MAX_ADMIN_PIPE_FRAME;
pub(crate) use win32::process_user_sid;

#[cfg(test)]
mod ancestor_lock_tests {
    use super::protected::open_protected_ancestors;
    use super::win32::{OwnedHandle, wide_path};
    use crate::PlatformError;
    use std::path::{Path, PathBuf};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::GENERIC_WRITE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    struct TestDirectory(PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    fn open_writer(path: &Path) -> Result<OwnedHandle, PlatformError> {
        let path = wide_path(path)?;
        let raw = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                null_mut(),
            )
        };
        OwnedHandle::new(raw, "open test ancestor writer")
    }

    #[test]
    fn retained_ancestor_prevents_write_open_until_release()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("watchdog-ancestor-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&path)?;
        let directory = TestDirectory(path);
        drop(open_writer(&directory.0)?);
        let guards = open_protected_ancestors(&directory.0.join("payload.json"))?;
        assert!(
            open_writer(&directory.0).is_err(),
            "validated ancestor remained writable"
        );
        drop(guards);
        drop(open_writer(&directory.0)?);
        Ok(())
    }
}
