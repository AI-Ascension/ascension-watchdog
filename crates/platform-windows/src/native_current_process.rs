//! Current-controller identity capture for the Windows worker bootstrap.
//!
//! This module is a child of the reviewed native boundary so it can retain the
//! same immutable executable guard and use the existing process/SID helpers.
//! It deliberately accepts no PID or path from a caller: the identity is read
//! only from this process' pseudo handle and `std::process::id()`.

use super::{
    IntegrityGuards, PlatformError, check_image_deadline, normalize_path, process_creation_time,
    process_session, query_image_path,
};
use crate::admin_pipe::process_user_sid;
use std::fmt;
use std::path::PathBuf;
use std::time::Instant;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessId};

/// The current watchdog/controller process identity captured from Windows.
///
/// The private integrity guard keeps the executable handle, release-directory
/// handle, digest, and kernel file identity alive for as long as this value is
/// retained.  Callers may copy the public fields into a bootstrap frame, then
/// drop this value once that frame has been durably prepared.
pub struct CurrentControllerIdentity {
    /// PID observed from the current process pseudo handle.
    pub pid: u32,
    /// Windows process creation timestamp in 100-nanosecond units.
    pub creation_time_100ns: u64,
    /// Image path returned by `QueryFullProcessImageNameW`.
    pub executable: PathBuf,
    /// Lowercase SHA-256 digest of the held executable image.
    pub sha256: String,
    /// Canonical numeric SID of the current process token's user.
    pub user_sid: String,
    /// Windows session containing the current process.
    pub session_id: u32,
    #[allow(dead_code)]
    integrity: IntegrityGuards,
}

impl fmt::Debug for CurrentControllerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrentControllerIdentity")
            .field("pid", &self.pid)
            .field("creation_time_100ns", &self.creation_time_100ns)
            .field("executable", &"<protected-reference>")
            .field("sha256", &self.sha256)
            .field("user_sid", &"<protected-policy>")
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessSnapshot {
    pid: u32,
    creation_time_100ns: u64,
    executable: PathBuf,
    user_sid: String,
    session_id: u32,
}

/// Capture the exact current controller identity before a worker bootstrap is
/// encoded. The hash loop and admission checks use the supplied deadline;
/// native queries are checked before and after, not kernel-preempted. An
/// already-expired deadline rejects before obtaining any process data.
pub fn capture_current_controller(
    deadline: Instant,
) -> Result<CurrentControllerIdentity, PlatformError> {
    check_image_deadline(Some(deadline))?;
    let process = unsafe { GetCurrentProcess() };
    let initial = snapshot(process, deadline)?;

    // The first guard hashes and retains the image object selected by the
    // current process.  A second guard below repeats the path/file identity
    // check after the process metadata has been read.
    let integrity = IntegrityGuards::open_until(&initial.executable, Some(deadline))?;
    check_image_deadline(Some(deadline))?;
    let protected = snapshot(process, deadline)?;
    ensure_same_identity(&initial, &protected)?;

    let barrier = IntegrityGuards::open_until(&protected.executable, Some(deadline))?;
    if barrier.file_identity != integrity.file_identity
        || barrier.digest() != integrity.digest()
        || normalize_path(barrier.path()) != normalize_path(integrity.path())
    {
        return Err(PlatformError::IdentityMismatch(
            "current controller executable changed during bootstrap capture".to_owned(),
        ));
    }
    check_image_deadline(Some(deadline))?;
    let final_snapshot = snapshot(process, deadline)?;
    ensure_same_identity(&protected, &final_snapshot)?;
    check_image_deadline(Some(deadline))?;

    Ok(CurrentControllerIdentity {
        pid: final_snapshot.pid,
        creation_time_100ns: final_snapshot.creation_time_100ns,
        executable: final_snapshot.executable,
        sha256: integrity.digest().to_owned(),
        user_sid: final_snapshot.user_sid,
        session_id: final_snapshot.session_id,
        integrity,
    })
}

fn snapshot(process: HANDLE, deadline: Instant) -> Result<ProcessSnapshot, PlatformError> {
    check_image_deadline(Some(deadline))?;
    let pid = current_pid(process)?;
    check_image_deadline(Some(deadline))?;
    let executable = query_image_path(process)?;
    if !executable.is_absolute() || executable.as_os_str().is_empty() {
        return Err(PlatformError::IdentityMismatch(
            "current controller image path is not absolute".to_owned(),
        ));
    }
    check_image_deadline(Some(deadline))?;
    let creation_time_100ns = process_creation_time(process)?;
    if creation_time_100ns == 0 {
        return Err(PlatformError::IdentityMismatch(
            "current controller creation token is zero".to_owned(),
        ));
    }
    check_image_deadline(Some(deadline))?;
    let user_sid = process_user_sid(process)?;
    check_image_deadline(Some(deadline))?;
    let session_id = process_session(pid)?;
    if session_id == u32::MAX {
        return Err(PlatformError::IdentityMismatch(
            "current controller session token is invalid".to_owned(),
        ));
    }
    check_image_deadline(Some(deadline))?;
    Ok(ProcessSnapshot {
        pid,
        creation_time_100ns,
        executable,
        user_sid,
        session_id,
    })
}

fn current_pid(process: HANDLE) -> Result<u32, PlatformError> {
    let native_pid = unsafe { GetProcessId(process) };
    if native_pid == 0 {
        return Err(PlatformError::Win32 {
            operation: "GetProcessId(current controller)".to_owned(),
            code: unsafe { GetLastError() },
        });
    }
    let std_pid = std::process::id();
    if native_pid != std_pid {
        return Err(PlatformError::IdentityMismatch(
            "current controller PID differs between native and Rust observations".to_owned(),
        ));
    }
    Ok(native_pid)
}

fn ensure_same_identity(
    expected: &ProcessSnapshot,
    observed: &ProcessSnapshot,
) -> Result<(), PlatformError> {
    if expected.pid != observed.pid
        || expected.creation_time_100ns != observed.creation_time_100ns
        || expected.session_id != observed.session_id
        || expected.user_sid != observed.user_sid
        || normalize_path(&expected.executable) != normalize_path(&observed.executable)
    {
        return Err(PlatformError::IdentityMismatch(
            "current controller identity changed during bootstrap capture".to_owned(),
        ));
    }
    Ok(())
}
