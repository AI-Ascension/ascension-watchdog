//! Worker bootstrap image capture.
//!
//! Captures this controller's own held image identity (never a configured or
//! request-supplied PID) so a supervised worker can be bound to the exact
//! controller process that launched it.  No credential bytes pass through here.

use super::ensure_deadline;
use super::peer::{hash_file_until, process_start_token};
use crate::error::{Result, WatchdogError};
use std::fs;
use std::fs::File;
use std::path::Path;
use std::time::Instant;

/// Capture this controller's held image, not a configured or request-supplied PID.
#[allow(dead_code)]
pub(crate) fn capture_linux_controller(
    deadline: Instant,
) -> Result<crate::worker_bootstrap::LinuxPeer> {
    use std::os::unix::fs::MetadataExt;
    let pid = std::process::id();
    let creation_token = process_start_token(pid, deadline)?;
    let image_path = Path::new("/proc/self/exe");
    let executable = fs::read_link(image_path)?;
    let mut image = File::open(image_path)?;
    let before = image.metadata()?;
    if !before.is_file() || before.mode() & 0o222 != 0 {
        return Err(WatchdogError::Unauthorized(
            "worker controller image must be immutable".to_owned(),
        ));
    }
    let executable_sha256 = hash_file_until(&mut image, Some(deadline))?;
    let after = image.metadata()?;
    let named = fs::metadata(&executable)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.dev() != named.dev()
        || before.ino() != named.ino()
        || fs::read_link(image_path)? != executable
    {
        return Err(WatchdogError::IdentityMismatch(
            "worker controller image changed during bootstrap capture".to_owned(),
        ));
    }
    ensure_deadline(deadline, "worker controller bootstrap capture")?;
    Ok(crate::worker_bootstrap::LinuxPeer {
        pid,
        creation_token,
        executable: executable
            .to_str()
            .ok_or_else(|| {
                WatchdogError::InvalidInput("worker controller image must be Unicode".to_owned())
            })?
            .to_owned(),
        executable_sha256,
        uid: rustix::process::geteuid().as_raw(),
        gid: rustix::process::getegid().as_raw(),
    })
}
