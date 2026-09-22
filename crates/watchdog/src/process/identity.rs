//! Launch identity, observation-free identity validation and executable
//! digests for the restricted process adapter.
//!
//! Identity is deliberately richer than a PID: a launch nonce, the canonical
//! executable path, the approved digest and a creation fingerprint must all
//! agree before a process is observed or terminated.

use crate::error::{Result, WatchdogError};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::Child;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

use super::observation::observe_child_exit;

#[cfg(target_os = "linux")]
const PROCESS_IDENTITY_SETTLE_TIMEOUT: Duration = Duration::from_secs(1);

/// Immutable launch identity.  It is persisted alongside the component state
/// and is intentionally richer than a PID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub launch_nonce: String,
    pub executable: PathBuf,
    pub executable_digest: String,
    pub started_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_fingerprint: Option<String>,
}

/// The direct child handle is authoritative, but Linux briefly exposes the
/// pre-exec image through `/proc/<pid>/exe` while the forked child is entering
/// the approved executable. Wait for that kernel-visible image to settle, or
/// observe the exact child exit, before treating a path mismatch as identity
/// substitution.
pub(super) fn ensure_spawn_identity(child: &mut Child, identity: &ProcessIdentity) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let deadline = Instant::now() + PROCESS_IDENTITY_SETTLE_TIMEOUT;
        loop {
            if observe_child_exit(child)?.is_some() {
                return Ok(());
            }
            match std::fs::canonicalize(format!("/proc/{}/exe", identity.pid)) {
                Ok(actual) if actual == identity.executable => {
                    return ensure_identity(identity);
                }
                Ok(_) | Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Ok(_) | Err(_) => return ensure_identity(identity),
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = child;
        ensure_identity(identity)
    }
}

#[cfg(target_os = "linux")]
pub(super) fn parse_proc_stat_identity(stat: &str) -> Option<(u32, i32)> {
    let closing_paren = stat.rfind(')')?;
    let mut fields = stat.get(closing_paren + 1..)?.split_whitespace();
    let _state = fields.next()?;
    let _parent = fields.next()?;
    let process_group = fields.next()?.parse::<i32>().ok()?;
    let pid = stat
        .split_once(' ')
        .and_then(|(pid, _)| pid.parse::<u32>().ok())?;
    Some((pid, process_group))
}

/// Verify an exact process identity before observation or termination.
pub fn ensure_identity(identity: &ProcessIdentity) -> Result<()> {
    if identity.pid == 0 || identity.launch_nonce.is_empty() {
        return Err(WatchdogError::IdentityMismatch(
            "identity is incomplete".to_string(),
        ));
    }
    if !identity.executable.is_absolute() || identity.executable.as_os_str().is_empty() {
        return Err(WatchdogError::IdentityMismatch(
            "identity executable path is incomplete".to_string(),
        ));
    }
    if crate::config::validate_digest(&identity.executable_digest).is_err() {
        return Err(WatchdogError::IdentityMismatch(
            "identity executable digest is invalid".to_string(),
        ));
    }
    if let Some(expected) = &identity.creation_fingerprint {
        let Some(actual) = process_creation_fingerprint(identity.pid) else {
            return Err(WatchdogError::IdentityMismatch(format!(
                "pid {} is no longer present",
                identity.pid
            )));
        };
        if &actual != expected {
            return Err(WatchdogError::IdentityMismatch(format!(
                "pid {} creation fingerprint changed",
                identity.pid
            )));
        }
    }
    if let Ok(actual) = std::fs::canonicalize(format!("/proc/{}/exe", identity.pid)) {
        if actual != identity.executable {
            return Err(WatchdogError::IdentityMismatch(format!(
                "pid {} executable changed from {} to {}",
                identity.pid,
                identity.executable.display(),
                actual.display()
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn process_creation_fingerprint(pid: u32) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = text.rfind(')')?;
    let fields = text
        .get(close + 2..)?
        .split_whitespace()
        .collect::<Vec<_>>();
    // Fields after the command name start at field 3; starttime is field 22,
    // hence index 19 in this suffix.
    fields.get(19).map(|value| (*value).to_string())
}

#[cfg(not(target_os = "linux"))]
pub(super) fn process_creation_fingerprint(_pid: u32) -> Option<String> {
    // The native Windows adapter will replace this hook with a process
    // creation-time query.  The Child handle remains the cleanup authority in
    // this portable slice.
    None
}

pub(super) fn hash_file(path: &Path) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
