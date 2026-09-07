//! Restricted direct process adapter.
//!
//! Only an exact, preconfigured executable is launched.  Cleanup uses the
//! owned `Child` handle plus a creation fingerprint and canonical executable
//! path; a PID or executable name by itself is never sufficient.

use crate::config::ComponentConfig;
use crate::error::{Result, WatchdogError};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use uuid::Uuid;

const MAX_OUTPUT_BYTES: usize = 64 * 1024;

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

/// Bounded captured child output.  Output is diagnostic only and never used as
/// a health or settlement witness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OutputSnapshot {
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Clone, Debug, Default)]
struct BoundedOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

/// Owned process and its exact identity.
pub struct OwnedChild {
    child: Child,
    identity: ProcessIdentity,
    output: Arc<Mutex<BoundedOutput>>,
    readers: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for OwnedChild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedChild")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl OwnedChild {
    /// Spawn one approved component directly (without a shell or proxy).
    pub fn spawn(spec: &ComponentConfig, now_ms: u64) -> Result<Self> {
        validate_component(spec)?;
        let executable = std::fs::canonicalize(&spec.executable).map_err(|error| {
            WatchdogError::InvalidInput(format!(
                "component {} executable cannot be resolved: {error}",
                spec.id
            ))
        })?;
        let metadata = std::fs::metadata(&executable)?;
        if !metadata.is_file() {
            return Err(WatchdogError::InvalidInput(format!(
                "component {} executable is not a regular file",
                spec.id
            )));
        }
        let executable_digest = hash_file(&executable)?;
        if let Some(expected) = &spec.executable_sha256 {
            if expected != &executable_digest {
                return Err(WatchdogError::Conflict(format!(
                    "component {} executable digest does not match approved bytes",
                    spec.id
                )));
            }
        }
        let cwd = match &spec.cwd {
            Some(path) => {
                let canonical = std::fs::canonicalize(path)?;
                if !canonical.is_dir() {
                    return Err(WatchdogError::InvalidInput(format!(
                        "component {} cwd is not a directory",
                        spec.id
                    )));
                }
                Some(canonical)
            }
            None => None,
        };
        let mut command = Command::new(&executable);
        command
            .args(&spec.args)
            .env_clear()
            .envs(spec.environment.iter())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }
        let mut child = command.spawn().map_err(|error| {
            WatchdogError::Io(std::io::Error::new(
                error.kind(),
                format!("spawn component {}: {error}", spec.id),
            ))
        })?;
        let pid = child.id();
        let identity = ProcessIdentity {
            pid,
            launch_nonce: Uuid::new_v4().to_string(),
            executable,
            executable_digest,
            started_at_ms: now_ms,
            creation_fingerprint: process_creation_fingerprint(pid),
        };
        // The direct Child handle is authoritative, but checking a still-live
        // process immediately catches a surprising platform adapter result
        // early. A very short-lived child may already have exited; that is a
        // normal observation for the reconciler, not an identity mismatch.
        let still_running = match child.try_wait() {
            Ok(status) => status.is_none(),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(WatchdogError::Io(error));
            }
        };
        if still_running && let Err(error) = ensure_identity(&identity) {
            // The direct Child handle is still the exact object returned by
            // spawn, so cleanup does not fall back to a PID/name lookup.
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        let output = Arc::new(Mutex::new(BoundedOutput::default()));
        let mut readers = Vec::new();
        if let Some(stdout) = child.stdout.take() {
            readers.push(spawn_reader(stdout, Arc::clone(&output), true));
        }
        if let Some(stderr) = child.stderr.take() {
            readers.push(spawn_reader(stderr, Arc::clone(&output), false));
        }
        Ok(Self {
            child,
            identity,
            output,
            readers,
        })
    }

    /// Return the immutable launch identity.
    #[must_use]
    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    /// Check whether the exact child is still running.
    pub fn is_running(&mut self) -> Result<bool> {
        if self.child.try_wait()?.is_some() {
            return Ok(false);
        }
        ensure_identity(&self.identity)?;
        Ok(true)
    }

    /// Non-blocking wait for the exact child.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        if status.is_none() {
            ensure_identity(&self.identity)?;
        }
        Ok(status)
    }

    /// Wait for an exact child to exit.
    pub fn wait(&mut self) -> Result<ExitStatus> {
        if self.child.try_wait()?.is_none() {
            ensure_identity(&self.identity)?;
        }
        let status = self.child.wait()?;
        self.join_readers_bounded(Duration::from_millis(250));
        Ok(status)
    }

    /// Stop only the exact owned child, with a bounded cleanup wait.  The
    /// standard-library handle sends the platform's forceful termination
    /// signal; future native adapters can add a graceful request before this
    /// final step while retaining the same identity check.
    pub fn terminate(&mut self, timeout: Duration) -> Result<ExitStatus> {
        if let Some(status) = self.child.try_wait()? {
            self.join_readers_bounded(Duration::from_millis(250));
            return Ok(status);
        }
        ensure_identity(&self.identity)?;
        self.child.kill()?;
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.join_readers_bounded(Duration::from_millis(250));
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(WatchdogError::Timeout(format!(
                    "owned child {} did not terminate",
                    self.identity.pid
                )));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Snapshot bounded output without using it as a health signal.
    pub fn output(&self) -> OutputSnapshot {
        let output = self
            .output
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        OutputSnapshot {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            stdout_truncated: output.stdout_truncated,
            stderr_truncated: output.stderr_truncated,
        }
    }

    fn join_readers_bounded(&mut self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while !self.readers.iter().all(JoinHandle::is_finished) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let readers = std::mem::take(&mut self.readers);
        for reader in readers {
            if reader.is_finished() {
                let _ = reader.join();
            }
            // An inherited pipe can remain open in a grandchild. Dropping an
            // unfinished JoinHandle detaches it instead of blocking teardown.
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        // This is the original Child object, never a reconstructed PID/name
        // handle. Keep ownership until the child is reaped: on Unix an exited
        // unreaped child retains its PID; Windows retains the process handle.
        // Dropping during a post-spawn persistence failure must not detach it.
        // This fallback cleans the direct child only; native cgroup/Job
        // containment remains responsible for arbitrary descendants.
        let deadline = Instant::now() + Duration::from_secs(5);
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                let _ = self.child.kill();
                while Instant::now() < deadline {
                    match self.child.try_wait() {
                        Ok(Some(_)) | Err(_) => break,
                        Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
            }
            Err(_) => {}
        }
        self.join_readers_bounded(Duration::from_millis(50));
    }
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

fn validate_component(spec: &ComponentConfig) -> Result<()> {
    if spec.id.is_empty() || spec.id.len() > 128 || spec.id.as_bytes().contains(&0) {
        return Err(WatchdogError::InvalidInput(
            "component id is invalid".to_string(),
        ));
    }
    if !spec.executable.is_absolute() || spec.executable.as_os_str().is_empty() {
        return Err(WatchdogError::InvalidInput(format!(
            "component {} executable must be absolute",
            spec.id
        )));
    }
    let executable_text = spec
        .executable
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if executable_text.starts_with("/mnt/")
        || executable_text.starts_with("//wsl")
        || executable_text.contains("/proc/")
    {
        return Err(WatchdogError::InvalidInput(format!(
            "component {} executable must be owner-local",
            spec.id
        )));
    }
    if spec.args.len() > 64
        || spec
            .args
            .iter()
            .any(|arg| arg.as_bytes().len() > 8 * 1024 || arg.as_bytes().contains(&0))
    {
        return Err(WatchdogError::InvalidInput(format!(
            "component {} arguments are outside bounds",
            spec.id
        )));
    }
    if let Some(cwd) = &spec.cwd {
        if !cwd.is_absolute() {
            return Err(WatchdogError::InvalidInput(format!(
                "component {} cwd must be absolute",
                spec.id
            )));
        }
        let cwd_text = cwd
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        if cwd_text.starts_with("/mnt/") || cwd_text.starts_with("//wsl") {
            return Err(WatchdogError::InvalidInput(format!(
                "component {} cwd must be owner-local",
                spec.id
            )));
        }
    }
    if spec.environment.len() > 64
        || spec.environment.iter().any(|(key, value)| {
            key.is_empty()
                || key.as_bytes().contains(&0)
                || value.as_bytes().len() > 8 * 1024
                || value.as_bytes().contains(&0)
        })
    {
        return Err(WatchdogError::InvalidInput(format!(
            "component {} environment is outside bounds",
            spec.id
        )));
    }
    if let Some(digest) = &spec.executable_sha256 {
        crate::config::validate_digest(digest).map_err(|message| {
            WatchdogError::InvalidInput(format!("component {}: {message}", spec.id))
        })?;
    }
    Ok(())
}

fn spawn_reader<R: Read + Send + 'static>(
    mut reader: R,
    output: Arc<Mutex<BoundedOutput>>,
    stdout: bool,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buffer = [0_u8; 4 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if let Ok(mut output) = output.lock() {
                        if stdout {
                            let remaining = MAX_OUTPUT_BYTES.saturating_sub(output.stdout.len());
                            if read > remaining {
                                output.stdout.extend_from_slice(&buffer[..remaining]);
                                output.stdout_truncated = true;
                            } else {
                                output.stdout.extend_from_slice(&buffer[..read]);
                            }
                        } else {
                            let remaining = MAX_OUTPUT_BYTES.saturating_sub(output.stderr.len());
                            if read > remaining {
                                output.stderr.extend_from_slice(&buffer[..remaining]);
                                output.stderr_truncated = true;
                            } else {
                                output.stderr.extend_from_slice(&buffer[..read]);
                            }
                        }
                    }
                }
            }
        }
    })
}

#[cfg(target_os = "linux")]
fn process_creation_fingerprint(pid: u32) -> Option<String> {
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
fn process_creation_fingerprint(_pid: u32) -> Option<String> {
    // The native Windows adapter will replace this hook with a process
    // creation-time query.  The Child handle remains the cleanup authority in
    // this portable slice.
    None
}

fn hash_file(path: &Path) -> Result<String> {
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

#[allow(dead_code)]
fn _path_for_docs(path: &Path) -> &Path {
    path
}
