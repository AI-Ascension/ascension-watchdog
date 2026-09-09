// SPDX-License-Identifier: MIT

//! OS-backed ownership for the opt-in real-harness daemon.
//!
//! The test process keeps a `Child` handle and a pidfd, while systemd owns an
//! individually named transient scope containing the daemon and its future
//! descendants.  The scope is deliberately verified from systemd's live
//! properties and cgroup-v2 state; an environment variable or a local name
//! registry is not accepted as an ownership proof.

use ascension_watchdog::config::{DesiredMode, WatchdogConfig, validate_digest};
use ascension_watchdog::storage::Store;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const ENV: &str = "/usr/bin/env";
const CGROUP_MOUNT: &str = "/sys/fs/cgroup";
const MAX_RUNTIME: Duration = Duration::from_mins(2);
const MAX_STOP: Duration = Duration::from_secs(5);
const START_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_TIMEOUT: Duration = Duration::from_secs(12);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(8);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_COMMAND_OUTPUT: usize = 64 * 1024;
const MAX_IMAGE_BYTES: u64 = 512 * 1024 * 1024;

#[cfg(test)]
#[path = "real_harness_worker_scope_tests.rs"]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ScopeProperties {
    pub(super) values: BTreeMap<String, String>,
}

impl ScopeProperties {
    fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    fn state(&self) -> Option<&str> {
        self.get("ActiveState")
    }

    fn control_group(&self) -> Option<&str> {
        self.get("ControlGroup").filter(|value| !value.is_empty())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(super) struct ScopeProof {
    pub(super) schema_version: u32,
    pub(super) state: String,
    pub(super) unit: String,
    pub(super) description: String,
    pub(super) config_path: String,
    pub(super) config_digest: String,
    pub(super) daemon_image: String,
    pub(super) daemon_sha256: String,
    pub(super) control_group: Option<String>,
    pub(super) daemon_pid: Option<u32>,
    pub(super) worker_pid: Option<u32>,
    pub(super) expected: BTreeMap<String, String>,
    pub(super) actual: BTreeMap<String, String>,
    pub(super) detail: String,
}

/// Parse `systemctl show` output without accepting duplicate or malformed
/// fields.  Keeping this parser pure makes the negative tests independent of
/// the local user manager.
pub(super) fn parse_properties(output: &str) -> Result<ScopeProperties, String> {
    let mut values = BTreeMap::new();
    for line in output.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("systemd property has no '=': {line:?}"));
        };
        if key.is_empty() || values.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(format!("duplicate or empty systemd property: {key:?}"));
        }
    }
    if values.is_empty() {
        return Err("systemd returned no properties".to_owned());
    }
    Ok(ScopeProperties { values })
}

/// Validate all properties that establish bounded, exclusive ownership.
pub(super) fn validate_scope_properties(
    properties: &ScopeProperties,
    unit: &str,
    description: &str,
) -> Result<String, String> {
    if properties.get("LoadState") == Some("not-found") {
        return Err("scope disappeared before it became active".to_owned());
    }
    if properties.state() != Some("active") {
        return Err(format!("scope is not active: {:?}", properties.state()));
    }
    let id = properties
        .get("Id")
        .ok_or_else(|| "scope has no Id property".to_owned())?;
    if id != unit {
        return Err(format!("scope Id {id:?} does not match {unit:?}"));
    }
    if properties.get("Description") != Some(description) {
        return Err("scope description does not match the owner proof".to_owned());
    }
    if properties.get("Delegate") != Some("yes") {
        return Err("scope is not delegated".to_owned());
    }
    if properties.get("KillMode") != Some("control-group") {
        return Err("scope KillMode is not control-group".to_owned());
    }
    if properties.get("SendSIGKILL") != Some("yes") {
        return Err("scope SendSIGKILL is not enabled".to_owned());
    }
    if properties.get("CollectMode") != Some("inactive-or-failed") {
        return Err("scope is not collectable after stop".to_owned());
    }
    let runtime = parse_duration_usec(
        properties
            .get("RuntimeMaxUSec")
            .ok_or_else(|| "scope has no RuntimeMaxUSec property".to_owned())?,
    )
    .ok_or_else(|| "scope RuntimeMaxUSec is infinite or malformed".to_owned())?;
    if runtime == 0 || runtime > duration_usec(MAX_RUNTIME) {
        return Err(format!(
            "scope runtime bound is outside 0..={MAX_RUNTIME:?}"
        ));
    }
    let timeout = parse_duration_usec(
        properties
            .get("TimeoutStopUSec")
            .ok_or_else(|| "scope has no TimeoutStopUSec property".to_owned())?,
    )
    .ok_or_else(|| "scope TimeoutStopUSec is malformed".to_owned())?;
    if timeout > duration_usec(MAX_STOP) {
        return Err("scope stop timeout exceeds the bounded cleanup limit".to_owned());
    }
    let control_group = properties
        .control_group()
        .ok_or_else(|| "scope has no live ControlGroup property".to_owned())?;
    if !control_group.starts_with('/') || !control_group.ends_with(&format!("/{unit}")) {
        return Err(format!("unexpected scope ControlGroup {control_group:?}"));
    }
    Ok(control_group.to_owned())
}

pub(super) fn validate_scope_proof(proof: &ScopeProof) -> Result<(), String> {
    if proof.schema_version != 1 {
        return Err("unsupported scope proof schema".to_owned());
    }
    if proof.state != "planned"
        && proof.state != "active"
        && proof.state != "stopped"
        && proof.state != "uncertain"
    {
        return Err(format!("invalid proof state {:?}", proof.state));
    }
    if Path::new(&proof.unit)
        .extension()
        .and_then(|extension| extension.to_str())
        != Some("scope")
        || proof.unit.contains('/')
        || proof.unit.is_empty()
    {
        return Err("invalid transient scope unit".to_owned());
    }
    if proof.description.is_empty()
        || !Path::new(&proof.config_path).is_absolute()
        || !Path::new(&proof.daemon_image).is_absolute()
        || proof.daemon_sha256.len() != 64
        || !proof
            .daemon_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("scope proof has invalid protected identity".to_owned());
    }
    validate_digest(&proof.config_digest)
        .map_err(|error| format!("scope proof config digest is invalid: {error}"))?;
    for (key, expected) in [
        ("Delegate", "yes"),
        ("KillMode", "control-group"),
        ("SendSIGKILL", "yes"),
        ("RuntimeMaxUSec", "<=120s"),
        ("TimeoutStopUSec", "<=5s"),
        ("CollectMode", "inactive-or-failed"),
    ] {
        if proof.expected.get(key).map(String::as_str) != Some(expected) {
            return Err(format!("scope proof expected {key}={expected}"));
        }
    }
    if proof.state == "active" {
        let control_group = proof
            .control_group
            .as_deref()
            .ok_or_else(|| "active scope proof has no cgroup".to_owned())?;
        if !control_group.starts_with('/') || !control_group.ends_with(&format!("/{}", proof.unit))
        {
            return Err("active scope proof cgroup does not identify its unit".to_owned());
        }
        let properties = ScopeProperties {
            values: proof.actual.clone(),
        };
        let actual_group = validate_scope_properties(&properties, &proof.unit, &proof.description)
            .map_err(|error| format!("active proof properties are invalid: {error}"))?;
        if actual_group != control_group {
            return Err("active proof cgroup differs from its actual properties".to_owned());
        }
    }
    Ok(())
}

/// Validate the identity fields returned by a live unit observation.  A
/// state transition is not evidence that the observed object is still the
/// owner-created unit; Id and Description must remain bound to the proof.
pub(super) fn validate_observed_scope_identity(
    properties: &ScopeProperties,
    unit: &str,
    description: &str,
) -> Result<(), String> {
    if properties.get("Id") != Some(unit) {
        return Err(format!(
            "observed scope Id {:?} does not match {:?}",
            properties.get("Id"),
            unit
        ));
    }
    if properties.get("Description") != Some(description) {
        return Err(format!(
            "observed scope description {:?} does not match {:?}",
            properties.get("Description"),
            description
        ));
    }
    Ok(())
}

/// Validate the cgroup portion of a stopped observation without touching the
/// host.  Runtime code additionally checks the retained directory inode and
/// `cgroup.events` handle; this pure boundary test prevents a recreated unit
/// or missing admission handle from being treated as a successful stop.
pub(super) fn validate_stopped_scope_identity(
    properties: &ScopeProperties,
    unit: &str,
    description: &str,
    original_control_group: Option<&str>,
) -> Result<(), String> {
    validate_observed_scope_identity(properties, unit, description)?;
    if !matches!(properties.state(), Some("inactive" | "failed")) {
        return Err(format!("scope is not stopped: {:?}", properties.state()));
    }
    let original = original_control_group
        .ok_or_else(|| "stopped observation has no retained original cgroup".to_owned())?;
    if let Some(current) = properties.control_group()
        && current != original
    {
        return Err(format!(
            "observed cgroup {current:?} does not match retained original {original:?}"
        ));
    }
    Ok(())
}

fn duration_usec(duration: Duration) -> u128 {
    duration.as_micros()
}

fn parse_duration_usec(value: &str) -> Option<u128> {
    let mut total = 0_u128;
    let mut token_count = 0_u8;
    for token in value.split_whitespace() {
        let (number, multiplier) = if let Some(value) = token.strip_suffix("min") {
            (value, 60_000_000_u128)
        } else if let Some(value) = token.strip_suffix("ms") {
            (value, 1_000_u128)
        } else if let Some(value) = token.strip_suffix("us") {
            (value, 1_u128)
        } else if let Some(value) = token.strip_suffix('h') {
            (value, 3_600_000_000_u128)
        } else if let Some(value) = token.strip_suffix('d') {
            (value, 86_400_000_000_u128)
        } else {
            (token.strip_suffix('s')?, 1_000_000_u128)
        };
        let amount = number.parse::<u128>().ok()?.checked_mul(multiplier)?;
        total = total.checked_add(amount)?;
        token_count = token_count.checked_add(1)?;
    }
    (token_count != 0).then_some(total)
}

fn canonical_regular(path: &Path, label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(io::Error::other(format!("{label} is not a regular non-symlink file")).into());
    }
    let canonical = fs::canonicalize(path)?;
    let canonical_metadata = fs::metadata(&canonical)?;
    if !canonical_metadata.file_type().is_file()
        || canonical_metadata.permissions().mode() & 0o111 == 0
    {
        return Err(io::Error::other(format!("{label} is not an executable regular file")).into());
    }
    Ok(canonical)
}

fn canonical_config(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(io::Error::other("watchdog config is not a regular non-symlink file").into());
    }
    Ok(fs::canonicalize(path)?)
}

fn sha256_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_IMAGE_BYTES {
        return Err(io::Error::other("daemon image exceeds bounded hash size").into());
    }
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read)?)
            .ok_or_else(|| io::Error::other("daemon image hash length overflow"))?;
        if total > MAX_IMAGE_BYTES {
            return Err(io::Error::other("daemon image grew beyond bounded hash size").into());
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        let _ = write!(&mut output, "{byte:02x}");
    }
    Ok(output)
}

fn preserve_bus_environment(command: &mut Command) -> Result<(), Box<dyn std::error::Error>> {
    let bus = std::env::var_os("DBUS_SESSION_BUS_ADDRESS")
        .ok_or_else(|| io::Error::other("DBUS_SESSION_BUS_ADDRESS is required for user systemd"))?;
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| io::Error::other("XDG_RUNTIME_DIR is required for user systemd"))?;
    command
        .env_clear()
        .env("DBUS_SESSION_BUS_ADDRESS", bus)
        .env("XDG_RUNTIME_DIR", runtime);
    Ok(())
}

fn systemd_command(path: &str) -> Result<Command, Box<dyn std::error::Error>> {
    let mut command = Command::new(path);
    preserve_bus_environment(&mut command)?;
    Ok(command)
}

fn run_bounded(
    mut command: Command,
    timeout: Duration,
) -> Result<(bool, String), Box<dyn std::error::Error>> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = CommandChildGuard::spawn(command)?;
    let stdout = child.take_stdout()?;
    let stderr = child.take_stderr()?;
    set_nonblocking_pipe(&stdout)?;
    set_nonblocking_pipe(&stderr)?;
    let deadline = Instant::now() + timeout;
    let stdout_reader = thread::spawn(move || read_bounded_output(stdout, deadline));
    let stderr_reader = thread::spawn(move || read_bounded_output(stderr, deadline));
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let text = join_command_output(stdout_reader, stderr_reader)?;
                child.disarm();
                return Ok((!status.success(), text));
            }
            Ok(None) if Instant::now() >= deadline => {
                let cleanup = child.kill_and_reap(Instant::now() + Duration::from_secs(2));
                let text = join_command_output(stdout_reader, stderr_reader)?;
                cleanup.map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("bounded systemd helper cleanup failed: {error}; output={text}"),
                    )
                })?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("systemd helper exceeded its bounded timeout; output={text}"),
                )
                .into());
            }
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(error) => {
                let cleanup = child.kill_and_reap(Instant::now() + Duration::from_secs(2));
                let _ = join_command_output(stdout_reader, stderr_reader);
                cleanup?;
                return Err(error.into());
            }
        }
    }
}

fn set_nonblocking_pipe(pipe: &impl AsFd) -> io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(pipe)?;
    rustix::fs::fcntl_setfl(pipe, flags | rustix::fs::OFlags::NONBLOCK).map_err(io::Error::from)
}

fn read_bounded_output(mut reader: impl Read, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut retained = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        if Instant::now() >= deadline {
            return Ok(retained);
        }
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(retained),
            Ok(read) => {
                let keep = MAX_COMMAND_OUTPUT.saturating_sub(retained.len()).min(read);
                retained.extend_from_slice(&buffer[..keep]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error),
        }
    }
}

fn join_command_output(
    stdout_reader: thread::JoinHandle<io::Result<Vec<u8>>>,
    stderr_reader: thread::JoinHandle<io::Result<Vec<u8>>>,
) -> Result<String, Box<dyn std::error::Error>> {
    let stdout = stdout_reader
        .join()
        .map_err(|_| io::Error::other("systemd stdout reader panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| io::Error::other("systemd stderr reader panicked"))??;
    let mut text = String::from_utf8_lossy(&stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&stderr));
    if text.len() > MAX_COMMAND_OUTPUT {
        let mut boundary = MAX_COMMAND_OUTPUT;
        while !text.is_char_boundary(boundary) {
            boundary -= 1;
        }
        text.truncate(boundary);
        text.push_str("...[truncated]");
    }
    Ok(text)
}

struct CommandChildGuard {
    child: Option<Child>,
    pidfd: Option<OwnedFd>,
}

impl CommandChildGuard {
    fn spawn(mut command: Command) -> io::Result<Self> {
        let child = command.spawn()?;
        let mut guard = Self {
            child: Some(child),
            pidfd: None,
        };
        let pidfd = {
            let child = guard
                .child
                .as_ref()
                .ok_or_else(|| io::Error::other("systemd helper lost its child"))?;
            rustix::process::pidfd_open(
                rustix::process::Pid::from_child(child),
                rustix::process::PidfdFlags::NONBLOCK,
            )
            .map_err(|error| io::Error::other(format!("cannot open helper pidfd: {error}")))?
        };
        guard.pidfd = Some(pidfd);
        Ok(guard)
    }

    fn take_stdout(&mut self) -> io::Result<std::process::ChildStdout> {
        self.child
            .as_mut()
            .ok_or_else(|| io::Error::other("systemd helper lost its child"))?
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("systemd helper stdout pipe was not created"))
    }

    fn take_stderr(&mut self) -> io::Result<std::process::ChildStderr> {
        self.child
            .as_mut()
            .ok_or_else(|| io::Error::other("systemd helper lost its child"))?
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("systemd helper stderr pipe was not created"))
    }

    fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.child
            .as_mut()
            .ok_or_else(|| io::Error::other("systemd helper lost its child"))?
            .try_wait()
    }

    fn kill_and_reap(&mut self, deadline: Instant) -> io::Result<()> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| io::Error::other("systemd helper lost its child"))?;
        let initial_wait_error = match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => None,
            Err(error) => Some(error),
        };
        let pidfd_error = self.pidfd.as_ref().and_then(|pidfd| {
            rustix::process::pidfd_send_signal(pidfd, rustix::process::Signal::KILL).err()
        });
        // A numeric Child::kill fallback is safe only after a fresh Ok(None)
        // observation and only when pidfd capture itself failed.  If the
        // initial wait was uncertain, the retained pidfd remains the only
        // exact signal authority.
        if self.pidfd.is_none() && initial_wait_error.is_none() {
            let _ = child.kill();
        }
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
                Ok(None) => {
                    let wait_detail = initial_wait_error
                        .map(|error| format!("; initial wait failed: {error}"))
                        .unwrap_or_default();
                    let signal_detail = pidfd_error
                        .map(|error| format!("; pidfd kill failed: {error}"))
                        .unwrap_or_default();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "systemd helper remained live after bounded kill{wait_detail}{signal_detail}"
                        ),
                    ));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn disarm(&mut self) {
        self.child = None;
    }
}

impl Drop for CommandChildGuard {
    fn drop(&mut self) {
        if self.child.is_some()
            && let Err(error) = self.kill_and_reap(Instant::now() + Duration::from_secs(2))
        {
            eprintln!("systemd helper cleanup is uncertain: {error}");
        }
    }
}

fn show_unit(unit: &str) -> Result<ScopeProperties, Box<dyn std::error::Error>> {
    let mut command = systemd_command(SYSTEMCTL)?;
    command.args([
        "--user",
        "show",
        "--no-pager",
        "-p",
        "Id",
        "-p",
        "LoadState",
        "-p",
        "ActiveState",
        "-p",
        "ControlGroup",
        "-p",
        "Description",
        "-p",
        "Delegate",
        "-p",
        "KillMode",
        "-p",
        "SendSIGKILL",
        "-p",
        "RuntimeMaxUSec",
        "-p",
        "TimeoutStopUSec",
        "-p",
        "CollectMode",
        unit,
    ]);
    let (failed, output) = run_bounded(command, COMMAND_TIMEOUT)?;
    if failed && output.trim().is_empty() {
        return Err(io::Error::other("systemctl show failed without a diagnostic").into());
    }
    Ok(parse_properties(&output).map_err(io::Error::other)?)
}

fn cgroup_path(control_group: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if !control_group.starts_with('/') || control_group.contains("..") {
        return Err(io::Error::other("unsafe systemd cgroup path").into());
    }
    Ok(Path::new(CGROUP_MOUNT).join(control_group.trim_start_matches('/')))
}

fn require_cgroup_v2() -> Result<(), Box<dyn std::error::Error>> {
    for name in ["cgroup.controllers", "cgroup.procs"] {
        let path = Path::new(CGROUP_MOUNT).join(name);
        if !path.is_file() {
            return Err(io::Error::other(format!(
                "required cgroup-v2 file is unavailable: {}",
                path.display()
            ))
            .into());
        }
    }
    Ok(())
}

/// The cgroup directory and events file are opened while the live scope is
/// admitted and retained until stop proof is written.  Looking up the path on
/// every poll is insufficient: systemd can remove it and a later unit can
/// recreate the same pathname for a different cgroup.
struct OriginalCgroup {
    control_group: String,
    directory: File,
    events: File,
    directory_dev: u64,
    directory_ino: u64,
    events_dev: u64,
    events_ino: u64,
}

fn open_cgroup_directory(path: &Path) -> io::Result<File> {
    Ok(File::from(rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )?))
}

fn open_cgroup_events(directory: &File) -> io::Result<File> {
    Ok(File::from(rustix::fs::openat(
        directory.as_fd(),
        "cgroup.events",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )?))
}

impl OriginalCgroup {
    fn open(control_group: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let path = cgroup_path(control_group)?;
        let directory = open_cgroup_directory(&path)?;
        let directory_metadata = directory.metadata()?;
        if !directory_metadata.is_dir() {
            return Err(io::Error::other("original cgroup path is not a directory").into());
        }
        // Open events relative to the retained directory descriptor.  A
        // pathname open here could pair an old directory with a newly
        // recreated cgroup.events file after a remove/recreate race.
        let events = open_cgroup_events(&directory)?;
        let events_metadata = events.metadata()?;
        if events_metadata.dev() != directory_metadata.dev() {
            return Err(io::Error::other("cgroup.events is on a different filesystem").into());
        }
        let original = Self {
            control_group: control_group.to_owned(),
            directory,
            events,
            directory_dev: directory_metadata.dev(),
            directory_ino: directory_metadata.ino(),
            events_dev: events_metadata.dev(),
            events_ino: events_metadata.ino(),
        };
        if original.verify_path()? {
            return Err(io::Error::other("original cgroup was removed during admission").into());
        }
        Ok(original)
    }

    fn verify_retained_handles(&self) -> io::Result<()> {
        let directory = self.directory.metadata()?;
        if !directory.is_dir()
            || directory.dev() != self.directory_dev
            || directory.ino() != self.directory_ino
        {
            return Err(io::Error::other(
                "retained cgroup directory identity changed",
            ));
        }
        let events = self.events.metadata()?;
        if events.dev() != self.events_dev || events.ino() != self.events_ino {
            return Err(io::Error::other("retained cgroup.events identity changed"));
        }
        Ok(())
    }

    /// Return whether the original pathname is still the original inode.
    /// `false` means it is present; `true` means it was positively unlinked.
    fn verify_path(&self) -> Result<bool, Box<dyn std::error::Error>> {
        self.verify_retained_handles()?;
        let path = cgroup_path(&self.control_group)?;
        match fs::metadata(path) {
            Ok(metadata) => {
                if !metadata.is_dir()
                    || metadata.dev() != self.directory_dev
                    || metadata.ino() != self.directory_ino
                {
                    return Err(io::Error::other(
                        "current cgroup path does not identify the admitted cgroup",
                    )
                    .into());
                }
                Ok(false)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error.into()),
        }
    }

    fn empty(&mut self) -> Result<bool, Box<dyn std::error::Error>> {
        let unlinked = self.verify_path()?;
        self.events.seek(SeekFrom::Start(0))?;
        let mut text = String::new();
        match self.events.read_to_string(&mut text) {
            Ok(_) => {}
            Err(error) if is_enodev(&error) => {
                // An ENODEV events read is not itself proof of emptiness. It
                // is accepted only when retained metadata proves this exact
                // cgroup was unlinked, which is a positive stop observation.
                return Ok(unlinked);
            }
            Err(error) => return Err(error.into()),
        }
        let populated = text
            .lines()
            .find_map(|line| line.strip_prefix("populated "))
            .ok_or_else(|| io::Error::other("cgroup.events lacks populated state"))?;
        match populated {
            "0" => Ok(true),
            "1" => Ok(false),
            value => Err(io::Error::other(format!(
                "cgroup.events has invalid populated state {value:?}"
            ))
            .into()),
        }
    }
}

fn is_enodev(error: &io::Error) -> bool {
    error.raw_os_error() == io::Error::from(rustix::io::Errno::NODEV).raw_os_error()
}

fn process_cgroup(pid: u32) -> Result<String, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    text.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .filter(|path| path.starts_with('/'))
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            io::Error::other(format!("process {pid} has no cgroup-v2 membership")).into()
        })
}

fn process_in_scope(pid: u32, control_group: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let path = process_cgroup(pid)?;
    Ok(path == control_group || path.starts_with(&format!("{control_group}/")))
}

fn process_matches_image(
    pid: u32,
    image: &Path,
    digest: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let exe = fs::read_link(format!("/proc/{pid}/exe"))?;
    let canonical = fs::canonicalize(exe)?;
    if canonical != image {
        return Ok(false);
    }
    Ok(sha256_file(&canonical)? == digest)
}

fn write_proof(path: &Path, proof: &ScopeProof) -> Result<(), Box<dyn std::error::Error>> {
    validate_scope_proof(proof).map_err(io::Error::other)?;
    let bytes = serde_json::to_vec_pretty(proof)?;
    let temporary = path.with_extension(format!("proof.json.{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    if let Some(parent) = path.parent() {
        let directory = File::open(parent)?;
        directory.sync_all()?;
    }
    Ok(())
}

pub(super) struct ScopeLaunch {
    pub(super) child: Child,
    pub(super) pidfd: OwnedFd,
    pub(super) scope: ScopeOwner,
}

/// Own the systemd-run launcher from the instant it is spawned.  The
/// launcher is normally an exec'd daemon, so dropping its `Child` on any
/// startup error would otherwise leave the scope's process unmanaged by the
/// Rust side. Durable Stop is recorded first, then the exact pidfd is used
/// for bounded cleanup. The already configured manager lifetime remains the
/// authority for descendants when direct cleanup cannot be proved complete.
struct LauncherGuard {
    child: Option<Child>,
    pidfd: Option<OwnedFd>,
    pidfd_error: Option<String>,
    scope: Option<ScopeOwner>,
}

impl LauncherGuard {
    fn new(child: Child, scope: ScopeOwner) -> Self {
        let (pidfd, pidfd_error) = match rustix::process::pidfd_open(
            rustix::process::Pid::from_child(&child),
            rustix::process::PidfdFlags::NONBLOCK,
        ) {
            Ok(pidfd) => (Some(pidfd), None),
            Err(error) => (None, Some(error.to_string())),
        };
        Self {
            child: Some(child),
            pidfd,
            pidfd_error,
            scope: Some(scope),
        }
    }

    fn child_id(&self) -> Result<u32, Box<dyn std::error::Error>> {
        self.child
            .as_ref()
            .map(Child::id)
            .ok_or_else(|| io::Error::other("scope launcher lost its child").into())
    }

    fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>, io::Error> {
        self.child
            .as_mut()
            .ok_or_else(|| io::Error::other("scope launcher lost its child"))?
            .try_wait()
    }

    fn scope_mut(&mut self) -> Result<&mut ScopeOwner, Box<dyn std::error::Error>> {
        self.scope
            .as_mut()
            .ok_or_else(|| io::Error::other("scope launcher lost its scope").into())
    }

    fn into_launch(mut self) -> Result<ScopeLaunch, Box<dyn std::error::Error>> {
        let pidfd = self.pidfd.take().ok_or_else(|| {
            io::Error::other(format!(
                "cannot retain daemon pidfd before scope admission: {}",
                self.pidfd_error
                    .as_deref()
                    .unwrap_or("pidfd was not captured")
            ))
        })?;
        Ok(ScopeLaunch {
            child: self
                .child
                .take()
                .ok_or_else(|| io::Error::other("scope launcher lost its child"))?,
            pidfd,
            scope: self
                .scope
                .take()
                .ok_or_else(|| io::Error::other("scope launcher lost its scope"))?,
        })
    }

    fn cleanup(&mut self) {
        if self.child.is_none() {
            return;
        }
        let Some(scope) = self.scope.as_mut() else {
            eprintln!("pre-admission launcher lost its durable scope proof");
            return;
        };
        if let Err(error) = scope.persist_stop() {
            eprintln!("pre-admission durable stop is uncertain: {error}");
            return;
        }
        let Some(child) = self.child.as_mut() else {
            return;
        };
        let initial_wait_error = match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => None,
            Err(error) => {
                eprintln!("pre-admission child liveness is uncertain: {error}");
                Some(error)
            }
        };
        if let Some(pidfd) = self.pidfd.as_ref() {
            if let Err(error) =
                rustix::process::pidfd_send_signal(pidfd, rustix::process::Signal::KILL)
            {
                eprintln!("pre-admission pidfd kill failed: {error}");
            }
        } else if initial_wait_error.is_none()
            && let Err(error) = child.kill()
        {
            // This still-owned Child was just observed as live and has not
            // been reaped. This path covers failure to capture the pidfd.
            eprintln!("pre-admission owned Child kill failed: {error}");
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
                Ok(None) => {
                    let wait_detail = initial_wait_error
                        .map(|error| format!("; initial wait failed: {error}"))
                        .unwrap_or_default();
                    eprintln!(
                        "pre-admission launcher remained live after bounded cleanup{wait_detail}"
                    );
                    return;
                }
                Err(error) => {
                    eprintln!("pre-admission launcher reap is uncertain: {error}");
                    return;
                }
            }
        }
    }
}

impl Drop for LauncherGuard {
    fn drop(&mut self) {
        if self.child.is_some() {
            self.cleanup();
        }
    }
}

pub(super) struct ScopeOwner {
    unit: String,
    description: String,
    proof_path: PathBuf,
    config_path: PathBuf,
    config_digest: String,
    daemon_image: PathBuf,
    daemon_sha256: String,
    config: WatchdogConfig,
    control_group: Option<String>,
    original_cgroup: Option<OriginalCgroup>,
    daemon_pid: Option<u32>,
    worker_pid: Option<u32>,
    expected: BTreeMap<String, String>,
    actual: BTreeMap<String, String>,
    started: bool,
    stopped: bool,
}

impl ScopeOwner {
    pub(super) fn start(
        config: &WatchdogConfig,
        daemon_image: &Path,
    ) -> Result<ScopeLaunch, Box<dyn std::error::Error>> {
        let owner = Self::new(config, daemon_image)?;
        let launcher = owner.spawn()?;
        admit_scope(launcher)
    }

    fn new(
        config: &WatchdogConfig,
        daemon_image: &Path,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let raw_config = config
            .source_path
            .as_deref()
            .ok_or_else(|| io::Error::other("loaded config lost its source path"))?;
        let config_path = canonical_config(raw_config)?;
        let config_digest = config.digest()?;
        // Config files are read by the daemon but are not executables.  The
        // executable checks above are intentionally only applied to image.
        let config_metadata = fs::metadata(&config_path)?;
        if !config_metadata.file_type().is_file() {
            return Err(io::Error::other("watchdog config is not regular").into());
        }
        let daemon_image = canonical_regular(daemon_image, "daemon image")?;
        let daemon_sha256 = sha256_file(&daemon_image)?;
        let suffix = Uuid::new_v4().simple().to_string();
        let unit = format!("ascension-watchdog-real-{suffix}.scope");
        let description = format!("ascension-watchdog-real-harness-{suffix}");
        let proof_path = config_path
            .parent()
            .ok_or_else(|| io::Error::other("config has no parent directory"))?
            .join(format!("{unit}.proof.json"));
        let expected = BTreeMap::from([
            ("Delegate".to_owned(), "yes".to_owned()),
            ("KillMode".to_owned(), "control-group".to_owned()),
            ("SendSIGKILL".to_owned(), "yes".to_owned()),
            ("RuntimeMaxUSec".to_owned(), "<=120s".to_owned()),
            ("TimeoutStopUSec".to_owned(), "<=5s".to_owned()),
            ("CollectMode".to_owned(), "inactive-or-failed".to_owned()),
        ]);
        let owner = Self {
            unit,
            description,
            proof_path,
            config_path,
            config_digest,
            daemon_image,
            daemon_sha256,
            config: config.clone(),
            control_group: None,
            original_cgroup: None,
            daemon_pid: None,
            worker_pid: None,
            expected,
            actual: BTreeMap::new(),
            started: false,
            stopped: false,
        };
        owner.write_state("planned", "scope has not been spawned")?;
        require_cgroup_v2()?;
        if let Ok(properties) = show_unit(&owner.unit)
            && properties.get("LoadState") != Some("not-found")
        {
            return Err(io::Error::other("random scope unit unexpectedly already exists").into());
        }
        Ok(owner)
    }

    fn spawn(mut self) -> Result<LauncherGuard, Box<dyn std::error::Error>> {
        let mut command = systemd_command(SYSTEMD_RUN)?;
        command
            .args([
                "--user",
                "--scope",
                "--collect",
                "--quiet",
                "--unit",
                &self.unit,
                "--description",
                &self.description,
                "--property=Delegate=yes",
                "--property=RuntimeMaxSec=120s",
                "--property=TimeoutStopSec=5s",
                "--property=KillMode=control-group",
                "--property=SendSIGKILL=yes",
                ENV,
                "-i",
            ])
            .arg(&self.daemon_image)
            .args(["daemon", "--config"])
            .arg(&self.config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let child = command.spawn()?;
        self.started = true;
        self.daemon_pid = Some(child.id());
        Ok(LauncherGuard::new(child, self))
    }
}

fn admit_scope(mut launcher: LauncherGuard) -> Result<ScopeLaunch, Box<dyn std::error::Error>> {
    if launcher.pidfd.is_none() {
        return Err(io::Error::other(format!(
            "cannot retain daemon pidfd before scope admission: {}",
            launcher
                .pidfd_error
                .as_deref()
                .unwrap_or("pidfd was not captured")
        ))
        .into());
    }
    let deadline = Instant::now() + START_TIMEOUT;
    let mut last_detail = String::new();
    while Instant::now() < deadline {
        if let Some(status) = launcher.try_wait()? {
            return Err(io::Error::other(format!(
                "daemon exited before scope admission: {status}; {last_detail}"
            ))
            .into());
        }
        let child_pid = launcher.child_id()?;
        let (unit, description, daemon_image, daemon_sha256) = {
            let scope = launcher.scope_mut()?;
            (
                scope.unit.clone(),
                scope.description.clone(),
                scope.daemon_image.clone(),
                scope.daemon_sha256.clone(),
            )
        };
        match show_unit(&unit) {
            Ok(properties) => match validate_scope_properties(&properties, &unit, &description) {
                Ok(control_group)
                    if process_in_scope(child_pid, &control_group).unwrap_or(false)
                        && process_matches_image(child_pid, &daemon_image, &daemon_sha256)
                            .unwrap_or(false) =>
                {
                    let original_cgroup = match OriginalCgroup::open(&control_group) {
                        Ok(original_cgroup) => original_cgroup,
                        Err(error) => {
                            last_detail = format!(
                                "original cgroup could not be retained during admission: {error}"
                            );
                            thread::sleep(POLL_INTERVAL);
                            continue;
                        }
                    };
                    // The daemon can move or exit while the cgroup handles
                    // are being captured.  Recheck membership after capture
                    // so the proof and process snapshot refer to one stable
                    // admission point.
                    if !process_in_scope(child_pid, &control_group).unwrap_or(false) {
                        "daemon left the scope while retaining cgroup handles"
                            .clone_into(&mut last_detail);
                        thread::sleep(POLL_INTERVAL);
                        continue;
                    }
                    let scope = launcher.scope_mut()?;
                    scope.control_group = Some(control_group);
                    scope.original_cgroup = Some(original_cgroup);
                    scope.actual = properties.values;
                    scope.write_state("active", "scope properties and daemon cgroup verified")?;
                    return launcher.into_launch();
                }
                Ok(_) => {
                    "daemon is not in the verified scope or image".clone_into(&mut last_detail);
                }
                Err(error) => last_detail = error,
            },
            Err(error) => last_detail = error.to_string(),
        }
        thread::sleep(POLL_INTERVAL);
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("scope admission did not settle: {last_detail}"),
    )
    .into())
}

impl ScopeOwner {
    fn write_state(&self, state: &str, detail: &str) -> Result<(), Box<dyn std::error::Error>> {
        let proof = ScopeProof {
            schema_version: 1,
            state: state.to_owned(),
            unit: self.unit.clone(),
            description: self.description.clone(),
            config_path: self.config_path.display().to_string(),
            config_digest: self.config_digest.clone(),
            daemon_image: self.daemon_image.display().to_string(),
            daemon_sha256: self.daemon_sha256.clone(),
            control_group: self.control_group.clone(),
            daemon_pid: self.daemon_pid,
            worker_pid: self.worker_pid,
            expected: self.expected.clone(),
            actual: self.actual.clone(),
            detail: detail.to_owned(),
        };
        write_proof(&self.proof_path, &proof)
    }

    pub(super) fn verify_and_record_worker(
        &mut self,
        worker_pid: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let control_group = self
            .control_group
            .as_deref()
            .ok_or_else(|| io::Error::other("scope has no verified cgroup"))?;
        if !process_in_scope(worker_pid, control_group)? {
            return Err(io::Error::other(format!(
                "worker {worker_pid} is outside daemon scope {control_group}"
            ))
            .into());
        }
        self.worker_pid = Some(worker_pid);
        self.write_state("active", "daemon and worker cgroup membership verified")
    }

    pub(super) fn wait_stopped(
        &mut self,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + timeout;
        let mut last_detail = String::new();
        while Instant::now() < deadline {
            match show_unit(&self.unit) {
                Ok(properties) => {
                    let absent = properties.get("LoadState") == Some("not-found");
                    if absent {
                        // A not-found response cannot retain the old
                        // Description, but systemd still echoes the exact
                        // requested Id.  The retained cgroup handle below is
                        // the authority for the old scope's emptiness.
                        if properties.get("Id") != Some(self.unit.as_str()) {
                            let detail = format!(
                                "missing scope Id {:?} does not match {:?}",
                                properties.get("Id"),
                                self.unit
                            );
                            return self.mark_uncertain(&detail);
                        }
                        if properties.state() != Some("inactive") {
                            let detail = format!(
                                "missing scope has unexpected state {:?}",
                                properties.state()
                            );
                            return self.mark_uncertain(&detail);
                        }
                        let empty = match self.original_cgroup_empty(None) {
                            Ok(empty) => empty,
                            Err(error) => {
                                let detail = format!(
                                    "scope not found but original cgroup proof failed: {error}"
                                );
                                return self.mark_uncertain(&detail);
                            }
                        };
                        if empty {
                            self.actual = properties.values;
                            self.stopped = true;
                            self.write_state(
                                "stopped",
                                "scope not found and retained original cgroup is empty",
                            )?;
                            return Ok(());
                        }
                        "scope not found but retained original cgroup is still populated"
                            .clone_into(&mut last_detail);
                    } else {
                        if let Err(error) = validate_observed_scope_identity(
                            &properties,
                            &self.unit,
                            &self.description,
                        ) {
                            return self.mark_uncertain(&error);
                        }
                        let inactive = matches!(properties.state(), Some("inactive" | "failed"));
                        if inactive {
                            if let Err(error) = self.validate_inactive_scope(&properties) {
                                return self.mark_uncertain(&error);
                            }
                            let empty = match self.original_cgroup_empty(properties.control_group())
                            {
                                Ok(empty) => empty,
                                Err(error) => {
                                    let detail = format!(
                                        "scope identity/cgroup proof failed while stopping: {error}"
                                    );
                                    return self.mark_uncertain(&detail);
                                }
                            };
                            if empty {
                                self.actual = properties.values;
                                self.stopped = true;
                                self.write_state(
                                    "stopped",
                                    "scope inactive and retained original cgroup is empty",
                                )?;
                                return Ok(());
                            }
                            last_detail = format!(
                                "scope state={:?}; retained original cgroup is populated",
                                properties.state()
                            );
                        } else {
                            last_detail = format!(
                                "scope state={:?}; waiting for inactive state",
                                properties.state()
                            );
                        }
                    }
                }
                Err(error) => last_detail = error.to_string(),
            }
            thread::sleep(POLL_INTERVAL);
        }
        self.write_state(
            "uncertain",
            &format!("scope stop did not settle: {last_detail}"),
        )?;
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("scope did not become inactive with empty cgroup: {last_detail}"),
        )
        .into())
    }

    fn validate_inactive_scope(&self, properties: &ScopeProperties) -> Result<(), String> {
        validate_stopped_scope_identity(
            properties,
            &self.unit,
            &self.description,
            self.original_cgroup
                .as_ref()
                .map(|original| original.control_group.as_str()),
        )
    }

    fn original_cgroup_empty(
        &mut self,
        observed_control_group: Option<&str>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let original = self.original_cgroup.as_mut().ok_or_else(|| {
            io::Error::other("no retained original cgroup is available for stop proof")
        })?;
        if let Some(observed) = observed_control_group
            && observed != original.control_group
        {
            return Err(io::Error::other(format!(
                "observed cgroup {observed:?} does not match retained original {:?}",
                original.control_group
            ))
            .into());
        }
        original.empty()
    }

    fn mark_uncertain(&self, detail: &str) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.write_state("uncertain", detail);
        Err(io::Error::other(detail.to_owned()).into())
    }

    pub(super) fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.started || self.stopped {
            return Ok(());
        }
        self.persist_stop()?;
        // Never issue a stop by unit name: a check followed by StopUnit could
        // target a recreated unit. The daemon observes durable Stop; its
        // retained pidfd is owned by the launcher/daemon guard. If it cannot
        // exit, the manager's preconfigured RuntimeMaxSec remains the bounded
        // descendant-cleanup authority. A timeout here is uncertainty, not a
        // successful stop or permission to address another process.
        self.wait_stopped(STOP_TIMEOUT)
    }

    pub(super) fn persist_stop(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Err(error) = Store::open(&self.config.database, &self.config)
            .and_then(|mut store| store.set_desired_mode_at(DesiredMode::Stopped, unix_now_ms()))
        {
            let detail = format!("durable stop intent failed: {error}; manager lifetime retained");
            let _ = self.write_state("uncertain", &detail);
            return Err(io::Error::other(detail).into());
        }
        Ok(())
    }
}

impl Drop for ScopeOwner {
    fn drop(&mut self) {
        if self.started
            && !self.stopped
            && let Err(error) = self.stop()
        {
            eprintln!("real harness scope cleanup is uncertain: {error}");
        }
    }
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
