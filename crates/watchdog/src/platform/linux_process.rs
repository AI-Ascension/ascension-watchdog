//! Linux process authority backed by delegated cgroup v2.
//!
//! This module intentionally uses only safe Rust.  A cgroup is created before
//! a child is spawned, and the child is transferred to that cgroup before the
//! adapter returns an ownership record.  The cgroup is the authority used for
//! descendant cleanup; a PID is checked against both `/proc` birth data and the
//! exact cgroup before it is observed or signalled.  If the current service
//! does not have a writable delegated cgroup with `cgroup.kill`, construction
//! fails explicitly with [`AdapterError::Unavailable`].
//!
//! The standard library has no race-free Linux signal or pre-exec API.  The
//! adapter therefore uses the exact `Child` handle for launch-failure cleanup,
//! a fixed system `kill` helper for the bounded graceful TERM request, and
//! cgroup v2 `cgroup.kill` for force cleanup.  The latter is the only operation
//! that is allowed to terminate descendants.  A future reviewed pidfd/pre-exec
//! boundary can replace those two narrow seams without changing the contract.

use super::contract::{
    AdapterError, ComponentKind, ContainmentId, LaunchSpec, Observation, OwnedProcess,
    ProcessAdapter, ProcessCreation, ProcessIdentity, SessionSelector, StopOutcome,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CGROUP_PREFIX: &str = "cgroup-v2:";
const MAX_CGROUP_PIDS: usize = 4_096;
const MAX_ACTIVE_CHILDREN: usize = 64;
const MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_BOOT_ID_BYTES: usize = 128;
const DEFAULT_GRACEFUL_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_FORCE_TIMEOUT: Duration = Duration::from_secs(10);

/// A Linux adapter that owns one delegated cgroup per launched component.
///
/// The allowlist is keyed by component role and contains canonical executable
/// paths.  An empty allowlist is valid as a value but every launch is rejected;
/// this prevents the adapter from turning into a general command runner.
#[derive(Debug)]
pub struct LinuxProcessAdapter {
    cgroup_root: CgroupRoot,
    boot_id: String,
    allowlist: BTreeMap<ComponentKind, PathBuf>,
    children: BTreeMap<String, ManagedProcess>,
    max_children: usize,
    signal_helper: Option<PathBuf>,
}

impl LinuxProcessAdapter {
    /// Discover the cgroup delegated to the current process and construct an
    /// adapter.  Failure is explicit when cgroup v2 is absent or not delegated.
    pub fn new(allowlist: BTreeMap<ComponentKind, PathBuf>) -> Result<Self, AdapterError> {
        let root = discover_delegated_cgroup()?;
        Self::with_cgroup_root(root, allowlist)
    }

    /// Construct an adapter against an explicit cgroup root.  This is useful
    /// for a service that receives a delegated subtree from its supervisor and
    /// for deterministic tests; callers must still provide the actual writable
    /// cgroup v2 directory, not a parent mount guessed by name.
    pub fn with_cgroup_root(
        root: impl Into<PathBuf>,
        allowlist: BTreeMap<ComponentKind, PathBuf>,
    ) -> Result<Self, AdapterError> {
        Self::with_cgroup_root_and_limit(root, allowlist, MAX_ACTIVE_CHILDREN)
    }

    /// Construct an adapter with an explicit active-child bound.
    pub fn with_cgroup_root_and_limit(
        root: impl Into<PathBuf>,
        allowlist: BTreeMap<ComponentKind, PathBuf>,
        max_children: usize,
    ) -> Result<Self, AdapterError> {
        if max_children == 0 || max_children > MAX_ACTIVE_CHILDREN {
            return Err(AdapterError::Invalid(
                "Linux process limit is outside bounds".to_owned(),
            ));
        }
        let root = root.into();
        let cgroup_root = CgroupRoot::open(&root)?;
        let boot_id = read_boot_id()?;
        let allowlist = validate_allowlist(allowlist)?;
        // Creating and removing a probe proves that the caller can create a
        // delegated child cgroup.  It avoids reporting a read-only cgroup
        // mount as a merely unhealthy adapter at the first launch attempt.
        cgroup_root.probe_delegation()?;
        Ok(Self {
            cgroup_root,
            boot_id,
            allowlist,
            children: BTreeMap::new(),
            max_children,
            signal_helper: find_signal_helper(),
        })
    }

    /// Return the delegated cgroup root used for this adapter.
    #[must_use]
    pub fn cgroup_root(&self) -> &Path {
        self.cgroup_root.path()
    }

    /// Return the configured role-to-executable allowlist.
    #[must_use]
    pub fn allowlist(&self) -> &BTreeMap<ComponentKind, PathBuf> {
        &self.allowlist
    }

    fn maybe_cgroup_for_identity(
        &self,
        identity: &ProcessIdentity,
    ) -> Result<Option<Cgroup>, AdapterError> {
        let name = containment_name(identity.containment.as_str())?;
        self.cgroup_root.maybe_existing(&name)
    }

    fn observe_identity(
        &mut self,
        identity: &ProcessIdentity,
        cgroup: &Cgroup,
    ) -> Result<Observation, AdapterError> {
        let pids = cgroup.pids()?;
        if pids.is_empty() {
            let exit_code = self
                .children
                .get_mut(identity.containment.as_str())
                .and_then(ManagedProcess::exit_code);
            return Ok(
                exit_code.map_or(Observation::Exited { code: None }, |code| {
                    Observation::Exited { code: Some(code) }
                }),
            );
        }
        if !pids.contains(&identity.creation.pid) {
            // The cgroup is still populated but its recorded leader is gone.
            // Do not guess which remaining process is the replacement.
            return Ok(Observation::Ambiguous);
        }
        match read_live_process(&self.boot_id, identity.creation.pid) {
            Ok(actual) if identities_match(identity, &actual) => {
                Ok(Observation::Running(identity.clone()))
            }
            Ok(_) => Ok(Observation::IdentityMismatch),
            Err(AdapterError::Unavailable(_)) => Ok(Observation::Ambiguous),
            Err(error) => Err(error),
        }
    }

    fn cleanup_if_empty(
        &mut self,
        identity: &ProcessIdentity,
        cgroup: &Cgroup,
    ) -> Result<bool, AdapterError> {
        if !cgroup.pids()?.is_empty() {
            return Ok(false);
        }
        cgroup.remove()?;
        self.children.remove(identity.containment.as_str());
        Ok(true)
    }

    fn wait_for_empty(
        &mut self,
        identity: &ProcessIdentity,
        cgroup: &Cgroup,
        timeout: Duration,
    ) -> Result<bool, AdapterError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        loop {
            if let Some(managed) = self.children.get_mut(identity.containment.as_str()) {
                if let Some(child) = managed.child.as_mut() {
                    let _ = child.try_wait();
                }
            }
            if cgroup.pids()?.is_empty() {
                cgroup.remove()?;
                self.children.remove(identity.containment.as_str());
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn send_graceful_term(
        &self,
        identity: &ProcessIdentity,
        cgroup: &Cgroup,
    ) -> Result<(), AdapterError> {
        let Some(helper) = &self.signal_helper else {
            return Err(AdapterError::Unavailable(
                "no fixed /bin/kill or /usr/bin/kill helper is available".to_owned(),
            ));
        };
        // Re-read both birth identity and cgroup membership immediately before
        // the helper call.  cgroup.kill remains the only descendant authority.
        let pids = cgroup.pids()?;
        if !pids.contains(&identity.creation.pid) {
            return Err(AdapterError::IdentityMismatch(
                "recorded leader is not in its cgroup".to_owned(),
            ));
        }
        match read_live_process(&self.boot_id, identity.creation.pid) {
            Ok(actual) if identities_match(identity, &actual) => {}
            Ok(_) => {
                return Err(AdapterError::IdentityMismatch(
                    "process birth or executable identity changed".to_owned(),
                ));
            }
            Err(error) => return Err(error),
        }
        let status = Command::new(helper)
            .arg("-TERM")
            .arg(identity.creation.pid.to_string())
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| AdapterError::Io(format!("graceful TERM helper: {error}")))?;
        if status.success() {
            Ok(())
        } else {
            Err(AdapterError::Io(format!(
                "graceful TERM helper exited with {status}"
            )))
        }
    }
}

impl ProcessAdapter for LinuxProcessAdapter {
    fn inventory(&mut self, expected: &[OwnedProcess]) -> Result<Vec<Observation>, AdapterError> {
        if expected.len() > MAX_CGROUP_PIDS {
            return Err(AdapterError::Invalid(
                "process inventory exceeds bounds".to_owned(),
            ));
        }
        expected
            .iter()
            .map(|process| self.inspect(process))
            .collect()
    }

    fn launch(&mut self, specification: &LaunchSpec) -> Result<OwnedProcess, AdapterError> {
        specification.validate()?;
        if self.children.len() >= self.max_children {
            return Err(AdapterError::Unavailable(
                "Linux process adapter active-child limit reached".to_owned(),
            ));
        }
        if let SessionSelector::Explicit(_) = specification.session {
            return Err(AdapterError::Unsupported(
                "Linux adapter does not select Windows user sessions".to_owned(),
            ));
        }

        let executable = canonical_approved_executable(
            self.allowlist.get(&specification.component),
            &specification.executable,
            &specification.executable_sha256,
        )?;
        validate_working_directory(specification.working_directory.as_deref())?;
        validate_environment(&specification.environment)?;

        let name = make_containment_name(specification);
        let cgroup = self.cgroup_root.create(&name)?;
        let mut child = match spawn_direct(specification, &executable) {
            Ok(child) => child,
            Err(error) => {
                let _ = cgroup.remove();
                return Err(error);
            }
        };
        let pid = child.id();
        let actual = match read_live_process(&self.boot_id, pid) {
            Ok(actual) => actual,
            Err(error) => {
                terminate_failed_child(&mut child);
                let _ = cgroup.remove();
                return Err(error);
            }
        };
        if actual.executable != executable
            || actual.executable_sha256 != specification.executable_sha256
        {
            terminate_failed_child(&mut child);
            let _ = cgroup.remove();
            return Err(AdapterError::IdentityMismatch(
                "spawned executable identity does not match the approved launch".to_owned(),
            ));
        }
        if let Err(error) = cgroup.add_process(pid) {
            terminate_failed_child(&mut child);
            let _ = cgroup.remove();
            return Err(error);
        }
        let containment = ContainmentId::new(format!("{CGROUP_PREFIX}{name}"))?;
        let identity = ProcessIdentity {
            deployment_id: specification.deployment_id.clone(),
            instance_id: specification.instance_id.clone(),
            component: specification.component,
            incarnation: specification.incarnation.clone(),
            launch_nonce: specification.launch_nonce.clone(),
            creation: ProcessCreation {
                token: actual.token,
                pid,
            },
            executable,
            executable_sha256: actual.executable_sha256,
            containment,
            session: None,
        };
        let owned = OwnedProcess {
            identity: identity.clone(),
        };
        if !cgroup.pids()?.contains(&pid) {
            terminate_failed_child(&mut child);
            let _ = cgroup.remove();
            return Err(AdapterError::Unavailable(
                "child could not be observed in its delegated cgroup".to_owned(),
            ));
        }
        self.children.insert(
            identity.containment.as_str().to_owned(),
            ManagedProcess {
                child: Some(child),
                graceful_timeout: specification.graceful_timeout,
                force_timeout: specification.force_timeout,
            },
        );
        Ok(owned)
    }

    fn inspect(&mut self, process: &OwnedProcess) -> Result<Observation, AdapterError> {
        let Some(cgroup) = self.maybe_cgroup_for_identity(&process.identity)? else {
            return Ok(Observation::Missing);
        };
        self.observe_identity(&process.identity, &cgroup)
    }

    fn graceful_stop(&mut self, process: &OwnedProcess) -> Result<StopOutcome, AdapterError> {
        let Some(cgroup) = self.maybe_cgroup_for_identity(&process.identity)? else {
            return Ok(StopOutcome::AlreadyExited);
        };
        match self.observe_identity(&process.identity, &cgroup)? {
            Observation::Exited { .. } | Observation::Missing => {
                let _ = self.cleanup_if_empty(&process.identity, &cgroup)?;
                return Ok(StopOutcome::AlreadyExited);
            }
            Observation::IdentityMismatch | Observation::Ambiguous => {
                return Err(AdapterError::IdentityMismatch(
                    "cannot gracefully stop an unverified cgroup member".to_owned(),
                ));
            }
            Observation::Running(_) => {}
        }
        self.send_graceful_term(&process.identity, &cgroup)?;
        if self.wait_for_empty(
            &process.identity,
            &cgroup,
            self.timeout_for(&process.identity, true),
        )? {
            Ok(StopOutcome::Exited)
        } else {
            Ok(StopOutcome::TimedOut)
        }
    }

    fn force_stop(&mut self, process: &OwnedProcess) -> Result<StopOutcome, AdapterError> {
        let Some(cgroup) = self.maybe_cgroup_for_identity(&process.identity)? else {
            return Ok(StopOutcome::AlreadyExited);
        };
        match self.observe_identity(&process.identity, &cgroup)? {
            Observation::Missing => return Ok(StopOutcome::AlreadyExited),
            Observation::Exited { .. } => {
                if self.cleanup_if_empty(&process.identity, &cgroup)? {
                    return Ok(StopOutcome::AlreadyExited);
                }
            }
            Observation::IdentityMismatch => {
                return Err(AdapterError::IdentityMismatch(
                    "cannot force-stop an unverified cgroup owner".to_owned(),
                ));
            }
            Observation::Ambiguous => {
                // The cgroup itself is an exact generated containment ID.  If
                // its recorded leader died while descendants remain, the
                // cgroup authority is still sufficient for bounded cleanup;
                // no PID/name lookup is used.
            }
            Observation::Running(_) => {}
        }
        cgroup.kill_all()?;
        if self.wait_for_empty(
            &process.identity,
            &cgroup,
            self.timeout_for(&process.identity, false),
        )? {
            Ok(StopOutcome::Exited)
        } else {
            Ok(StopOutcome::TimedOut)
        }
    }
}

impl LinuxProcessAdapter {
    fn timeout_for(&self, identity: &ProcessIdentity, graceful: bool) -> Duration {
        self.children.get(identity.containment.as_str()).map_or(
            if graceful {
                DEFAULT_GRACEFUL_TIMEOUT
            } else {
                DEFAULT_FORCE_TIMEOUT
            },
            |managed| {
                if graceful {
                    managed.graceful_timeout
                } else {
                    managed.force_timeout
                }
            },
        )
    }
}

#[derive(Debug)]
struct ManagedProcess {
    child: Option<Child>,
    graceful_timeout: Duration,
    force_timeout: Duration,
}

impl ManagedProcess {
    fn exit_code(&mut self) -> Option<i32> {
        self.child
            .as_mut()
            .and_then(|child| child.try_wait().ok().flatten())
            .and_then(|status| status.code())
    }
}

#[derive(Clone, Debug)]
struct CgroupRoot {
    path: PathBuf,
}

impl CgroupRoot {
    fn open(path: &Path) -> Result<Self, AdapterError> {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            AdapterError::Unavailable(format!("cgroup root is unavailable: {error}"))
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(AdapterError::Unavailable(
                "cgroup root is not a directory".to_owned(),
            ));
        }
        let path = fs::canonicalize(path).map_err(|error| {
            AdapterError::Unavailable(format!("cgroup root cannot be canonicalized: {error}"))
        })?;
        for file in ["cgroup.procs", "cgroup.events", "cgroup.kill"] {
            let control = path.join(file);
            let metadata = fs::symlink_metadata(&control).map_err(|error| {
                AdapterError::Unavailable(format!("required {file} is unavailable: {error}"))
            })?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(AdapterError::Unavailable(format!(
                    "required cgroup control {file} is not a regular control file"
                )));
            }
        }
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn create(&self, name: &str) -> Result<Cgroup, AdapterError> {
        validate_cgroup_name(name)?;
        let path = self.path.join(name);
        if fs::symlink_metadata(&path).is_ok() {
            return Err(AdapterError::Unavailable(
                "requested cgroup containment already exists".to_owned(),
            ));
        }
        fs::create_dir(&path).map_err(|error| {
            AdapterError::Unavailable(format!("delegated cgroup creation failed: {error}"))
        })?;
        match Cgroup::existing(self, name) {
            Ok(cgroup) => Ok(cgroup),
            Err(error) => {
                let _ = fs::remove_dir(&path);
                Err(error)
            }
        }
    }

    fn maybe_existing(&self, name: &str) -> Result<Option<Cgroup>, AdapterError> {
        validate_cgroup_name(name)?;
        let path = self.path.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => Cgroup::existing(self, name).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(AdapterError::Unavailable(format!(
                "cannot inspect cgroup {name}: {error}"
            ))),
        }
    }

    fn probe_delegation(&self) -> Result<(), AdapterError> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let name = format!("ascension-probe-{}-{nonce}", std::process::id());
        let cgroup = self.create(&name)?;
        cgroup.remove()
    }
}

#[derive(Clone, Debug)]
struct Cgroup {
    name: String,
    path: PathBuf,
}

impl Cgroup {
    fn existing(root: &CgroupRoot, name: &str) -> Result<Self, AdapterError> {
        let path = root.path.join(name);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            AdapterError::Unavailable(format!("cgroup {name} does not exist: {error}"))
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(AdapterError::Unavailable(format!(
                "cgroup {name} is not a trusted directory"
            )));
        }
        let canonical = fs::canonicalize(&path).map_err(|error| {
            AdapterError::Unavailable(format!("cgroup {name} cannot be canonicalized: {error}"))
        })?;
        if !canonical.starts_with(&root.path) || canonical != path {
            return Err(AdapterError::Unavailable(format!(
                "cgroup {name} escaped the delegated root"
            )));
        }
        for file in ["cgroup.procs", "cgroup.events", "cgroup.kill"] {
            let control = path.join(file);
            let metadata = fs::symlink_metadata(&control).map_err(|error| {
                AdapterError::Unavailable(format!("cgroup {name} lacks {file}: {error}"))
            })?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(AdapterError::Unavailable(format!(
                    "cgroup {name} has invalid {file}"
                )));
            }
        }
        Ok(Self {
            name: name.to_owned(),
            path,
        })
    }

    fn add_process(&self, pid: u32) -> Result<(), AdapterError> {
        if pid == 0 {
            return Err(AdapterError::Invalid("cannot assign pid zero".to_owned()));
        }
        self.write_control("cgroup.procs", &pid.to_string())
            .map_err(|error| {
                AdapterError::Unavailable(format!("cgroup assignment failed: {error}"))
            })
    }

    fn pids(&self) -> Result<Vec<u32>, AdapterError> {
        let content = fs::read_to_string(self.path.join("cgroup.procs")).map_err(|error| {
            AdapterError::Unavailable(format!("cannot inspect cgroup {}: {error}", self.name))
        })?;
        let mut pids = Vec::new();
        for line in content.lines() {
            if pids.len() >= MAX_CGROUP_PIDS {
                return Err(AdapterError::Unavailable(
                    "cgroup process membership exceeds bounds".to_owned(),
                ));
            }
            let pid = line.trim().parse::<u32>().map_err(|_| {
                AdapterError::Unavailable(format!("cgroup {} contains an invalid pid", self.name))
            })?;
            if pid == 0 {
                return Err(AdapterError::Unavailable(
                    "cgroup process membership contains pid zero".to_owned(),
                ));
            }
            if !pids.contains(&pid) {
                pids.push(pid);
            }
        }
        Ok(pids)
    }

    fn kill_all(&self) -> Result<(), AdapterError> {
        self.write_control("cgroup.kill", "1").map_err(|error| {
            AdapterError::Unavailable(format!("cgroup force cleanup failed: {error}"))
        })
    }

    fn write_control(&self, file: &str, value: &str) -> std::io::Result<()> {
        let path = self.path.join(file);
        let mut handle = OpenOptions::new().write(true).open(path)?;
        handle.write_all(value.as_bytes())
    }

    fn remove(&self) -> Result<(), AdapterError> {
        if !self.pids()?.is_empty() {
            return Err(AdapterError::Timeout(format!(
                "cgroup {} still contains processes",
                self.name
            )));
        }
        fs::remove_dir(&self.path).map_err(|error| {
            AdapterError::Io(format!("cannot remove empty cgroup {}: {error}", self.name))
        })?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct LiveProcess {
    token: String,
    executable: PathBuf,
    executable_sha256: String,
}

fn validate_allowlist(
    allowlist: BTreeMap<ComponentKind, PathBuf>,
) -> Result<BTreeMap<ComponentKind, PathBuf>, AdapterError> {
    for path in allowlist.values() {
        if !path.is_absolute() || path.as_os_str().is_empty() {
            return Err(AdapterError::Invalid(
                "Linux executable allowlist paths must be absolute".to_owned(),
            ));
        }
    }
    Ok(allowlist)
}

fn canonical_approved_executable(
    approved: Option<&PathBuf>,
    requested: &Path,
    expected_digest: &str,
) -> Result<PathBuf, AdapterError> {
    let Some(approved) = approved else {
        return Err(AdapterError::Unsupported(
            "component role has no Linux executable allowlist entry".to_owned(),
        ));
    };
    let approved = fs::canonicalize(approved).map_err(|error| {
        AdapterError::Unavailable(format!("approved executable is unavailable: {error}"))
    })?;
    let requested = fs::canonicalize(requested).map_err(|error| {
        AdapterError::Invalid(format!("requested executable cannot be resolved: {error}"))
    })?;
    if approved != requested {
        return Err(AdapterError::IdentityMismatch(
            "requested executable is outside the role allowlist".to_owned(),
        ));
    }
    let metadata = fs::metadata(&requested).map_err(|error| {
        AdapterError::Unavailable(format!("approved executable metadata failed: {error}"))
    })?;
    if !metadata.is_file() {
        return Err(AdapterError::Invalid(
            "approved executable is not a regular file".to_owned(),
        ));
    }
    let digest = hash_file(&requested)?;
    if digest != expected_digest {
        return Err(AdapterError::IdentityMismatch(
            "approved executable digest does not match the launch".to_owned(),
        ));
    }
    Ok(requested)
}

fn validate_working_directory(path: Option<&Path>) -> Result<(), AdapterError> {
    let Some(path) = path else {
        return Ok(());
    };
    if !path.is_absolute() {
        return Err(AdapterError::Invalid(
            "Linux working directory must be absolute".to_owned(),
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        AdapterError::Invalid(format!("working directory cannot be resolved: {error}"))
    })?;
    if !canonical.is_dir() {
        return Err(AdapterError::Invalid(
            "Linux working directory is not a directory".to_owned(),
        ));
    }
    Ok(())
}

fn validate_environment(environment: &[(String, String)]) -> Result<(), AdapterError> {
    for (name, value) in environment {
        if name.is_empty()
            || name.contains('=')
            || name.chars().any(char::is_control)
            || value.chars().any(char::is_control)
        {
            return Err(AdapterError::Invalid(
                "Linux environment contains an invalid name or value".to_owned(),
            ));
        }
    }
    Ok(())
}

fn spawn_direct(specification: &LaunchSpec, executable: &Path) -> Result<Child, AdapterError> {
    let mut command = Command::new(executable);
    command
        .args(&specification.arguments)
        .env_clear()
        .envs(
            specification
                .environment
                .iter()
                .map(|(name, value)| (name, value)),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(path) = specification.working_directory.as_deref() {
        let canonical = fs::canonicalize(path).map_err(|error| {
            AdapterError::Invalid(format!("working directory cannot be resolved: {error}"))
        })?;
        command.current_dir(canonical);
    }
    command
        .spawn()
        .map_err(|error| AdapterError::Io(format!("direct child launch failed: {error}")))
}

fn terminate_failed_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn identities_match(expected: &ProcessIdentity, actual: &LiveProcess) -> bool {
    expected.creation.token == actual.token
        && expected.executable == actual.executable
        && expected.executable_sha256 == actual.executable_sha256
}

fn read_live_process(boot_id: &str, pid: u32) -> Result<LiveProcess, AdapterError> {
    if pid == 0 {
        return Err(AdapterError::Invalid("cannot inspect pid zero".to_owned()));
    }
    let stat_path = format!("/proc/{pid}/stat");
    let stat = fs::read_to_string(&stat_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AdapterError::Unavailable(format!("process {pid} does not exist"))
        } else {
            AdapterError::Io(format!("cannot read process {pid} birth data: {error}"))
        }
    })?;
    let start_ticks = parse_start_ticks(&stat)
        .ok_or_else(|| AdapterError::Io(format!("process {pid} has malformed /proc stat data")))?;
    let executable = fs::canonicalize(format!("/proc/{pid}/exe")).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AdapterError::Unavailable(format!("process {pid} executable is gone"))
        } else {
            AdapterError::Io(format!("cannot read process {pid} executable: {error}"))
        }
    })?;
    let executable_sha256 = hash_file(&executable)?;
    Ok(LiveProcess {
        token: format!("{boot_id}:{start_ticks}"),
        executable,
        executable_sha256,
    })
}

fn parse_start_ticks(stat: &str) -> Option<u64> {
    let close = stat.rfind(')')?;
    let suffix = stat.get(close + 2..)?;
    suffix.split_whitespace().nth(19)?.parse().ok()
}

fn read_boot_id() -> Result<String, AdapterError> {
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|error| {
        AdapterError::Unavailable(format!("Linux boot identity is unavailable: {error}"))
    })?;
    let boot_id = boot_id.trim();
    if boot_id.is_empty()
        || boot_id.len() > MAX_BOOT_ID_BYTES
        || boot_id.contains(['\0', '\n', '\r'])
    {
        return Err(AdapterError::Unavailable(
            "Linux boot identity is malformed".to_owned(),
        ));
    }
    Ok(boot_id.to_owned())
}

fn hash_file(path: &Path) -> Result<String, AdapterError> {
    let metadata = fs::metadata(path).map_err(|error| {
        AdapterError::Unavailable(format!("cannot inspect executable bytes: {error}"))
    })?;
    if metadata.len() > MAX_HASH_BYTES {
        return Err(AdapterError::Invalid(
            "executable exceeds the hash size bound".to_owned(),
        ));
    }
    let file = File::open(path).map_err(|error| {
        AdapterError::Unavailable(format!("cannot open executable bytes: {error}"))
    })?;
    let mut reader = file;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| AdapterError::Io(format!("cannot hash executable: {error}")))?;
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

fn make_containment_name(specification: &LaunchSpec) -> String {
    let mut hasher = Sha256::new();
    for value in [
        specification.deployment_id.as_bytes(),
        specification.instance_id.as_bytes(),
        specification.incarnation.as_bytes(),
        specification.launch_nonce.as_bytes(),
    ] {
        hasher.update(value);
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let suffix = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("ascension-{suffix}")
}

fn containment_name(value: &str) -> Result<String, AdapterError> {
    let Some(name) = value.strip_prefix(CGROUP_PREFIX) else {
        return Err(AdapterError::Invalid(
            "process containment is not a Linux cgroup identity".to_owned(),
        ));
    };
    validate_cgroup_name(name)?;
    Ok(name.to_owned())
}

fn validate_cgroup_name(name: &str) -> Result<(), AdapterError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(AdapterError::Invalid(
            "process containment name is outside bounds".to_owned(),
        ));
    }
    Ok(())
}

fn find_signal_helper() -> Option<PathBuf> {
    [Path::new("/bin/kill"), Path::new("/usr/bin/kill")]
        .iter()
        .find_map(|path| {
            let canonical = fs::canonicalize(path).ok()?;
            let metadata = fs::metadata(&canonical).ok()?;
            metadata.is_file().then_some(canonical)
        })
}

fn discover_delegated_cgroup() -> Result<PathBuf, AdapterError> {
    let mountpoint = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| {
            AdapterError::Unavailable(format!("cgroup mountinfo unavailable: {error}"))
        })?
        .lines()
        .find_map(parse_cgroup2_mountpoint)
        .ok_or_else(|| AdapterError::Unavailable("no cgroup v2 mount is available".to_owned()))?;
    let relative = fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| AdapterError::Unavailable(format!("process cgroup unavailable: {error}")))?
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
        .ok_or_else(|| AdapterError::Unavailable("process has no cgroup v2 path".to_owned()))?;
    let relative = relative.trim_start_matches('/');
    if relative
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(AdapterError::Unavailable(
            "process cgroup path is malformed".to_owned(),
        ));
    }
    let path = if relative.is_empty() {
        mountpoint
    } else {
        mountpoint.join(relative)
    };
    Ok(path)
}

fn parse_cgroup2_mountpoint(line: &str) -> Option<PathBuf> {
    let mut sections = line.split(" - ");
    let pre = sections.next()?;
    let post = sections.next()?;
    if post
        .split_whitespace()
        .next()
        .is_none_or(|kind| kind != "cgroup2")
    {
        return None;
    }
    let fields = pre.split_whitespace().collect::<Vec<_>>();
    fields
        .get(4)
        .map(|field| PathBuf::from(unescape_mountinfo(field)))
}

fn unescape_mountinfo(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\134", "\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_start_time_after_comm_field() {
        let mut fields = vec!["123", "(command with spaces)", "R"];
        fields.extend(std::iter::repeat_n("0", 18));
        fields.push("987654");
        let stat = fields.join(" ");
        assert_eq!(parse_start_ticks(&stat), Some(987_654));
    }

    #[test]
    fn containment_identity_rejects_path_traversal() {
        assert!(containment_name("cgroup-v2:../outside").is_err());
        assert!(containment_name("cgroup-v2:ascension-good").is_ok());
    }

    #[test]
    fn mountinfo_parser_only_accepts_cgroup_v2() {
        let line = "42 30 0:99 / /sys/fs/cgroup rw,nosuid,nodev - cgroup2 cgroup rw";
        assert_eq!(
            parse_cgroup2_mountpoint(line),
            Some(PathBuf::from("/sys/fs/cgroup"))
        );
        let other = "42 30 0:99 / /sys/fs/cgroup rw - tmpfs tmpfs rw";
        assert!(parse_cgroup2_mountpoint(other).is_none());
    }

    #[test]
    fn adapter_reports_unavailable_for_non_cgroup_root() {
        let result = LinuxProcessAdapter::with_cgroup_root(PathBuf::from("/tmp"), BTreeMap::new());
        assert!(matches!(result, Err(AdapterError::Unavailable(_))));
    }

    #[test]
    fn native_synthetic_process_authority_is_explicitly_gated()
    -> Result<(), Box<dyn std::error::Error>> {
        let executable = fs::canonicalize("/bin/sh")?;
        let digest = hash_file(&executable)?;
        let mut allowlist = BTreeMap::new();
        allowlist.insert(ComponentKind::Synthetic, executable.clone());
        let mut adapter = match LinuxProcessAdapter::new(allowlist) {
            Ok(adapter) => adapter,
            Err(AdapterError::Unavailable(_)) => return Ok(()),
            Err(error) => return Err(Box::new(error)),
        };
        let specification = LaunchSpec {
            deployment_id: "native-test-deployment".to_owned(),
            instance_id: "native-test-instance".to_owned(),
            component: ComponentKind::Synthetic,
            incarnation: "native-test-incarnation".to_owned(),
            launch_nonce: format!("native-test-{}", std::process::id()),
            executable,
            executable_sha256: digest,
            arguments: vec!["-c".to_owned(), "sleep 30 & wait".to_owned()],
            working_directory: None,
            environment: Vec::new(),
            session: SessionSelector::ActiveUser,
            graceful_timeout: Duration::from_millis(100),
            force_timeout: Duration::from_secs(2),
        };
        let owned = adapter.launch(&specification)?;
        assert!(matches!(adapter.inspect(&owned)?, Observation::Running(_)));
        let outcome = adapter.force_stop(&owned)?;
        assert!(matches!(
            outcome,
            StopOutcome::Exited | StopOutcome::AlreadyExited
        ));
        assert!(matches!(adapter.inspect(&owned)?, Observation::Missing));
        Ok(())
    }
}
