//! Linux process authority backed by delegated cgroup v2.
//!
//! This module intentionally uses only safe Rust.  A durable cgroup is created
//! before a trusted helper is spawned; the helper is moved into that cgroup,
//! verified there, and only then allowed to create the requested target.  The
//! cgroup is the authority used for descendant cleanup; a PID is checked
//! against both `/proc` birth data and the exact cgroup before it is observed
//! or signalled.  If the current service does not have a writable delegated
//! cgroup with `cgroup.kill`, construction fails explicitly with
//! [`AdapterError::Unavailable`].
//!
//! The adapter uses the exact helper `Child` handle for launch-failure cleanup,
//! a Linux pidfd for the bounded graceful TERM request, and cgroup v2
//! `cgroup.kill` for force cleanup.  The latter is the only operation that is
//! allowed to terminate descendants.  The helper barrier is a safe supervisor
//! seam; the target executable is handed off through a verified file
//! sealed executable snapshot by the launcher.

use super::contract::{
    AdapterError, ComponentKind, ContainmentId, LaunchSpec, Observation, OwnedProcess,
    ProcessAdapter, ProcessCreation, ProcessIdentity, SessionSelector, StopOutcome,
};
use super::linux_launcher::TrustedLinuxLauncher;
use crate::worker_bootstrap::WorkerBootstrapLaunch;
use rustix::fs::{SealFlags, fcntl_get_seals};
use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CGROUP_PREFIX: &str = "cgroup-v2:";
const MAX_CGROUP_PIDS: usize = 4_096;
const MAX_ACTIVE_CHILDREN: usize = 64;
const MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_BOOT_ID_BYTES: usize = 128;
const DEFAULT_GRACEFUL_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_FORCE_TIMEOUT: Duration = Duration::from_secs(10);
const FAILED_LAUNCH_CLEANUP_TIMEOUT: Duration = Duration::from_millis(500);

/// Stable marker for the runtime integration: an adapter launch error carries
/// retained containment authority and must not clean the durable launch intent
/// or admit a replacement until exact cgroup reconciliation succeeds.
pub const CLEANUP_UNCERTAIN_MARKER: &str = "linux-launch-cleanup-uncertain";

/// Return whether a Linux launch error retains a planned cgroup authority.
/// Runtime code can use this without parsing the full diagnostic string.
#[must_use]
pub fn is_cleanup_uncertain(error: &AdapterError) -> bool {
    matches!(
        error,
        AdapterError::Unavailable(message) if message.contains(CLEANUP_UNCERTAIN_MARKER)
    )
}

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
    /// Containments whose launch failed while cleanup could not prove that
    /// the cgroup was removed.  Keeping this authority in the adapter makes
    /// a retry fail closed until the exact planned containment is reconciled.
    uncertain_containments: BTreeMap<String, Cgroup>,
    max_children: usize,
    launcher: TrustedLinuxLauncher,
}

impl LinuxProcessAdapter {
    /// Discover the cgroup delegated to the current process and construct an
    /// adapter.  Failure is explicit when cgroup v2 is absent or not delegated.
    pub fn new(allowlist: BTreeMap<ComponentKind, PathBuf>) -> Result<Self, AdapterError> {
        let root = discover_delegated_cgroup()?;
        Self::with_cgroup_root(root, allowlist)
    }

    /// Discover the current delegated cgroup and construct an adapter with a
    /// caller-supplied trusted helper executable.  This is the native service
    /// test seam; production callers should use [`Self::new`] after the
    /// watchdog executable has wired its hidden helper entrypoint.
    pub fn new_with_launcher(
        allowlist: BTreeMap<ComponentKind, PathBuf>,
        launcher: TrustedLinuxLauncher,
    ) -> Result<Self, AdapterError> {
        let root = discover_delegated_cgroup()?;
        Self::with_cgroup_root_and_limit_and_launcher(
            root,
            allowlist,
            MAX_ACTIVE_CHILDREN,
            launcher,
        )
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
        let launcher = TrustedLinuxLauncher::current_executable()?;
        Self::with_cgroup_root_and_limit_and_launcher(root, allowlist, max_children, launcher)
    }

    /// Construct an adapter with an explicit helper executable.
    ///
    /// This is the seam used by a real watchdog executable and by platform
    /// tests.  The helper must dispatch [`super::linux_launcher::helper_argument`]
    /// before normal CLI parsing; no direct-spawn fallback exists.
    pub fn with_cgroup_root_and_limit_and_launcher(
        root: impl Into<PathBuf>,
        allowlist: BTreeMap<ComponentKind, PathBuf>,
        max_children: usize,
        launcher: TrustedLinuxLauncher,
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
            uncertain_containments: BTreeMap::new(),
            max_children,
            launcher,
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

    /// Return the configured trusted helper launcher.
    #[must_use]
    pub fn launcher(&self) -> &TrustedLinuxLauncher {
        &self.launcher
    }

    /// Return whether a planned containment remains retained after an
    /// unproven launch cleanup.  The runtime must keep the corresponding
    /// durable launch intent unsettled while this is true.
    #[must_use]
    pub fn has_uncertain_containment(&self, containment: &ContainmentId) -> bool {
        containment_name(containment.as_str())
            .ok()
            .is_some_and(|name| self.uncertain_containments.contains_key(&name))
    }

    /// Reconcile one exact planned containment without requiring a process
    /// identity.  This is the recovery path for a launch that never produced
    /// an `OwnedProcess` but whose cgroup authority could not be proven clean.
    /// A new launch using the same containment is rejected until this method
    /// returns [`StopOutcome::AlreadyExited`] or [`StopOutcome::Exited`].
    pub fn force_cleanup_planned_containment(
        &mut self,
        containment: &ContainmentId,
    ) -> Result<StopOutcome, AdapterError> {
        let name = containment_name(containment.as_str())?;
        let Some(cgroup) = self.cgroup_root.maybe_existing(&name)? else {
            self.uncertain_containments.remove(&name);
            return Ok(StopOutcome::AlreadyExited);
        };
        self.uncertain_containments
            .insert(name.clone(), cgroup.clone());
        cgroup.kill_all()?;
        if self.wait_for_empty_by_containment(&name, &cgroup, DEFAULT_FORCE_TIMEOUT)? {
            self.uncertain_containments.remove(&name);
            Ok(StopOutcome::Exited)
        } else {
            self.uncertain_containments.insert(name, cgroup);
            Ok(StopOutcome::TimedOut)
        }
    }

    /// Derive the exact containment identity that must be persisted before a
    /// launch effect is attempted.  The value is deterministic only from the
    /// complete launch identity, including its fresh nonce.
    pub fn planned_containment_for(
        specification: &LaunchSpec,
    ) -> Result<ContainmentId, AdapterError> {
        specification.validate()?;
        let name = make_containment_name(specification);
        ContainmentId::new(format!("{CGROUP_PREFIX}{name}"))
    }

    /// Launch using the exact containment identity already recorded in the
    /// durable launch intent.  A mismatched or malformed value is rejected;
    /// the adapter never silently substitutes a newly generated cgroup.
    pub fn launch_with_planned_containment(
        &mut self,
        specification: &LaunchSpec,
        planned_containment: &ContainmentId,
    ) -> Result<OwnedProcess, AdapterError> {
        let expected = Self::planned_containment_for(specification)?;
        if &expected != planned_containment {
            return Err(AdapterError::IdentityMismatch(
                "planned Linux containment does not match the launch identity".to_owned(),
            ));
        }
        self.launch_with_containment(specification, Some(planned_containment))
    }

    /// Launch a Harness worker with the exact immutable bootstrap frame
    /// delivered through a dedicated anonymous pipe after helper GO.
    pub fn launch_with_worker_bootstrap(
        &mut self,
        specification: &LaunchSpec,
        worker: &WorkerBootstrapLaunch,
    ) -> Result<OwnedProcess, AdapterError> {
        self.launch_with_containment_and_worker(specification, None, Some(worker))
    }

    /// Launch a Harness worker with a durable containment identity and the
    /// exact immutable bootstrap frame delivered through a dedicated pipe.
    pub fn launch_with_planned_containment_and_worker_bootstrap(
        &mut self,
        specification: &LaunchSpec,
        planned_containment: &ContainmentId,
        worker: &WorkerBootstrapLaunch,
    ) -> Result<OwnedProcess, AdapterError> {
        let expected = Self::planned_containment_for(specification)?;
        if &expected != planned_containment {
            return Err(AdapterError::IdentityMismatch(
                "planned Linux containment does not match the launch identity".to_owned(),
            ));
        }
        self.launch_with_containment_and_worker(
            specification,
            Some(planned_containment),
            Some(worker),
        )
    }

    fn maybe_cgroup_for_identity(
        &self,
        identity: &ProcessIdentity,
    ) -> Result<Option<Cgroup>, AdapterError> {
        let name = containment_name(identity.containment.as_str())?;
        self.cgroup_root.maybe_existing(&name)
    }

    fn wait_for_empty_by_containment(
        &mut self,
        name: &str,
        cgroup: &Cgroup,
        timeout: Duration,
    ) -> Result<bool, AdapterError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        loop {
            if cgroup.pids()?.is_empty() {
                cgroup.remove()?;
                self.uncertain_containments.remove(name);
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(POLL_INTERVAL);
        }
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
        // Open a pidfd before the final identity check.  The fd binds the
        // kernel operation to this process incarnation; sending a signal to
        // the numeric PID after a `/proc` check would still permit a PID reuse
        // race.  cgroup.kill remains the only descendant authority.
        let pids = cgroup.pids()?;
        if !pids.contains(&identity.creation.pid) {
            return Err(AdapterError::IdentityMismatch(
                "recorded leader is not in its cgroup".to_owned(),
            ));
        }
        let raw_pid = i32::try_from(identity.creation.pid).map_err(|_| {
            AdapterError::Invalid("recorded Linux PID exceeds the pidfd range".to_owned())
        })?;
        let pid = Pid::from_raw(raw_pid)
            .ok_or_else(|| AdapterError::Invalid("recorded Linux PID is zero".to_owned()))?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty()).map_err(|error| {
            AdapterError::Unavailable(format!(
                "Linux pidfd_open could not bind the graceful-stop target: {error}"
            ))
        })?;
        match read_live_process(&self.boot_id, identity.creation.pid) {
            Ok(actual) if identities_match(identity, &actual) => {}
            Ok(_) => {
                return Err(AdapterError::IdentityMismatch(
                    "process birth or executable identity changed".to_owned(),
                ));
            }
            Err(error) => return Err(error),
        }
        // Re-check membership after pidfd_open.  If the process exits and its
        // PID is reused, the pidfd still refers to the original process and
        // the creation-token check above rejects the replacement.
        if !cgroup.pids()?.contains(&identity.creation.pid) {
            return Err(AdapterError::IdentityMismatch(
                "recorded leader left its cgroup before graceful stop".to_owned(),
            ));
        }
        pidfd_send_signal(&pidfd, Signal::TERM).map_err(|error| {
            AdapterError::Unavailable(format!(
                "Linux pidfd_send_signal could not deliver graceful TERM: {error}"
            ))
        })
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
        self.launch_with_containment(specification, None)
    }

    fn inspect(&mut self, process: &OwnedProcess) -> Result<Observation, AdapterError> {
        LinuxProcessAdapter::inspect(self, process)
    }

    fn graceful_stop(&mut self, process: &OwnedProcess) -> Result<StopOutcome, AdapterError> {
        LinuxProcessAdapter::graceful_stop(self, process)
    }

    fn force_stop(&mut self, process: &OwnedProcess) -> Result<StopOutcome, AdapterError> {
        LinuxProcessAdapter::force_stop(self, process)
    }
}

impl LinuxProcessAdapter {
    fn launch_with_containment(
        &mut self,
        specification: &LaunchSpec,
        planned_containment: Option<&ContainmentId>,
    ) -> Result<OwnedProcess, AdapterError> {
        self.launch_with_containment_and_worker(specification, planned_containment, None)
    }

    fn launch_with_containment_and_worker(
        &mut self,
        specification: &LaunchSpec,
        planned_containment: Option<&ContainmentId>,
        worker: Option<&WorkerBootstrapLaunch>,
    ) -> Result<OwnedProcess, AdapterError> {
        specification.validate()?;
        if self.children.len() >= self.max_children {
            return Err(AdapterError::Unavailable(
                "Linux process adapter active-child limit reached".to_owned(),
            ));
        }
        if specification.component == ComponentKind::HostBroker {
            return Err(AdapterError::Unsupported(
                "Linux adapter does not launch graphical HostBroker sessions".to_owned(),
            ));
        }
        if let SessionSelector::Explicit(session) = specification.session
            && session != 0
        {
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

        let containment = match planned_containment {
            Some(containment) => containment.clone(),
            None => Self::planned_containment_for(specification)?,
        };
        let name = containment_name(containment.as_str())?;
        if self.uncertain_containments.contains_key(&name) {
            return Err(AdapterError::Unavailable(format!(
                "{CLEANUP_UNCERTAIN_MARKER}: planned Linux containment {CGROUP_PREFIX}{name} remains retained; reconcile it before relaunch"
            )));
        }
        let cgroup = self.cgroup_root.create(&name)?;
        let mut pending = match match worker {
            Some(worker) => {
                self.launcher
                    .prepare_with_worker_bootstrap(specification, cgroup.path(), worker)
            }
            None => self.launcher.prepare(specification, cgroup.path()),
        } {
            Ok(pending) => pending,
            Err(error) => {
                return Err(self.launch_error_after_cleanup(&cgroup, None, error));
            }
        };
        let Some(helper_pid) = pending.pid() else {
            drop(pending);
            return Err(self.launch_error_after_cleanup(
                &cgroup,
                None,
                AdapterError::Unavailable("Linux helper did not expose a PID".to_owned()),
            ));
        };
        let launch_timeout = pending.timeout();
        if let Err(error) = cgroup.add_process(helper_pid) {
            drop(pending);
            return Err(self.launch_error_after_cleanup(&cgroup, None, error));
        }
        let helper_identity = match read_live_process(&self.boot_id, helper_pid) {
            Ok(identity) => identity,
            Err(error) => {
                drop(pending);
                return Err(self.launch_error_after_cleanup(&cgroup, None, error));
            }
        };
        if !live_process_matches_executable(
            &helper_identity,
            self.launcher.helper_executable(),
            self.launcher.helper_executable_sha256(),
        ) {
            drop(pending);
            return Err(self.launch_error_after_cleanup(
                &cgroup,
                None,
                AdapterError::IdentityMismatch(
                    "spawned Linux helper executable identity is unexpected".to_owned(),
                ),
            ));
        }
        let helper_is_member = match cgroup.pids() {
            Ok(pids) => pids.contains(&helper_pid),
            Err(error) => {
                drop(pending);
                return Err(self.launch_error_after_cleanup(&cgroup, None, error));
            }
        };
        if !helper_is_member {
            drop(pending);
            return Err(self.launch_error_after_cleanup(
                &cgroup,
                None,
                AdapterError::Unavailable(
                    "Linux helper could not be observed in its delegated cgroup".to_owned(),
                ),
            ));
        }
        if let Err(error) = pending.release_gate() {
            drop(pending);
            return Err(self.launch_error_after_cleanup(&cgroup, None, error));
        }
        let mut child = match pending.into_child() {
            Ok(child) => child,
            Err(error) => {
                return Err(self.launch_error_after_cleanup(&cgroup, None, error));
            }
        };
        let (pid, actual) = match wait_for_target_in_cgroup(
            &self.boot_id,
            &cgroup,
            helper_pid,
            &executable,
            &specification.executable_sha256,
            launch_timeout,
            &mut child,
        ) {
            Ok(identity) => identity,
            Err(error) => {
                return Err(self.launch_error_after_cleanup(&cgroup, Some(&mut child), error));
            }
        };
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
        let target_is_member = match cgroup.pids() {
            Ok(pids) => pids.contains(&pid),
            Err(error) => {
                return Err(self.launch_error_after_cleanup(&cgroup, Some(&mut child), error));
            }
        };
        if !target_is_member {
            return Err(self.launch_error_after_cleanup(
                &cgroup,
                Some(&mut child),
                AdapterError::Unavailable(
                    "child could not be observed in its delegated cgroup".to_owned(),
                ),
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

    fn launch_error_after_cleanup(
        &mut self,
        cgroup: &Cgroup,
        child: Option<&mut Child>,
        launch_error: AdapterError,
    ) -> AdapterError {
        match cleanup_failed_cgroup_launch(cgroup, child) {
            Ok(()) => launch_error,
            Err(failure) => {
                if failure.containment_retained {
                    self.uncertain_containments
                        .insert(cgroup.name.clone(), cgroup.clone());
                    return AdapterError::Unavailable(format!(
                        "{CLEANUP_UNCERTAIN_MARKER}: launch failed ({launch_error}); planned containment {CGROUP_PREFIX}{} cleanup could not be proven: {}",
                        cgroup.name, failure.error
                    ));
                }
                AdapterError::Unavailable(format!(
                    "launch failed ({launch_error}); planned containment {CGROUP_PREFIX}{} cleanup reported an error after removal was proven: {}",
                    cgroup.name, failure.error
                ))
            }
        }
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
            return Err(AdapterError::Unavailable(format!(
                "{CLEANUP_UNCERTAIN_MARKER}: requested cgroup containment {name} already exists; exact planned authority must be reconciled"
            )));
        }
        fs::create_dir(&path).map_err(|error| {
            AdapterError::Unavailable(format!("delegated cgroup creation failed: {error}"))
        })?;
        match Cgroup::existing(self, name) {
            Ok(cgroup) => Ok(cgroup),
            Err(error) => match fs::remove_dir(&path) {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(AdapterError::Unavailable(format!(
                    "{CLEANUP_UNCERTAIN_MARKER}: cgroup {name} verification failed ({error}); planned containment remains retained because removal failed: {cleanup_error}"
                ))),
            },
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

    fn path(&self) -> &Path {
        &self.path
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
    executable_sealed: bool,
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

fn wait_for_target_in_cgroup(
    boot_id: &str,
    cgroup: &Cgroup,
    helper_pid: u32,
    executable: &Path,
    digest: &str,
    timeout: Duration,
    child: &mut Child,
) -> Result<(u32, LiveProcess), AdapterError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    loop {
        if let Some(status) = child.try_wait().map_err(|error| {
            AdapterError::Io(format!("Linux helper status check failed: {error}"))
        })? {
            return Err(AdapterError::Io(format!(
                "Linux helper exited before the approved target appeared: {status}"
            )));
        }
        if !cgroup.pids()?.contains(&helper_pid) {
            return Err(AdapterError::IdentityMismatch(
                "Linux helper left its delegated cgroup before target exec".to_owned(),
            ));
        }
        match read_live_process_for_executable(boot_id, helper_pid, executable) {
            Ok(Some(actual)) if actual.executable_sha256 == digest => {
                return Ok((helper_pid, actual));
            }
            Ok(Some(_) | None) => {}
            Err(AdapterError::Unavailable(_)) => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(AdapterError::Timeout(
                "Linux helper did not produce the approved target in time".to_owned(),
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn read_live_process_for_executable(
    boot_id: &str,
    pid: u32,
    expected_executable: &Path,
) -> Result<Option<LiveProcess>, AdapterError> {
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
    let executable_sealed = is_sealed_memfd(&executable);
    if executable != expected_executable {
        if !executable_sealed || !executable_fd_is_sealed(pid)? {
            return Ok(None);
        }
    }
    let executable_sha256 = hash_live_executable(pid)?;
    Ok(Some(LiveProcess {
        token: format!("{boot_id}:{start_ticks}"),
        executable: if executable == expected_executable {
            executable
        } else {
            expected_executable.to_owned()
        },
        executable_sha256,
        executable_sealed,
    }))
}

#[derive(Debug)]
struct CleanupFailure {
    error: AdapterError,
    containment_retained: bool,
}

/// Kill and reap a failed launch, then prove that its planned cgroup is empty
/// and removed.  Every failure is returned to the caller; when the proof is
/// incomplete the containment remains a live authority and callers must retain
/// the launch intent rather than report a clean failure and relaunch.
fn cleanup_failed_cgroup_launch(
    cgroup: &Cgroup,
    child: Option<&mut Child>,
) -> Result<(), CleanupFailure> {
    cleanup_failed_cgroup_launch_with(cgroup, child, terminate_failed_child)
}

fn cleanup_failed_cgroup_launch_with(
    cgroup: &Cgroup,
    child: Option<&mut Child>,
    terminate: impl FnOnce(&mut Child, Instant) -> Result<(), AdapterError>,
) -> Result<(), CleanupFailure> {
    // The deadline covers both direct-child termination and the cgroup
    // membership/removal proof.  Starting this clock only after `wait()`
    // would let a failed launch hang indefinitely before containment is
    // checked.
    let deadline = Instant::now()
        .checked_add(FAILED_LAUNCH_CLEANUP_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let mut first_error = None;
    if let Err(error) = cgroup.kill_all() {
        first_error = Some(error);
    }
    let mut child_cleanup_failed = false;
    if let Some(child) = child {
        if let Err(error) = terminate(child, deadline) {
            if first_error.is_none() {
                first_error = Some(error);
            }
            child_cleanup_failed = true;
        }
    }

    loop {
        match cgroup.pids() {
            Ok(pids) if pids.is_empty() => {
                if child_cleanup_failed {
                    // An empty cgroup proves no member remains, but it does
                    // not prove that the exact Child handle was reaped.  Keep
                    // the cgroup as the durable recovery authority until the
                    // next reconciliation pass proves both facts.
                    let error = match first_error {
                        Some(error) => error,
                        None => AdapterError::Timeout(
                            "child cleanup failed without a diagnostic".to_owned(),
                        ),
                    };
                    return Err(CleanupFailure {
                        error,
                        containment_retained: true,
                    });
                }
                break;
            }
            Ok(_) if Instant::now() < deadline => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                std::thread::sleep(POLL_INTERVAL.min(remaining));
            }
            Ok(_) => {
                return Err(CleanupFailure {
                    error: AdapterError::Timeout(format!(
                        "planned containment {} still has members after failed launch cleanup",
                        cgroup.name
                    )),
                    containment_retained: true,
                });
            }
            Err(error) => {
                return Err(CleanupFailure {
                    error,
                    containment_retained: true,
                });
            }
        }
    }

    if let Err(error) = cgroup.remove() {
        return Err(CleanupFailure {
            error,
            containment_retained: true,
        });
    }
    if let Some(error) = first_error {
        // The final empty-and-removed proof means no process authority was
        // retained.  Preserve the cleanup diagnostic without falsely blocking
        // a future launch on a cgroup that is demonstrably gone.
        return Err(CleanupFailure {
            error,
            containment_retained: false,
        });
    }
    Ok(())
}

fn terminate_failed_child(child: &mut Child, deadline: Instant) -> Result<(), AdapterError> {
    terminate_failed_child_with(child, deadline, Child::kill)
}

fn terminate_failed_child_with(
    child: &mut Child,
    deadline: Instant,
    mut kill: impl FnMut(&mut Child) -> std::io::Result<()>,
) -> Result<(), AdapterError> {
    if child
        .try_wait()
        .map_err(|error| AdapterError::Io(format!("failed launch child status: {error}")))?
        .is_some()
    {
        return Ok(());
    }
    let kill_error = kill(child)
        .err()
        .map(|error| AdapterError::Io(format!("failed launch child kill: {error}")));
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return match kill_error {
                    None => Ok(()),
                    Some(error) => Err(error),
                };
            }
            Ok(None) if Instant::now() < deadline => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                std::thread::sleep(POLL_INTERVAL.min(remaining));
            }
            Ok(None) => {
                return Err(AdapterError::Timeout(format!(
                    "failed launch child did not exit before cleanup deadline ({:?})",
                    kill_error.map(|error| error.to_string())
                )));
            }
            Err(error) => {
                return Err(AdapterError::Io(format!(
                    "failed launch child reap status ({:?}): {error}",
                    kill_error.map(|error| error.to_string())
                )));
            }
        }
    }
}

fn identities_match(expected: &ProcessIdentity, actual: &LiveProcess) -> bool {
    expected.creation.token == actual.token
        && expected.executable_sha256 == actual.executable_sha256
        && live_process_matches_executable(
            actual,
            &expected.executable,
            &expected.executable_sha256,
        )
}

fn live_process_matches_executable(
    actual: &LiveProcess,
    expected_executable: &Path,
    expected_digest: &str,
) -> bool {
    (actual.executable == expected_executable
        || (actual.executable_sealed && is_sealed_memfd(&actual.executable)))
        && actual.executable_sha256 == expected_digest
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
    let executable_sha256 = hash_live_executable(pid)?;
    let executable_sealed = is_sealed_memfd(&executable) && executable_fd_is_sealed(pid)?;
    Ok(LiveProcess {
        token: format!("{boot_id}:{start_ticks}"),
        executable,
        executable_sha256,
        executable_sealed,
    })
}

fn is_sealed_memfd(path: &Path) -> bool {
    path.to_str()
        .is_some_and(|value| value.starts_with("/memfd:"))
}

fn executable_fd_is_sealed(pid: u32) -> Result<bool, AdapterError> {
    let path = format!("/proc/{pid}/exe");
    let flags = rustix::fs::OFlags::NONBLOCK
        .bits()
        .try_into()
        .map_err(|_| AdapterError::Invalid("Linux nonblocking flag is out of range".to_owned()))?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|error| {
            AdapterError::Unavailable(format!(
                "cannot open live executable for seal check: {error}"
            ))
        })?;
    let seals = fcntl_get_seals(&file).map_err(|error| {
        AdapterError::Unavailable(format!("cannot inspect live executable seals: {error}"))
    })?;
    Ok(seals.contains(SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL))
}

fn hash_live_executable(pid: u32) -> Result<String, AdapterError> {
    hash_file(Path::new(&format!("/proc/{pid}/exe")))
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
    let flags = rustix::fs::OFlags::NONBLOCK
        .bits()
        .try_into()
        .map_err(|_| AdapterError::Invalid("Linux nonblocking flag is out of range".to_owned()))?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|error| {
            AdapterError::Unavailable(format!("cannot open executable bytes: {error}"))
        })?;
    let metadata = file.metadata().map_err(|error| {
        AdapterError::Unavailable(format!("cannot inspect executable bytes: {error}"))
    })?;
    if !metadata.is_file() {
        return Err(AdapterError::Invalid(
            "executable is not a regular file".to_owned(),
        ));
    }
    if metadata.len() > MAX_HASH_BYTES {
        return Err(AdapterError::Invalid(
            "executable exceeds the hash size bound".to_owned(),
        ));
    }
    let mut reader = file;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total_read = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| AdapterError::Io(format!("cannot hash executable: {error}")))?;
        if read == 0 {
            break;
        }
        total_read = total_read
            .checked_add(u64::try_from(read).map_err(|_| {
                AdapterError::Invalid("executable read size exceeds bounds".to_owned())
            })?)
            .ok_or_else(|| {
                AdapterError::Invalid("executable exceeds the hash size bound".to_owned())
            })?;
        if total_read > MAX_HASH_BYTES {
            return Err(AdapterError::Invalid(
                "executable exceeds the hash size bound".to_owned(),
            ));
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
    use std::fs;
    use std::process::{Child, Command};
    use tempfile::tempdir;

    struct ChildGuard(Option<Child>);

    impl ChildGuard {
        fn sleep() -> Result<Self, std::io::Error> {
            Ok(Self(Some(Command::new("/bin/sleep").arg("30").spawn()?)))
        }

        fn as_mut(&mut self) -> &mut Child {
            self.0.as_mut().expect("test child guard owns a child")
        }

        fn reap(&mut self) -> Result<(), std::io::Error> {
            if let Some(mut child) = self.0.take() {
                child.kill()?;
                child.wait()?;
            }
            Ok(())
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.reap();
        }
    }

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
    fn cleanup_uncertainty_is_distinguishable_from_ordinary_launch_failure() {
        let uncertain =
            AdapterError::Unavailable(format!("{CLEANUP_UNCERTAIN_MARKER}: cgroup-v2:planned"));
        let ordinary = AdapterError::Unavailable("helper did not start".to_owned());
        assert!(is_cleanup_uncertain(&uncertain));
        assert!(!is_cleanup_uncertain(&ordinary));
    }

    #[test]
    fn pidfd_identity_input_rejects_zero_and_overflow() {
        assert!(Pid::from_raw(0).is_none());
        assert!(i32::try_from(u32::MAX).is_err());
        assert!(Pid::from_raw(1).is_some());
    }

    fn fake_cgroup(procs: &str) -> Result<(tempfile::TempDir, Cgroup), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let root_path = directory.path().join("root");
        let cgroup_path = root_path.join("failed-launch");
        fs::create_dir_all(&cgroup_path)?;
        for file in ["cgroup.procs", "cgroup.events", "cgroup.kill"] {
            fs::write(
                cgroup_path.join(file),
                if file == "cgroup.procs" { procs } else { "" },
            )?;
        }
        let root = CgroupRoot { path: root_path };
        let cgroup = Cgroup::existing(&root, "failed-launch")?;
        Ok((directory, cgroup))
    }

    #[test]
    fn failed_launch_cleanup_retains_authority_when_membership_read_faults()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, cgroup) = fake_cgroup("not-a-pid\n")?;
        let failure = cleanup_failed_cgroup_launch(&cgroup, None).unwrap_err();
        assert!(failure.containment_retained);
        assert!(matches!(failure.error, AdapterError::Unavailable(_)));
        assert!(cgroup.path().exists());
        Ok(())
    }

    #[test]
    fn synthetic_child_termination_fault_is_deadline_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut child = ChildGuard::sleep()?;
        let started = Instant::now();
        let result = terminate_failed_child_with(child.as_mut(), Instant::now(), |_| {
            Err(std::io::Error::other("synthetic kill failure"))
        });
        assert!(matches!(result, Err(AdapterError::Timeout(_))));
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "synthetic termination fault exceeded deadline: {:?}",
            started.elapsed()
        );
        child.reap()?;
        Ok(())
    }

    #[test]
    fn synthetic_unproven_reap_retains_empty_containment() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_directory, cgroup) = fake_cgroup("")?;
        let mut child = ChildGuard::sleep()?;
        let failure = cleanup_failed_cgroup_launch_with(&cgroup, Some(child.as_mut()), |_, _| {
            Err(AdapterError::Timeout(
                "synthetic child reap timeout".to_owned(),
            ))
        })
        .unwrap_err();
        assert!(failure.containment_retained);
        assert!(matches!(failure.error, AdapterError::Timeout(_)));
        assert!(cgroup.path().exists());
        child.reap()?;
        Ok(())
    }

    #[test]
    #[ignore = "requires a writable delegated cgroup v2 and a real watchdog helper entrypoint"]
    fn native_synthetic_process_authority_is_explicitly_gated()
    -> Result<(), Box<dyn std::error::Error>> {
        let executable = fs::canonicalize("/bin/sh")?;
        let digest = hash_file(&executable)?;
        let mut allowlist = BTreeMap::new();
        allowlist.insert(ComponentKind::Synthetic, executable.clone());
        let mut adapter = LinuxProcessAdapter::new(allowlist)?;
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
            session: SessionSelector::Explicit(0),
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
