//! observe component of the Linux process adapter.
//!
//! Extracted from `platform::linux_process` into a cohesive module; the
//! coordinator preserves the public `platform::linux_process` paths and
//! delegates to these items.  Bodies are behaviour-preserving moves.

#[allow(clippy::wildcard_imports)]
use super::*;

impl LinuxProcessAdapter {
    pub(super) fn maybe_cgroup_for_identity(
        &self,
        identity: &ProcessIdentity,
    ) -> Result<Option<Cgroup>, AdapterError> {
        let name = containment_name(identity.containment.as_str())?;
        self.cgroup_root.maybe_existing(&name)
    }

    pub(super) fn wait_for_empty_by_containment(
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

    pub(super) fn observe_identity(
        &mut self,
        identity: &ProcessIdentity,
        cgroup: &Cgroup,
    ) -> Result<Observation, AdapterError> {
        let pids = cgroup.pids()?;
        if pids.is_empty() {
            // An empty cgroup is not itself proof that the exact target died:
            // a membership read can race a still-running child or a cgroup
            // implementation can report an empty snapshot during teardown.
            // Require the retained Child handle to observe an actual exit.
            return Ok(match self.child_state(identity.containment.as_str())? {
                ManagedChildState::Exited(code) => Observation::Exited { code },
                ManagedChildState::Alive | ManagedChildState::Unknown => Observation::Ambiguous,
            });
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

    pub(super) fn cleanup_if_empty(
        &mut self,
        identity: &ProcessIdentity,
        cgroup: &Cgroup,
    ) -> Result<bool, AdapterError> {
        if !cgroup.pids()?.is_empty() {
            return Ok(false);
        }
        if !matches!(
            self.child_state(identity.containment.as_str())?,
            ManagedChildState::Exited(_)
        ) {
            return Ok(false);
        }
        cgroup.remove()?;
        self.children.remove(identity.containment.as_str());
        Ok(true)
    }

    pub(super) fn wait_for_empty(
        &mut self,
        identity: &ProcessIdentity,
        cgroup: &Cgroup,
        timeout: Duration,
    ) -> Result<bool, AdapterError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        loop {
            let child_state = self.child_state(identity.containment.as_str())?;
            if cgroup.pids()?.is_empty() {
                if matches!(child_state, ManagedChildState::Exited(_)) {
                    cgroup.remove()?;
                    self.children.remove(identity.containment.as_str());
                    return Ok(true);
                }
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    pub(super) fn child_state(
        &mut self,
        containment: &str,
    ) -> Result<ManagedChildState, AdapterError> {
        let Some(managed) = self.children.get_mut(containment) else {
            return Ok(ManagedChildState::Unknown);
        };
        managed.state()
    }

    pub(super) fn missing_containment_status(
        &self,
        identity: &ProcessIdentity,
    ) -> Result<MissingContainmentStatus, AdapterError> {
        read_process_creation_status(
            &self.boot_id,
            identity.creation.pid,
            &identity.creation.token,
        )
    }

    pub(super) fn stop_missing_containment(
        &mut self,
        identity: &ProcessIdentity,
    ) -> Result<StopOutcome, AdapterError> {
        if !self.children.contains_key(identity.containment.as_str()) {
            return match self.missing_containment_status(identity)? {
                MissingContainmentStatus::Absent | MissingContainmentStatus::Reused => {
                    Ok(StopOutcome::AlreadyExited)
                }
                MissingContainmentStatus::Present => Err(AdapterError::Unavailable(
                    "Linux containment is missing while the recorded process remains present"
                        .to_owned(),
                )),
            };
        }
        match self.child_state(identity.containment.as_str())? {
            ManagedChildState::Exited(_) => {
                self.children.remove(identity.containment.as_str());
                Ok(StopOutcome::AlreadyExited)
            }
            ManagedChildState::Alive => Err(AdapterError::Unavailable(
                "Linux containment is missing before exact child exit was proven".to_owned(),
            )),
            ManagedChildState::Unknown => match self.missing_containment_status(identity)? {
                MissingContainmentStatus::Absent | MissingContainmentStatus::Reused => {
                    self.children.remove(identity.containment.as_str());
                    Ok(StopOutcome::AlreadyExited)
                }
                MissingContainmentStatus::Present => Err(AdapterError::Unavailable(
                    "Linux containment is missing while the recorded process remains present"
                        .to_owned(),
                )),
            },
        }
    }

    pub(super) fn send_graceful_term(
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

impl LinuxProcessAdapter {
    pub(super) fn inspect(&mut self, process: &OwnedProcess) -> Result<Observation, AdapterError> {
        let Some(cgroup) = self.maybe_cgroup_for_identity(&process.identity)? else {
            // A missing containment is only a clean observation once either
            // the exact retained child has exited or the persisted process
            // start token proves that the original process is absent/replaced.
            // If the token still belongs to a live process, a vanished cgroup
            // must remain ambiguous rather than becoming an implicit
            // exit/relaunch authorization.
            if !self
                .children
                .contains_key(process.identity.containment.as_str())
            {
                return match self.missing_containment_status(&process.identity)? {
                    MissingContainmentStatus::Absent | MissingContainmentStatus::Reused => {
                        Ok(Observation::Missing)
                    }
                    MissingContainmentStatus::Present => Ok(Observation::Ambiguous),
                };
            }
            return match self.child_state(process.identity.containment.as_str())? {
                ManagedChildState::Exited(_) => Ok(Observation::Missing),
                ManagedChildState::Alive => Ok(Observation::Ambiguous),
                ManagedChildState::Unknown => {
                    match self.missing_containment_status(&process.identity)? {
                        MissingContainmentStatus::Absent | MissingContainmentStatus::Reused => {
                            Ok(Observation::Missing)
                        }
                        MissingContainmentStatus::Present => Ok(Observation::Ambiguous),
                    }
                }
            };
        };
        self.observe_identity(&process.identity, &cgroup)
    }

    pub(super) fn graceful_stop(
        &mut self,
        process: &OwnedProcess,
    ) -> Result<StopOutcome, AdapterError> {
        let Some(cgroup) = self.maybe_cgroup_for_identity(&process.identity)? else {
            return self.stop_missing_containment(&process.identity);
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

    pub(super) fn force_stop(
        &mut self,
        process: &OwnedProcess,
    ) -> Result<StopOutcome, AdapterError> {
        let Some(cgroup) = self.maybe_cgroup_for_identity(&process.identity)? else {
            return self.stop_missing_containment(&process.identity);
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
    pub(super) fn timeout_for(&self, identity: &ProcessIdentity, graceful: bool) -> Duration {
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
pub(super) struct ManagedProcess {
    pub(super) child: Option<Child>,
    pub(super) exit_status: Option<ExitStatus>,
    pub(super) graceful_timeout: Duration,
    pub(super) force_timeout: Duration,
}

impl ManagedProcess {
    pub(super) fn state(&mut self) -> Result<ManagedChildState, AdapterError> {
        if let Some(status) = self.exit_status.as_ref() {
            return Ok(ManagedChildState::Exited(status.code()));
        }
        let Some(child) = self.child.as_mut() else {
            return Ok(ManagedChildState::Unknown);
        };
        match child.try_wait().map_err(|error| {
            AdapterError::Io(format!("Linux managed child status check failed: {error}"))
        })? {
            Some(status) => {
                let code = status.code();
                self.exit_status = Some(status);
                Ok(ManagedChildState::Exited(code))
            }
            None => Ok(ManagedChildState::Alive),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ManagedChildState {
    Alive,
    Exited(Option<i32>),
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MissingContainmentStatus {
    Present,
    Absent,
    Reused,
}

#[derive(Debug)]
pub(super) struct CleanupFailure {
    pub(super) error: AdapterError,
    pub(super) containment_retained: bool,
}

/// Kill and reap a failed launch, then prove that its planned cgroup is empty
/// and removed.  Every failure is returned to the caller; when the proof is
/// incomplete the containment remains a live authority and callers must retain
/// the launch intent rather than report a clean failure and relaunch.
pub(super) fn cleanup_failed_cgroup_launch(
    cgroup: &Cgroup,
    child: Option<&mut Child>,
) -> Result<(), CleanupFailure> {
    cleanup_failed_cgroup_launch_with(cgroup, child, terminate_failed_child)
}

pub(super) fn cleanup_failed_cgroup_launch_with(
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

pub(super) fn terminate_failed_child(
    child: &mut Child,
    deadline: Instant,
) -> Result<(), AdapterError> {
    terminate_failed_child_with(child, deadline, Child::kill)
}

pub(super) fn terminate_failed_child_with(
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
