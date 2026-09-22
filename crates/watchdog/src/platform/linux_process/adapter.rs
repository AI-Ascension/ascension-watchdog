//! Adapter configuration and launch orchestration for the Linux process
//! adapter.
//!
//! This module owns the [`LinuxProcessAdapter`] constructors, delegated
//! cgroup admission at construction time, the planned-containment entry
//! points and the bootstrap/launch pipeline.  Observation, stop/uncertain
//! cleanup and the cgroup control primitives live in sibling modules; the
//! coordinator preserves the public `platform::linux_process` paths.

#[allow(clippy::wildcard_imports)]
use super::*;

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
    /// returns [`StopOutcome::AlreadyExited`] or [`StopOutcome::Exited`].  A
    /// missing cgroup is not a terminal outcome: without a process identity or
    /// a retained cgroup handle, its absence cannot prove that a helper or
    /// descendant was not moved out of the planned containment.
    pub fn force_cleanup_planned_containment(
        &mut self,
        containment: &ContainmentId,
    ) -> Result<StopOutcome, AdapterError> {
        let name = containment_name(containment.as_str())?;
        let Some(cgroup) = self.cgroup_root.maybe_existing(&name)? else {
            return Err(AdapterError::Unavailable(format!(
                "{CLEANUP_UNCERTAIN_MARKER}: planned Linux containment {CGROUP_PREFIX}{name} is missing; exact cleanup cannot be proven"
            )));
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

    /// Launch a Gateway with a durable containment identity and a fixed,
    /// one-shot health bootstrap delivered through the target's exclusive
    /// standard input.
    ///
    /// The health frame is not part of the helper control stream and is never
    /// copied into command-line arguments, environment variables, or config.
    /// The helper validates its magic, fixed length, Gateway role, and exact
    /// launch nonce after GO before replacing itself with the approved target.
    pub fn launch_with_planned_containment_and_gateway_health_bootstrap(
        &mut self,
        specification: &LaunchSpec,
        planned_containment: &ContainmentId,
        gateway_health: &GatewayHealthBootstrap,
    ) -> Result<OwnedProcess, AdapterError> {
        let expected = Self::planned_containment_for(specification)?;
        if &expected != planned_containment {
            return Err(AdapterError::IdentityMismatch(
                "planned Linux containment does not match the launch identity".to_owned(),
            ));
        }
        self.launch_with_containment_and_gateway_health(
            specification,
            Some(planned_containment),
            gateway_health,
        )
    }
}

impl LinuxProcessAdapter {
    pub(super) fn launch_with_containment(
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
        self.launch_with_bootstraps(specification, planned_containment, worker, None)
    }

    fn launch_with_containment_and_gateway_health(
        &mut self,
        specification: &LaunchSpec,
        planned_containment: Option<&ContainmentId>,
        gateway_health: &GatewayHealthBootstrap,
    ) -> Result<OwnedProcess, AdapterError> {
        self.launch_with_bootstraps(
            specification,
            planned_containment,
            None,
            Some(gateway_health),
        )
    }

    fn launch_with_bootstraps(
        &mut self,
        specification: &LaunchSpec,
        planned_containment: Option<&ContainmentId>,
        worker: Option<&WorkerBootstrapLaunch>,
        gateway_health: Option<&GatewayHealthBootstrap>,
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
        let mut pending = match match (worker, gateway_health) {
            (Some(worker), None) => {
                self.launcher
                    .prepare_with_worker_bootstrap(specification, cgroup.path(), worker)
            }
            (None, Some(gateway_health)) => self.launcher.prepare_with_gateway_health_bootstrap(
                specification,
                cgroup.path(),
                gateway_health,
            ),
            (None, None) => self.launcher.prepare(specification, cgroup.path()),
            (Some(_), Some(_)) => Err(AdapterError::Invalid(
                "Linux worker and Gateway health bootstraps cannot be combined".to_owned(),
            )),
        } {
            Ok(pending) => pending,
            Err(error) => {
                return Err(self.launch_error_after_cleanup(&cgroup, None, error));
            }
        };
        let Some(helper_pid) = pending.pid() else {
            return Err(self.launch_error_after_pending_cleanup(
                &cgroup,
                pending,
                AdapterError::Unavailable("Linux helper did not expose a PID".to_owned()),
            ));
        };
        let launch_timeout = pending.timeout();
        if let Err(error) = cgroup.add_process(helper_pid) {
            return Err(self.launch_error_after_pending_cleanup(&cgroup, pending, error));
        }
        let helper_identity = match read_live_process(&self.boot_id, helper_pid) {
            Ok(identity) => identity,
            Err(error) => {
                return Err(self.launch_error_after_pending_cleanup(&cgroup, pending, error));
            }
        };
        if !live_process_matches_executable(
            &helper_identity,
            self.launcher.helper_executable(),
            self.launcher.helper_executable_sha256(),
        ) {
            return Err(self.launch_error_after_pending_cleanup(
                &cgroup,
                pending,
                AdapterError::IdentityMismatch(
                    "spawned Linux helper executable identity is unexpected".to_owned(),
                ),
            ));
        }
        let helper_is_member = match cgroup.pids() {
            Ok(pids) => pids.contains(&helper_pid),
            Err(error) => {
                return Err(self.launch_error_after_pending_cleanup(&cgroup, pending, error));
            }
        };
        if !helper_is_member {
            return Err(self.launch_error_after_pending_cleanup(
                &cgroup,
                pending,
                AdapterError::Unavailable(
                    "Linux helper could not be observed in its delegated cgroup".to_owned(),
                ),
            ));
        }
        if let Err(error) = pending.release_gate() {
            return Err(self.launch_error_after_pending_cleanup(&cgroup, pending, error));
        }
        let mut child = match pending.take_child() {
            Ok(child) => child,
            Err(error) => {
                return Err(self.launch_error_after_pending_cleanup(&cgroup, pending, error));
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
                exit_status: None,
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
        let cleanup = cleanup_failed_cgroup_launch(cgroup, child);
        self.finish_launch_error_after_cleanup(cgroup, launch_error, cleanup)
    }

    fn launch_error_after_pending_cleanup(
        &mut self,
        cgroup: &Cgroup,
        mut pending: PendingLaunch,
        launch_error: AdapterError,
    ) -> AdapterError {
        // Keep the exact Child handle alive while the cgroup cleanup proof is
        // performed.  Dropping PendingLaunch first would discard that proof
        // and could incorrectly turn a failed helper termination into a clean
        // launch failure.
        pending.close_handoff_descriptors();
        let cleanup = cleanup_failed_cgroup_launch(cgroup, pending.child_mut());
        drop(pending);
        self.finish_launch_error_after_cleanup(cgroup, launch_error, cleanup)
    }

    fn finish_launch_error_after_cleanup(
        &mut self,
        cgroup: &Cgroup,
        launch_error: AdapterError,
        cleanup: Result<(), CleanupFailure>,
    ) -> AdapterError {
        match cleanup {
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
}
