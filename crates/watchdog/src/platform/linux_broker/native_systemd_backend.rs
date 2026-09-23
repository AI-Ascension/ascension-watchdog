//! `SystemdBackend` lifecycle effects for the native backend.
//!
//! This is the effectful half of [`super::NativeSystemdBackend`]: starting and
//! inspecting units, capturing retained containment for the exact freshly
//! started process, proving the original containment is empty before retiring
//! it, and stopping only the unit bound to an exact live observation. The
//! retained-containment state itself is owned by the coordinator; every check
//! here reuses the transport accessors and exact process-identity proofs rather
//! than resolving a replacement unit path.

#[allow(clippy::wildcard_imports)]
use super::*;

#[cfg(target_os = "linux")]
impl SystemdBackend for NativeSystemdBackend {
    #[allow(clippy::vec_init_then_push)]
    fn start(
        &mut self,
        unit: &str,
        request: &BrokerRequest,
        policy: &LaunchPolicy,
        bootstrap: Option<&bootstrap::BrokerBootstrapLaunch>,
        deadline: Instant,
    ) -> BrokerResult<UnitObservation> {
        if self.descriptor_store.is_none() {
            return Err(BrokerError::Unavailable(
                "authenticated manager descriptor store is unavailable".to_owned(),
            ));
        }
        if hash_open_file_until(File::open(&policy.executable).map_err(io_error)?, deadline)?
            != policy.executable_sha256
        {
            return Err(BrokerError::Conflict(
                "launch executable changed after policy admission".to_owned(),
            ));
        }
        let connection = Self::connection(deadline)?;
        let manager = Self::manager(&connection)?;
        let mut argv = Vec::with_capacity(policy.arguments.len() + 1);
        argv.push(policy.executable.to_string_lossy().into_owned());
        argv.extend(policy.arguments.iter().cloned());
        let exec_start = zbus::zvariant::Value::new(vec![(
            policy.executable.to_string_lossy().into_owned(),
            argv,
            false,
        )])
        .try_to_owned()
        .map_err(|error| {
            BrokerError::Invalid(format!("systemd ExecStart value failed: {error}"))
        })?;
        let environment = bootstrap_transport::launch_environment(policy, request, bootstrap)?;
        let mut properties = Vec::new();
        // The broker service is the owner of every transient unit.  If PID 1
        // observes this service leave active state, BindsTo tears down the
        // target instead of leaving an immortal process after owner death.
        properties.push((
            "BindsTo",
            zbus::zvariant::Value::new(vec![BROKER_UNIT_NAME.to_owned()])
                .try_to_owned()
                .map_err(|error| BrokerError::Invalid(error.to_string()))?,
        ));
        properties.push((
            "After",
            zbus::zvariant::Value::new(vec![BROKER_UNIT_NAME.to_owned()])
                .try_to_owned()
                .map_err(|error| BrokerError::Invalid(error.to_string()))?,
        ));
        properties.push(("ExecStart", exec_start));
        if let Some(bootstrap) = bootstrap {
            // D-Bus transports this value as an out-of-band Unix descriptor,
            // not StandardInputData or secret bytes in unit properties.
            properties.push((
                "StandardInputFileDescriptor",
                native_bootstrap::stdin_property(request, bootstrap)?,
            ));
        }
        properties.push((
            "User",
            zbus::zvariant::Value::new(policy.target_uid.to_string())
                .try_to_owned()
                .map_err(|error| BrokerError::Invalid(error.to_string()))?,
        ));
        properties.push((
            "Group",
            zbus::zvariant::Value::new(policy.target_gid.to_string())
                .try_to_owned()
                .map_err(|error| BrokerError::Invalid(error.to_string()))?,
        ));
        properties.push((
            "SupplementaryGroups",
            zbus::zvariant::Value::new(Vec::<String>::new())
                .try_to_owned()
                .map_err(|error| BrokerError::Invalid(error.to_string()))?,
        ));
        properties.push((
            "WorkingDirectory",
            zbus::zvariant::Value::new(policy.working_directory.to_string_lossy().into_owned())
                .try_to_owned()
                .map_err(|error| BrokerError::Invalid(error.to_string()))?,
        ));
        properties.push((
            "Environment",
            zbus::zvariant::Value::new(environment)
                .try_to_owned()
                .map_err(|error| BrokerError::Invalid(error.to_string()))?,
        ));
        properties.push((
            "CapabilityBoundingSet",
            zbus::zvariant::OwnedValue::from(policy.capabilities.bounding_set),
        ));
        properties.push((
            "AmbientCapabilities",
            zbus::zvariant::OwnedValue::from(policy.capabilities.ambient_set),
        ));
        properties.push((
            "NoNewPrivileges",
            zbus::zvariant::OwnedValue::from(policy.capabilities.no_new_privileges),
        ));
        properties.push(("Delegate", zbus::zvariant::OwnedValue::from(false)));
        properties.push((
            "KillMode",
            zbus::zvariant::Value::new("control-group")
                .try_to_owned()
                .map_err(|error| BrokerError::Invalid(error.to_string()))?,
        ));
        properties.push((
            "StandardOutput",
            zbus::zvariant::Value::new("null")
                .try_to_owned()
                .map_err(|error| BrokerError::Invalid(error.to_string()))?,
        ));
        properties.push((
            "StandardError",
            zbus::zvariant::Value::new("null")
                .try_to_owned()
                .map_err(|error| BrokerError::Invalid(error.to_string()))?,
        ));
        properties.push((
            "TasksMax",
            zbus::zvariant::OwnedValue::from(policy.cgroup.tasks_max),
        ));
        properties.push((
            "MemoryMax",
            zbus::zvariant::OwnedValue::from(policy.cgroup.memory_max_bytes),
        ));
        let timeout_us: u64 = policy.timeout.as_micros().try_into().map_err(|_| {
            BrokerError::Invalid("launch timeout overflows systemd property".to_owned())
        })?;
        properties.push((
            "TimeoutStartUSec",
            zbus::zvariant::OwnedValue::from(timeout_us),
        ));
        properties.push((
            "TimeoutStopUSec",
            zbus::zvariant::OwnedValue::from(timeout_us),
        ));
        let aux: Vec<(String, Vec<(String, zbus::zvariant::OwnedValue)>)> = Vec::new();
        let job_path: zbus::zvariant::OwnedObjectPath = manager
            .call("StartTransientUnit", &(unit, "fail", properties, aux))
            .map_err(|error| {
                BrokerError::Unavailable(format!("systemd transient unit start failed: {error}"))
            })?;
        // Keep the exact object returned by PID 1.  Reconstructing a job ID
        // from `unit` would permit a late or reused job to be mistaken for
        // this launch; the durable ledger binding is populated by the broker
        // integration seam after this method returns.
        let binding = ledger::JobBinding::from_object_path(unit, job_path.as_str())?;
        self.remember_queued_job(binding)?;
        loop {
            if let Some(observation) = Self::unit_observation(unit, policy, deadline)? {
                return Ok(observation);
            }
            let sleep_for = remaining(deadline)?.min(POLL_INTERVAL);
            thread::sleep(sleep_for);
        }
    }

    fn inspect(
        &mut self,
        unit: &str,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<Option<UnitObservation>> {
        Self::unit_observation(unit, policy, deadline)
    }

    fn retain_containment(
        &mut self,
        request: &BrokerRequest,
        expected: &UnitObservation,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<()> {
        remaining(deadline)?;
        expected.verify(&expected.unit, policy)?;
        if let Some(retained) = self.retained.get(&expected.unit) {
            if retained.observation != *expected {
                return Err(BrokerError::Conflict(
                    "retained containment identity changed".to_owned(),
                ));
            }
            return if retained.manager_stored {
                Ok(())
            } else {
                Err(BrokerError::Conflict(
                    "original capability has no manager-store acknowledgement".to_owned(),
                ))
            };
        }
        if self.retained.len() + self.unavailable.len() >= MAX_RECEIPTS {
            return Err(BrokerError::Unavailable(
                "retained containment capacity is exhausted".to_owned(),
            ));
        }
        let mut controls = HeldCgroup::open(&expected.control_group, deadline)?;
        // Acquire and recheck against the live process before publishing the
        // capability. Merely opening the expected pathname is not ownership.
        let _pidfd =
            super::native_process_identity::verify_held_process(expected, &mut controls, deadline)?;
        let receipt = receipt_from(request, expected, false);
        let name = descriptor_store::DescriptorName::for_receipt(&receipt)?;
        let store = self.descriptor_store.as_ref().ok_or_else(|| {
            BrokerError::Unavailable("authenticated descriptor store is unavailable".to_owned())
        })?;
        self.retained.insert(
            expected.unit.clone(),
            RetainedContainment {
                observation: expected.clone(),
                controls,
                empty_verified: false,
                manager_stored: false,
            },
        );
        let retained = self.retained.get_mut(&expected.unit).ok_or_else(|| {
            BrokerError::Conflict("newly captured containment is unavailable".to_owned())
        })?;
        // Preserve the locally verified original even if notification or
        // snapshot verification fails, so exact failed-launch cleanup can run.
        store.retain(&name, retained.controls.directory(), deadline)?;
        retained.manager_stored = true;
        Ok(())
    }

    fn verify_retirement(
        &mut self,
        expected: &LaunchReceipt,
        deadline: Instant,
    ) -> BrokerResult<bool> {
        remaining(deadline)?;
        let Some(retained) = self.retained.get_mut(&expected.unit) else {
            // Broker replacement loses process-local capabilities. Do not
            // substitute a fresh pathname or NoSuchUnit for the original proof.
            return Ok(false);
        };
        let original = receipt_from(&expected.request, &retained.observation, false);
        if !ledger::same_process_binding(&original, expected) {
            return Err(BrokerError::Conflict(
                "retirement receipt differs from retained containment".to_owned(),
            ));
        }
        if !retained.empty_verified {
            retained.empty_verified = retained.controls.is_empty(deadline)?;
        }
        Ok(retained.empty_verified)
    }

    fn release_retired(&mut self, receipt: &LaunchReceipt, deadline: Instant) -> BrokerResult<()> {
        if let Some(retained) = self.retained.get(&receipt.unit) {
            let original = receipt_from(&receipt.request, &retained.observation, false);
            if !ledger::same_process_binding(&original, receipt) {
                return Err(BrokerError::Conflict(
                    "retired descriptor receipt binding differs".to_owned(),
                ));
            }
        }
        let name = descriptor_store::DescriptorName::for_receipt(receipt)?;
        let store = self.descriptor_store.as_ref().ok_or_else(|| {
            BrokerError::Unavailable("authenticated descriptor store is unavailable".to_owned())
        })?;
        let directory = self
            .retained
            .get(&receipt.unit)
            .map(|retained| retained.controls.directory())
            .or_else(|| self.unavailable.get(&name));
        store.remove_retired(&name, directory, deadline)?;
        self.retained.remove(&receipt.unit);
        self.unavailable.remove(&name);
        Ok(())
    }

    fn require_retained_containment(
        &mut self,
        receipt: &LaunchReceipt,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<()> {
        remaining(deadline)?;
        verify_receipt_identity(
            receipt,
            &receipt.request,
            &unit_name(&receipt.request),
            policy,
        )?;
        let retained = self.retained.get(&receipt.unit).ok_or_else(|| {
            BrokerError::Conflict("original containment capability is unavailable".to_owned())
        })?;
        retained.observation.verify(&receipt.unit, policy)?;
        let original = receipt_from(&receipt.request, &retained.observation, false);
        if !ledger::same_process_binding(&original, receipt) {
            return Err(BrokerError::Conflict(
                "orphan cleanup receipt binding differs".to_owned(),
            ));
        }
        Ok(())
    }

    fn stop_retained_containment(
        &mut self,
        receipt: &LaunchReceipt,
        deadline: Instant,
    ) -> BrokerResult<()> {
        remaining(deadline)?;
        receipt.request.validate()?;
        if receipt.unit != unit_name(&receipt.request) {
            return Err(BrokerError::Conflict(
                "orphan cleanup unit binding differs".to_owned(),
            ));
        }
        let retained = self.retained.get_mut(&receipt.unit).ok_or_else(|| {
            BrokerError::Conflict("original containment capability is unavailable".to_owned())
        })?;
        let original = receipt_from(&receipt.request, &retained.observation, false);
        if !ledger::same_process_binding(&original, receipt) {
            return Err(BrokerError::Conflict(
                "orphan cleanup receipt binding differs".to_owned(),
            ));
        }
        // No leader is available for authenticated graceful signalling. Allow
        // a bounded drain interval for existing teardown, then force only the
        // held original group. Do not look up any current PID or unit object.
        let grace = (remaining(deadline)? / 2).min(Duration::from_secs(5));
        let graceful_deadline = Instant::now()
            .checked_add(grace)
            .unwrap_or(deadline)
            .min(deadline);
        loop {
            if retained.controls.is_empty(deadline)? {
                retained.empty_verified = true;
                return Ok(());
            }
            if Instant::now() >= graceful_deadline {
                break;
            }
            thread::sleep(
                graceful_deadline
                    .saturating_duration_since(Instant::now())
                    .min(POLL_INTERVAL),
            );
        }
        retained.controls.force_stop(deadline)?;
        loop {
            if retained.controls.is_empty(deadline)? {
                retained.empty_verified = true;
                return Ok(());
            }
            thread::sleep(remaining(deadline)?.min(POLL_INTERVAL));
        }
    }

    fn require_containment(
        &mut self,
        expected: &UnitObservation,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<()> {
        self.require_local_containment(expected, policy, deadline)?;
        if !self
            .retained
            .get(&expected.unit)
            .is_some_and(|retained| retained.manager_stored)
        {
            return Err(BrokerError::Conflict(
                "original capability has no manager-store acknowledgement".to_owned(),
            ));
        }
        Ok(())
    }

    fn require_local_containment(
        &mut self,
        expected: &UnitObservation,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<()> {
        remaining(deadline)?;
        expected.verify(&expected.unit, policy)?;
        let original = self.retained.get(&expected.unit).ok_or_else(|| {
            BrokerError::Conflict("original containment capability is unavailable".to_owned())
        })?;
        if original.observation != *expected {
            return Err(BrokerError::Conflict(
                "live process differs from retained containment".to_owned(),
            ));
        }
        Ok(())
    }

    fn stop(
        &mut self,
        unit: &str,
        expected: &UnitObservation,
        deadline: Instant,
    ) -> BrokerResult<()> {
        if expected.unit != unit || expected.pid == 0 || expected.creation_token.is_empty() {
            return Err(BrokerError::Conflict(
                "exact stop binding is invalid".to_owned(),
            ));
        }
        let retained = self.retained.get_mut(unit).ok_or_else(|| {
            BrokerError::Conflict("original containment capability is unavailable".to_owned())
        })?;
        if retained.observation != *expected {
            return Err(BrokerError::Conflict(
                "exact stop differs from retained containment".to_owned(),
            ));
        }
        let controls = &mut retained.controls;
        let pidfd =
            super::native_process_identity::verify_held_process(expected, controls, deadline)?;
        let remaining_time = remaining(deadline)?;
        let grace = (remaining_time / 2).min(Duration::from_secs(5));
        let graceful_deadline = Instant::now()
            .checked_add(grace)
            .unwrap_or(deadline)
            .min(deadline);
        match pidfd_send_signal(&pidfd, Signal::TERM) {
            Ok(()) | Err(Errno::SRCH) => {}
            Err(error) => {
                return Err(BrokerError::Unavailable(format!(
                    "exact graceful stop failed: {error}"
                )));
            }
        }
        loop {
            if controls.is_empty(deadline)? {
                retained.empty_verified = true;
                return Ok(());
            }
            if Instant::now() >= graceful_deadline {
                break;
            }
            thread::sleep(
                graceful_deadline
                    .saturating_duration_since(Instant::now())
                    .min(POLL_INTERVAL),
            );
        }
        controls.force_stop(deadline)?;
        loop {
            if controls.is_empty(deadline)? {
                retained.empty_verified = true;
                return Ok(());
            }
            thread::sleep(remaining(deadline)?.min(POLL_INTERVAL));
        }
    }
}
