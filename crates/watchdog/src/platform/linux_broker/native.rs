#[allow(clippy::wildcard_imports)]
use super::*;
use rustix::process::{Signal, pidfd_send_signal};

#[path = "native_cgroup.rs"]
mod native_cgroup;
use native_cgroup::HeldCgroup;

#[path = "native_descriptor_store.rs"]
mod native_descriptor_store;
use native_descriptor_store::NativeDescriptorStore;

#[path = "native_activation.rs"]
mod native_activation;

struct NativeSystemdBackend {
    retained: BTreeMap<String, RetainedContainment>,
    descriptor_store: Option<NativeDescriptorStore>,
    unavailable: native_activation::CapturedDescriptors,
}

struct RetainedContainment {
    observation: UnitObservation,
    controls: HeldCgroup,
    empty_verified: bool,
    manager_stored: bool,
}

fn unit_is_missing(error: &zbus::Error) -> bool {
    matches!(error, zbus::Error::MethodError(name, _, _)
        if name.as_str() == "org.freedesktop.systemd1.NoSuchUnit")
}

#[cfg(target_os = "linux")]
impl NativeSystemdBackend {
    fn connect() -> Self {
        Self {
            retained: BTreeMap::new(),
            descriptor_store: None,
            unavailable: BTreeMap::new(),
        }
    }

    fn recover_inherited(
        &mut self,
        mut descriptors: native_activation::CapturedDescriptors,
        ledger: &BrokerLedger,
        policy: &BrokerPolicy,
        deadline: Instant,
    ) -> BrokerResult<()> {
        self.descriptor_store.as_ref().ok_or_else(|| {
            BrokerError::Unavailable("authenticated descriptor store is unavailable".to_owned())
        })?;
        NativeDescriptorStore::verify_inherited(&descriptors, deadline)?;
        for receipt in ledger.recoverable_receipts(policy)? {
            let name = descriptor_store::DescriptorName::for_receipt(&receipt)?;
            let Some(directory) = descriptors.remove(&name) else {
                continue;
            };
            let launch_policy = policy.component(receipt.request.component)?;
            let observation = UnitObservation {
                unit: receipt.unit.clone(),
                pid: receipt.pid,
                creation_token: receipt.creation_token.clone(),
                executable: receipt.executable.clone(),
                executable_sha256: receipt.executable_sha256.clone(),
                uid: receipt.uid,
                gid: receipt.gid,
                capability_bounding_set: receipt.capability_bounding_set,
                ambient_capabilities: receipt.ambient_capabilities,
                no_new_privileges: launch_policy.capabilities.no_new_privileges,
                control_group: receipt.control_group.clone(),
            };
            observation.verify(&unit_name(&receipt.request), launch_policy)?;
            match HeldCgroup::from_directory(&directory, deadline) {
                Ok(controls) => {
                    self.retained.insert(
                        receipt.unit,
                        RetainedContainment {
                            observation,
                            controls,
                            empty_verified: false,
                            manager_stored: true,
                        },
                    );
                }
                Err(_) => {
                    // A deleted/offline control is not positive retirement.
                    // Keep its original directory bounded and diagnosable; do
                    // not substitute a fresh unit path or discard its evidence.
                    self.unavailable.insert(name, directory);
                }
            }
            remaining(deadline)?;
        }
        self.unavailable.extend(descriptors);
        Ok(())
    }

    fn connection(deadline: Instant) -> BrokerResult<zbus::blocking::Connection> {
        validate_protected_directory(Path::new("/run"), "system bus runtime")?;
        validate_protected_directory(Path::new("/run/dbus"), "system bus runtime")?;
        let metadata = fs::symlink_metadata("/run/dbus/system_bus_socket").map_err(io_error)?;
        if !metadata.file_type().is_socket() || metadata.uid() != 0 {
            return Err(BrokerError::Unauthorized(
                "system bus endpoint is not the protected root-owned socket".to_owned(),
            ));
        }
        let timeout = remaining(deadline)?;
        zbus::blocking::connection::Builder::address("unix:path=/run/dbus/system_bus_socket")
            .map_err(|error| {
                BrokerError::Unavailable(format!("system D-Bus builder failed: {error}"))
            })?
            .method_timeout(timeout)
            .build()
            .map_err(|error| {
                BrokerError::Unavailable(format!("system D-Bus connection failed: {error}"))
            })
    }

    fn manager(connection: &zbus::blocking::Connection) -> BrokerResult<zbus::blocking::Proxy<'_>> {
        zbus::blocking::Proxy::new(
            connection,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        )
        .map_err(|error| BrokerError::Unavailable(format!("systemd manager proxy failed: {error}")))
    }

    fn unit_proxy<'a>(
        connection: &'a zbus::blocking::Connection,
        path: &'a str,
    ) -> BrokerResult<zbus::blocking::Proxy<'a>> {
        zbus::blocking::Proxy::new(
            connection,
            "org.freedesktop.systemd1",
            path,
            "org.freedesktop.DBus.Properties",
        )
        .map_err(|error| {
            BrokerError::Unavailable(format!("systemd property proxy failed: {error}"))
        })
    }

    fn property<T>(
        path: &str,
        interface: &str,
        property: &str,
        deadline: Instant,
    ) -> BrokerResult<T>
    where
        T: TryFrom<zbus::zvariant::OwnedValue>,
        T::Error: fmt::Display,
    {
        let connection = Self::connection(deadline)?;
        let proxy = Self::unit_proxy(&connection, path)?;
        let value: zbus::zvariant::OwnedValue =
            proxy.call("Get", &(interface, property)).map_err(|error| {
                BrokerError::Unavailable(format!("systemd property read failed: {error}"))
            })?;
        T::try_from(value).map_err(|error| {
            BrokerError::Unavailable(format!("systemd property type failed: {error}"))
        })
    }

    fn unit_observation(
        unit: &str,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<Option<UnitObservation>> {
        let connection = Self::connection(deadline)?;
        let manager = Self::manager(&connection)?;
        let path: zbus::zvariant::OwnedObjectPath = match manager.call("GetUnit", &unit) {
            Ok(path) => path,
            Err(error) if unit_is_missing(&error) => return Ok(None),
            Err(error) => {
                return Err(BrokerError::Unavailable(format!(
                    "systemd unit lookup failed: {error}"
                )));
            }
        };
        let path = path.as_str();
        let active: String = Self::property(
            path,
            "org.freedesktop.systemd1.Unit",
            "ActiveState",
            deadline,
        )?;
        if active != "active" {
            return Ok(None);
        }
        let pid: u32 = Self::property(
            path,
            "org.freedesktop.systemd1.Service",
            "MainPID",
            deadline,
        )?;
        if pid == 0 {
            return Ok(None);
        }
        let control_group: String = Self::property(
            path,
            "org.freedesktop.systemd1.Unit",
            "ControlGroup",
            deadline,
        )?;
        let process = read_process_postcondition(pid, policy, &control_group, deadline)?;
        Ok(Some(UnitObservation {
            unit: unit.to_owned(),
            pid,
            creation_token: process.creation_token,
            executable: process.executable,
            executable_sha256: process.executable_sha256,
            uid: process.uid,
            gid: process.gid,
            capability_bounding_set: process.capability_bounding_set,
            ambient_capabilities: process.ambient_capabilities,
            no_new_privileges: process.no_new_privileges,
            control_group,
        }))
    }

    fn observation_policy(expected: &UnitObservation) -> LaunchPolicy {
        LaunchPolicy {
            executable: expected.executable.clone(),
            executable_sha256: expected.executable_sha256.clone(),
            arguments: Vec::new(),
            working_directory: PathBuf::from("/"),
            environment: Vec::new(),
            target_uid: expected.uid,
            target_gid: expected.gid,
            capabilities: CapabilityPolicy {
                bounding_set: expected.capability_bounding_set,
                ambient_set: expected.ambient_capabilities,
                no_new_privileges: expected.no_new_privileges,
            },
            cgroup: CgroupPolicy {
                tasks_max: MAX_TASKS,
                memory_max_bytes: MAX_MEMORY_BYTES,
            },
            timeout: MAX_CLEANUP_TIMEOUT,
        }
    }
}

#[cfg(target_os = "linux")]
impl SystemdBackend for NativeSystemdBackend {
    #[allow(clippy::vec_init_then_push)]
    fn start(
        &mut self,
        unit: &str,
        _request: &BrokerRequest,
        policy: &LaunchPolicy,
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
        let environment = policy
            .environment
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>();
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
        let _: zbus::zvariant::OwnedObjectPath = manager
            .call("StartTransientUnit", &(unit, "fail", properties, aux))
            .map_err(|error| {
                BrokerError::Unavailable(format!("systemd transient unit start failed: {error}"))
            })?;
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
        let _pidfd = verify_held_process(expected, &mut controls, deadline)?;
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
        let pidfd = verify_held_process(expected, controls, deadline)?;
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

fn verify_held_process(
    expected: &UnitObservation,
    controls: &mut HeldCgroup,
    deadline: Instant,
) -> BrokerResult<rustix::fd::OwnedFd> {
    if !controls.contains(expected.pid, deadline)? {
        return Err(BrokerError::Conflict(
            "original process is not in held containment".to_owned(),
        ));
    }
    let pid =
        Pid::from_raw(i32::try_from(expected.pid).map_err(|_| {
            BrokerError::Conflict("process PID is outside native bounds".to_owned())
        })?)
        .ok_or_else(|| BrokerError::Conflict("process PID is zero".to_owned()))?;
    let pidfd = pidfd_open(pid, PidfdFlags::empty())
        .map_err(|error| BrokerError::Conflict(format!("exact process is unavailable: {error}")))?;
    let policy = NativeSystemdBackend::observation_policy(expected);
    let process =
        read_process_postcondition(expected.pid, &policy, &expected.control_group, deadline)?;
    if process.creation_token != expected.creation_token
        || process.executable != expected.executable
        || process.executable_sha256 != expected.executable_sha256
        || process.uid != expected.uid
        || process.gid != expected.gid
        || process.capability_bounding_set != expected.capability_bounding_set
        || process.ambient_capabilities != expected.ambient_capabilities
        || process.no_new_privileges != expected.no_new_privileges
        || !controls.contains(expected.pid, deadline)?
    {
        return Err(BrokerError::Conflict(
            "exact process binding changed during containment verification".to_owned(),
        ));
    }
    Ok(pidfd)
}

#[cfg(target_os = "linux")]
struct ProcessPostcondition {
    creation_token: String,
    executable: PathBuf,
    executable_sha256: String,
    uid: u32,
    gid: u32,
    capability_bounding_set: u64,
    ambient_capabilities: u64,
    no_new_privileges: bool,
}

#[cfg(target_os = "linux")]
fn read_process_postcondition(
    pid: u32,
    policy: &LaunchPolicy,
    control_group: &str,
    deadline: Instant,
) -> BrokerResult<ProcessPostcondition> {
    let executable = process_executable_proof(pid, policy, deadline)?;
    let status = String::from_utf8(read_bounded_file(
        Path::new(&format!("/proc/{pid}/status")),
        MAX_FRAME_BYTES,
        "process status",
    )?)
    .map_err(|_| BrokerError::Conflict("process status is not UTF-8".to_owned()))?;
    let uid = parse_status_quad(&status, "Uid")?;
    let gid = parse_status_quad(&status, "Gid")?;
    if uid.iter().any(|value| *value != policy.target_uid)
        || gid.iter().any(|value| *value != policy.target_gid)
    {
        return Err(BrokerError::Conflict(
            "systemd target UID/GID postcheck failed".to_owned(),
        ));
    }
    require_no_supplementary_groups(&status)?;
    let cap_bounding_set = parse_hex_status(&status, "CapBnd")?;
    let ambient_capabilities = parse_hex_status(&status, "CapAmb")?;
    let no_new_privileges = status
        .lines()
        .find_map(|line| line.strip_prefix("NoNewPrivs:"))
        .map(str::trim)
        .is_some_and(|value| value == "1");
    if !no_new_privileges
        || cap_bounding_set != policy.capabilities.bounding_set
        || ambient_capabilities != policy.capabilities.ambient_set
    {
        return Err(BrokerError::Conflict(
            "systemd capability postcheck failed".to_owned(),
        ));
    }
    let cgroup = String::from_utf8(read_bounded_file(
        Path::new(&format!("/proc/{pid}/cgroup")),
        MAX_FRAME_BYTES,
        "process cgroup",
    )?)
    .map_err(|_| BrokerError::Conflict("process cgroup is not UTF-8".to_owned()))?;
    let actual_cgroup = cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| {
            BrokerError::Conflict("target has no unified cgroup membership".to_owned())
        })?;
    if actual_cgroup != control_group {
        return Err(BrokerError::Conflict(
            "target cgroup does not match exact systemd unit".to_owned(),
        ));
    }
    let final_executable = process_executable_proof(pid, policy, deadline)?;
    if executable.creation_token != final_executable.creation_token
        || executable.executable != final_executable.executable
        || executable.executable_sha256 != final_executable.executable_sha256
    {
        return Err(BrokerError::Conflict(
            "target executable identity changed during postcheck".to_owned(),
        ));
    }
    Ok(ProcessPostcondition {
        creation_token: final_executable.creation_token,
        executable: final_executable.executable,
        executable_sha256: final_executable.executable_sha256,
        uid: policy.target_uid,
        gid: policy.target_gid,
        capability_bounding_set: cap_bounding_set,
        ambient_capabilities,
        no_new_privileges,
    })
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessExecutableProof {
    creation_token: String,
    executable: PathBuf,
    executable_sha256: String,
}

/// Pin the PID while checking its current executable.  The start token alone
/// does not bind an execve result, and a path-only check does not bind the
/// inode contents.  Both the exact /proc/PID/exe path and its digest must
/// match the immutable launch policy before a unit is acknowledged.
#[cfg(target_os = "linux")]
fn process_executable_proof(
    pid: u32,
    policy: &LaunchPolicy,
    deadline: Instant,
) -> BrokerResult<ProcessExecutableProof> {
    let process = Pid::from_raw(
        i32::try_from(pid)
            .map_err(|_| BrokerError::Conflict("process PID is out of bounds".to_owned()))?,
    )
    .ok_or_else(|| BrokerError::Conflict("process PID is zero".to_owned()))?;
    let _pidfd = pidfd_open(process, PidfdFlags::empty()).map_err(|error| {
        BrokerError::Conflict(format!("process identity is unavailable: {error}"))
    })?;
    let creation_before = process_start_token(pid)?;
    let proc_executable = PathBuf::from(format!("/proc/{pid}/exe"));
    let executable = fs::read_link(&proc_executable).map_err(io_error)?;
    if executable != policy.executable {
        return Err(BrokerError::Conflict(
            "process executable path does not match fixed policy".to_owned(),
        ));
    }
    let executable_sha256 =
        hash_open_file_until(File::open(&proc_executable).map_err(io_error)?, deadline)?;
    let creation_after = process_start_token(pid)?;
    let executable_after = fs::read_link(&proc_executable).map_err(io_error)?;
    if creation_before != creation_after || executable != executable_after {
        return Err(BrokerError::Conflict(
            "process executable identity changed during proof".to_owned(),
        ));
    }
    if executable_sha256 != policy.executable_sha256 {
        return Err(BrokerError::Conflict(
            "process executable digest does not match fixed policy".to_owned(),
        ));
    }
    Ok(ProcessExecutableProof {
        creation_token: creation_after,
        executable: executable_after,
        executable_sha256,
    })
}

#[cfg(all(target_os = "linux", test))]
pub(crate) fn verify_process_executable(pid: u32, policy: &LaunchPolicy) -> BrokerResult<()> {
    process_executable_proof(pid, policy, Instant::now() + policy.timeout).map(|_| ())
}

#[cfg(target_os = "linux")]
pub(crate) fn require_no_supplementary_groups(status: &str) -> BrokerResult<()> {
    let groups = status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:"))
        .ok_or_else(|| BrokerError::Conflict("process status lacks Groups".to_owned()))?;
    if !groups.trim().is_empty() {
        return Err(BrokerError::Conflict(
            "systemd supplementary-group postcheck failed".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_status_quad(status: &str, field: &str) -> BrokerResult<[u32; 4]> {
    let values = status
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{field}:")))
        .ok_or_else(|| BrokerError::Conflict(format!("process status lacks {field}")))?
        .split_whitespace()
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| BrokerError::Conflict(format!("process status has invalid {field}")))
        })
        .collect::<BrokerResult<Vec<_>>>()?;
    values
        .try_into()
        .map_err(|_| BrokerError::Conflict(format!("process status has incomplete {field}")))
}

#[cfg(target_os = "linux")]
fn parse_hex_status(status: &str, field: &str) -> BrokerResult<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{field}:")))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .ok_or_else(|| BrokerError::Conflict(format!("process status has invalid {field}")))
}

#[cfg(target_os = "linux")]
pub(crate) fn process_start_token(pid: u32) -> BrokerResult<String> {
    let boot_id = String::from_utf8(read_bounded_file(
        Path::new("/proc/sys/kernel/random/boot_id"),
        37,
        "kernel boot identity",
    )?)
    .map_err(|_| BrokerError::Conflict("kernel boot identity is not UTF-8".to_owned()))?;
    let stat = String::from_utf8(read_bounded_file(
        Path::new(&format!("/proc/{pid}/stat")),
        MAX_FRAME_BYTES,
        "process stat",
    )?)
    .map_err(|_| BrokerError::Conflict("process stat is not UTF-8".to_owned()))?;
    boot_scoped_start_token(&boot_id, &stat)
}

fn boot_scoped_start_token(boot_id: &str, stat: &str) -> BrokerResult<String> {
    let boot_id = boot_id.strip_suffix('\n').unwrap_or(boot_id);
    let boot = uuid::Uuid::parse_str(boot_id)
        .map_err(|_| BrokerError::Conflict("kernel boot identity is invalid".to_owned()))?;
    if boot.is_nil() || boot.to_string() != boot_id {
        return Err(BrokerError::Conflict(
            "kernel boot identity is not canonical".to_owned(),
        ));
    }
    let close = stat.rfind(')').ok_or_else(|| {
        BrokerError::Conflict("process stat has no command terminator".to_owned())
    })?;
    let ticks = stat
        .get(close + 2..)
        .and_then(|suffix| suffix.split_whitespace().nth(19))
        .ok_or_else(|| BrokerError::Conflict("process stat has no start token".to_owned()))?;
    let value = ticks
        .parse::<u64>()
        .map_err(|_| BrokerError::Conflict("process start ticks are invalid".to_owned()))?;
    if value.to_string() != ticks {
        return Err(BrokerError::Conflict(
            "process start ticks are not canonical".to_owned(),
        ));
    }
    // A durable receipt must not collide with the same PID/start tick after a
    // reboot. This broker token is separate from decimal worker-IPC birth fields.
    Ok(format!("boot:{boot_id}:{ticks}"))
}

#[cfg(test)]
#[path = "native_identity_tests.rs"]
mod identity_tests;

/// Start the root-owned broker binary after loading the protected policy.
#[cfg(target_os = "linux")]
pub fn run_native_broker(
    socket: &Path,
    policy_path: &Path,
    ledger_path: &Path,
) -> BrokerResult<()> {
    // This must remain the first operation: before protected-file loading,
    // socket binding, D-Bus connections, or background thread creation.
    let inherited = native_activation::capture()?;
    let policy = BrokerPolicy::from_file(policy_path)?;
    let peer_gid = policy.peer.gid;
    let ledger = BrokerLedger::open(ledger_path)?;
    let mut backend = NativeSystemdBackend::connect();
    let deadline = Instant::now()
        .checked_add(MAX_IO_TIMEOUT)
        .unwrap_or_else(Instant::now);
    backend.descriptor_store = Some(NativeDescriptorStore::connect(deadline)?);
    backend.recover_inherited(inherited, &ledger, &policy, deadline)?;
    let listener = bind_root_owned_socket(socket, peer_gid)?;
    serve(
        &listener,
        LinuxSystemdBroker::new_with_ledger(policy, backend, ledger),
    )
}
