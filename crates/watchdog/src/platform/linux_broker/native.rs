#[allow(clippy::wildcard_imports)]
use super::*;

struct NativeSystemdBackend;

#[cfg(target_os = "linux")]
impl NativeSystemdBackend {
    fn connect() -> Self {
        Self
    }

    fn connection(deadline: Instant) -> BrokerResult<zbus::blocking::Connection> {
        let timeout = remaining(deadline)?;
        zbus::blocking::connection::Builder::system()
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
            Err(error) if error.to_string().contains("NoSuchUnit") => return Ok(None),
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
        let process = read_process_postcondition(pid, policy, &control_group)?;
        Ok(Some(UnitObservation {
            unit: unit.to_owned(),
            pid,
            creation_token: process.creation_token,
            uid: process.uid,
            gid: process.gid,
            capability_bounding_set: process.capability_bounding_set,
            ambient_capabilities: process.ambient_capabilities,
            no_new_privileges: process.no_new_privileges,
            control_group,
        }))
    }

    fn unit_is_active(unit: &str, deadline: Instant) -> BrokerResult<bool> {
        let connection = Self::connection(deadline)?;
        let manager = Self::manager(&connection)?;
        let path: zbus::zvariant::OwnedObjectPath = match manager.call("GetUnit", &unit) {
            Ok(path) => path,
            Err(error) if error.to_string().contains("NoSuchUnit") => return Ok(false),
            Err(error) => {
                return Err(BrokerError::Unavailable(format!(
                    "systemd unit lookup during cleanup failed: {error}"
                )));
            }
        };
        let active: String = Self::property(
            path.as_str(),
            "org.freedesktop.systemd1.Unit",
            "ActiveState",
            deadline,
        )?;
        Ok(active == "active" || active == "activating" || active == "deactivating")
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
        if hash_file(&policy.executable)? != policy.executable_sha256 {
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

    fn stop(&mut self, unit: &str, deadline: Instant) -> BrokerResult<()> {
        let connection = Self::connection(deadline)?;
        let manager = Self::manager(&connection)?;
        let _: zbus::zvariant::OwnedObjectPath = manager
            .call("StopUnit", &(unit, "replace"))
            .map_err(|error| {
                BrokerError::Unavailable(format!("systemd exact-unit cleanup failed: {error}"))
            })?;
        loop {
            if !Self::unit_is_active(unit, deadline)? {
                return Ok(());
            }
            thread::sleep(remaining(deadline)?.min(POLL_INTERVAL));
        }
    }
}

#[cfg(target_os = "linux")]
struct ProcessPostcondition {
    creation_token: String,
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
) -> BrokerResult<ProcessPostcondition> {
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
    let creation_token = process_start_token(pid)?;
    Ok(ProcessPostcondition {
        creation_token,
        uid: policy.target_uid,
        gid: policy.target_gid,
        capability_bounding_set: cap_bounding_set,
        ambient_capabilities,
        no_new_privileges,
    })
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
    let stat = String::from_utf8(read_bounded_file(
        Path::new(&format!("/proc/{pid}/stat")),
        MAX_FRAME_BYTES,
        "process stat",
    )?)
    .map_err(|_| BrokerError::Conflict("process stat is not UTF-8".to_owned()))?;
    let close = stat.rfind(')').ok_or_else(|| {
        BrokerError::Conflict("process stat has no command terminator".to_owned())
    })?;
    stat.get(close + 2..)
        .and_then(|suffix| suffix.split_whitespace().nth(19))
        .map(str::to_owned)
        .ok_or_else(|| BrokerError::Conflict("process stat has no start token".to_owned()))
}

/// Start the root-owned broker binary after loading the protected policy.
#[cfg(target_os = "linux")]
pub fn run_native_broker(
    socket: &Path,
    policy_path: &Path,
    ledger_path: &Path,
) -> BrokerResult<()> {
    let policy = BrokerPolicy::from_file(policy_path)?;
    let peer_gid = policy.peer.gid;
    let ledger = BrokerLedger::open(ledger_path)?;
    let listener = bind_root_owned_socket(socket, peer_gid)?;
    let backend = NativeSystemdBackend::connect();
    serve(
        &listener,
        LinuxSystemdBroker::new_with_ledger(policy, backend, ledger),
    )
}
