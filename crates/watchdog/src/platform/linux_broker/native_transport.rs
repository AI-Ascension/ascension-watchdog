//! Native systemd transport and unit/property inspection helpers.
//!
//! These are the raw D-Bus/systemd accessors used to open the system bus, build
//! the manager and property proxies, and turn a unit name plus launch policy
//! into a verified [`UnitObservation`]. They are inherent helpers of
//! [`super::NativeSystemdBackend`]; the backend's lifecycle effects live in the
//! coordinator module so the exact same connection and inspection code is used
//! by both start and inspect paths.

#[allow(clippy::wildcard_imports)]
use super::*;

#[cfg(target_os = "linux")]
impl NativeSystemdBackend {
    pub(super) fn connect() -> Self {
        Self {
            retained: BTreeMap::new(),
            descriptor_store: None,
            unavailable: BTreeMap::new(),
            queued_jobs: BTreeMap::new(),
        }
    }

    pub(super) fn connection(deadline: Instant) -> BrokerResult<zbus::blocking::Connection> {
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

    pub(super) fn manager(
        connection: &zbus::blocking::Connection,
    ) -> BrokerResult<zbus::blocking::Proxy<'_>> {
        zbus::blocking::Proxy::new(
            connection,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        )
        .map_err(|error| BrokerError::Unavailable(format!("systemd manager proxy failed: {error}")))
    }

    pub(super) fn unit_proxy<'a>(
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

    pub(super) fn property<T>(
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

    pub(super) fn unit_observation(
        unit: &str,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<Option<UnitObservation>> {
        let connection = Self::connection(deadline)?;
        let manager = Self::manager(&connection)?;
        let path: zbus::zvariant::OwnedObjectPath = match manager.call("GetUnit", &unit) {
            Ok(path) => path,
            Err(error) if super::native_queued_job::unit_is_missing(&error) => return Ok(None),
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
        let process = super::native_process_identity::read_process_postcondition(
            pid,
            policy,
            &control_group,
            deadline,
        )?;
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

    pub(super) fn observation_policy(expected: &UnitObservation) -> LaunchPolicy {
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
