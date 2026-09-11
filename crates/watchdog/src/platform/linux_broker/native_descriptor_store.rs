//! Authenticated PID-1 descriptor-store postconditions for the packaged broker.

use super::super::descriptor_store::{DescriptorName, DescriptorStoreTransport, snapshot};
use super::super::{
    BROKER_UNIT_NAME, BrokerError, BrokerResult, MAX_RECEIPTS, io_error, remaining,
    validate_protected_directory,
};
use super::NativeSystemdBackend;
use super::native_activation::CapturedDescriptors;
use std::fs::File;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::time::Instant;

pub(super) struct NativeDescriptorStore {
    transport: DescriptorStoreTransport,
}

impl NativeDescriptorStore {
    pub(super) fn verify_inherited(
        descriptors: &CapturedDescriptors,
        deadline: Instant,
    ) -> BrokerResult<()> {
        authenticate_owner(deadline)?;
        let entries = inventory(deadline)?;
        if entries.len() != descriptors.len() {
            return Err(BrokerError::Conflict(
                "inherited descriptor inventory differs from manager store".to_owned(),
            ));
        }
        for (name, directory) in descriptors {
            snapshot::verify_directory(&entries, name, directory)?;
            let metadata = directory.metadata().map_err(io_error)?;
            let filesystem =
                rustix::fs::fstatfs(directory).map_err(|error| io_error(error.into()))?;
            if filesystem.f_type != 0x6367_7270
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
            {
                return Err(BrokerError::Conflict(
                    "inherited directory is not a protected cgroup-v2 capability".to_owned(),
                ));
            }
        }
        remaining(deadline)?;
        Ok(())
    }

    pub(super) fn remove_retired(
        &self,
        name: &DescriptorName,
        directory: Option<&File>,
        deadline: Instant,
    ) -> BrokerResult<()> {
        authenticate_owner(deadline)?;
        let before = inventory(deadline)?;
        if !snapshot::require_removal_binding(&before, name, directory)? {
            return Ok(());
        }
        let _processed = self.transport.remove(name, deadline)?;
        let entries = inventory(deadline)?;
        snapshot::verify_absent(&entries, name)?;
        remaining(deadline)?;
        Ok(())
    }

    pub(super) fn connect(deadline: Instant) -> BrokerResult<Self> {
        // This supported deployment uses the system manager's canonical local
        // endpoint. Do not forward inherited notifications to arbitrary paths,
        // abstract names, user managers, or environment-selected D-Bus peers.
        if std::env::var_os("NOTIFY_SOCKET").as_deref()
            != Some(std::ffi::OsStr::new("/run/systemd/notify"))
        {
            return Err(BrokerError::Unavailable(
                "broker requires the protected system-manager notification endpoint".to_owned(),
            ));
        }
        validate_protected_directory(Path::new("/run"), "system-manager runtime")?;
        validate_protected_directory(Path::new("/run/systemd"), "system-manager runtime")?;
        let metadata = std::fs::symlink_metadata("/run/systemd/notify").map_err(io_error)?;
        if !metadata.file_type().is_socket() || metadata.uid() != 0 {
            return Err(BrokerError::Unauthorized(
                "system-manager notification socket is not root-owned".to_owned(),
            ));
        }
        authenticate_owner(deadline)?;
        // A successful typed dump also establishes availability of the v254+
        // API. Older or disabled stores fail closed before a process launch.
        let _existing = inventory(deadline)?;
        let socket = UnixDatagram::unbound().map_err(io_error)?;
        socket.connect("/run/systemd/notify").map_err(io_error)?;
        Ok(Self {
            transport: DescriptorStoreTransport::from_connected(socket)?,
        })
    }

    pub(super) fn retain(
        &self,
        name: &DescriptorName,
        directory: &File,
        deadline: Instant,
    ) -> BrokerResult<()> {
        let _processed = self.transport.submit(name, directory, deadline)?;
        authenticate_owner(deadline)?;
        let entries = inventory(deadline)?;
        // This query's snapshot point is the linearization point for the
        // state-level guarantee. It does not promise that this particular
        // notification inserted a new open-file description. All submissions
        // from this version use FDPOLL=0; exact duplicates are idempotent.
        snapshot::verify_directory(&entries, name, directory)?;
        remaining(deadline)?;
        Ok(())
    }
}

fn bus_owner_property(method: &str, deadline: Instant) -> BrokerResult<u32> {
    let connection = NativeSystemdBackend::connection(deadline)?;
    let bus = zbus::blocking::Proxy::new(
        &connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .map_err(unavailable)?;
    let value = bus
        .call(method, &"org.freedesktop.systemd1")
        .map_err(unavailable)?;
    remaining(deadline)?;
    Ok(value)
}

fn authenticate_owner(deadline: Instant) -> BrokerResult<()> {
    // Every call gets the remaining timeout, never the initial request budget.
    let pid = bus_owner_property("GetConnectionUnixProcessID", deadline)?;
    let uid = bus_owner_property("GetConnectionUnixUser", deadline)?;
    if pid != 1 || uid != 0 {
        return Err(BrokerError::Unauthorized(
            "descriptor-store authority is not the root system manager".to_owned(),
        ));
    }
    let connection = NativeSystemdBackend::connection(deadline)?;
    let manager = NativeSystemdBackend::manager(&connection)?;
    let path: zbus::zvariant::OwnedObjectPath = manager
        .call("GetUnitByPID", &std::process::id())
        .map_err(unavailable)?;
    let unit: String = NativeSystemdBackend::property(
        path.as_str(),
        "org.freedesktop.systemd1.Unit",
        "Id",
        deadline,
    )?;
    let main_pid: u32 = NativeSystemdBackend::property(
        path.as_str(),
        "org.freedesktop.systemd1.Service",
        "MainPID",
        deadline,
    )?;
    let notify: String = NativeSystemdBackend::property(
        path.as_str(),
        "org.freedesktop.systemd1.Service",
        "NotifyAccess",
        deadline,
    )?;
    let capacity: u32 = NativeSystemdBackend::property(
        path.as_str(),
        "org.freedesktop.systemd1.Service",
        "FileDescriptorStoreMax",
        deadline,
    )?;
    let preserve: String = NativeSystemdBackend::property(
        path.as_str(),
        "org.freedesktop.systemd1.Service",
        "FileDescriptorStorePreserve",
        deadline,
    )?;
    validate_owner(
        &unit,
        main_pid,
        &notify,
        capacity,
        &preserve,
        std::process::id(),
    )?;
    remaining(deadline)?;
    Ok(())
}

fn validate_owner(
    unit: &str,
    main_pid: u32,
    notify: &str,
    capacity: u32,
    preserve: &str,
    own_pid: u32,
) -> BrokerResult<()> {
    if unit != BROKER_UNIT_NAME
        || own_pid == 0
        || main_pid != own_pid
        || notify != "main"
        || usize::try_from(capacity).ok() != Some(MAX_RECEIPTS)
        || preserve != "yes"
    {
        return Err(BrokerError::Unauthorized(
            "broker descriptor-store owner or protected service policy is incompatible".to_owned(),
        ));
    }
    Ok(())
}

fn inventory(deadline: Instant) -> BrokerResult<Vec<snapshot::StoreEntry>> {
    remaining(deadline)?;
    let connection = NativeSystemdBackend::connection(deadline)?;
    let manager = NativeSystemdBackend::manager(&connection)?;
    let message = manager
        .call_method("DumpUnitFileDescriptorStore", &BROKER_UNIT_NAME)
        .map_err(unavailable)?;
    remaining(deadline)?;
    snapshot::decode(&message)
}

fn unavailable(error: impl std::fmt::Display) -> BrokerError {
    BrokerError::Unavailable(format!("manager descriptor-store query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_manager_owner_or_policy_cannot_admit_descriptors() -> BrokerResult<()> {
        validate_owner(BROKER_UNIT_NAME, 42, "main", 128, "yes", 42)?;
        for (unit, main_pid, notify, capacity, preserve, own_pid) in [
            ("foreign.service", 42, "main", 128, "yes", 42),
            (BROKER_UNIT_NAME, 41, "main", 128, "yes", 42),
            (BROKER_UNIT_NAME, 0, "main", 128, "yes", 0),
            (BROKER_UNIT_NAME, 42, "all", 128, "yes", 42),
            (BROKER_UNIT_NAME, 42, "exec", 128, "yes", 42),
            (BROKER_UNIT_NAME, 42, "none", 128, "yes", 42),
            (BROKER_UNIT_NAME, 42, "main", 0, "yes", 42),
            (BROKER_UNIT_NAME, 42, "main", 129, "yes", 42),
            (BROKER_UNIT_NAME, 42, "main", 127, "yes", 42),
            (BROKER_UNIT_NAME, 42, "main", 128, "restart", 42),
            (BROKER_UNIT_NAME, 42, "main", 128, "no", 42),
        ] {
            assert!(validate_owner(unit, main_pid, notify, capacity, preserve, own_pid).is_err());
        }
        Ok(())
    }
}
