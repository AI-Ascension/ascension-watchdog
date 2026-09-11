//! Held cgroup-v2 controls: no pathname lookup occurs at the kill effect.

use super::super::{BrokerError, BrokerResult, MAX_FRAME_BYTES, MAX_TASKS, remaining};
use rustix::fs::{Mode, OFlags, fstatfs, open, openat};
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

pub(super) struct HeldCgroup {
    directory: File,
    processes: File,
    events: File,
    kill: File,
}

fn io_error(error: impl std::fmt::Display) -> BrokerError {
    BrokerError::Io(error.to_string())
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK
}

impl HeldCgroup {
    pub(super) fn directory(&self) -> &File {
        &self.directory
    }

    pub(super) fn open(control_group: &str, deadline: Instant) -> BrokerResult<Self> {
        validate_path(control_group)?;
        let mut root = open("/", directory_flags(), Mode::empty()).map_err(io_error)?;
        // The packaged broker uses the standard unified hierarchy. An absent,
        // symlinked or non-cgroup2 mount is unsupported, never a fallback to an
        // ordinary filesystem or a controller-v1 hierarchy.
        for component in ["sys", "fs", "cgroup"] {
            remaining(deadline)?;
            root = openat(&root, component, directory_flags(), Mode::empty()).map_err(io_error)?;
        }
        if fstatfs(&root).map_err(io_error)?.f_type != 0x6367_7270 {
            return Err(BrokerError::Unavailable(
                "unified cgroup-v2 mount is unavailable".to_owned(),
            ));
        }
        let controls = Self::beneath(&File::from(root), control_group, deadline)?;
        controls.validate()?;
        Ok(controls)
    }

    fn validate(&self) -> BrokerResult<()> {
        for file in [&self.directory, &self.processes, &self.events, &self.kill] {
            if fstatfs(file).map_err(io_error)?.f_type != 0x6367_7270 {
                return Err(BrokerError::Conflict(
                    "cgroup control escaped the unified hierarchy".to_owned(),
                ));
            }
            let metadata = file.metadata().map_err(io_error)?;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(BrokerError::Conflict(
                    "cgroup control is not exclusively root-managed".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Recover controls only relative to the authenticated original directory
    /// descriptor. No systemd/unit cgroup pathname is resolved by this path.
    pub(super) fn from_directory(directory: &File, deadline: Instant) -> BrokerResult<Self> {
        let controls =
            Self::controls_for_directory(directory.try_clone().map_err(io_error)?, deadline)?;
        controls.validate()?;
        Ok(controls)
    }

    fn beneath(root: &File, control_group: &str, deadline: Instant) -> BrokerResult<Self> {
        validate_path(control_group)?;
        let mut directory = root.try_clone().map_err(io_error)?;
        for component in control_group[1..].split('/') {
            remaining(deadline)?;
            directory = File::from(
                openat(&directory, component, directory_flags(), Mode::empty())
                    .map_err(io_error)?,
            );
        }
        Self::controls_for_directory(directory, deadline)
    }

    fn controls_for_directory(directory: File, deadline: Instant) -> BrokerResult<Self> {
        remaining(deadline)?;
        if !directory.metadata().map_err(io_error)?.is_dir() {
            return Err(BrokerError::Conflict(
                "original cgroup is not a directory".to_owned(),
            ));
        }
        let read_flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let processes = File::from(
            openat(&directory, "cgroup.procs", read_flags, Mode::empty()).map_err(io_error)?,
        );
        let events = File::from(
            openat(&directory, "cgroup.events", read_flags, Mode::empty()).map_err(io_error)?,
        );
        let kill = File::from(
            openat(
                &directory,
                "cgroup.kill",
                OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(io_error)?,
        );
        for file in [&processes, &events, &kill] {
            if !file.metadata().map_err(io_error)?.is_file() {
                return Err(BrokerError::Conflict(
                    "cgroup control is not a regular kernel file".to_owned(),
                ));
            }
        }
        Ok(Self {
            directory,
            processes,
            events,
            kill,
        })
    }

    pub(super) fn contains(&mut self, pid: u32, deadline: Instant) -> BrokerResult<bool> {
        let maximum_tasks = usize::try_from(MAX_TASKS)
            .map_err(|_| BrokerError::Unavailable("task bound exceeds native size".to_owned()))?;
        let contents = read_control(&mut self.processes, maximum_tasks * 12, deadline)?;
        let mut found = false;
        for (index, line) in contents.lines().enumerate() {
            if index >= maximum_tasks {
                return Err(BrokerError::Conflict(
                    "cgroup membership exceeds task bound".to_owned(),
                ));
            }
            let current = line
                .parse::<u32>()
                .map_err(|_| BrokerError::Conflict("invalid cgroup PID".to_owned()))?;
            if current == 0 {
                return Err(BrokerError::Conflict("invalid zero cgroup PID".to_owned()));
            }
            found |= current == pid;
        }
        Ok(found)
    }

    pub(super) fn is_empty(&mut self, deadline: Instant) -> BrokerResult<bool> {
        let contents = read_control(&mut self.events, MAX_FRAME_BYTES, deadline)?;
        let mut populated = None;
        for line in contents.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() != 2 {
                return Err(BrokerError::Conflict("malformed cgroup events".to_owned()));
            }
            if fields[0] == "populated" {
                if populated.is_some() || !matches!(fields[1], "0" | "1") {
                    return Err(BrokerError::Conflict(
                        "ambiguous cgroup population".to_owned(),
                    ));
                }
                populated = Some(fields[1] == "1");
            }
        }
        populated
            .map(|value| !value)
            .ok_or_else(|| BrokerError::Conflict("cgroup population is missing".to_owned()))
    }

    pub(super) fn force_stop(&mut self, deadline: Instant) -> BrokerResult<()> {
        remaining(deadline)?;
        self.kill.write_all(b"1").map_err(io_error)
    }
}

fn validate_path(path: &str) -> BrokerResult<()> {
    if path.len() > MAX_FRAME_BYTES
        || !path.starts_with('/')
        || path.len() == 1
        || path.contains('\0')
        || path[1..]
            .split('/')
            .any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(BrokerError::Conflict(
            "systemd cgroup path is not canonical".to_owned(),
        ));
    }
    Ok(())
}

fn read_control(file: &mut File, maximum: usize, deadline: Instant) -> BrokerResult<String> {
    remaining(deadline)?;
    file.rewind().map_err(io_error)?;
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    remaining(deadline)?;
    if bytes.len() > maximum {
        return Err(BrokerError::Conflict(
            "cgroup control exceeds read bound".to_owned(),
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| BrokerError::Conflict("cgroup control is not UTF-8".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::super::{NativeSystemdBackend, RetainedContainment};
    use super::*;
    use crate::platform::linux_broker::{
        BrokerComponent, BrokerRequest, SystemdBackend, UnitObservation, receipt_from,
    };
    use std::fs;
    use std::time::Duration;

    fn fixture(path: &std::path::Path, pid: u32) -> std::io::Result<()> {
        fs::create_dir(path)?;
        fs::write(path.join("cgroup.procs"), format!("{pid}\n"))?;
        fs::write(path.join("cgroup.events"), "populated 1\nfrozen 0\n")?;
        fs::write(path.join("cgroup.kill"), "0")
    }

    #[test]
    fn native_retirement_cache_uses_original_files_and_complete_receipt_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        // Ordinary files exercise the native backend's retained-capability
        // logic without claiming that this fixture is a native kernel cgroup.
        let directory = tempfile::tempdir()?;
        let unit = directory.path().join("unit");
        fixture(&unit, 42)?;
        let root = File::open(directory.path())?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let controls = HeldCgroup::beneath(&root, "/unit", deadline)?;
        let request = BrokerRequest {
            component: BrokerComponent::Synthetic,
            instance: "fixture".to_owned(),
            incarnation: "fixture".to_owned(),
            nonce: "retained-fixture".to_owned(),
        };
        let observation = UnitObservation {
            unit: "unit".to_owned(),
            pid: 42,
            creation_token: "original-process".to_owned(),
            executable: "/approved/fixture".into(),
            executable_sha256: "a".repeat(64),
            uid: 1001,
            gid: 1001,
            capability_bounding_set: 0,
            ambient_capabilities: 0,
            no_new_privileges: true,
            control_group: "/unit".to_owned(),
        };
        let receipt = receipt_from(&request, &observation, false);
        let expected = observation.clone();
        let policy = NativeSystemdBackend::observation_policy(&expected);
        let mut backend = NativeSystemdBackend::connect();
        backend.retained.insert(
            "unit".to_owned(),
            RetainedContainment {
                observation,
                controls,
                empty_verified: false,
                manager_stored: true,
            },
        );
        backend
            .retained
            .get_mut("unit")
            .ok_or("missing native fixture")?
            .manager_stored = false;
        backend.require_local_containment(&expected, &policy, deadline)?;
        assert!(
            backend
                .require_containment(&expected, &policy, deadline)
                .is_err(),
            "local cleanup proof cannot acknowledge manager storage"
        );
        backend
            .retained
            .get_mut("unit")
            .ok_or("missing native fixture")?
            .manager_stored = true;
        backend.require_containment(&expected, &policy, deadline)?;
        assert!(!backend.verify_retirement(&receipt, deadline)?);
        let moved = directory.path().join("original");
        fs::rename(&unit, &moved)?;
        fixture(&unit, 43)?;
        fs::write(unit.join("cgroup.events"), "populated 0\n")?;
        assert!(
            !backend.verify_retirement(&receipt, deadline)?,
            "replacement empty is irrelevant"
        );
        fs::write(moved.join("cgroup.events"), "populated 0\n")?;
        assert!(backend.verify_retirement(&receipt, deadline)?);
        fs::remove_file(moved.join("cgroup.events"))?;
        assert!(
            backend.verify_retirement(&receipt, deadline)?,
            "already proven empty fact is retained"
        );
        let mut foreign = receipt.clone();
        foreign.creation_token = "reused-process".to_owned();
        assert!(backend.verify_retirement(&foreign, deadline).is_err());
        assert!(
            !NativeSystemdBackend::connect().verify_retirement(&receipt, deadline)?,
            "replacement owner cannot reconstruct the lost capability from a pathname"
        );
        Ok(())
    }

    #[test]
    fn recovery_opens_controls_only_from_original_directory_descriptor()
    -> Result<(), Box<dyn std::error::Error>> {
        // Ordinary-file transport test, not native cgroup evidence.
        let root = tempfile::tempdir()?;
        let original = root.path().join("unit");
        fixture(&original, 42)?;
        let retained = File::open(&original)?;
        let moved = root.path().join("old-unit");
        fs::rename(&original, &moved)?;
        fixture(&original, 99)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut recovered = HeldCgroup::controls_for_directory(retained.try_clone()?, deadline)?;
        assert!(recovered.contains(42, deadline)?);
        assert!(!recovered.contains(99, deadline)?);
        recovered.force_stop(deadline)?;
        assert_eq!(fs::read_to_string(moved.join("cgroup.kill"))?, "1");
        assert_eq!(fs::read_to_string(original.join("cgroup.kill"))?, "0");
        assert!(
            HeldCgroup::from_directory(&retained, deadline).is_err(),
            "production rejects ordinary-filesystem controls"
        );
        Ok(())
    }

    #[test]
    fn orphan_cleanup_never_redirects_to_replacement_or_requires_a_leader_pid()
    -> Result<(), Box<dyn std::error::Error>> {
        // Exercise the real native backend against ordinary control files.
        // Production acquisition rejects these files; this is not a cgroup
        // enforcement, descendant signalling, or native service test.
        let root = tempfile::tempdir()?;
        let request = BrokerRequest {
            component: BrokerComponent::Synthetic,
            instance: "fixture".to_owned(),
            incarnation: "fixture".to_owned(),
            nonce: "orphan-fixture".to_owned(),
        };
        let unit = crate::platform::linux_broker::unit_name(&request);
        let path = root.path().join(&unit);
        fixture(&path, 43)?;
        let control_group = format!("/{unit}");
        let observation = UnitObservation {
            unit: unit.clone(),
            pid: u32::MAX,
            creation_token: "original-process".to_owned(),
            executable: "/approved/fixture".into(),
            executable_sha256: "a".repeat(64),
            uid: 1001,
            gid: 1001,
            capability_bounding_set: 0,
            ambient_capabilities: 0,
            no_new_privileges: true,
            control_group: control_group.clone(),
        };
        let receipt = receipt_from(&request, &observation, false);
        let policy = NativeSystemdBackend::observation_policy(&observation);
        let controls = HeldCgroup::beneath(
            &File::open(root.path())?,
            &control_group,
            Instant::now() + Duration::from_secs(5),
        )?;
        let mut backend = NativeSystemdBackend::connect();
        backend.retained.insert(
            unit.clone(),
            RetainedContainment {
                observation,
                controls,
                empty_verified: false,
                manager_stored: true,
            },
        );
        let moved = root.path().join("original");
        fs::rename(&path, &moved)?;
        fixture(&path, 99)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        backend.require_retained_containment(&receipt, &policy, deadline)?;
        let mut foreign = receipt.clone();
        foreign.creation_token = "foreign".to_owned();
        assert!(
            backend
                .require_retained_containment(&foreign, &policy, deadline)
                .is_err()
        );
        assert!(
            backend
                .stop_retained_containment(&foreign, deadline)
                .is_err()
        );
        assert_eq!(fs::read_to_string(moved.join("cgroup.kill"))?, "0");
        assert_eq!(fs::read_to_string(path.join("cgroup.kill"))?, "0");

        fs::write(moved.join("cgroup.events"), "populated invalid\n")?;
        assert!(
            backend
                .stop_retained_containment(&receipt, deadline)
                .is_err()
        );
        assert_eq!(fs::read_to_string(moved.join("cgroup.kill"))?, "0");
        fs::write(moved.join("cgroup.events"), "populated 1\n")?;

        // No empty witness is produced: the bounded operation must fail even
        // after its original-object kill write. No PID lookup of u32::MAX can
        // succeed, so reaching the write also rejects leader-based cleanup.
        let result =
            backend.stop_retained_containment(&receipt, Instant::now() + Duration::from_secs(2));
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(moved.join("cgroup.kill"))?, "1");
        assert_eq!(fs::read_to_string(path.join("cgroup.kill"))?, "0");
        assert!(
            !backend
                .retained
                .get(&unit)
                .ok_or("retained")?
                .empty_verified
        );
        fs::write(moved.join("cgroup.events"), "populated 0\n")?;
        backend.stop_retained_containment(&receipt, Instant::now() + Duration::from_secs(2))?;
        assert!(backend.verify_retirement(&receipt, Instant::now() + Duration::from_secs(2))?);
        assert_eq!(
            fs::read_to_string(moved.join("cgroup.kill"))?,
            "1",
            "an already empty original is not killed again"
        );
        assert_eq!(fs::read_to_string(path.join("cgroup.kill"))?, "0");
        Ok(())
    }

    #[test]
    fn held_controls_cannot_be_redirected_to_a_replacement_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let original = directory.path().join("unit");
        fixture(&original, 42)?;
        let root = File::open(directory.path())?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut controls = HeldCgroup::beneath(&root, "/unit", deadline)?;
        let moved = directory.path().join("original");
        fs::rename(&original, &moved)?;
        fixture(&original, 43)?;
        assert!(controls.contains(42, deadline)?);
        assert!(!controls.contains(43, deadline)?);
        controls.force_stop(deadline)?;
        assert_eq!(fs::read_to_string(moved.join("cgroup.kill"))?, "1");
        assert_eq!(fs::read_to_string(original.join("cgroup.kill"))?, "0");
        fs::write(moved.join("cgroup.events"), "populated 0\n")?;
        assert!(controls.is_empty(deadline)?);
        assert_eq!(
            fs::read_to_string(original.join("cgroup.events"))?,
            "populated 1\nfrozen 0\n"
        );
        Ok(())
    }

    #[test]
    fn cgroup_relative_paths_are_closed_and_canonical() {
        for path in [
            "/",
            "unit",
            "/unit/",
            "/unit//child",
            "/unit/../child",
            "/unit/./child",
            "/unit\0",
        ] {
            assert!(validate_path(path).is_err());
        }
        assert!(validate_path("/system.slice/exact.service").is_ok());
    }

    #[test]
    fn linked_controls_and_ambiguous_population_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let unit = directory.path().join("unit");
        fixture(&unit, 42)?;
        let root = File::open(directory.path())?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut controls = HeldCgroup::beneath(&root, "/unit", deadline)?;
        for contents in [
            "",
            "populated 2\n",
            "populated 0\npopulated 1\n",
            "populated\n",
        ] {
            fs::write(unit.join("cgroup.events"), contents)?;
            assert!(controls.is_empty(deadline).is_err());
        }
        fs::rename(unit.join("cgroup.kill"), unit.join("old-kill"))?;
        std::os::unix::fs::symlink("old-kill", unit.join("cgroup.kill"))?;
        assert!(HeldCgroup::beneath(&root, "/unit", deadline).is_err());
        Ok(())
    }
}
