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
use super::gateway_health::GatewayHealthBootstrap;
use super::linux_launcher::{PendingLaunch, TrustedLinuxLauncher};
use crate::worker_bootstrap::WorkerBootstrapLaunch;
use rustix::fs::{SealFlags, fcntl_get_seals};
use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod adapter;
mod cgroup;
#[allow(clippy::wildcard_imports)]
use self::cgroup::*;
mod identity;
#[allow(clippy::wildcard_imports)]
use self::identity::*;
mod observe;
#[allow(clippy::wildcard_imports)]
use self::observe::*;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::{Child, Command};
    use tempfile::tempdir;

    #[test]
    fn sealed_memfd_process_is_observed_without_canonicalizing_deleted_name()
    -> Result<(), Box<dyn std::error::Error>> {
        use rustix::fs::{MemfdFlags, fcntl_add_seals, memfd_create};
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        let source = fs::canonicalize("/bin/sleep")?;
        let mut image = fs::File::from(memfd_create(
            "ascension-sealed-observation-test",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )?);
        std::io::copy(&mut fs::File::open(&source)?, &mut image)?;
        fcntl_add_seals(
            &image,
            SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL,
        )?;
        let mut child = ChildGuard(Some(
            Command::new(format!("/proc/self/fd/{}", image.as_raw_fd()))
                .arg0("sleep")
                .arg("30")
                .spawn()?,
        ));
        let pid = child.as_mut().id();
        // `Child::spawn` returns as soon as the forked child exists, while an
        // exec-from-memfd can still be settling. Poll the bounded identity
        // observation until the sealed image and source digest agree instead
        // of making the test depend on that scheduler race.
        let digest = hash_file(&source)?;
        let mut observed = None;
        for _ in 0..100 {
            if let Ok(candidate) = read_live_process("test-boot", pid)
                && candidate.executable_sealed
                && is_sealed_memfd(&candidate.executable)
                && live_process_matches_executable(&candidate, &source, &digest)
            {
                observed = Some(candidate);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let observed = observed.ok_or("sealed memfd identity did not settle")?;
        assert!(observed.executable_sealed);
        assert!(is_sealed_memfd(&observed.executable));
        assert!(live_process_matches_executable(&observed, &source, &digest));
        let normalized = read_live_process_for_executable("test-boot", pid, &source)?
            .expect("sealed image observation");
        assert_eq!(normalized.executable, source);
        assert_eq!(normalized.executable_sha256, digest);
        assert!(normalized.executable_sealed);
        child.reap()?;
        Ok(())
    }

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
    fn missing_planned_containment_is_not_treated_as_clean()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let launcher = TrustedLinuxLauncher::new("/bin/true")?;
        let mut adapter = LinuxProcessAdapter {
            cgroup_root: CgroupRoot {
                path: directory.path().to_owned(),
            },
            boot_id: "test-boot".to_owned(),
            allowlist: BTreeMap::new(),
            children: BTreeMap::new(),
            uncertain_containments: BTreeMap::new(),
            max_children: MAX_ACTIVE_CHILDREN,
            launcher,
        };
        let planned = ContainmentId::new("cgroup-v2:missing-planned")?;

        let error = adapter
            .force_cleanup_planned_containment(&planned)
            .expect_err("missing containment cannot prove failed-launch cleanup");
        assert!(is_cleanup_uncertain(&error));
        assert!(!adapter.has_uncertain_containment(&planned));
        Ok(())
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
    fn missing_containment_requires_creation_token_proof() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let mut child = ChildGuard::sleep()?;
        let pid = child.as_mut().id();
        let live = read_live_process("test-boot", pid)?;
        let containment = ContainmentId::new("cgroup-v2:missing")?;
        let identity = ProcessIdentity {
            deployment_id: "deployment".to_owned(),
            instance_id: "instance".to_owned(),
            component: ComponentKind::Synthetic,
            incarnation: "incarnation".to_owned(),
            launch_nonce: "nonce".to_owned(),
            creation: ProcessCreation {
                token: live.token,
                pid,
            },
            executable: live.executable,
            executable_sha256: live.executable_sha256,
            containment,
            session: None,
        };
        let launcher = TrustedLinuxLauncher::new("/bin/true")?;
        let mut adapter = LinuxProcessAdapter {
            cgroup_root: CgroupRoot {
                path: directory.path().to_owned(),
            },
            boot_id: "test-boot".to_owned(),
            allowlist: BTreeMap::new(),
            children: BTreeMap::new(),
            uncertain_containments: BTreeMap::new(),
            max_children: MAX_ACTIVE_CHILDREN,
            launcher,
        };
        let owned = OwnedProcess {
            identity: identity.clone(),
        };
        assert_eq!(adapter.inspect(&owned)?, Observation::Ambiguous);
        assert!(matches!(
            adapter.graceful_stop(&owned),
            Err(AdapterError::Unavailable(message))
                if message.contains("recorded process remains present")
        ));

        child.reap()?;
        assert_eq!(adapter.inspect(&owned)?, Observation::Missing);
        assert_eq!(adapter.graceful_stop(&owned)?, StopOutcome::AlreadyExited);

        let mut replacement = ChildGuard::sleep()?;
        let reused_pid = replacement.as_mut().id();
        let mut reused = identity;
        reused.creation.pid = reused_pid;
        reused.creation.token = "test-boot:0".to_owned();
        let reused = OwnedProcess { identity: reused };
        assert_eq!(adapter.inspect(&reused)?, Observation::Missing);
        replacement.reap()?;
        Ok(())
    }

    #[test]
    fn empty_cgroup_requires_exact_child_exit_proof() -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, cgroup) = fake_cgroup("")?;
        let child = Command::new("/bin/sleep").arg("30").spawn()?;
        let pid = child.id();
        let containment = ContainmentId::new("cgroup-v2:failed-launch")?;
        let identity = ProcessIdentity {
            deployment_id: "deployment".to_owned(),
            instance_id: "instance".to_owned(),
            component: ComponentKind::Synthetic,
            incarnation: "incarnation".to_owned(),
            launch_nonce: "nonce".to_owned(),
            creation: ProcessCreation {
                token: "test:0".to_owned(),
                pid,
            },
            executable: PathBuf::from("/bin/sleep"),
            executable_sha256: "a".repeat(64),
            containment,
            session: None,
        };
        let launcher = TrustedLinuxLauncher::new("/bin/true")?;
        let mut adapter = LinuxProcessAdapter {
            cgroup_root: CgroupRoot {
                path: cgroup
                    .path()
                    .parent()
                    .ok_or_else(|| std::io::Error::other("fake cgroup has no root"))?
                    .to_owned(),
            },
            boot_id: "test".to_owned(),
            allowlist: BTreeMap::new(),
            children: BTreeMap::new(),
            uncertain_containments: BTreeMap::new(),
            max_children: MAX_ACTIVE_CHILDREN,
            launcher,
        };
        adapter.children.insert(
            identity.containment.as_str().to_owned(),
            ManagedProcess {
                child: Some(child),
                exit_status: None,
                graceful_timeout: DEFAULT_GRACEFUL_TIMEOUT,
                force_timeout: DEFAULT_FORCE_TIMEOUT,
            },
        );

        let observation = adapter.observe_identity(&identity, &cgroup)?;
        assert_eq!(observation, Observation::Ambiguous);

        let managed = adapter
            .children
            .get_mut(identity.containment.as_str())
            .ok_or_else(|| std::io::Error::other("test managed child missing"))?;
        let child = managed
            .child
            .as_mut()
            .ok_or_else(|| std::io::Error::other("test child missing"))?;
        child.kill()?;
        child.wait()?;
        assert!(matches!(
            adapter.observe_identity(&identity, &cgroup)?,
            Observation::Exited { .. }
        ));
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
