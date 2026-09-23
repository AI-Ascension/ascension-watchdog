//! Scope ownership: launcher guard, admission and durable stop proof.

use super::cgroup::{OriginalCgroup, process_in_scope, process_matches_image, require_cgroup_v2};
use super::commands::{show_unit, systemd_command};
use super::evidence::write_proof;
use super::paths::{canonical_config, canonical_regular, sha256_file};
use super::properties::{
    ScopeProof, ScopeProperties, validate_observed_scope_identity, validate_scope_properties,
    validate_stopped_scope_identity,
};
use super::{ENV, POLL_INTERVAL, START_TIMEOUT, STOP_TIMEOUT, SYSTEMD_RUN};
use ascension_watchdog::config::{DesiredMode, WatchdogConfig};
use ascension_watchdog::storage::Store;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub(crate) struct ScopeLaunch {
    pub(crate) child: Child,
    pub(crate) pidfd: OwnedFd,
    pub(crate) scope: ScopeOwner,
}

/// Own the systemd-run launcher from the instant it is spawned.  The
/// launcher is normally an exec'd daemon, so dropping its `Child` on any
/// startup error would otherwise leave the scope's process unmanaged by the
/// Rust side. Durable Stop is recorded first, then the exact pidfd is used
/// for bounded cleanup. The already configured manager lifetime remains the
/// authority for descendants when direct cleanup cannot be proved complete.
/// Own the systemd-run launcher from the instant it is spawned.  The
/// launcher is normally an exec'd daemon, so dropping its `Child` on any
/// startup error would otherwise leave the scope's process unmanaged by the
/// Rust side. Durable Stop is recorded first, then the exact pidfd is used
/// for bounded cleanup. The already configured manager lifetime remains the
/// authority for descendants when direct cleanup cannot be proved complete.
pub(crate) struct LauncherGuard {
    child: Option<Child>,
    pidfd: Option<OwnedFd>,
    pidfd_error: Option<String>,
    scope: Option<ScopeOwner>,
}

impl LauncherGuard {
    pub(crate) fn new(child: Child, scope: ScopeOwner) -> Self {
        let (pidfd, pidfd_error) = match rustix::process::pidfd_open(
            rustix::process::Pid::from_child(&child),
            rustix::process::PidfdFlags::NONBLOCK,
        ) {
            Ok(pidfd) => (Some(pidfd), None),
            Err(error) => (None, Some(error.to_string())),
        };
        Self {
            child: Some(child),
            pidfd,
            pidfd_error,
            scope: Some(scope),
        }
    }

    pub(crate) fn child_id(&self) -> Result<u32, Box<dyn std::error::Error>> {
        self.child
            .as_ref()
            .map(Child::id)
            .ok_or_else(|| io::Error::other("scope launcher lost its child").into())
    }

    pub(crate) fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>, io::Error> {
        self.child
            .as_mut()
            .ok_or_else(|| io::Error::other("scope launcher lost its child"))?
            .try_wait()
    }

    pub(crate) fn scope_mut(&mut self) -> Result<&mut ScopeOwner, Box<dyn std::error::Error>> {
        self.scope
            .as_mut()
            .ok_or_else(|| io::Error::other("scope launcher lost its scope").into())
    }

    pub(crate) fn into_launch(mut self) -> Result<ScopeLaunch, Box<dyn std::error::Error>> {
        let pidfd = self.pidfd.take().ok_or_else(|| {
            io::Error::other(format!(
                "cannot retain daemon pidfd before scope admission: {}",
                self.pidfd_error
                    .as_deref()
                    .unwrap_or("pidfd was not captured")
            ))
        })?;
        Ok(ScopeLaunch {
            child: self
                .child
                .take()
                .ok_or_else(|| io::Error::other("scope launcher lost its child"))?,
            pidfd,
            scope: self
                .scope
                .take()
                .ok_or_else(|| io::Error::other("scope launcher lost its scope"))?,
        })
    }

    pub(crate) fn cleanup(&mut self) {
        if self.child.is_none() {
            return;
        }
        let Some(scope) = self.scope.as_mut() else {
            eprintln!("pre-admission launcher lost its durable scope proof");
            return;
        };
        if let Err(error) = scope.persist_stop() {
            eprintln!("pre-admission durable stop is uncertain: {error}");
            return;
        }
        let Some(child) = self.child.as_mut() else {
            return;
        };
        let initial_wait_error = match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => None,
            Err(error) => {
                eprintln!("pre-admission child liveness is uncertain: {error}");
                Some(error)
            }
        };
        if let Some(pidfd) = self.pidfd.as_ref() {
            if let Err(error) =
                rustix::process::pidfd_send_signal(pidfd, rustix::process::Signal::KILL)
            {
                eprintln!("pre-admission pidfd kill failed: {error}");
            }
        } else if initial_wait_error.is_none()
            && let Err(error) = child.kill()
        {
            // This still-owned Child was just observed as live and has not
            // been reaped. This path covers failure to capture the pidfd.
            eprintln!("pre-admission owned Child kill failed: {error}");
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
                Ok(None) => {
                    let wait_detail = initial_wait_error
                        .map(|error| format!("; initial wait failed: {error}"))
                        .unwrap_or_default();
                    eprintln!(
                        "pre-admission launcher remained live after bounded cleanup{wait_detail}"
                    );
                    return;
                }
                Err(error) => {
                    eprintln!("pre-admission launcher reap is uncertain: {error}");
                    return;
                }
            }
        }
    }
}

impl Drop for LauncherGuard {
    fn drop(&mut self) {
        if self.child.is_some() {
            self.cleanup();
        }
    }
}

pub(crate) struct ScopeOwner {
    unit: String,
    description: String,
    proof_path: PathBuf,
    config_path: PathBuf,
    config_digest: String,
    daemon_image: PathBuf,
    daemon_sha256: String,
    config: WatchdogConfig,
    control_group: Option<String>,
    original_cgroup: Option<OriginalCgroup>,
    daemon_pid: Option<u32>,
    worker_pid: Option<u32>,
    expected: BTreeMap<String, String>,
    actual: BTreeMap<String, String>,
    started: bool,
    stopped: bool,
}

impl ScopeOwner {
    pub(crate) fn start(
        config: &WatchdogConfig,
        daemon_image: &Path,
    ) -> Result<ScopeLaunch, Box<dyn std::error::Error>> {
        let owner = Self::new(config, daemon_image)?;
        let launcher = owner.spawn()?;
        admit_scope(launcher)
    }

    pub(crate) fn new(
        config: &WatchdogConfig,
        daemon_image: &Path,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let raw_config = config
            .source_path
            .as_deref()
            .ok_or_else(|| io::Error::other("loaded config lost its source path"))?;
        let config_path = canonical_config(raw_config)?;
        let config_digest = config.digest()?;
        // Config files are read by the daemon but are not executables.  The
        // executable checks above are intentionally only applied to image.
        let config_metadata = fs::metadata(&config_path)?;
        if !config_metadata.file_type().is_file() {
            return Err(io::Error::other("watchdog config is not regular").into());
        }
        let daemon_image = canonical_regular(daemon_image, "daemon image")?;
        let daemon_sha256 = sha256_file(&daemon_image)?;
        let suffix = Uuid::new_v4().simple().to_string();
        let unit = format!("ascension-watchdog-real-{suffix}.scope");
        let description = format!("ascension-watchdog-real-harness-{suffix}");
        let proof_path = config_path
            .parent()
            .ok_or_else(|| io::Error::other("config has no parent directory"))?
            .join(format!("{unit}.proof.json"));
        let expected = BTreeMap::from([
            ("Delegate".to_owned(), "yes".to_owned()),
            ("KillMode".to_owned(), "control-group".to_owned()),
            ("SendSIGKILL".to_owned(), "yes".to_owned()),
            ("RuntimeMaxUSec".to_owned(), "<=120s".to_owned()),
            ("TimeoutStopUSec".to_owned(), "<=5s".to_owned()),
            ("CollectMode".to_owned(), "inactive-or-failed".to_owned()),
        ]);
        let owner = Self {
            unit,
            description,
            proof_path,
            config_path,
            config_digest,
            daemon_image,
            daemon_sha256,
            config: config.clone(),
            control_group: None,
            original_cgroup: None,
            daemon_pid: None,
            worker_pid: None,
            expected,
            actual: BTreeMap::new(),
            started: false,
            stopped: false,
        };
        owner.write_state("planned", "scope has not been spawned")?;
        require_cgroup_v2()?;
        if let Ok(properties) = show_unit(&owner.unit)
            && properties.get("LoadState") != Some("not-found")
        {
            return Err(io::Error::other("random scope unit unexpectedly already exists").into());
        }
        Ok(owner)
    }

    pub(crate) fn spawn(mut self) -> Result<LauncherGuard, Box<dyn std::error::Error>> {
        let mut command = systemd_command(SYSTEMD_RUN)?;
        command
            .args([
                "--user",
                "--scope",
                "--collect",
                "--quiet",
                "--unit",
                &self.unit,
                "--description",
                &self.description,
                "--property=Delegate=yes",
                "--property=RuntimeMaxSec=120s",
                "--property=TimeoutStopSec=5s",
                "--property=KillMode=control-group",
                "--property=SendSIGKILL=yes",
                ENV,
                "-i",
            ])
            .arg(&self.daemon_image)
            .args(["daemon", "--config"])
            .arg(&self.config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let child = command.spawn()?;
        self.started = true;
        self.daemon_pid = Some(child.id());
        Ok(LauncherGuard::new(child, self))
    }
}

pub(crate) fn admit_scope(
    mut launcher: LauncherGuard,
) -> Result<ScopeLaunch, Box<dyn std::error::Error>> {
    if launcher.pidfd.is_none() {
        return Err(io::Error::other(format!(
            "cannot retain daemon pidfd before scope admission: {}",
            launcher
                .pidfd_error
                .as_deref()
                .unwrap_or("pidfd was not captured")
        ))
        .into());
    }
    let deadline = Instant::now() + START_TIMEOUT;
    let mut last_detail = String::new();
    while Instant::now() < deadline {
        if let Some(status) = launcher.try_wait()? {
            return Err(io::Error::other(format!(
                "daemon exited before scope admission: {status}; {last_detail}"
            ))
            .into());
        }
        let child_pid = launcher.child_id()?;
        let (unit, description, daemon_image, daemon_sha256) = {
            let scope = launcher.scope_mut()?;
            (
                scope.unit.clone(),
                scope.description.clone(),
                scope.daemon_image.clone(),
                scope.daemon_sha256.clone(),
            )
        };
        match show_unit(&unit) {
            Ok(properties) => match validate_scope_properties(&properties, &unit, &description) {
                Ok(control_group)
                    if process_in_scope(child_pid, &control_group).unwrap_or(false)
                        && process_matches_image(child_pid, &daemon_image, &daemon_sha256)
                            .unwrap_or(false) =>
                {
                    let original_cgroup = match OriginalCgroup::open(&control_group) {
                        Ok(original_cgroup) => original_cgroup,
                        Err(error) => {
                            last_detail = format!(
                                "original cgroup could not be retained during admission: {error}"
                            );
                            thread::sleep(POLL_INTERVAL);
                            continue;
                        }
                    };
                    // The daemon can move or exit while the cgroup handles
                    // are being captured.  Recheck membership after capture
                    // so the proof and process snapshot refer to one stable
                    // admission point.
                    if !process_in_scope(child_pid, &control_group).unwrap_or(false) {
                        "daemon left the scope while retaining cgroup handles"
                            .clone_into(&mut last_detail);
                        thread::sleep(POLL_INTERVAL);
                        continue;
                    }
                    let scope = launcher.scope_mut()?;
                    scope.control_group = Some(control_group);
                    scope.original_cgroup = Some(original_cgroup);
                    scope.actual = properties.values;
                    scope.write_state("active", "scope properties and daemon cgroup verified")?;
                    return launcher.into_launch();
                }
                Ok(_) => {
                    "daemon is not in the verified scope or image".clone_into(&mut last_detail);
                }
                Err(error) => last_detail = error,
            },
            Err(error) => last_detail = error.to_string(),
        }
        thread::sleep(POLL_INTERVAL);
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("scope admission did not settle: {last_detail}"),
    )
    .into())
}

impl ScopeOwner {
    pub(crate) fn write_state(
        &self,
        state: &str,
        detail: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let proof = ScopeProof {
            schema_version: 1,
            state: state.to_owned(),
            unit: self.unit.clone(),
            description: self.description.clone(),
            config_path: self.config_path.display().to_string(),
            config_digest: self.config_digest.clone(),
            daemon_image: self.daemon_image.display().to_string(),
            daemon_sha256: self.daemon_sha256.clone(),
            control_group: self.control_group.clone(),
            daemon_pid: self.daemon_pid,
            worker_pid: self.worker_pid,
            expected: self.expected.clone(),
            actual: self.actual.clone(),
            detail: detail.to_owned(),
        };
        write_proof(&self.proof_path, &proof)
    }

    pub(crate) fn verify_and_record_worker(
        &mut self,
        worker_pid: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let control_group = self
            .control_group
            .as_deref()
            .ok_or_else(|| io::Error::other("scope has no verified cgroup"))?;
        if !process_in_scope(worker_pid, control_group)? {
            return Err(io::Error::other(format!(
                "worker {worker_pid} is outside daemon scope {control_group}"
            ))
            .into());
        }
        self.worker_pid = Some(worker_pid);
        self.write_state("active", "daemon and worker cgroup membership verified")
    }

    pub(crate) fn wait_stopped(
        &mut self,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + timeout;
        let mut last_detail = String::new();
        while Instant::now() < deadline {
            match show_unit(&self.unit) {
                Ok(properties) => {
                    let absent = properties.get("LoadState") == Some("not-found");
                    if absent {
                        // A not-found response cannot retain the old
                        // Description, but systemd still echoes the exact
                        // requested Id.  The retained cgroup handle below is
                        // the authority for the old scope's emptiness.
                        if properties.get("Id") != Some(self.unit.as_str()) {
                            let detail = format!(
                                "missing scope Id {:?} does not match {:?}",
                                properties.get("Id"),
                                self.unit
                            );
                            return self.mark_uncertain(&detail);
                        }
                        if properties.state() != Some("inactive") {
                            let detail = format!(
                                "missing scope has unexpected state {:?}",
                                properties.state()
                            );
                            return self.mark_uncertain(&detail);
                        }
                        let empty = match self.original_cgroup_empty(None) {
                            Ok(empty) => empty,
                            Err(error) => {
                                let detail = format!(
                                    "scope not found but original cgroup proof failed: {error}"
                                );
                                return self.mark_uncertain(&detail);
                            }
                        };
                        if empty {
                            self.actual = properties.values;
                            self.stopped = true;
                            self.write_state(
                                "stopped",
                                "scope not found and retained original cgroup is empty",
                            )?;
                            return Ok(());
                        }
                        "scope not found but retained original cgroup is still populated"
                            .clone_into(&mut last_detail);
                    } else {
                        if let Err(error) = validate_observed_scope_identity(
                            &properties,
                            &self.unit,
                            &self.description,
                        ) {
                            return self.mark_uncertain(&error);
                        }
                        let inactive = matches!(properties.state(), Some("inactive" | "failed"));
                        if inactive {
                            if let Err(error) = self.validate_inactive_scope(&properties) {
                                return self.mark_uncertain(&error);
                            }
                            let empty = match self.original_cgroup_empty(properties.control_group())
                            {
                                Ok(empty) => empty,
                                Err(error) => {
                                    let detail = format!(
                                        "scope identity/cgroup proof failed while stopping: {error}"
                                    );
                                    return self.mark_uncertain(&detail);
                                }
                            };
                            if empty {
                                self.actual = properties.values;
                                self.stopped = true;
                                self.write_state(
                                    "stopped",
                                    "scope inactive and retained original cgroup is empty",
                                )?;
                                return Ok(());
                            }
                            last_detail = format!(
                                "scope state={:?}; retained original cgroup is populated",
                                properties.state()
                            );
                        } else {
                            last_detail = format!(
                                "scope state={:?}; waiting for inactive state",
                                properties.state()
                            );
                        }
                    }
                }
                Err(error) => last_detail = error.to_string(),
            }
            thread::sleep(POLL_INTERVAL);
        }
        self.write_state(
            "uncertain",
            &format!("scope stop did not settle: {last_detail}"),
        )?;
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("scope did not become inactive with empty cgroup: {last_detail}"),
        )
        .into())
    }

    pub(crate) fn validate_inactive_scope(
        &self,
        properties: &ScopeProperties,
    ) -> Result<(), String> {
        validate_stopped_scope_identity(
            properties,
            &self.unit,
            &self.description,
            self.original_cgroup
                .as_ref()
                .map(|original| original.control_group.as_str()),
        )
    }

    pub(crate) fn original_cgroup_empty(
        &mut self,
        observed_control_group: Option<&str>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let original = self.original_cgroup.as_mut().ok_or_else(|| {
            io::Error::other("no retained original cgroup is available for stop proof")
        })?;
        if let Some(observed) = observed_control_group
            && observed != original.control_group
        {
            return Err(io::Error::other(format!(
                "observed cgroup {observed:?} does not match retained original {:?}",
                original.control_group
            ))
            .into());
        }
        original.empty()
    }

    pub(crate) fn mark_uncertain(&self, detail: &str) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.write_state("uncertain", detail);
        Err(io::Error::other(detail.to_owned()).into())
    }

    pub(crate) fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.started || self.stopped {
            return Ok(());
        }
        self.persist_stop()?;
        // Never issue a stop by unit name: a check followed by StopUnit could
        // target a recreated unit. The daemon observes durable Stop; its
        // retained pidfd is owned by the launcher/daemon guard. If it cannot
        // exit, the manager's preconfigured RuntimeMaxSec remains the bounded
        // descendant-cleanup authority. A timeout here is uncertainty, not a
        // successful stop or permission to address another process.
        self.wait_stopped(STOP_TIMEOUT)
    }

    pub(crate) fn persist_stop(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Err(error) = Store::open(&self.config.database, &self.config)
            .and_then(|mut store| store.set_desired_mode_at(DesiredMode::Stopped, unix_now_ms()))
        {
            let detail = format!("durable stop intent failed: {error}; manager lifetime retained");
            let _ = self.write_state("uncertain", &detail);
            return Err(io::Error::other(detail).into());
        }
        Ok(())
    }
}

impl Drop for ScopeOwner {
    fn drop(&mut self) {
        if self.started
            && !self.stopped
            && let Err(error) = self.stop()
        {
            eprintln!("real harness scope cleanup is uncertain: {error}");
        }
    }
}

pub(crate) fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
