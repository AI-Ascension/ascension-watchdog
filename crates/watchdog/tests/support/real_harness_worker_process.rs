// SPDX-License-Identifier: MIT

//! Real daemon process ownership and durable worker observations.

use ascension_watchdog::config::{DesiredMode, WatchdogConfig};
use ascension_watchdog::policy::ComponentState;
use ascension_watchdog::storage::{Store, WorkerControlMode, WorkerHandoffState};
use std::fs;
use std::io;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

#[path = "real_harness_worker_scope.rs"]
mod real_harness_worker_scope;
use real_harness_worker_scope::{ScopeLaunch, ScopeOwner};

const DAEMON_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const HANDOFF_TIMEOUT: Duration = Duration::from_secs(30);
pub(super) const DAEMON_STOP_TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(super) struct DaemonGuard {
    child: Option<Child>,
    pidfd: OwnedFd,
    config: WatchdogConfig,
    scope: Option<ScopeOwner>,
}

impl DaemonGuard {
    pub(super) fn start(
        config: &WatchdogConfig,
        daemon_image: &Path,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Verify pidfd support before spawning anything. Emergency cleanup can
        // then target this exact child even if its numeric PID is reused; no
        // process-group signal is needed or safe here.
        let current_pid = rustix::process::getpid();
        let _ = rustix::process::pidfd_open(current_pid, rustix::process::PidfdFlags::NONBLOCK)
            .map_err(|error| io::Error::other(format!("pidfd support is required: {error}")))?;
        let ScopeLaunch {
            child,
            pidfd,
            scope,
        } = ScopeOwner::start(config, daemon_image)?;
        Ok(Self {
            child: Some(child),
            pidfd,
            config: config.clone(),
            scope: Some(scope),
        })
    }

    fn ensure_running(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(status) = self
            .child
            .as_mut()
            .ok_or_else(|| io::Error::other("daemon guard lost its child"))?
            .try_wait()?
        {
            return Err(io::Error::other(format!(
                "watchdog daemon exited before completing the smoke: {status}"
            ))
            .into());
        }
        Ok(())
    }

    pub(super) fn wait_for_worker(
        &mut self,
        config: &WatchdogConfig,
    ) -> Result<(u32, PathBuf), Box<dyn std::error::Error>> {
        let worker = config
            .worker
            .as_ref()
            .ok_or_else(|| io::Error::other("smoke config has no worker binding"))?;
        let expected_component = config
            .components
            .iter()
            .find(|component| component.id == worker.component_id)
            .ok_or_else(|| io::Error::other("smoke worker component is missing"))?;
        let deadline = Instant::now() + DAEMON_STARTUP_TIMEOUT;
        let mut last_detail = String::new();
        let mut last_error = None;
        while Instant::now() < deadline {
            self.ensure_running()?;
            match Store::open_read_only(&config.database, config) {
                Ok(store) => {
                    let component = store.component(&worker.component_id)?;
                    let control = store.current_worker_control()?;
                    if let Some(record) = component {
                        if record.last_error != last_error {
                            if let Some(error) = &record.last_error {
                                eprintln!("native worker launch diagnostic: {error}");
                            }
                            last_error.clone_from(&record.last_error);
                        }
                        if record.state == ComponentState::Quarantined {
                            return Err(io::Error::other(format!(
                                "native harness component was quarantined: {}",
                                record
                                    .last_error
                                    .unwrap_or_else(|| "no diagnostic".to_owned())
                            ))
                            .into());
                        }
                        if record.state == ComponentState::Running
                            && let (Some(pid), Some(nonce), Some(control)) =
                                (record.pid, record.launch_nonce, control.as_ref())
                            && control.mode == WorkerControlMode::Running
                        {
                            let identity = store.component_identity(&worker.component_id)?;
                            let matching_identity = identity.as_ref().is_some_and(|identity| {
                                identity.pid == pid
                                    && identity.launch_nonce == nonce
                                    && identity.executable == expected_component.executable
                                    && Some(identity.executable_digest.as_str())
                                        == expected_component.executable_sha256.as_deref()
                                    && Some(identity.started_at_ms) == record.started_at_ms
                                    && live_birth_matches(identity).unwrap_or(false)
                            });
                            if !matching_identity {
                                "worker identity changed during readiness observation"
                                    .clone_into(&mut last_detail);
                                thread::sleep(POLL_INTERVAL);
                                continue;
                            }
                            let endpoint = worker.endpoint_for_launch(&nonce)?;
                            let metadata = fs::symlink_metadata(&endpoint);
                            if metadata
                                .as_ref()
                                .is_ok_and(|metadata| metadata.file_type().is_socket())
                            {
                                self.scope
                                    .as_mut()
                                    .ok_or_else(|| io::Error::other("daemon guard lost scope"))?
                                    .verify_and_record_worker(pid)?;
                                // Bracket the observation with the complete
                                // persisted witnesses so a restart cannot mix
                                // a prior PID/nonce with new control state.
                                if store.component_identity(&worker.component_id)? != identity
                                    || store.current_worker_control()?.as_ref() != Some(control)
                                {
                                    "worker changed while scope membership was checked"
                                        .clone_into(&mut last_detail);
                                    thread::sleep(POLL_INTERVAL);
                                    continue;
                                }
                                return Ok((pid, endpoint));
                            }
                            last_detail = format!(
                                "component running/control running but worker endpoint is absent: {}",
                                endpoint.display()
                            );
                        } else {
                            last_detail = format!(
                                "component={:?} control={:?}",
                                record.state,
                                control.map(|value| value.mode)
                            );
                        }
                    } else {
                        "harness component record is not published yet"
                            .clone_into(&mut last_detail);
                    }
                }
                Err(error) => last_detail = error.to_string(),
            }
            thread::sleep(POLL_INTERVAL);
        }
        Err(io::Error::other(format!(
            "watchdog/harness worker did not become ready: {last_detail}"
        ))
        .into())
    }

    pub(super) fn wait_for_dispatch_outcome(
        &mut self,
        config: &WatchdogConfig,
        job_id: &str,
    ) -> Result<ascension_watchdog::storage::WorkerHandoff, Box<dyn std::error::Error>> {
        let deadline = Instant::now() + HANDOFF_TIMEOUT;
        let mut last_detail = String::new();
        let mut handoff_id = None;
        while Instant::now() < deadline {
            self.ensure_running()?;
            match Store::open_read_only(&config.database, config) {
                Ok(store) => {
                    if handoff_id.is_none()
                        && let Some(handoff) = store.next_worker_handoff_for_reconciliation()?
                    {
                        if handoff.job_id != job_id {
                            return Err(io::Error::other(format!(
                                "unexpected worker handoff {} while waiting for job {job_id}",
                                handoff.handoff_id
                            ))
                            .into());
                        }
                        handoff_id = Some(handoff.handoff_id);
                    }
                    if let Some(handoff_id) = handoff_id.as_deref() {
                        let handoff = store.worker_handoff(handoff_id)?.ok_or_else(|| {
                            io::Error::other(format!("worker handoff {handoff_id} disappeared"))
                        })?;
                        if handoff.job_id != job_id {
                            return Err(io::Error::other(format!(
                                "worker handoff {handoff_id} changed to job {}",
                                handoff.job_id
                            ))
                            .into());
                        }
                        if matches!(
                            handoff.state,
                            WorkerHandoffState::Admitted
                                | WorkerHandoffState::Completed
                                | WorkerHandoffState::Failed
                                | WorkerHandoffState::Acknowledged
                        ) {
                            return Ok(handoff);
                        }
                        if handoff.state == WorkerHandoffState::Rejected {
                            return Err(io::Error::other(
                                "real harness worker rejected the dispatched handoff",
                            )
                            .into());
                        }
                        last_detail = format!("handoff state={:?}", handoff.state);
                    } else {
                        "handoff has not been prepared yet".clone_into(&mut last_detail);
                    }
                }
                Err(error) => last_detail = error.to_string(),
            }
            thread::sleep(POLL_INTERVAL);
        }
        Err(io::Error::other(format!(
            "real harness worker did not acknowledge dispatch: {last_detail}"
        ))
        .into())
    }

    pub(super) fn wait_for_successful_exit(
        &mut self,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + timeout;
        let status = loop {
            let child = self
                .child
                .as_mut()
                .ok_or_else(|| io::Error::other("daemon guard lost its child"))?;
            match child.try_wait()? {
                Some(status) => break status,
                None if Instant::now() >= deadline => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "watchdog daemon did not exit after durable stop",
                    )
                    .into());
                }
                None => thread::sleep(POLL_INTERVAL),
            }
        };
        if let Some(scope) = self.scope.as_mut() {
            scope.wait_stopped(timeout)?;
        }
        self.child = None;
        if !status.success() {
            return Err(io::Error::other(format!(
                "watchdog daemon exited unsuccessfully after durable stop: {status}"
            ))
            .into());
        }
        Ok(())
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        if self.child.is_none() {
            if let Some(scope) = self.scope.as_mut()
                && let Err(error) = scope.stop()
            {
                eprintln!("daemon scope cleanup could not settle: {error}");
            }
            return;
        }
        match Store::open(&self.config.database, &self.config)
            .and_then(|mut store| store.set_desired_mode_at(DesiredMode::Stopped, unix_now_ms()))
        {
            Ok(()) => {}
            Err(error) => {
                eprintln!(
                    "daemon cleanup could not persist stop intent: {error}; manager lifetime retained"
                );
                return;
            }
        }
        if let Some(scope) = self.scope.as_mut()
            && let Err(error) = scope.stop()
        {
            eprintln!("daemon scope cleanup could not settle: {error}");
        }
        match self
            .child
            .as_mut()
            .expect("child presence checked")
            .try_wait()
        {
            Ok(Some(_)) => {
                self.child = None;
                return;
            }
            Ok(None) => {}
            Err(error) => {
                eprintln!("daemon cleanup could not establish child liveness: {error}");
                let _ =
                    rustix::process::pidfd_send_signal(&self.pidfd, rustix::process::Signal::KILL);
                return;
            }
        }
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        loop {
            let child = self.child.as_mut().expect("child remains owned");
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.child = None;
                    return;
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
                Ok(None) => break,
                Err(error) => {
                    eprintln!("daemon cleanup lost child wait authority: {error}");
                    let _ = rustix::process::pidfd_send_signal(
                        &self.pidfd,
                        rustix::process::Signal::KILL,
                    );
                    return;
                }
            }
        }
        // The latest observation was exactly Ok(None), so the child was known
        // live. pidfd_send_signal remains identity-safe if it exits before the
        // syscall; a reused numeric PID can never receive this signal.
        if let Err(error) =
            rustix::process::pidfd_send_signal(&self.pidfd, rustix::process::Signal::KILL)
        {
            eprintln!("daemon emergency pidfd kill failed: {error}");
        }
        let reap_deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let child = self.child.as_mut().expect("child remains owned");
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.child = None;
                    return;
                }
                Ok(None) if Instant::now() < reap_deadline => thread::sleep(POLL_INTERVAL),
                Ok(None) => {
                    eprintln!("daemon remained live after bounded pidfd cleanup");
                    return;
                }
                Err(error) => {
                    eprintln!("daemon cleanup reap lost child wait authority: {error}");
                    return;
                }
            }
        }
    }
}

fn live_birth_matches(identity: &ascension_watchdog::process::ProcessIdentity) -> io::Result<bool> {
    fn read_proc(path: &Path) -> io::Result<String> {
        let mut value = String::new();
        fs::File::open(path)?
            .take(4097)
            .read_to_string(&mut value)?;
        if value.len() > 4096 {
            return Err(io::Error::other(
                "process identity evidence exceeds its bound",
            ));
        }
        Ok(value)
    }
    let boot = read_proc(Path::new("/proc/sys/kernel/random/boot_id"))?;
    let stat = read_proc(&PathBuf::from(format!("/proc/{}/stat", identity.pid)))?;
    let start_ticks = stat
        .rsplit_once(") ")
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|value| value.parse::<u64>().ok());
    Ok(start_ticks.is_some_and(|ticks| {
        ticks != 0
            && identity.creation_fingerprint.as_deref()
                == Some(format!("{}:{ticks}", boot.trim()).as_str())
    }))
}

pub(super) fn wait_for_cleanup(
    config: &WatchdogConfig,
    endpoint: &Path,
    worker_pid: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let process_path = PathBuf::from("/proc").join(worker_pid.to_string());
    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    let mut last_detail = String::new();
    while Instant::now() < deadline {
        let endpoint_present = fs::symlink_metadata(endpoint).is_ok();
        let process_present = process_path.exists();
        let component_stopped = match Store::open_read_only(&config.database, config) {
            Ok(store) => store.component("harness")?.is_some_and(|record| {
                record.state == ComponentState::Stopped
                    && record.pid.is_none()
                    && record.launch_nonce.is_none()
            }),
            Err(_) => false,
        };
        if !endpoint_present && !process_present && component_stopped {
            return Ok(());
        }
        last_detail = format!(
            "endpoint_present={endpoint_present}; process_present={process_present}; component_stopped={component_stopped}"
        );
        thread::sleep(POLL_INTERVAL);
    }
    Err(io::Error::other(format!("native stop cleanup did not settle: {last_detail}")).into())
}

pub(super) fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
