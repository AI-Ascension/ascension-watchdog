//! Process-boundary authenticated job submission coverage.
//!
//! The in-process test exercises the queue directly. These tests launch the
//! compiled watchdog daemon and invoke the compiled CLI as separate processes
//! so token loading, endpoint binding, framing, queue admission, and durable
//! replay are covered together.

#![cfg(target_os = "linux")]

use ascension_watchdog::WatchdogError;
use ascension_watchdog::admin::{
    AdminClient, AdminClientConfig, AdminResult, Capability, ReplyStatus,
};
use ascension_watchdog::config::{AdminConfig, WatchdogConfig};
use ascension_watchdog::storage::{SingletonLock, Store, now_unix_ms};
use serde_json::json;
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const CLI_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const DAEMON_STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const READINESS_REQUEST_TIMEOUT: Duration = Duration::from_millis(100);
const CHILD_REAP_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_CLI_OUTPUT_BYTES: usize = 256 * 1024;

#[test]
fn actual_daemon_and_cli_processes_submit_complete_reopen_replay_and_deny_read()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcessFixture::new()?;
    fixture.config().to_file(&fixture.config_path)?;
    let mut init_command = ProcessFixture::command();
    init_command
        .args(["init", "--config"])
        .arg(&fixture.config_path);
    let init = run_bounded_cli(init_command)?;
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let mut daemon = fixture.start_daemon()?;
    let payload = fixture.temp.path().join("submission.json");
    std::fs::write(&payload, br#"{"episode":7,"private":"owner-local"}"#)?;
    std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o600))?;

    let first_output = ProcessFixture::submit(&fixture.config_path, "process-job", &payload)?;
    assert!(
        first_output.status.success(),
        "first submission failed: {}",
        String::from_utf8_lossy(&first_output.stderr)
    );
    let first: ascension_watchdog::admin::AdminResponse =
        serde_json::from_slice(&first_output.stdout)?;
    assert_eq!(first.status, ReplyStatus::Accepted);
    let first_id = response_job_id(&first)?;
    let replay_while_running_output =
        ProcessFixture::submit(&fixture.config_path, "process-job", &payload)?;
    assert!(
        replay_while_running_output.status.success(),
        "same-key replay failed: {}",
        String::from_utf8_lossy(&replay_while_running_output.stderr)
    );
    let replay_while_running: ascension_watchdog::admin::AdminResponse =
        serde_json::from_slice(&replay_while_running_output.stdout)?;
    assert_eq!(replay_while_running.status, ReplyStatus::Accepted);
    assert_eq!(response_job_id(&replay_while_running)?, first_id);

    // The CLI has no production completion mutation. Stop the exact daemon
    // handle, then use an owner-held Store to model the authorized worker
    // completing the queued job before the daemon is reopened.
    let read_denial_config = fixture.write_read_denial_config()?;
    let denied = ProcessFixture::submit(&read_denial_config, "read-denial", &payload)?;
    assert!(!denied.status.success());
    let denied_stderr = String::from_utf8_lossy(&denied.stderr);
    assert!(denied_stderr.contains("Forbidden"));
    assert!(!denied_stderr.contains("owner-local"));

    daemon.stop()?;
    {
        let owner = SingletonLock::acquire(&fixture.database)?;
        let config = fixture.config();
        let mut store = Store::open_for_owner(&fixture.database, &config, &owner)?;
        let now = now_unix_ms();
        store.set_desired_mode_at(ascension_watchdog::DesiredMode::Running, now)?;
        let claim = store
            .claim_next_job("process-test-worker", now.saturating_add(1))?
            .ok_or_else(|| {
                WatchdogError::Conflict("submitted process job was not claimable".to_owned())
            })?;
        store.complete_job_at(
            &claim.job.id,
            &claim.attempt_id,
            &json!({"completed": true}),
            now.saturating_add(2),
        )?;
        store.set_desired_mode_at(
            ascension_watchdog::DesiredMode::Stopped,
            now.saturating_add(3),
        )?;
    }

    let mut reopened = fixture.start_daemon()?;
    let replay_after_reopen_output =
        ProcessFixture::submit(&fixture.config_path, "process-job", &payload)?;
    assert!(
        replay_after_reopen_output.status.success(),
        "replay after reopen failed: {}",
        String::from_utf8_lossy(&replay_after_reopen_output.stderr)
    );
    let replay_after_reopen: ascension_watchdog::admin::AdminResponse =
        serde_json::from_slice(&replay_after_reopen_output.stdout)?;
    assert_eq!(replay_after_reopen.status, ReplyStatus::Accepted);
    assert_eq!(response_job_id(&replay_after_reopen)?, first_id);

    let mut list_command = ProcessFixture::command();
    list_command
        .args(["job", "list", "--config"])
        .arg(&fixture.config_path)
        .args(["--filter", "all"]);
    let listed = run_bounded_cli(list_command)?;
    assert!(
        listed.status.success(),
        "list failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed_response: ascension_watchdog::admin::AdminResponse =
        serde_json::from_slice(&listed.stdout)?;
    assert_eq!(listed_response.status, ReplyStatus::Ok);
    let Some(AdminResult::Jobs(jobs)) = listed_response.result else {
        return Err("job list did not return a Jobs result".into());
    };
    assert_eq!(jobs.jobs.len(), 1);
    assert!(!String::from_utf8_lossy(&listed.stdout).contains("owner-local"));

    reopened.stop()?;
    Ok(())
}

#[test]
fn cli_process_rejects_payload_file_with_a_symlinked_ancestor_before_ipc()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcessFixture::new()?;
    fixture.config().to_file(&fixture.config_path)?;
    let real_directory = fixture.temp.path().join("real");
    std::fs::create_dir(&real_directory)?;
    std::fs::set_permissions(&real_directory, std::fs::Permissions::from_mode(0o700))?;
    let payload = real_directory.join("submission.json");
    std::fs::write(&payload, br#"{"private":"must-not-leak"}"#)?;
    std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o600))?;
    let linked_directory = fixture.temp.path().join("linked");
    std::os::unix::fs::symlink(&real_directory, &linked_directory)?;

    let output = ProcessFixture::submit(
        &fixture.config_path,
        "symlinked-payload",
        &linked_directory.join("submission.json"),
    )?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("must-not-leak"));
    assert!(!fixture.endpoint.exists());
    Ok(())
}

#[test]
fn cli_process_rejects_fifo_payload_without_blocking_before_ipc()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcessFixture::new()?;
    fixture.config().to_file(&fixture.config_path)?;
    let fifo = fixture.temp.path().join("payload.fifo");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
    )?;

    let started = Instant::now();
    let output = ProcessFixture::submit(&fixture.config_path, "fifo-payload", &fifo)?;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "FIFO payload validation exceeded the bounded process window"
    );
    assert!(!output.status.success());
    assert!(!fixture.endpoint.exists());
    Ok(())
}

#[test]
fn bounded_cli_runner_cleans_descendant_holding_output_pipes()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let descendant_pid = temp.path().join("descendant.pid");
    let mut command = Command::new("sh");
    command.args([
        "-c",
        "sleep 30 & printf '%s' $! > \"$1\"; exit 0",
        "watchdog-test",
    ]);
    command.arg(&descendant_pid);
    let started = Instant::now();
    let output = run_bounded_cli(command)?;
    assert!(output.status.success());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "runner waited for a descendant-owned output pipe"
    );
    let pid = std::fs::read_to_string(&descendant_pid)?.parse::<i32>()?;
    let pid = rustix::process::Pid::from_raw(pid).ok_or("descendant PID was zero")?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if rustix::process::test_kill_process(pid).is_err() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err("synthetic descendant survived bounded CLI cleanup".into())
}

fn response_job_id(
    response: &ascension_watchdog::admin::AdminResponse,
) -> Result<String, Box<dyn std::error::Error>> {
    let Some(AdminResult::JobSubmitted(view)) = &response.result else {
        return Err("job submission did not return a JobSubmitted result".into());
    };
    Ok(view.job_id.clone())
}

struct ProcessFixture {
    temp: TempDir,
    config_path: PathBuf,
    database: PathBuf,
    endpoint: PathBuf,
    read_token: PathBuf,
    admin_token: PathBuf,
}

impl ProcessFixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))?;
        let read_token = temp.path().join("read.token");
        let admin_token = temp.path().join("admin.token");
        for (path, value) in [
            (&read_token, "process-read-token"),
            (&admin_token, "process-admin-token"),
        ] {
            std::fs::write(path, value)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self {
            config_path: temp.path().join("watchdog.json"),
            database: temp.path().join("watchdog.sqlite3"),
            endpoint: temp.path().join("watchdog.sock"),
            read_token,
            admin_token,
            temp,
        })
    }

    fn config(&self) -> WatchdogConfig {
        WatchdogConfig {
            database: self.database.clone(),
            probe_interval_ms: 10,
            admin: Some(AdminConfig {
                endpoint: self.endpoint.clone(),
                read_token_path: self.read_token.clone(),
                admin_token_path: self.admin_token.clone(),
                allowed_peer_sid: None,
            }),
            ..WatchdogConfig::default()
        }
    }

    fn command() -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_watchdog"));
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        command
    }

    fn start_daemon(&self) -> Result<DaemonGuard, Box<dyn std::error::Error>> {
        DaemonGuard::start(&self.config_path, self.endpoint.clone(), &self.read_token)
    }

    fn submit(
        config_path: &Path,
        key: &str,
        payload: &Path,
    ) -> Result<Output, Box<dyn std::error::Error>> {
        let mut command = Self::command();
        command
            .args(["job", "submit", "--config"])
            .arg(config_path)
            .args([
                "--idempotency-key",
                key,
                "--kind",
                "episode",
                "--payload-file",
            ])
            .arg(payload);
        run_bounded_cli(command)
    }

    fn write_read_denial_config(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let read_as_admin = self.temp.path().join("read-as-admin.token");
        std::fs::copy(&self.read_token, &read_as_admin)?;
        std::fs::set_permissions(&read_as_admin, std::fs::Permissions::from_mode(0o600))?;
        let path = self.temp.path().join("read-denial.json");
        let config = WatchdogConfig {
            database: self.database.clone(),
            admin: Some(AdminConfig {
                endpoint: self.endpoint.clone(),
                read_token_path: self.read_token.clone(),
                admin_token_path: read_as_admin,
                allowed_peer_sid: None,
            }),
            ..WatchdogConfig::default()
        };
        config.to_file(&path)?;
        Ok(path)
    }
}

struct DaemonGuard {
    child: Option<Child>,
    endpoint: PathBuf,
}

impl DaemonGuard {
    fn start(
        config_path: &Path,
        endpoint: PathBuf,
        read_token: &Path,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let child = Command::new(env!("CARGO_BIN_EXE_watchdog"))
            .args(["daemon", "--config"])
            .arg(config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut guard = Self {
            child: Some(child),
            endpoint,
        };
        let deadline = Instant::now() + DAEMON_STARTUP_TIMEOUT;
        let client_config =
            AdminClientConfig::new(guard.endpoint.clone(), read_token, Capability::Read)?;
        let mut attempt = 0_u64;
        let mut last_status_error = None;
        loop {
            guard.ensure_child_running()?;
            if guard.endpoint_metadata_is_socket() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let timeout = remaining.min(READINESS_REQUEST_TIMEOUT);
                if timeout < Duration::from_millis(1) {
                    break;
                }
                let client = AdminClient::new(client_config.clone().with_timeout(timeout)?)?;
                let key = format!("daemon-startup-readiness-{attempt}");
                attempt = attempt.saturating_add(1);
                match client.status(&key) {
                    Ok(response)
                        if response.status == ReplyStatus::Ok
                            && response.health.ready
                            && matches!(
                                response.result.as_ref(),
                                Some(AdminResult::Status(status)) if status.health.ready
                            ) =>
                    {
                        guard.ensure_child_running()?;
                        return Ok(guard);
                    }
                    Ok(response) => {
                        last_status_error = Some(format!(
                            "status was {:?} with readiness {:?}",
                            response.status, response.health.ready
                        ));
                    }
                    Err(error) => last_status_error = Some(error.to_string()),
                }
            }
            if Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let detail = last_status_error
            .map(|error| format!("; last status attempt: {error}"))
            .unwrap_or_default();
        Err(format!("watchdog daemon did not become ready before startup deadline{detail}").into())
    }

    fn ensure_child_running(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(status) = self
            .child
            .as_mut()
            .and_then(|child| child.try_wait().transpose())
            .transpose()?
        {
            return Err(format!("watchdog daemon exited during startup: {status}").into());
        }
        Ok(())
    }

    fn endpoint_metadata_is_socket(&self) -> bool {
        std::fs::symlink_metadata(&self.endpoint)
            .is_ok_and(|metadata| metadata.file_type().is_socket())
    }

    fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(child) = self.child.as_mut() {
            if child.try_wait()?.is_none()
                && let Err(error) = child.kill()
                && child.try_wait()?.is_none()
            {
                return Err(error.into());
            }
            reap_child_until(child, Instant::now() + CHILD_REAP_TIMEOUT)?;
        }
        self.child = None;
        self.remove_owned_test_endpoint();
        Ok(())
    }

    fn remove_owned_test_endpoint(&self) {
        if self.endpoint_metadata_is_socket() {
            let _ = std::fs::remove_file(&self.endpoint);
        }
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = reap_child_until(child, Instant::now() + CHILD_REAP_TIMEOUT);
        }
        self.child = None;
        self.remove_owned_test_endpoint();
    }
}

fn run_bounded_cli(mut command: Command) -> Result<Output, Box<dyn std::error::Error>> {
    command.process_group(0);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = CliChildGuard::spawn(command)?;
    let stdout = child
        .child_mut()?
        .stdout
        .take()
        .ok_or("CLI stdout pipe was not created")?;
    let stderr = child
        .child_mut()?
        .stderr
        .take()
        .ok_or("CLI stderr pipe was not created")?;
    set_nonblocking_pipe(&stdout)?;
    set_nonblocking_pipe(&stderr)?;

    let deadline = Instant::now() + CLI_COMMAND_TIMEOUT;
    let stdout_reader = thread::spawn(move || read_bounded_output(stdout, deadline));
    let stderr_reader = thread::spawn(move || read_bounded_output(stderr, deadline));
    let status = loop {
        match child.child_mut()?.try_wait() {
            Ok(Some(status)) => {
                child.kill_and_wait()?;
                break status;
            }
            Ok(None) if Instant::now() >= deadline => {
                let cleanup = child.kill_and_wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                cleanup?;
                return Err("CLI process exceeded its bounded timeout".into());
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                let _ = child.kill_and_wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(error.into());
            }
        }
    };
    let stdout = join_bounded_reader(stdout_reader)?;
    let stderr = join_bounded_reader(stderr_reader)?;
    child.disarm();
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn set_nonblocking_pipe(pipe: &impl AsFd) -> std::io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(pipe)?;
    rustix::fs::fcntl_setfl(pipe, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(std::io::Error::from)
}

fn read_bounded_output(mut reader: impl Read, deadline: Instant) -> std::io::Result<Vec<u8>> {
    let mut retained = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        if Instant::now() >= deadline {
            return Ok(retained);
        }
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(retained),
            Ok(read) => {
                if retained.len() < MAX_CLI_OUTPUT_BYTES {
                    let keep = (MAX_CLI_OUTPUT_BYTES - retained.len()).min(read);
                    retained.extend_from_slice(&buffer[..keep]);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Ok(retained);
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error),
        }
    }
}

fn join_bounded_reader(
    reader: thread::JoinHandle<std::io::Result<Vec<u8>>>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    reader
        .join()
        .map_err(|_| "CLI output reader panicked")?
        .map_err(Into::into)
}

struct CliChildGuard {
    child: Option<Child>,
}

impl CliChildGuard {
    fn spawn(mut command: Command) -> std::io::Result<Self> {
        Ok(Self {
            child: Some(command.spawn()?),
        })
    }

    fn child_mut(&mut self) -> std::io::Result<&mut Child> {
        self.child
            .as_mut()
            .ok_or_else(|| std::io::Error::other("CLI child guard lost its child"))
    }

    fn kill_and_wait(&mut self) -> std::io::Result<()> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        let group = rustix::process::Pid::from_child(child);
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        if child.try_wait()?.is_none() {
            let _ = child.kill();
        }
        reap_child_until(child, Instant::now() + CHILD_REAP_TIMEOUT)
    }

    fn disarm(&mut self) {
        self.child = None;
    }
}

impl Drop for CliChildGuard {
    fn drop(&mut self) {
        let _ = self.kill_and_wait();
        self.child = None;
    }
}

fn reap_child_until(child: &mut Child, deadline: Instant) -> std::io::Result<()> {
    loop {
        match child.try_wait()? {
            Some(_) => return Ok(()),
            None if Instant::now() >= deadline => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "child did not exit before the bounded reap deadline",
                ));
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
}
