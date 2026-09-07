//! Process-boundary authenticated job submission coverage.
//!
//! The in-process test exercises the queue directly. These tests launch the
//! compiled watchdog daemon and invoke the compiled CLI as separate processes
//! so token loading, endpoint binding, framing, queue admission, and durable
//! replay are covered together.

#![cfg(target_os = "linux")]

use ascension_watchdog::WatchdogError;
use ascension_watchdog::admin::{AdminResult, ReplyStatus};
use ascension_watchdog::config::{AdminConfig, WatchdogConfig};
use ascension_watchdog::storage::{SingletonLock, Store, now_unix_ms};
use serde_json::json;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[test]
fn actual_daemon_and_cli_processes_submit_complete_reopen_replay_and_deny_read()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProcessFixture::new()?;
    fixture.config().to_file(&fixture.config_path)?;
    let init = ProcessFixture::command()
        .args(["init", "--config"])
        .arg(&fixture.config_path)
        .output()?;
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let mut daemon = DaemonGuard::start(&fixture.config_path, fixture.endpoint.clone())?;
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

    let mut reopened = DaemonGuard::start(&fixture.config_path, fixture.endpoint.clone())?;
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

    let listed = ProcessFixture::command()
        .args(["job", "list", "--config"])
        .arg(&fixture.config_path)
        .args(["--filter", "all"])
        .output()?;
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

    fn submit(config_path: &Path, key: &str, payload: &Path) -> Result<Output, std::io::Error> {
        Self::command()
            .args(["job", "submit", "--config"])
            .arg(config_path)
            .args([
                "--idempotency-key",
                key,
                "--kind",
                "episode",
                "--payload-file",
            ])
            .arg(payload)
            .output()
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
    fn start(config_path: &Path, endpoint: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
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
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if guard.endpoint_metadata_is_socket() {
                return Ok(guard);
            }
            if let Some(status) = guard
                .child
                .as_mut()
                .and_then(|child| child.try_wait().transpose())
                .transpose()?
            {
                return Err(format!("watchdog daemon exited during startup: {status}").into());
            }
            if Instant::now() >= deadline {
                return Err("watchdog daemon did not bind its admin endpoint".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn endpoint_metadata_is_socket(&self) -> bool {
        std::fs::symlink_metadata(&self.endpoint)
            .is_ok_and(|metadata| metadata.file_type().is_socket())
    }

    fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(mut child) = self.child.take() {
            if child.try_wait()?.is_none() {
                child.kill()?;
            }
            let _ = child.wait()?;
        }
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
        if let Some(mut child) = self.child.take() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        self.remove_owned_test_endpoint();
    }
}
