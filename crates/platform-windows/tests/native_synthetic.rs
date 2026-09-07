#![cfg(windows)]

use ascension_platform_windows::{
    ComponentKind, JobOwnedProcess, SessionSelector, WindowsLaunchSpec, WindowsPlatformConfig,
    WindowsProcessLauncher,
};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn create() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ascension-platform-windows-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_platform_synthetic"))
}

fn config(executable: &Path, pipe_suffix: &str) -> WindowsPlatformConfig {
    let mut allowlisted_executables = BTreeMap::new();
    allowlisted_executables.insert(ComponentKind::Synthetic, executable.to_owned());
    WindowsPlatformConfig {
        service_name: "ascension-watchdog".to_owned(),
        pipe_name: format!(r"\\.\pipe\ascension-watchdog-{pipe_suffix}"),
        allowlisted_executables,
        authorized_peer_executable: executable.to_owned(),
        max_arguments: 8,
        max_environment: 8,
        max_processes: 8,
    }
}

fn launch_spec(
    executable: &Path,
    working_directory: &Path,
    session: u32,
    nonce: &str,
    arguments: Vec<String>,
) -> WindowsLaunchSpec {
    WindowsLaunchSpec {
        component: ComponentKind::Synthetic,
        executable: executable.to_owned(),
        arguments,
        environment: BTreeMap::new(),
        working_directory: Some(working_directory.to_owned()),
        session: SessionSelector::Explicit(session),
        launch_nonce: nonce.to_owned(),
        graceful_timeout_ms: 500,
        force_timeout_ms: 5_000,
    }
}

fn wait_until<F>(mut check: F) -> Result<bool, Box<dyn Error>>
where
    F: FnMut() -> Result<bool, Box<dyn Error>>,
{
    let deadline = std::time::Instant::now() + WAIT_TIMEOUT;
    loop {
        if check()? {
            return Ok(true);
        }
        if std::time::Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn unique_nonce(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!("{label}-{}-{nanos}", std::process::id())
}

#[test]
fn native_synthetic_child_crash_restart_and_durable_job_stop() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create()?;
    let executable = fixture();
    let launcher = WindowsProcessLauncher::new(config(&executable, &unique_nonce("pipe")))?;

    let child_marker = directory.path().join("descendant.pid");
    let owner = launcher.launch(&launch_spec(
        &executable,
        directory.path(),
        0,
        &unique_nonce("descendant"),
        vec![
            "--spawn-descendant".to_owned(),
            child_marker.to_string_lossy().into_owned(),
        ],
    ))?;
    let child_pid = wait_until(|| {
        let text = fs::read_to_string(&child_marker).ok();
        Ok(text
            .and_then(|value| value.trim().parse::<u32>().ok())
            .is_some_and(|pid| pid != 0))
    })?;
    assert!(child_pid, "synthetic descendant did not publish its PID");
    let child_pid = fs::read_to_string(&child_marker)?.trim().parse::<u32>()?;
    assert!(owner.is_member_running(child_pid)?);
    assert!(owner.is_running()?);

    // Reopening the named Job Object models a watchdog restart while the
    // original owner still exists, then force-stop proves descendant cleanup.
    let reopened = JobOwnedProcess::reopen(
        owner.identity().clone(),
        8,
        Duration::from_millis(500),
        Duration::from_secs(5),
    )?;
    assert!(reopened.is_running()?);
    assert_eq!(
        owner.force_stop()?,
        ascension_platform_windows::StopOutcome::Exited
    );
    assert!(wait_until(|| Ok(!reopened.is_member_running(child_pid)?))?);
    assert!(!reopened.is_running()?);
    drop(reopened);
    drop(owner);

    let crashed = launcher.launch(&launch_spec(
        &executable,
        directory.path(),
        0,
        &unique_nonce("crash"),
        vec!["--crash-after-ms".to_owned(), "50".to_owned()],
    ))?;
    assert!(wait_until(|| Ok(!crashed.is_running()?))?);
    drop(crashed);

    let restarted = launcher.launch(&launch_spec(
        &executable,
        directory.path(),
        0,
        &unique_nonce("restart"),
        vec!["--crash-after-ms".to_owned(), "5000".to_owned()],
    ))?;
    assert!(restarted.is_running()?);
    assert_eq!(
        restarted.force_stop()?,
        ascension_platform_windows::StopOutcome::Exited
    );
    assert!(!restarted.is_running()?);
    Ok(())
}

#[test]
fn native_launch_reopens_integrity_barrier_before_resuming_child() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create()?;
    let executable = fixture();
    let launcher = WindowsProcessLauncher::new(config(&executable, &unique_nonce("barrier")))?;
    let owner = launcher.launch(&launch_spec(
        &executable,
        directory.path(),
        0,
        &unique_nonce("barrier-child"),
        vec!["--crash-after-ms".to_owned(), "5000".to_owned()],
    ))?;
    assert!(owner.is_running()?);
    assert_eq!(
        owner.force_stop()?,
        ascension_platform_windows::StopOutcome::Exited
    );
    Ok(())
}
