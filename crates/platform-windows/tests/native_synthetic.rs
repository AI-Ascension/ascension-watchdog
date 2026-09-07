#![cfg(windows)]

use ascension_platform_windows::{
    ComponentKind, JobOwnedProcess, PlatformError, ProcessIdentity, SessionSelector, StopOutcome,
    WindowsLaunchSpec, WindowsPlatformConfig, WindowsProcessLauncher,
};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
use windows_sys::Win32::System::Threading::{
    GetProcessId, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE, TerminateProcess,
};

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
    let mut approved_executable_sha256 = BTreeMap::new();
    approved_executable_sha256.insert(
        ComponentKind::Synthetic,
        ascension_platform_windows::executable_sha256(executable)
            .expect("synthetic fixture digest must be readable"),
    );
    WindowsPlatformConfig {
        service_name: "ascension-watchdog".to_owned(),
        pipe_name: format!(r"\\.\pipe\ascension-watchdog-{pipe_suffix}"),
        allowlisted_executables,
        approved_executable_sha256,
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

#[test]
fn native_launch_rejects_an_approved_digest_mismatch_before_job_creation()
-> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create()?;
    let executable = fixture();
    let mut platform_config = config(&executable, &unique_nonce("digest-mismatch"));
    platform_config
        .approved_executable_sha256
        .insert(ComponentKind::Synthetic, "0".repeat(64));
    let launcher = WindowsProcessLauncher::new(platform_config)?;
    let error = launcher
        .launch(&launch_spec(
            &executable,
            directory.path(),
            0,
            &unique_nonce("digest-mismatch-child"),
            vec!["--crash-after-ms".to_owned(), "5000".to_owned()],
        ))
        .expect_err("a digest mismatch must reject before creating a Job Object");
    assert!(matches!(
        error,
        ascension_platform_windows::WindowsLaunchError::Ordinary(
            PlatformError::IdentityMismatch(message)
        ) if message.contains("configured release digest")
    ));
    Ok(())
}

fn unique_nonce(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!("{label}-{}-{nanos}", std::process::id())
}

fn terminate_exact_process(identity: &ProcessIdentity) -> Result<(), Box<dyn Error>> {
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
            0,
            identity.pid,
        )
    };
    if process.is_null() {
        let error = unsafe { GetLastError() };
        return Err(format!("OpenProcess for exact leader failed with {error}").into());
    }
    let result = (|| {
        if unsafe { GetProcessId(process) } != identity.pid {
            return Err("leader PID changed while preparing the exact test termination".into());
        }
        let mut creation = windows_sys::Win32::Foundation::FILETIME::default();
        let mut exit = windows_sys::Win32::Foundation::FILETIME::default();
        let mut kernel = windows_sys::Win32::Foundation::FILETIME::default();
        let mut user = windows_sys::Win32::Foundation::FILETIME::default();
        let ok = unsafe {
            GetProcessTimes(
                process,
                &raw mut creation,
                &raw mut exit,
                &raw mut kernel,
                &raw mut user,
            )
        };
        if ok == 0 {
            return Err("GetProcessTimes for exact test termination failed".into());
        }
        let creation_time =
            (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        if creation_time != identity.creation_time_100ns {
            return Err("leader creation token changed before exact test termination".into());
        }
        if unsafe { TerminateProcess(process, 41) } == 0 {
            let error = unsafe { GetLastError() };
            return Err(
                format!("TerminateProcess for exact test leader failed with {error}").into(),
            );
        }
        Ok::<(), Box<dyn Error>>(())
    })();
    unsafe { CloseHandle(process) };
    result
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
fn native_leader_exit_still_forces_job_descendant_cleanup() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create()?;
    let executable = fixture();
    let launcher = WindowsProcessLauncher::new(config(&executable, &unique_nonce("pipe")))?;
    let child_marker = directory.path().join("leader-exit-descendant.pid");
    let owner = launcher.launch(&launch_spec(
        &executable,
        directory.path(),
        0,
        &unique_nonce("leader-exit"),
        vec![
            "--spawn-descendant".to_owned(),
            child_marker.to_string_lossy().into_owned(),
        ],
    ))?;
    assert!(wait_until(|| {
        Ok(fs::read_to_string(&child_marker)
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
            .is_some_and(|pid| pid != 0))
    })?);
    let child_pid = fs::read_to_string(&child_marker)?.trim().parse::<u32>()?;
    assert!(owner.is_member_running(child_pid)?);

    // Kill only the exact leader after checking its creation token.  The
    // descendant remains in the Job Object, which is the recovery state that
    // must not be mistaken for an already-empty process tree.
    terminate_exact_process(owner.identity())?;
    assert!(wait_until(|| Ok(!owner.is_running()?))?);
    let graceful = owner.graceful_stop();
    assert!(matches!(graceful, Err(PlatformError::Unsupported(_))));
    assert_eq!(owner.force_stop()?, StopOutcome::Exited);
    assert!(wait_until(|| Ok(!owner.is_member_running(child_pid)?))?);
    Ok(())
}

#[test]
fn native_prepared_job_recovery_uses_exact_authority() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create()?;
    let executable = fixture();
    let launcher = WindowsProcessLauncher::new(config(&executable, &unique_nonce("pipe")))?;
    let nonce = unique_nonce("prepared");
    let owner = launcher.launch(&launch_spec(
        &executable,
        directory.path(),
        0,
        &nonce,
        vec!["--crash-after-ms".to_owned(), "5000".to_owned()],
    ))?;
    let planned = format!("windows-job:{nonce}");
    assert_eq!(
        launcher.force_cleanup_planned_containment(&planned, Duration::from_secs(5))?,
        StopOutcome::Exited
    );
    assert!(!owner.is_running()?);
    drop(owner);

    // Once the exact named object has no remaining handles, a missing-object
    // result is conclusive and idempotent.  A malformed namespace is rejected
    // before any named-object lookup.
    assert_eq!(
        launcher.force_cleanup_planned_containment(&planned, Duration::from_secs(5))?,
        StopOutcome::AlreadyExited
    );
    assert!(
        launcher
            .force_cleanup_planned_containment("windows-job:../unrelated", Duration::from_secs(5))
            .is_err()
    );
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
