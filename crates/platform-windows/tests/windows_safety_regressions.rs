//! Regression tests for the Windows boundary's source-level safety contract.
//!
//! The portable cases intentionally assert the policy that the native adapter
//! must enforce.  They are expected to fail against the review baseline until
//! the corresponding contract is tightened.  The native case is ignored
//! because it requires an interactive Windows session and exercises a real
//! process/Job Object boundary.

use ascension_platform_windows::{
    ComponentKind, SessionSelector, WindowsLaunchSpec, WindowsPlatformConfig,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn placeholder_executable() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\ascension\platform-synthetic.exe")
    } else {
        PathBuf::from("/opt/ascension/platform-synthetic")
    }
}

fn config(max_arguments: usize, max_environment: usize) -> WindowsPlatformConfig {
    let executable = placeholder_executable();
    let mut allowlisted_executables = BTreeMap::new();
    for component in [
        ComponentKind::Gateway,
        ComponentKind::Harness,
        ComponentKind::HostBroker,
        ComponentKind::Synthetic,
    ] {
        allowlisted_executables.insert(component, executable.clone());
    }
    WindowsPlatformConfig {
        service_name: "ascension-watchdog".to_owned(),
        pipe_name: r"\\.\pipe\ascension-watchdog-regression".to_owned(),
        allowlisted_executables,
        authorized_peer_executable: executable,
        max_arguments,
        max_environment,
        max_processes: 8,
    }
}

fn launch_spec(component: ComponentKind, session: SessionSelector) -> WindowsLaunchSpec {
    WindowsLaunchSpec {
        component,
        executable: placeholder_executable(),
        arguments: Vec::new(),
        environment: BTreeMap::new(),
        working_directory: None,
        session,
        launch_nonce: "regression-test".to_owned(),
        graceful_timeout_ms: 500,
        force_timeout_ms: 5_000,
    }
}

#[test]
fn background_roles_can_target_service_session_zero() {
    let config = config(8, 8);
    for component in [ComponentKind::Gateway, ComponentKind::Harness] {
        let specification = launch_spec(component, SessionSelector::Explicit(0));
        assert!(
            specification.validate(&config).is_ok(),
            "background component {component:?} must be able to target session 0"
        );
    }
}

#[test]
fn aggregate_command_line_arguments_are_rejected_before_process_creation() {
    let config = config(8, 8);
    let mut specification = launch_spec(ComponentKind::Synthetic, SessionSelector::Explicit(1));
    specification.arguments = (0..8).map(|_| "a".repeat(8 * 1024)).collect();

    assert!(
        specification.validate(&config).is_err(),
        "per-argument checks must be accompanied by a total command-line bound"
    );
}

#[test]
fn aggregate_environment_block_is_rejected_before_process_creation() {
    let config = config(8, 8);
    let mut specification = launch_spec(ComponentKind::Synthetic, SessionSelector::Explicit(1));
    specification.environment = (0..8)
        .map(|index| (format!("REGRESSION_{index}"), "e".repeat(8 * 1024)))
        .collect();

    assert!(
        specification.validate(&config).is_err(),
        "per-value checks must be accompanied by a total environment bound"
    );
}

#[test]
fn launch_spec_debug_does_not_expose_environment_values() {
    let config = config(8, 8);
    let mut specification = launch_spec(ComponentKind::Synthetic, SessionSelector::Explicit(1));
    let secret = "regression-secret-do-not-log";
    specification
        .environment
        .insert("WATCHDOG_TOKEN".to_owned(), secret.to_owned());
    assert!(specification.validate(&config).is_ok());

    let debug = format!("{specification:?}");
    assert!(
        !debug.contains(secret),
        "WindowsLaunchSpec Debug output must redact environment values"
    );
}

#[cfg(windows)]
mod native_owner_death {
    use super::*;
    use ascension_platform_windows::{ActiveSession, ProcessIdentity, WindowsProcessLauncher};
    use std::env;
    use std::fs;
    use std::path::Path;
    use std::process::{self, Command};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, FILETIME, GetLastError, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessId, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };

    const HELPER_ENV: &str = "WINDOWS_OWNER_DEATH_HELPER";
    const IDENTITY_ENV: &str = "WINDOWS_OWNER_DEATH_IDENTITY";

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_BIN_EXE_platform_synthetic"))
    }

    fn native_config(executable: &Path) -> WindowsPlatformConfig {
        let mut allowlisted_executables = BTreeMap::new();
        allowlisted_executables.insert(ComponentKind::Synthetic, executable.to_owned());
        WindowsPlatformConfig {
            service_name: "ascension-watchdog".to_owned(),
            pipe_name: format!(
                r"\\.\pipe\ascension-watchdog-owner-death-{}",
                unique_nonce("pipe")
            ),
            allowlisted_executables,
            authorized_peer_executable: executable.to_owned(),
            max_arguments: 8,
            max_environment: 8,
            max_processes: 8,
        }
    }

    fn unique_nonce(label: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        format!("{label}-{}-{nanos}", process::id())
    }

    fn write_identity(path: &Path, identity: &ProcessIdentity) {
        let contents = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n",
            identity.pid,
            identity.creation_time_100ns,
            identity.session_id,
            identity.launch_nonce,
            identity.executable.to_string_lossy(),
            identity.executable_sha256,
        );
        fs::write(path, contents).expect("owner-death helper must publish identity");
    }

    fn read_identity(path: &Path) -> ProcessIdentity {
        let contents =
            fs::read_to_string(path).expect("owner-death helper did not publish identity");
        let mut lines = contents.lines();
        let pid = lines
            .next()
            .expect("missing owner-death PID")
            .parse()
            .expect("invalid owner-death PID");
        let creation_time_100ns = lines
            .next()
            .expect("missing owner-death creation time")
            .parse()
            .expect("invalid owner-death creation time");
        let session_id = lines
            .next()
            .expect("missing owner-death session")
            .parse()
            .expect("invalid owner-death session");
        let launch_nonce = lines.next().expect("missing owner-death nonce").to_owned();
        let executable = PathBuf::from(
            lines
                .next()
                .expect("missing owner-death executable")
                .to_owned(),
        );
        ProcessIdentity {
            pid,
            creation_time_100ns,
            launch_nonce,
            executable,
            executable_sha256: lines.next().expect("missing executable digest").to_owned(),
            session_id,
        }
    }

    fn exact_process_running(identity: &ProcessIdentity) -> bool {
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                identity.pid,
            )
        };
        if process.is_null() {
            let error = unsafe { GetLastError() };
            assert_eq!(
                error, ERROR_INVALID_PARAMETER,
                "OpenProcess for the synthetic child failed with {error}"
            );
            return false;
        }

        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let times_ok = unsafe {
            GetProcessTimes(
                process,
                &raw mut creation,
                &raw mut exit,
                &raw mut kernel,
                &raw mut user,
            )
        };
        assert_ne!(times_ok, 0, "GetProcessTimes for the synthetic child");
        let creation_time =
            (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        let same_identity = unsafe { GetProcessId(process) } == identity.pid
            && creation_time == identity.creation_time_100ns;
        let running = unsafe { WaitForSingleObject(process, 0) } == WAIT_TIMEOUT;
        unsafe { CloseHandle(process) };
        same_identity && running
    }

    fn wait_until_stopped(identity: &ProcessIdentity) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if !exact_process_running(identity) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    #[test]
    #[ignore = "requires an interactive Windows session; launches only the synthetic fixture"]
    fn windows_owner_death_terminates_owned_child() {
        assert!(
            env::var_os(HELPER_ENV).is_none(),
            "the owner-death helper must be invoked by the parent test"
        );
        let identity_path = env::temp_dir().join(format!(
            "ascension-owner-death-{}-{}.txt",
            process::id(),
            unique_nonce("identity")
        ));
        let status = Command::new(env::current_exe().expect("current test executable"))
            .env(HELPER_ENV, "1")
            .env(IDENTITY_ENV, &identity_path)
            .args([
                "--ignored",
                "--exact",
                "native_owner_death::windows_owner_death_helper",
                "--nocapture",
            ])
            .status()
            .expect("spawn owner-death helper");
        assert!(status.success(), "owner-death helper exited with {status}");

        let identity = read_identity(&identity_path);
        let _ = fs::remove_file(&identity_path);
        assert!(
            wait_until_stopped(&identity),
            "KILL_ON_JOB_CLOSE must terminate the exact synthetic child after owner exit"
        );
    }

    #[test]
    #[ignore = "internal subprocess entrypoint for windows_owner_death_terminates_owned_child"]
    fn windows_owner_death_helper() {
        assert_eq!(
            env::var(HELPER_ENV).as_deref(),
            Ok("1"),
            "owner-death helper requires the parent test"
        );
        let identity_path = PathBuf::from(
            env::var_os(IDENTITY_ENV).expect("owner-death identity path must be provided"),
        );
        let executable = fixture();
        let launcher = WindowsProcessLauncher::new(native_config(&executable))
            .expect("synthetic launcher configuration");
        let session = match ascension_platform_windows::select_active_session() {
            ActiveSession::Available(session) => session,
            ActiveSession::WaitingForSession => {
                panic!("owner-death test requires an active interactive Windows session")
            }
        };
        let specification = WindowsLaunchSpec {
            component: ComponentKind::Synthetic,
            executable,
            arguments: vec!["--crash-after-ms".to_owned(), "10000".to_owned()],
            environment: BTreeMap::new(),
            working_directory: None,
            session: SessionSelector::Explicit(session),
            launch_nonce: unique_nonce("owner-death"),
            graceful_timeout_ms: 500,
            force_timeout_ms: 5_000,
        };
        let owner = launcher
            .launch(&specification)
            .expect("launch synthetic owner-death child");
        write_identity(&identity_path, owner.identity());
        // Deliberately bypass Rust drops.  Windows closes the job handle as it
        // tears down this helper process, which is the owner-death condition.
        process::exit(0);
    }
}
