use ascension_platform_windows::{MAX_WORKER_BOOTSTRAP_FRAME_BYTES, WorkerBootstrapLaunch};

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut bytes = b"ASC-WB01".to_vec();
    bytes.extend_from_slice(&(u32::try_from(payload.len()).unwrap()).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn transport_value_keeps_one_bounded_wire_frame() {
    let bytes = frame(br#"{"version":1}"#);
    let launch = WorkerBootstrapLaunch::new(bytes.clone()).expect("valid wire frame");
    assert_eq!(launch.frame(), bytes.as_slice());
    assert!(launch.frame().len() <= MAX_WORKER_BOOTSTRAP_FRAME_BYTES);
}

#[test]
fn transport_value_rejects_unbounded_or_unframed_bytes() {
    assert!(WorkerBootstrapLaunch::new(Vec::new()).is_err());
    assert!(WorkerBootstrapLaunch::new(frame(&[])).is_err());
    assert!(WorkerBootstrapLaunch::new(vec![b'x'; MAX_WORKER_BOOTSTRAP_FRAME_BYTES]).is_err());
}

#[cfg(windows)]
mod native {
    use super::*;
    use ascension_platform_windows::{
        ComponentKind, PlatformError, SessionSelector, StopOutcome, WindowsLaunchError,
        WindowsLaunchSpec, WindowsPlatformConfig, WindowsProcessLauncher,
    };
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn create() -> Result<Self, Box<dyn Error>> {
            let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let path = std::env::temp_dir().join(format!(
                "ascension-worker-pipe-{}-{stamp}",
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
        // Cross-built tests are copied together with their checked-in fixture
        // into one fresh Windows directory; the build-host path is not usable
        // there. Native Cargo execution retains its ordinary artifact path.
        let adjacent = std::env::current_exe()
            .expect("native test image path")
            .with_file_name("platform_synthetic.exe");
        if adjacent.is_file() {
            adjacent
        } else {
            PathBuf::from(env!("CARGO_BIN_EXE_platform_synthetic"))
        }
    }

    fn unique_nonce(label: &str) -> String {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        format!("{label}-{}-{stamp}", std::process::id())
    }

    fn config(executable: &Path) -> WindowsPlatformConfig {
        let mut allowlisted_executables = BTreeMap::new();
        allowlisted_executables.insert(ComponentKind::Harness, executable.to_owned());
        let mut approved_executable_sha256 = BTreeMap::new();
        approved_executable_sha256.insert(
            ComponentKind::Harness,
            ascension_platform_windows::executable_sha256(executable)
                .expect("synthetic fixture digest must be readable"),
        );
        WindowsPlatformConfig {
            service_name: "ascension-watchdog".to_owned(),
            pipe_name: format!(r"\\.\pipe\ascension-watchdog-{}", unique_nonce("admin")),
            allowlisted_executables,
            approved_executable_sha256,
            authorized_peer_executable: executable.to_owned(),
            max_arguments: 8,
            max_environment: 8,
            max_processes: 8,
        }
    }

    fn launch_spec(executable: &Path, working_directory: &Path, nonce: &str) -> WindowsLaunchSpec {
        WindowsLaunchSpec {
            component: ComponentKind::Harness,
            executable: executable.to_owned(),
            arguments: Vec::new(),
            environment: BTreeMap::new(),
            working_directory: Some(working_directory.to_owned()),
            session: SessionSelector::CurrentService,
            launch_nonce: nonce.to_owned(),
            graceful_timeout_ms: 500,
            force_timeout_ms: 5_000,
        }
    }

    fn wait_for_marker(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(bytes) = fs::read(path) {
                return Ok(bytes);
            }
            if Instant::now() >= deadline {
                return Err("worker fixture did not receive its startup frame".into());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    struct ResumeWitness {
        marker: PathBuf,
        observed: Arc<AtomicBool>,
    }

    impl Drop for ResumeWitness {
        fn drop(&mut self) {
            // A guard dropped before ResumeThread cannot observe this
            // child marker. Bound the regression even on that failure.
            self.observed
                .store(wait_for_marker(&self.marker).is_ok(), Ordering::Release);
        }
    }

    #[test]
    fn native_worker_frame_reaches_exclusive_child_stdin() -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::create()?;
        let executable = fixture();
        let launcher = WindowsProcessLauncher::new(config(&executable))?;
        let marker = directory.path().join("worker-frame.bin");
        let specification = launch_spec(
            &executable,
            directory.path(),
            &unique_nonce("worker-launch"),
        );
        let bytes = frame(&vec![b'j'; MAX_WORKER_BOOTSTRAP_FRAME_BYTES - 12]);
        let worker = WorkerBootstrapLaunch::new(bytes.clone())?;
        let barrier_called = Arc::new(AtomicBool::new(false));
        let barrier_called_by_callback = Arc::clone(&barrier_called);
        let guard_observed_resumed_child = Arc::new(AtomicBool::new(false));
        let guard = ResumeWitness {
            marker: marker.clone(),
            observed: Arc::clone(&guard_observed_resumed_child),
        };
        let mut specification = specification;
        specification.arguments = vec![
            "--read-worker-bootstrap".to_owned(),
            marker.to_string_lossy().into_owned(),
        ];
        let owner = launcher.launch_with_worker_bootstrap_and_barrier(
            &specification,
            &worker,
            move || {
                barrier_called_by_callback.store(true, Ordering::Release);
                Ok(guard)
            },
        )?;
        assert!(barrier_called.load(Ordering::Acquire));
        assert_eq!(wait_for_marker(&marker)?, bytes);
        assert_eq!(owner.force_stop()?, StopOutcome::Exited);
        assert!(guard_observed_resumed_child.load(Ordering::Acquire));
        Ok(())
    }

    #[test]
    fn native_worker_barrier_rejection_cleans_the_suspended_child() -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::create()?;
        let executable = fixture();
        let launcher = WindowsProcessLauncher::new(config(&executable))?;
        let marker = directory.path().join("barrier-rejected.bin");
        let mut specification = launch_spec(
            &executable,
            directory.path(),
            &unique_nonce("worker-barrier"),
        );
        specification.arguments = vec![
            "--read-worker-bootstrap".to_owned(),
            marker.to_string_lossy().into_owned(),
        ];
        let worker = WorkerBootstrapLaunch::new(frame(br#"{"version":1}"#))?;
        let error = launcher
            .launch_with_worker_bootstrap_and_barrier(&specification, &worker, || {
                Err::<(), _>(PlatformError::Unavailable(
                    "durable launch authorization denied".to_owned(),
                ))
            })
            .expect_err("a rejected durable barrier must prevent resumption");
        assert!(matches!(
            error,
            WindowsLaunchError::Ordinary(PlatformError::Unavailable(message))
                if message == "durable launch authorization denied"
        ));
        assert!(!marker.exists());
        Ok(())
    }

    #[cfg(feature = "native-worker-test-hooks")]
    #[test]
    fn native_worker_small_buffer_fails_bounded_before_resume_and_cleanup()
    -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::create()?;
        let executable = fixture();
        let launcher = WindowsProcessLauncher::new(config(&executable))?;
        let marker = directory.path().join("small-buffer.bin");
        let nonce = unique_nonce("worker-small-buffer");
        let mut specification = launch_spec(&executable, directory.path(), &nonce);
        specification.arguments = vec![
            "--read-worker-bootstrap".to_owned(),
            marker.to_string_lossy().into_owned(),
        ];
        let worker =
            WorkerBootstrapLaunch::new(frame(&vec![b'x'; MAX_WORKER_BOOTSTRAP_FRAME_BYTES - 12]))?;
        let barrier_called = Arc::new(AtomicBool::new(false));
        let barrier_called_by_callback = Arc::clone(&barrier_called);
        let started = Instant::now();
        let error = launcher
            .launch_with_worker_bootstrap_with_pipe_buffer_for_test(
                &specification,
                &worker,
                1,
                move || {
                    barrier_called_by_callback.store(true, Ordering::Release);
                    Ok(())
                },
            )
            .expect_err("an undersized nonblocking pipe must reject before resume");
        assert!(started.elapsed() < Duration::from_secs(30));
        assert!(matches!(error, WindowsLaunchError::Ordinary(_)));
        assert!(!barrier_called.load(Ordering::Acquire));
        assert!(!marker.exists());
        assert_eq!(
            launcher.force_cleanup_planned_containment(
                &format!("windows-job:{nonce}"),
                Duration::from_secs(5),
            )?,
            StopOutcome::AlreadyExited
        );
        Ok(())
    }
}
