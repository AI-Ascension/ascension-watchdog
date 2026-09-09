#[cfg(windows)]
mod native {
    use ascension_platform_windows::{
        ComponentKind, GatewayHealthBootstrapLaunch, PlatformError, SessionSelector, StopOutcome,
        WindowsLaunchError, WindowsLaunchSpec, WindowsPlatformConfig, WindowsProcessLauncher,
    };
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::fmt::Write as _;
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
                "ascension-gateway-health-{}-{stamp}",
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
        let adjacent = std::env::current_exe()
            .expect("native test image path")
            .with_file_name("platform_synthetic.exe");
        if adjacent.is_file() {
            adjacent
        } else {
            PathBuf::from(env!("CARGO_BIN_EXE_platform_synthetic"))
        }
    }

    fn unique_uuid() -> String {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        nonce_from_stamp(stamp)
    }

    fn nonce_from_stamp(stamp: u128) -> String {
        format!(
            "00112233-4455-4{:03x}-8{:03x}-{:012x}",
            stamp & 0xfff,
            (stamp >> 12) & 0xfff,
            stamp >> 26 & 0xffff_ffff_ffff
        )
    }

    #[test]
    fn fixture_nonce_has_fixed_uuidv4_shape_at_timestamp_extremes() {
        for stamp in [0, u128::MAX, 0x03ff_f000] {
            let nonce = nonce_from_stamp(stamp);
            assert_eq!(nonce.len(), 36);
            assert_eq!(&nonce[14..15], "4");
            assert_eq!(&nonce[19..20], "8");
            for index in [8, 13, 18, 23] {
                assert_eq!(&nonce[index..=index], "-");
            }
        }
    }

    fn config(executable: &Path) -> WindowsPlatformConfig {
        let mut allowlisted_executables = BTreeMap::new();
        allowlisted_executables.insert(ComponentKind::Gateway, executable.to_owned());
        let mut approved_executable_sha256 = BTreeMap::new();
        approved_executable_sha256.insert(
            ComponentKind::Gateway,
            ascension_platform_windows::executable_sha256(executable)
                .expect("synthetic fixture digest must be readable"),
        );
        WindowsPlatformConfig {
            service_name: "ascension-watchdog".to_owned(),
            pipe_name: format!(r"\\.\pipe\ascension-watchdog-gateway-{}", unique_uuid()),
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
            component: ComponentKind::Gateway,
            executable: executable.to_owned(),
            arguments: vec![
                "--read-gateway-health-bootstrap".to_owned(),
                working_directory
                    .join("gateway-health-frame.bin")
                    .to_string_lossy()
                    .into_owned(),
            ],
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
                return Err("Gateway health fixture did not receive its startup frame".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn gateway_health_frame_reaches_exclusive_child_stdin_after_barrier()
    -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::create()?;
        let executable = fixture();
        let nonce = unique_uuid();
        let specification = launch_spec(&executable, directory.path(), &nonce);
        let bootstrap = GatewayHealthBootstrapLaunch::new(&specification, [0xa5_u8; 32])?;
        let launcher = WindowsProcessLauncher::new(config(&executable))?;
        let barrier_called = Arc::new(AtomicBool::new(false));
        let barrier_witness = Arc::clone(&barrier_called);
        let marker = directory.path().join("gateway-health-frame.bin");
        let marker_for_barrier = marker.clone();
        let owner = launcher.launch_with_gateway_health_bootstrap_and_barrier(
            &specification,
            &bootstrap,
            move || {
                assert!(!marker_for_barrier.exists());
                barrier_witness.store(true, Ordering::Release);
                Ok::<_, ascension_platform_windows::PlatformError>(())
            },
        )?;
        assert!(barrier_called.load(Ordering::Acquire));
        let frame = wait_for_marker(&marker)?;
        assert_eq!(frame.len(), 56);
        assert_eq!(&frame[..8], b"STS2GH01");
        let mut received_nonce = String::with_capacity(32);
        for byte in &frame[8..24] {
            write!(received_nonce, "{byte:02x}")?;
        }
        assert_eq!(received_nonce, nonce.replace('-', ""));
        assert_ne!(&frame[8..24], &[0_u8; 16]);
        assert_eq!(frame[14] & 0xf0, 0x40);
        assert_eq!(frame[16] & 0xc0, 0x80);
        assert_eq!(&frame[24..], &[0xa5_u8; 32]);
        assert_eq!(owner.force_stop()?, StopOutcome::Exited);
        Ok(())
    }

    #[test]
    fn rejected_gateway_admission_cleans_the_suspended_job() -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::create()?;
        let executable = fixture();
        let nonce = unique_uuid();
        let specification = launch_spec(&executable, directory.path(), &nonce);
        let bootstrap = GatewayHealthBootstrapLaunch::new(&specification, [0xa5_u8; 32])?;
        let launcher = WindowsProcessLauncher::new(config(&executable))?;
        let marker = directory.path().join("gateway-health-frame.bin");
        let called = AtomicBool::new(false);
        let error = launcher
            .launch_with_gateway_health_bootstrap_and_barrier(&specification, &bootstrap, || {
                assert!(!marker.exists());
                called.store(true, Ordering::Release);
                Err::<(), _>(PlatformError::Unavailable(
                    "test admission revoked".to_owned(),
                ))
            })
            .expect_err("rejected admission cannot resume the child");
        assert!(called.load(Ordering::Acquire));
        assert!(matches!(error, WindowsLaunchError::Ordinary(_)));
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

    #[test]
    fn changed_gateway_nonce_rejects_before_admission_or_target_execution()
    -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::create()?;
        let executable = fixture();
        let mut specification = launch_spec(&executable, directory.path(), &unique_uuid());
        let bootstrap = GatewayHealthBootstrapLaunch::new(&specification, [0xa5_u8; 32])?;
        // The fixture's canonical nonce always starts with zero. Change only
        // that digit, retaining the required version and variant bits.
        specification.launch_nonce.replace_range(0..1, "1");
        let launcher = WindowsProcessLauncher::new(config(&executable))?;
        let called = AtomicBool::new(false);
        let error = launcher
            .launch_with_gateway_health_bootstrap_and_barrier(&specification, &bootstrap, || {
                called.store(true, Ordering::Release);
                Ok(())
            })
            .expect_err("a different launch nonce cannot reuse the frame");
        assert!(matches!(
            error,
            WindowsLaunchError::Ordinary(PlatformError::IdentityMismatch(_))
        ));
        assert!(!called.load(Ordering::Acquire));
        assert!(!directory.path().join("gateway-health-frame.bin").exists());
        assert_eq!(
            launcher.force_cleanup_planned_containment(
                &format!("windows-job:{}", specification.launch_nonce),
                Duration::from_secs(5),
            )?,
            StopOutcome::AlreadyExited
        );
        Ok(())
    }
}
