#![cfg(windows)]

use ascension_platform_windows::{PlatformError, capture_current_controller};
use std::error::Error;
use std::time::{Duration, Instant};

#[test]
fn captures_current_controller_identity_from_its_own_process() -> Result<(), Box<dyn Error>> {
    let identity = capture_current_controller(Instant::now() + Duration::from_secs(5))?;
    let current_executable = std::env::current_exe()?;
    let normalize = |path: &std::path::Path| {
        path.to_string_lossy()
            .replace('/', "\\")
            .to_ascii_lowercase()
    };

    assert_eq!(identity.pid, std::process::id());
    assert!(identity.creation_time_100ns > 0);
    assert!(identity.executable.is_absolute());
    assert_eq!(
        normalize(&identity.executable),
        normalize(&current_executable)
    );
    assert_eq!(identity.sha256.len(), 64);
    assert_eq!(
        identity.sha256,
        ascension_platform_windows::executable_sha256(&current_executable)?
    );
    if let Ok(expected) = std::env::var("ASCENSION_TEST_EXPECTED_SELF_SHA256") {
        assert_eq!(identity.sha256, expected);
    }
    assert!(identity.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(
        identity
            .sha256
            .bytes()
            .all(|byte| !byte.is_ascii_uppercase())
    );
    assert!(identity.user_sid.starts_with("S-1-"));
    assert!(identity.session_id != u32::MAX);
    Ok(())
}

#[test]
fn expired_current_controller_deadline_fails_before_capture() {
    let error = capture_current_controller(Instant::now())
        .expect_err("an expired current-controller deadline must reject before I/O");
    assert!(matches!(error, PlatformError::Timeout(message) if message.contains("deadline")));
}
