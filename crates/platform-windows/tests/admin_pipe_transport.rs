//! Native Windows admin named-pipe acceptance tests.
//!
//! These tests exercise the real Win32 endpoint and deliberately do not
//! replace unavailable native behavior with a synthetic success.  They are
//! compiled and run only on a Windows target.

#![cfg(windows)]

use ascension_platform_windows::{
    AdminPipeClient, AdminPipeServer, MAX_ADMIN_PIPE_FRAME, PlatformError,
    read_protected_payload_file, read_protected_service_config_file,
};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct TempDirectory(PathBuf);

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_icacls(path: &Path, arguments: &[&str]) -> Result<(), PlatformError> {
    let output = Command::new("icacls.exe")
        .arg(path)
        .args(arguments)
        .output()
        .map_err(|error| PlatformError::Io(format!("icacls test command: {error}")))?;
    if !output.status.success() {
        return Err(PlatformError::Unavailable(format!(
            "icacls test command failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

fn pipe_name(label: &str) -> String {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!(
        r"\\.\pipe\ascension-watchdog-admin-{label}-{}-{nonce}",
        std::process::id()
    )
}

fn join_result<T>(
    handle: thread::JoinHandle<Result<T, PlatformError>>,
) -> Result<T, PlatformError> {
    handle
        .join()
        .map_err(|_| PlatformError::Unavailable("admin pipe test worker panicked".to_owned()))?
}

#[test]
fn native_pipe_round_trip_checks_peer_sid_and_server_identity() -> Result<(), PlatformError> {
    let name = pipe_name("roundtrip");
    let server_image = std::env::current_exe()
        .map_err(|error| PlatformError::Io(format!("test executable: {error}")))?;
    let server = AdminPipeServer::create(name.clone(), None)?;
    let server_thread = thread::spawn(move || {
        let mut server = server;
        let peer = server
            .accept(Duration::from_secs(5))?
            .ok_or_else(|| PlatformError::Timeout("test server accept timed out".to_owned()))?;
        if peer.user_sid.is_empty()
            || peer.process_id == 0
            || peer.executable.as_os_str().is_empty()
        {
            return Err(PlatformError::IdentityMismatch(
                "test peer identity was not captured".to_owned(),
            ));
        }
        let payload = server.read_frame(Duration::from_secs(2))?;
        server.write_frame(&payload, Duration::from_secs(2))?;
        server.disconnect()?;
        Ok((peer, server.server_process_id(), payload))
    });

    let mut client = AdminPipeClient::connect(name, Some(&server_image), Duration::from_secs(5))?;
    assert!(client.server_process_id() != 0);
    assert!(client.server_creation_time() != 0);
    assert!(!client.server_executable().as_os_str().is_empty());
    let payload = br#"{"contract":"watchdog-admin-v1","kind":"status"}"#.to_vec();
    client.write_frame(&payload, Duration::from_secs(2))?;
    assert_eq!(client.read_frame(Duration::from_secs(2))?, payload);
    let (peer, server_pid, echoed) = join_result(server_thread)?;
    assert_eq!(server_pid, client.server_process_id());
    assert_eq!(echoed, payload);
    assert_eq!(peer.process_id, std::process::id());
    Ok(())
}

#[test]
fn native_pipe_rapid_round_trips_wait_for_each_response_drain() -> Result<(), PlatformError> {
    let name = pipe_name("rapid-roundtrip");
    let server_image = std::env::current_exe()
        .map_err(|error| PlatformError::Io(format!("test executable: {error}")))?;
    let server = AdminPipeServer::create(name.clone(), None)?;
    let server_thread = thread::spawn(move || {
        let mut server = server;
        server
            .accept(Duration::from_secs(5))?
            .ok_or_else(|| PlatformError::Timeout("test server accept timed out".to_owned()))?;
        for sequence in 0..32_u32 {
            let payload = format!(r#"{{"kind":"status","sequence":{sequence}}}"#).into_bytes();
            let request = server.read_frame(Duration::from_secs(2))?;
            if request != payload {
                return Err(PlatformError::Invalid(
                    "rapid round-trip request changed in transit".to_owned(),
                ));
            }
            server.write_frame(&payload, Duration::from_secs(2))?;
        }
        server.disconnect()
    });

    let mut client = AdminPipeClient::connect(name, Some(&server_image), Duration::from_secs(5))?;
    for sequence in 0..32_u32 {
        let payload = format!(r#"{{"kind":"status","sequence":{sequence}}}"#).into_bytes();
        client.write_frame(&payload, Duration::from_secs(2))?;
        assert_eq!(client.read_frame(Duration::from_secs(2))?, payload);
    }
    join_result(server_thread)
}

#[test]
fn native_pipe_nonreading_client_times_out_without_claiming_delivery() -> Result<(), PlatformError>
{
    let name = pipe_name("nonreading");
    let server = AdminPipeServer::create(name.clone(), None)?;
    let server_thread = thread::spawn(move || {
        let mut server = server;
        server
            .accept(Duration::from_secs(5))?
            .ok_or_else(|| PlatformError::Timeout("test server accept timed out".to_owned()))?;
        let payload = vec![b'x'; MAX_ADMIN_PIPE_FRAME];
        let result = server.write_frame(&payload, Duration::from_millis(120));
        server.disconnect()?;
        match result {
            Err(PlatformError::Timeout(_)) => Ok(()),
            Err(error) => Err(error),
            Ok(()) => Err(PlatformError::Invalid(
                "nonreading peer incorrectly reported a delivered response".to_owned(),
            )),
        }
    });
    let server_image = std::env::current_exe()
        .map_err(|error| PlatformError::Io(format!("test executable: {error}")))?;
    let client = AdminPipeClient::connect(name, Some(&server_image), Duration::from_secs(5))?;
    let started = Instant::now();
    let result = join_result(server_thread);
    assert!(started.elapsed() < Duration::from_secs(2));
    result?;
    drop(client);
    Ok(())
}

#[test]
fn native_pipe_peer_loss_returns_uncertain_error_without_false_success() -> Result<(), PlatformError>
{
    let name = pipe_name("peer-loss");
    let (accepted_sender, accepted_receiver) = mpsc::channel();
    let server = AdminPipeServer::create(name.clone(), None)?;
    let server_thread = thread::spawn(move || {
        let mut server = server;
        server
            .accept(Duration::from_secs(5))?
            .ok_or_else(|| PlatformError::Timeout("test server accept timed out".to_owned()))?;
        accepted_sender
            .send(())
            .map_err(|_| PlatformError::Unavailable("test peer-loss signal failed".to_owned()))?;
        let delivered = server
            .write_frame(
                b"response that must not be acknowledged",
                Duration::from_secs(2),
            )
            .is_ok();
        server.disconnect()?;
        Ok(delivered)
    });
    let server_image = std::env::current_exe()
        .map_err(|error| PlatformError::Io(format!("test executable: {error}")))?;
    let client = AdminPipeClient::connect(name, Some(&server_image), Duration::from_secs(5))?;
    accepted_receiver
        .recv_timeout(Duration::from_secs(2))
        .map_err(|error| PlatformError::Timeout(format!("server accept signal: {error}")))?;
    drop(client);
    assert!(!join_result(server_thread)?);
    Ok(())
}

#[test]
fn native_pipe_partial_frame_times_out_and_disconnect_is_recoverable() -> Result<(), PlatformError>
{
    let name = pipe_name("timeout");
    let server = AdminPipeServer::create(name.clone(), None)?;
    let server_thread = thread::spawn(move || {
        let mut server = server;
        let _ = server
            .accept(Duration::from_secs(5))?
            .ok_or_else(|| PlatformError::Timeout("test server accept timed out".to_owned()))?;
        let result = server.read_frame(Duration::from_millis(40));
        if !matches!(result, Err(PlatformError::Timeout(_))) {
            return Err(PlatformError::Invalid(
                "partial admin frame did not hit its deadline".to_owned(),
            ));
        }
        server.cancel()?;
        server.disconnect()?;
        Ok(())
    });
    // Keeping this handle alive while the server polls proves that an
    // incomplete frame cannot hold the native worker indefinitely.
    let server_image = std::env::current_exe()
        .map_err(|error| PlatformError::Io(format!("test executable: {error}")))?;
    let client = AdminPipeClient::connect(name, Some(&server_image), Duration::from_secs(5))?;
    join_result(server_thread)?;
    drop(client);
    Ok(())
}

#[test]
fn native_pipe_rejects_invalid_namespace_and_oversized_frames() {
    assert!(matches!(
        AdminPipeServer::create(r"\.pipeother", None),
        Err(PlatformError::Invalid(_))
    ));
    assert!(matches!(
        AdminPipeClient::connect(
            r"\\.\pipe\ascension-watchdog-admin-no-such-pipe",
            Some(std::path::Path::new(r"C:\missing\watchdog.exe")),
            Duration::from_millis(1),
        ),
        Err(PlatformError::Timeout(_) | PlatformError::Win32 { .. })
    ));
    assert!(MAX_ADMIN_PIPE_FRAME < u32::MAX as usize);
}

#[test]
fn protected_payload_reader_rejects_nonlocal_paths_at_the_boundary() {
    for path in [
        r"\\server\share\payload.json",
        r"\\.\PIPE\payload",
        r"C:\payload\..\secret.json",
        r"C:\payload\data.json:secret",
        r"relative\payload.json",
    ] {
        assert!(
            matches!(
                read_protected_payload_file(Path::new(path), 1024),
                Err(PlatformError::Invalid(_))
            ),
            "path should be rejected before opening: {path}"
        );
    }
    assert!(matches!(
        read_protected_payload_file(Path::new(r"C:\payload.json"), 0),
        Err(PlatformError::Invalid(_))
    ));
}

#[test]
fn packaged_service_config_reader_accepts_the_fixed_acl_shape() -> Result<(), PlatformError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let directory = std::env::temp_dir().join(format!(
        "ascension-watchdog-config-acl-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&directory)
        .map_err(|error| PlatformError::Io(format!("create ACL test directory: {error}")))?;
    let _directory = TempDirectory(directory.clone());
    let path = directory.join("watchdog.json");
    std::fs::write(&path, br"{}")
        .map_err(|error| PlatformError::Io(format!("write ACL test config: {error}")))?;

    run_icacls(&path, &["/reset"])?;
    run_icacls(&path, &["/inheritance:r"])?;
    run_icacls(
        &path,
        &[
            "/grant:r",
            "*S-1-5-18:(F)",
            "*S-1-5-32-544:(F)",
            // TrustedInstaller is a built-in virtual service account. Use its
            // account spelling because hosted icacls does not accept raw
            // virtual-service SID syntax here; no SCM mutation is performed.
            r"NT SERVICE\TrustedInstaller:(R)",
        ],
    )?;
    run_icacls(&path, &["/setowner", "*S-1-5-18"])?;

    assert_eq!(read_protected_service_config_file(&path, 1024)?, br"{}");
    Ok(())
}
