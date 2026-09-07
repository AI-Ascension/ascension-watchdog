//! Native Windows admin named-pipe acceptance tests.
//!
//! These tests exercise the real Win32 endpoint and deliberately do not
//! replace unavailable native behavior with a synthetic success.  They are
//! compiled and run only on a Windows target.

#![cfg(windows)]

use ascension_platform_windows::{
    AdminPipeClient, AdminPipeServer, MAX_ADMIN_PIPE_FRAME, PlatformError,
    read_protected_payload_file,
};
use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
