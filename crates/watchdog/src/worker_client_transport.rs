//! Authenticated local IPC for the worker handoff client.

#[cfg(target_os = "linux")]
use super::auth::{LinuxPeerSession, authenticate_linux_peer};
use super::auth::{WorkerPeerIdentity, read_credential};
#[cfg(target_os = "linux")]
use crate::admin::validate_endpoint_path;
use crate::error::{Result, WatchdogError};
use crate::worker_protocol::{Frame, MAX_FRAME_BYTES, decode_response, encode_frame};
use std::fs;
#[cfg(target_os = "linux")]
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::time::{Duration, Instant};

/// Binary transport-authentication body.  It is not a worker-handoff JSON
/// frame and is consumed by the worker endpoint before the first protocol
/// frame.  The token is never logged, persisted, or included in a response.
const AUTH_MAGIC: &[u8] = b"ascension-worker-auth-v1\0";

pub(crate) fn exchange(
    endpoint: &Path,
    credential_path: &Path,
    peer: &WorkerPeerIdentity,
    timeout: Duration,
    request: &Frame,
) -> Result<Frame> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| WatchdogError::Timeout("worker transport deadline overflow".to_owned()))?;
    let request_bytes =
        encode_frame(request).map_err(|error| WatchdogError::InvalidInput(error.to_string()))?;
    if request_bytes.is_empty() || request_bytes.len() > MAX_FRAME_BYTES {
        return Err(WatchdogError::InvalidInput(
            "worker request exceeds the frame bound".to_owned(),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        exchange_unix(endpoint, peer, credential_path, &request_bytes, deadline)
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let _ = (endpoint, peer, credential_path, request_bytes, deadline);
        Err(WatchdogError::Unsupported(
            "worker handoff transport requires a Linux Unix-peer identity adapter or Windows named pipe".to_owned(),
        ))
    }
    #[cfg(windows)]
    {
        exchange_named_pipe(endpoint, peer, credential_path, &request_bytes, deadline)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (endpoint, peer, credential_path, request_bytes, deadline);
        Err(WatchdogError::Unsupported(
            "worker handoff transport is unsupported on this platform".to_owned(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn exchange_unix(
    endpoint: &Path,
    peer: &WorkerPeerIdentity,
    credential_path: &Path,
    request_bytes: &[u8],
    deadline: Instant,
) -> Result<Frame> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    validate_endpoint_path(endpoint)?;
    let before = endpoint_identity(endpoint)?;
    let metadata = fs::symlink_metadata(endpoint).map_err(|_| {
        WatchdogError::Io(std::io::Error::new(
            ErrorKind::NotFound,
            "worker endpoint is unavailable",
        ))
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_socket()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(WatchdogError::Unauthorized(
            "worker endpoint is not an owner-protected socket".to_owned(),
        ));
    }
    let mut stream = connect_unix_with_deadline(endpoint, deadline)?;
    let after = endpoint_identity(endpoint)?;
    if before != after {
        return Err(WatchdogError::IdentityMismatch(
            "worker endpoint changed while connecting".to_owned(),
        ));
    }
    let peer_session = authenticate_linux_peer(&stream, peer, deadline)?;
    peer_session.verify_current(deadline)?;
    // Do not open or read the worker credential until the OS peer identity
    // (including PID and process-start token) has been authenticated.
    let credential = read_credential(credential_path, deadline)?;
    peer_session.verify_current(deadline)?;
    let mut auth_body = Vec::with_capacity(AUTH_MAGIC.len() + credential.bytes().len());
    auth_body.extend_from_slice(AUTH_MAGIC);
    auth_body.extend_from_slice(credential.bytes());
    write_frame_unix(&mut stream, &auth_body, deadline, &peer_session)?;
    write_frame_unix(&mut stream, request_bytes, deadline, &peer_session)?;
    let response_bytes = read_frame_unix(&mut stream, deadline, &peer_session)?;
    peer_session.verify_current(deadline)?;
    decode_response(&response_bytes).map_err(|error| WatchdogError::InvalidInput(error.to_string()))
}

#[cfg(target_os = "linux")]
fn connect_unix_with_deadline(
    endpoint: &Path,
    deadline: Instant,
) -> Result<std::os::unix::net::UnixStream> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use rustix::io::Errno;
    use rustix::net::sockopt::socket_error;
    use rustix::net::{
        AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with,
    };
    use std::os::fd::OwnedFd;

    let descriptor: OwnedFd = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|error| WatchdogError::Io(error.into()))?;
    let address = SocketAddrUnix::new(endpoint).map_err(|error| {
        WatchdogError::InvalidInput(format!("worker endpoint address is invalid: {error}"))
    })?;
    match connect(&descriptor, &address) {
        Ok(()) => {}
        Err(error) if error == Errno::INPROGRESS || error == Errno::WOULDBLOCK => {
            let mut poll_fds = [PollFd::new(&descriptor, PollFlags::OUT)];
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(WatchdogError::Timeout(
                    "worker endpoint connection timed out".to_owned(),
                ));
            }
            let timeout = Timespec {
                tv_sec: remaining.as_secs().try_into().unwrap_or(i64::MAX),
                tv_nsec: remaining.subsec_nanos().into(),
            };
            if poll(&mut poll_fds, Some(&timeout))
                .map_err(|error| WatchdogError::Io(error.into()))?
                == 0
            {
                return Err(WatchdogError::Timeout(
                    "worker endpoint connection timed out".to_owned(),
                ));
            }
            socket_error(&descriptor)
                .map_err(|error| WatchdogError::Io(error.into()))?
                .map_err(|error| {
                    if error == Errno::TIMEDOUT {
                        WatchdogError::Timeout("worker endpoint connection timed out".to_owned())
                    } else {
                        WatchdogError::Io(error.into())
                    }
                })?;
        }
        Err(error) => return Err(WatchdogError::Io(error.into())),
    }
    if Instant::now() >= deadline {
        return Err(WatchdogError::Timeout(
            "worker endpoint connection timed out".to_owned(),
        ));
    }
    let stream: std::os::unix::net::UnixStream = descriptor.into();
    stream.set_nonblocking(false).map_err(WatchdogError::Io)?;
    Ok(stream)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EndpointIdentity {
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
fn endpoint_identity(path: &Path) -> Result<EndpointIdentity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        WatchdogError::Io(std::io::Error::new(
            ErrorKind::NotFound,
            "worker endpoint is unavailable",
        ))
    })?;
    Ok(EndpointIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(target_os = "linux")]
fn write_frame_unix(
    stream: &mut std::os::unix::net::UnixStream,
    body: &[u8],
    deadline: Instant,
    peer: &LinuxPeerSession,
) -> Result<()> {
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err(WatchdogError::InvalidInput(
            "worker transport frame exceeds the bound".to_owned(),
        ));
    }
    let length = u32::try_from(body.len()).map_err(|_| {
        WatchdogError::InvalidInput("worker transport frame length overflow".to_owned())
    })?;
    peer.verify_current(deadline)?;
    write_all_deadline(stream, &length.to_be_bytes(), deadline)?;
    peer.verify_current(deadline)?;
    write_all_deadline(stream, body, deadline)?;
    peer.verify_current(deadline)
}

#[cfg(target_os = "linux")]
fn read_frame_unix(
    stream: &mut std::os::unix::net::UnixStream,
    deadline: Instant,
    peer: &LinuxPeerSession,
) -> Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    read_exact_deadline(stream, &mut length, deadline, peer)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| {
        WatchdogError::InvalidInput("worker response frame length overflow".to_owned())
    })?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(WatchdogError::InvalidInput(
            "worker response frame exceeds the bound".to_owned(),
        ));
    }
    let mut body = vec![0_u8; length];
    read_exact_deadline(stream, &mut body, deadline, peer)?;
    Ok(body)
}

#[cfg(target_os = "linux")]
fn write_all_deadline(
    stream: &mut std::os::unix::net::UnixStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(WatchdogError::Timeout(
                "worker transport write timed out".to_owned(),
            ));
        }
        stream.set_write_timeout(Some(remaining))?;
        let count = stream.write(&bytes[offset..]).map_err(|error| {
            if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) {
                WatchdogError::Timeout("worker transport write timed out".to_owned())
            } else {
                WatchdogError::Io(error)
            }
        })?;
        if count == 0 {
            return Err(WatchdogError::Io(std::io::Error::new(
                ErrorKind::WriteZero,
                "worker transport closed during write",
            )));
        }
        offset += count;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_exact_deadline(
    stream: &mut std::os::unix::net::UnixStream,
    bytes: &mut [u8],
    deadline: Instant,
    peer: &LinuxPeerSession,
) -> Result<()> {
    use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};
    use std::io::IoSliceMut;
    use std::mem::MaybeUninit;

    let mut offset = 0;
    while offset < bytes.len() {
        peer.verify_current(deadline)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(WatchdogError::Timeout(
                "worker transport read timed out".to_owned(),
            ));
        }
        stream.set_read_timeout(Some(remaining))?;
        let mut control_space =
            [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1), ScmCredentials(1))];
        let mut control = RecvAncillaryBuffer::new(&mut control_space);
        let mut iov = [IoSliceMut::new(&mut bytes[offset..])];
        let message = recvmsg(
            &mut *stream,
            &mut iov,
            &mut control,
            RecvFlags::CMSG_CLOEXEC,
        )
        .map_err(|error| {
            if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) {
                WatchdogError::Timeout("worker transport read timed out".to_owned())
            } else {
                WatchdogError::Io(error.into())
            }
        })?;
        if message.bytes == 0 {
            return Err(WatchdogError::Io(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "worker transport closed during read",
            )));
        }
        if message.flags.contains(rustix::net::ReturnFlags::CTRUNC) {
            return Err(WatchdogError::Unauthorized(
                "worker response carried truncated ancillary credentials".to_owned(),
            ));
        }
        let mut credentials = None;
        for ancillary in control.drain() {
            match ancillary {
                RecvAncillaryMessage::ScmCredentials(value) => {
                    if credentials.replace(value).is_some() {
                        return Err(WatchdogError::Unauthorized(
                            "worker response carried duplicate peer credentials".to_owned(),
                        ));
                    }
                }
                RecvAncillaryMessage::ScmRights(_) => {
                    return Err(WatchdogError::Unauthorized(
                        "worker response carried unexpected file descriptors".to_owned(),
                    ));
                }
                _ => {
                    return Err(WatchdogError::Unauthorized(
                        "worker response carried unsupported ancillary data".to_owned(),
                    ));
                }
            }
        }
        let credentials = credentials.ok_or_else(|| {
            WatchdogError::Unauthorized(
                "worker response did not carry peer message credentials".to_owned(),
            )
        })?;
        peer.verify_message_credentials(&credentials)?;
        offset += message.bytes;
        peer.verify_current(deadline)?;
    }
    Ok(())
}

#[cfg(windows)]
fn exchange_named_pipe(
    endpoint: &Path,
    peer: &WorkerPeerIdentity,
    credential_path: &Path,
    request_bytes: &[u8],
    deadline: Instant,
) -> Result<Frame> {
    use ascension_platform_windows::AdminPipeClient;

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(WatchdogError::Timeout(
            "worker transport deadline expired".to_owned(),
        ));
    }
    let mut pipe = AdminPipeClient::connect(
        endpoint.to_string_lossy().into_owned(),
        Some(peer.executable()),
        remaining,
    )
    .map_err(|error| WatchdogError::Unauthorized(error.to_string()))?;
    let expected_pid = peer.pid();
    let actual_pid = pipe.server_process_id();
    let expected_creation = peer.creation_token().parse::<u64>().map_err(|_| {
        WatchdogError::IdentityMismatch(
            "worker peer Windows creation token is not a decimal timestamp".to_owned(),
        )
    })?;
    if actual_pid != expected_pid || pipe.server_creation_time() != expected_creation {
        return Err(WatchdogError::IdentityMismatch(
            "worker named-pipe peer process identity is not approved".to_owned(),
        ));
    }
    let mut executable_file = fs::File::open(pipe.server_executable()).map_err(|_| {
        WatchdogError::Unauthorized("worker peer executable is unavailable".to_owned())
    })?;
    let actual_digest = super::auth::hash_file_until(&mut executable_file, Some(deadline))?;
    if actual_digest != peer.executable_sha256 {
        return Err(WatchdogError::Unauthorized(
            "worker peer executable digest is not approved".to_owned(),
        ));
    }
    // The credential is opened only after the exact named-pipe server PID,
    // creation timestamp, image path, and image digest have been checked.
    let credential = read_credential(credential_path, deadline)?;
    let mut auth_body = Vec::with_capacity(AUTH_MAGIC.len() + credential.bytes().len());
    auth_body.extend_from_slice(AUTH_MAGIC);
    auth_body.extend_from_slice(credential.bytes());
    let remaining = deadline.saturating_duration_since(Instant::now());
    pipe.write_frame(&auth_body, remaining)
        .map_err(|error| WatchdogError::Io(std::io::Error::other(error.to_string())))?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    pipe.write_frame(request_bytes, remaining)
        .map_err(|error| WatchdogError::Io(std::io::Error::other(error.to_string())))?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    let response = pipe
        .read_frame(remaining)
        .map_err(|error| WatchdogError::Io(std::io::Error::other(error.to_string())))?;
    decode_response(&response).map_err(|error| WatchdogError::InvalidInput(error.to_string()))
}
