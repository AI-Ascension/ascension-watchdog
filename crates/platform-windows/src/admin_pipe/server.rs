//! Server side of the bounded Windows admin named-pipe transport.
//!
//! This module owns the fixed admin pipe instance: creation with the
//! local-only, owner/SID ACL mode, the accept and peer-authentication path,
//! bounded frame reads and writes, the outbound-drain proof, and cancel and
//! disconnect of the exact server handle.  Peer SID checks, the single-instance
//! local-only endpoint restriction, the bounded frames and the cancellation
//! semantics are unchanged from the pre-split file.

use super::{
    FILE_PIPE_CONNECTED_STATE, FILE_PIPE_SERVER_END, MAX_ADMIN_PIPE_FRAME, OwnedHandle,
    POLL_INTERVAL, SecurityDescriptor, current_user_sid, deadline, is_pending_pipe_error,
    last_error, process_creation_time, process_user_sid, query_image_path,
    query_pipe_local_information, read_exact_poll, set_message_nonblocking, validate_pipe_name,
    validate_sid, validate_timeout, wide, win32_error, write_all_poll,
};
use crate::PlatformError;
use std::mem::size_of;
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_NOT_FOUND, ERROR_OPERATION_ABORTED,
    ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, GetLastError,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::IO::CancelIoEx;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeClientSessionId, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_MESSAGE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, GetProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE,
};
const LOCAL_ONLY_PIPE_MODE: u32 =
    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS;
/// Identity captured from the authenticated local named-pipe peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminPipePeer {
    /// PID is diagnostic only; the pipe ACL and SID are the authority.
    pub process_id: u32,
    /// The Windows session in which the peer runs.
    pub session_id: u32,
    /// Canonical user SID captured from the peer token.
    pub user_sid: String,
    /// Exact executable path captured while the peer handle was open.
    pub executable: PathBuf,
}
/// A server-side named-pipe instance with local-only, owner/SID ACLs.
pub struct AdminPipeServer {
    handle: OwnedHandle,
    _name: String,
    expected_peer_sid: String,
    server_process_id: u32,
    connected: bool,
    peer: Option<AdminPipePeer>,
    peer_process: Option<OwnedHandle>,
    peer_creation_time: Option<u64>,
}
impl std::fmt::Debug for AdminPipeServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdminPipeServer")
            .field("name", &"<protected-pipe>")
            .field("server_process_id", &self.server_process_id)
            .field("connected", &self.connected)
            .finish_non_exhaustive()
    }
}
impl AdminPipeServer {
    /// Create the sole fixed worker instance.  `FILE_FLAG_FIRST_PIPE_INSTANCE`
    /// and a single kernel instance make a same-SID competing server fail at
    /// bind time; Windows integration must use one accept worker and perform
    /// bounded client work behind it.
    pub fn create(
        name: impl Into<String>,
        allowed_peer_sid: Option<&str>,
    ) -> Result<Self, PlatformError> {
        let name = name.into();
        validate_pipe_name(&name)?;
        let expected_peer_sid = match allowed_peer_sid {
            Some(sid) => {
                validate_sid(sid)?;
                sid.to_owned()
            }
            None => current_user_sid()?,
        };
        // Bind the ACL to the exact SID that was checked above.  The SDDL
        // owner-rights alias is not equivalent to an allow ACE for the
        // service account and can leave the pipe inaccessible to its client.
        let security = SecurityDescriptor::for_sid(&expected_peer_sid)?;
        let attributes = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>())
                .map_err(|_| {
                    PlatformError::Invalid("security attribute size overflow".to_owned())
                })?,
            lpSecurityDescriptor: security.raw(),
            bInheritHandle: 0,
        };
        let wide_name = wide(&name)?;
        let raw = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                LOCAL_ONLY_PIPE_MODE,
                1,
                u32::try_from(MAX_ADMIN_PIPE_FRAME)
                    .map_err(|_| PlatformError::Invalid("pipe frame size overflow".to_owned()))?,
                u32::try_from(MAX_ADMIN_PIPE_FRAME)
                    .map_err(|_| PlatformError::Invalid("pipe frame size overflow".to_owned()))?,
                1_000,
                &raw const attributes,
            )
        };
        let handle = OwnedHandle::new(raw, "CreateNamedPipeW")?;
        set_message_nonblocking(handle.raw())?;
        Ok(Self {
            handle,
            _name: name,
            expected_peer_sid,
            server_process_id: unsafe { GetCurrentProcessId() },
            connected: false,
            peer: None,
            peer_process: None,
            peer_creation_time: None,
        })
    }

    /// Wait for a peer for at most timeout.  A timeout is a normal poll result
    /// so a watchdog stop flag can be observed without a blocked call.
    pub fn accept(&mut self, timeout: Duration) -> Result<Option<AdminPipePeer>, PlatformError> {
        validate_timeout(timeout)?;
        if self.connected {
            return Err(PlatformError::Invalid(
                "admin pipe already has a connected peer".to_owned(),
            ));
        }
        let deadline = deadline(timeout);
        loop {
            let connected = unsafe { ConnectNamedPipe(self.handle.raw(), null_mut()) };
            if connected != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED {
                self.connected = true;
                let (peer, peer_process, peer_creation_time) = match self.capture_peer() {
                    Ok(peer) => peer,
                    Err(error) => {
                        let _ = self.disconnect();
                        return Err(error);
                    }
                };
                if peer.user_sid != self.expected_peer_sid {
                    let _ = self.disconnect();
                    return Err(PlatformError::IdentityMismatch(
                        "admin pipe peer SID is not authorized".to_owned(),
                    ));
                }
                self.peer = Some(peer.clone());
                self.peer_process = Some(peer_process);
                self.peer_creation_time = Some(peer_creation_time);
                return Ok(Some(peer));
            }
            let code = unsafe { GetLastError() };
            if code == ERROR_NO_DATA || code == ERROR_PIPE_NOT_CONNECTED {
                self.reset_listener()?;
                if Instant::now() >= deadline {
                    return Ok(None);
                }
                continue;
            }
            if !is_pending_pipe_error(code) {
                return Err(win32_error("ConnectNamedPipe", code));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
        }
    }

    /// Peer metadata captured during the last successful accept.
    pub fn peer(&self) -> Result<&AdminPipePeer, PlatformError> {
        self.peer
            .as_ref()
            .ok_or_else(|| PlatformError::Invalid("admin pipe has no connected peer".to_owned()))
    }

    /// Process ID of the server creating this exact pipe instance.
    #[must_use]
    pub const fn server_process_id(&self) -> u32 {
        self.server_process_id
    }

    /// Read one complete big-endian length-prefixed frame.
    pub fn read_frame(&mut self, timeout: Duration) -> Result<Vec<u8>, PlatformError> {
        validate_timeout(timeout)?;
        self.require_connected()?;
        let deadline = deadline(timeout);
        let mut length = [0_u8; 4];
        read_exact_poll(self.handle.raw(), &mut length, deadline)?;
        let length = usize::try_from(u32::from_be_bytes(length))
            .map_err(|_| PlatformError::Invalid("admin frame length overflow".to_owned()))?;
        if length == 0 || length > MAX_ADMIN_PIPE_FRAME {
            return Err(PlatformError::Invalid(
                "admin frame exceeds the fixed bound".to_owned(),
            ));
        }
        let mut payload = vec![0_u8; length];
        read_exact_poll(self.handle.raw(), &mut payload, deadline)?;
        Ok(payload)
    }

    /// Write one complete big-endian length-prefixed frame with bounded
    /// partial-write retries. The server waits for outbound quota to be
    /// restored before returning success, proving the peer consumed the
    /// response. A timeout, query failure, or identity failure after bytes
    /// were written is delivery uncertainty and must not be blindly retried.
    pub fn write_frame(&mut self, payload: &[u8], timeout: Duration) -> Result<(), PlatformError> {
        validate_timeout(timeout)?;
        self.require_connected()?;
        if payload.is_empty() || payload.len() > MAX_ADMIN_PIPE_FRAME {
            return Err(PlatformError::Invalid(
                "admin frame exceeds the fixed bound".to_owned(),
            ));
        }
        let deadline = deadline(timeout);
        let length = u32::try_from(payload.len())
            .map_err(|_| PlatformError::Invalid("admin frame length overflow".to_owned()))?;
        self.verify_peer_identity()?;
        write_all_poll(self.handle.raw(), &length.to_be_bytes(), deadline)?;
        write_all_poll(self.handle.raw(), payload, deadline)?;
        self.wait_for_outbound_drain(deadline)?;
        Ok(())
    }

    /// Cancel pending I/O and disconnect the exact server handle.  This is
    /// safe to call after EOF, timeout, or a peer disappearing.
    pub fn cancel(&mut self) -> Result<(), PlatformError> {
        let result = unsafe { CancelIoEx(self.handle.raw(), null()) };
        if result == 0 {
            let code = unsafe { GetLastError() };
            if code != ERROR_NOT_FOUND
                && code != ERROR_OPERATION_ABORTED
                && code != ERROR_PIPE_NOT_CONNECTED
            {
                return Err(win32_error("CancelIoEx", code));
            }
        }
        Ok(())
    }

    /// Release the peer and return this fixed instance to the listen state.
    pub fn disconnect(&mut self) -> Result<(), PlatformError> {
        if self.connected {
            let result = unsafe { DisconnectNamedPipe(self.handle.raw()) };
            if result == 0 {
                let code = unsafe { GetLastError() };
                if code != ERROR_NOT_FOUND
                    && code != ERROR_PIPE_NOT_CONNECTED
                    && code != ERROR_BROKEN_PIPE
                {
                    return Err(win32_error("DisconnectNamedPipe", code));
                }
            }
        }
        self.connected = false;
        self.peer = None;
        self.peer_process = None;
        self.peer_creation_time = None;
        Ok(())
    }

    fn capture_peer(&self) -> Result<(AdminPipePeer, OwnedHandle, u64), PlatformError> {
        let mut process_id = 0_u32;
        if unsafe { GetNamedPipeClientProcessId(self.handle.raw(), &raw mut process_id) } == 0
            || process_id == 0
        {
            return Err(last_error("GetNamedPipeClientProcessId"));
        }
        let mut session_id = 0_u32;
        if unsafe { GetNamedPipeClientSessionId(self.handle.raw(), &raw mut session_id) } == 0 {
            return Err(last_error("GetNamedPipeClientSessionId"));
        }
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                process_id,
            )
        };
        let process = OwnedHandle::new(process, "OpenProcess(admin pipe peer)")?;
        let user_sid = process_user_sid(process.raw())?;
        let executable = query_image_path(process.raw())?;
        let creation_time = process_creation_time(process.raw())?;
        Ok((
            AdminPipePeer {
                process_id,
                session_id,
                user_sid,
                executable,
            },
            process,
            creation_time,
        ))
    }

    fn reset_listener(&mut self) -> Result<(), PlatformError> {
        let result = unsafe { DisconnectNamedPipe(self.handle.raw()) };
        if result == 0 {
            let code = unsafe { GetLastError() };
            if code != ERROR_NOT_FOUND
                && code != ERROR_PIPE_NOT_CONNECTED
                && code != ERROR_BROKEN_PIPE
                && code != ERROR_NO_DATA
            {
                return Err(win32_error("DisconnectNamedPipe(admin listener)", code));
            }
        }
        self.connected = false;
        self.peer = None;
        self.peer_process = None;
        self.peer_creation_time = None;
        Ok(())
    }

    fn require_connected(&self) -> Result<(), PlatformError> {
        if self.connected {
            Ok(())
        } else {
            Err(PlatformError::Invalid(
                "admin pipe has no connected peer".to_owned(),
            ))
        }
    }

    fn verify_peer_identity(&self) -> Result<(), PlatformError> {
        let peer = self.peer.as_ref().ok_or_else(|| {
            PlatformError::IdentityMismatch("admin pipe has no captured peer".to_owned())
        })?;
        let peer_process = self.peer_process.as_ref().ok_or_else(|| {
            PlatformError::IdentityMismatch("admin pipe has no held peer process".to_owned())
        })?;
        let creation_time = self.peer_creation_time.ok_or_else(|| {
            PlatformError::IdentityMismatch("admin pipe has no peer creation identity".to_owned())
        })?;
        let mut process_id = 0_u32;
        if unsafe { GetNamedPipeClientProcessId(self.handle.raw(), &raw mut process_id) } == 0 {
            return Err(PlatformError::IdentityMismatch(
                "admin pipe peer is no longer connected".to_owned(),
            ));
        }
        if process_id == 0 || process_id != peer.process_id {
            return Err(PlatformError::IdentityMismatch(
                "admin pipe peer process changed while connected".to_owned(),
            ));
        }
        if unsafe { GetProcessId(peer_process.raw()) } != peer.process_id
            || process_creation_time(peer_process.raw())? != creation_time
        {
            return Err(PlatformError::IdentityMismatch(
                "admin pipe peer creation identity changed".to_owned(),
            ));
        }
        Ok(())
    }

    fn wait_for_outbound_drain(&self, deadline: Instant) -> Result<(), PlatformError> {
        loop {
            if Instant::now() >= deadline {
                return Err(PlatformError::Timeout(
                    "admin pipe outbound drain deadline elapsed; response delivery is uncertain"
                        .to_owned(),
                ));
            }
            self.verify_peer_identity()?;
            let information = query_pipe_local_information(self.handle.raw())?;
            if Instant::now() >= deadline {
                return Err(PlatformError::Timeout(
                    "admin pipe outbound drain deadline elapsed; response delivery is uncertain"
                        .to_owned(),
                ));
            }
            if information.named_pipe_state != FILE_PIPE_CONNECTED_STATE
                || information.named_pipe_end != FILE_PIPE_SERVER_END
            {
                return Err(PlatformError::IdentityMismatch(
                    "admin pipe left the connected server state before outbound drain".to_owned(),
                ));
            }
            if information.outbound_quota != 0
                && information.write_quota_available == information.outbound_quota
            {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(PlatformError::Timeout(
                    "admin pipe outbound drain deadline elapsed; response delivery is uncertain"
                        .to_owned(),
                ));
            }
            thread::sleep(POLL_INTERVAL.min(remaining));
        }
    }
}
