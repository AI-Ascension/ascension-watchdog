//! Bounded Windows named-pipe transport for watchdog administration.
//!
//! This module is separate from the lifecycle pipe in native.rs.  The
//! lifecycle channel has a different protocol and is deliberately not reused
//! for JSON admin requests.  The wrappers below keep all Win32 calls and
//! unsafe code in the platform boundary; the portable watchdog only sees
//! bounded byte frames and authenticated connection results.

#![cfg(windows)]

use crate::PlatformError;
use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};
use std::slice;
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_MORE_DATA, ERROR_NO_DATA, ERROR_NOT_FOUND,
    ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, ERROR_PIPE_NOT_CONNECTED,
    ERROR_SEM_TIMEOUT, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, GetAce, GetAclInformation,
    GetLengthSid, GetSecurityDescriptorControl, IsValidSid, OWNER_SECURITY_INFORMATION,
    SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_NONE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFileInformationByHandle, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, READ_CONTROL, ReadFile,
    WriteFile,
};
use windows_sys::Win32::System::IO::CancelIoEx;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeClientSessionId, GetNamedPipeServerProcessId, PIPE_NOWAIT, PIPE_READMODE_MESSAGE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, SetNamedPipeHandleState,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessId, GetProcessTimes, OpenProcess,
    OpenProcessToken, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    QueryFullProcessImageNameW,
};

// `FILE_PIPE_LOCAL_INFORMATION` is declared by ntifs.h rather than the user
// mode Windows SDK. The documented structure is ten ULONGs (40 bytes),
// FilePipeLocalInformation is information class 24, and the query is used
// only to prove that this server handle's outbound quota has returned after a
// successful write. A query failure is never treated as a successful drain.
#[repr(C)]
struct IoStatusBlock {
    status: i32,
    information: usize,
}

#[repr(C)]
struct FilePipeLocalInformation {
    named_pipe_type: u32,
    named_pipe_configuration: u32,
    maximum_instances: u32,
    current_instances: u32,
    inbound_quota: u32,
    read_data_available: u32,
    outbound_quota: u32,
    write_quota_available: u32,
    named_pipe_state: u32,
    named_pipe_end: u32,
}

const FILE_PIPE_LOCAL_INFORMATION_CLASS: u32 = 24;
const FILE_PIPE_CONNECTED_STATE: u32 = 3;
const FILE_PIPE_SERVER_END: u32 = 1;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationFile(
        file_handle: HANDLE,
        io_status_block: *mut IoStatusBlock,
        file_information: *mut c_void,
        length: u32,
        file_information_class: u32,
    ) -> i32;
}

/// Admin transport's complete JSON body bound.  The four-byte big-endian
/// length prefix is outside this value.
pub const MAX_ADMIN_PIPE_FRAME: usize = 256 * 1024;

const MAX_PIPE_NAME_BYTES: usize = 192;
const MAX_SID_BYTES: usize = 184;
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const LOCAL_ONLY_PIPE_MODE: u32 =
    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS;
const NONBLOCKING_MESSAGE_MODE: u32 = PIPE_READMODE_MESSAGE | PIPE_NOWAIT;

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

/// A client-side admin pipe handle with server PID/creation/image checks.
pub struct AdminPipeClient {
    handle: OwnedHandle,
    _name: String,
    server_process: OwnedHandle,
    server_process_id: u32,
    server_creation_time: u64,
    server_executable: PathBuf,
    server_image_guard: Option<crate::native::IntegrityGuards>,
    _server_image_ancestors: Vec<OwnedHandle>,
    _server_image_leaf: Option<OwnedHandle>,
}

impl std::fmt::Debug for AdminPipeClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdminPipeClient")
            .field("name", &"<protected-pipe>")
            .field("server_process_id", &self.server_process_id)
            .field("server_executable", &"<protected-path>")
            .finish_non_exhaustive()
    }
}

impl AdminPipeClient {
    /// Validate the exact local worker namespace without opening any handles.
    pub fn validate_worker_endpoint(name: &str) -> Result<(), PlatformError> {
        validate_worker_pipe_name(name)
    }

    /// Connect to a local nonce-bound worker byte-stream endpoint. This does
    /// not grant admin authority or reuse the admin message-mode namespace.
    pub fn connect_worker(
        name: impl Into<String>,
        expected_server_executable: &Path,
        timeout: Duration,
    ) -> Result<Self, PlatformError> {
        Self::connect_profile(name.into(), Some(expected_server_executable), timeout, true)
    }

    /// Connect to a local named pipe and verify the exact server process.  The
    /// expected executable is mandatory; its canonical path must match the
    /// path observed through the held server process handle.
    pub fn connect(
        name: impl Into<String>,
        expected_server_executable: Option<&Path>,
        timeout: Duration,
    ) -> Result<Self, PlatformError> {
        Self::connect_profile(name.into(), expected_server_executable, timeout, false)
    }

    fn connect_profile(
        name: String,
        expected_server_executable: Option<&Path>,
        timeout: Duration,
        worker: bool,
    ) -> Result<Self, PlatformError> {
        validate_timeout(timeout)?;
        let connection_deadline = deadline(timeout);
        let expected_server_executable = expected_server_executable.ok_or_else(|| {
            PlatformError::Invalid(
                "admin pipe clients must configure the expected server executable".to_owned(),
            )
        })?;
        if worker {
            validate_worker_pipe_name(&name)?;
        } else {
            validate_pipe_name(&name)?;
        }
        // Protect the configured worker image and all existing ancestors
        // before any canonicalization can resolve a reparse component.
        let server_image_ancestors = if worker {
            validate_local_protected_path(expected_server_executable)?;
            open_protected_ancestors(expected_server_executable)?
        } else {
            Vec::new()
        };
        let server_image_leaf = if worker {
            Some(open_worker_image_leaf(expected_server_executable)?)
        } else {
            None
        };
        let wide_name = wide(&name)?;
        let timeout_ms = timeout_millis(timeout)?;
        let waited = unsafe {
            windows_sys::Win32::System::Pipes::WaitNamedPipeW(wide_name.as_ptr(), timeout_ms)
        };
        if waited == 0 {
            let code = unsafe { GetLastError() };
            if code == ERROR_SEM_TIMEOUT {
                return Err(PlatformError::Timeout(
                    "waiting for the admin named pipe timed out".to_owned(),
                ));
            }
            return Err(win32_error("WaitNamedPipeW", code));
        }
        let raw = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_NONE,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        let handle = OwnedHandle::new(raw, "CreateFileW(admin pipe)")?;
        if worker {
            // PIPE_READMODE_BYTE is zero; use nonblocking byte-stream mode for
            // worker framing while retaining message-mode admin semantics.
            let mode = PIPE_NOWAIT;
            if unsafe { SetNamedPipeHandleState(handle.raw(), &raw const mode, null(), null()) }
                == 0
            {
                return Err(last_error("SetNamedPipeHandleState(worker)"));
            }
        } else {
            set_message_nonblocking(handle.raw())?;
        }
        let mut server_process_id = 0_u32;
        if unsafe { GetNamedPipeServerProcessId(handle.raw(), &raw mut server_process_id) } == 0
            || server_process_id == 0
        {
            return Err(last_error("GetNamedPipeServerProcessId"));
        }
        let server_process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                server_process_id,
            )
        };
        let server_process = OwnedHandle::new(server_process, "OpenProcess(admin pipe server)")?;
        let server_executable = query_image_path(server_process.raw())?;
        let expected = canonicalize_executable(expected_server_executable)?;
        if normalize_path(&expected) != normalize_path(&server_executable) {
            return Err(PlatformError::IdentityMismatch(
                "admin pipe server executable is not approved".to_owned(),
            ));
        }
        let server_creation_time = process_creation_time(server_process.raw())?;
        let server_image_guard = if worker {
            Some(crate::native::IntegrityGuards::open_until(
                &expected,
                Some(connection_deadline),
            )?)
        } else {
            None
        };
        Ok(Self {
            handle,
            _name: name,
            server_process,
            server_process_id,
            server_creation_time,
            server_executable,
            server_image_guard,
            _server_image_ancestors: server_image_ancestors,
            _server_image_leaf: server_image_leaf,
        })
    }

    /// Process ID observed from the named-pipe server end.
    #[must_use]
    pub const fn server_process_id(&self) -> u32 {
        self.server_process_id
    }

    /// Process creation timestamp captured from the held server process handle.
    #[must_use]
    pub const fn server_creation_time(&self) -> u64 {
        self.server_creation_time
    }

    /// Observe the connected server account from its held process handle.
    /// Callers must compare this value with trusted launch policy.
    pub fn server_user_sid(&self) -> Result<String, PlatformError> {
        self.verify_server_identity()?;
        process_user_sid(self.server_process.raw())
    }

    /// Observe the connected server session. This value is not authorization
    /// until compared with the trusted launch policy.
    pub fn server_session_id(&self) -> Result<u32, PlatformError> {
        self.verify_server_identity()?;
        let mut session_id = 0_u32;
        if unsafe {
            windows_sys::Win32::System::Pipes::GetNamedPipeServerSessionId(
                self.handle.raw(),
                &raw mut session_id,
            )
        } == 0
        {
            return Err(last_error("GetNamedPipeServerSessionId"));
        }
        Ok(session_id)
    }

    /// Require the connected server account/session to match trusted policy.
    pub fn verify_server_account(
        &self,
        expected_sid: &str,
        expected_session: u32,
    ) -> Result<(), PlatformError> {
        validate_sid(expected_sid)?;
        if self.server_user_sid()? != expected_sid || self.server_session_id()? != expected_session
        {
            return Err(PlatformError::IdentityMismatch(
                "worker server account or session does not match launch policy".to_owned(),
            ));
        }
        Ok(())
    }

    /// Exact image path observed while the server process handle was held.
    #[must_use]
    pub fn server_executable(&self) -> &Path {
        &self.server_executable
    }

    /// Digest of the worker image held against write/delete for this
    /// connection. Admin-mode clients have no image guard and return `None`.
    pub fn worker_image_digest(&self) -> Option<&str> {
        self.server_image_guard
            .as_ref()
            .map(crate::native::IntegrityGuards::digest)
    }

    /// Read one complete bounded admin frame.
    pub fn read_frame(&mut self, timeout: Duration) -> Result<Vec<u8>, PlatformError> {
        self.read_frame_bounded(timeout, MAX_ADMIN_PIPE_FRAME)
    }

    /// Read a frame with a stricter caller-selected bound before allocation.
    pub fn read_frame_bounded(
        &mut self,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<Vec<u8>, PlatformError> {
        validate_timeout(timeout)?;
        self.verify_server_identity()?;
        if max_bytes == 0 || max_bytes > MAX_ADMIN_PIPE_FRAME {
            return Err(PlatformError::Invalid(
                "invalid client frame bound".to_owned(),
            ));
        }
        let deadline = deadline(timeout);
        let mut length = [0_u8; 4];
        read_exact_poll(self.handle.raw(), &mut length, deadline)?;
        let length = usize::try_from(u32::from_be_bytes(length))
            .map_err(|_| PlatformError::Invalid("admin frame length overflow".to_owned()))?;
        if length == 0 || length > max_bytes {
            return Err(PlatformError::Invalid(
                "admin frame exceeds the fixed bound".to_owned(),
            ));
        }
        let mut payload = vec![0_u8; length];
        read_exact_poll(self.handle.raw(), &mut payload, deadline)?;
        Ok(payload)
    }

    /// Write one complete bounded admin frame.
    pub fn write_frame(&mut self, payload: &[u8], timeout: Duration) -> Result<(), PlatformError> {
        validate_timeout(timeout)?;
        self.verify_server_identity()?;
        if payload.is_empty() || payload.len() > MAX_ADMIN_PIPE_FRAME {
            return Err(PlatformError::Invalid(
                "admin frame exceeds the fixed bound".to_owned(),
            ));
        }
        let deadline = deadline(timeout);
        let length = u32::try_from(payload.len())
            .map_err(|_| PlatformError::Invalid("admin frame length overflow".to_owned()))?;
        write_all_poll(self.handle.raw(), &length.to_be_bytes(), deadline)?;
        write_all_poll(self.handle.raw(), payload, deadline)?;
        Ok(())
    }

    /// Cancel an in-flight exchange.  Dropping the handle closes the client
    /// endpoint and cannot affect any other pipe instance.
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

    fn verify_server_identity(&self) -> Result<(), PlatformError> {
        let process_id = unsafe { GetProcessId(self.server_process.raw()) };
        if process_id != self.server_process_id || process_id == 0 {
            return Err(PlatformError::IdentityMismatch(
                "admin pipe server PID changed while connected".to_owned(),
            ));
        }
        if process_creation_time(self.server_process.raw())? != self.server_creation_time {
            return Err(PlatformError::IdentityMismatch(
                "admin pipe server creation identity changed".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Validate and inspect a credential file on Windows.  Owner-only Unix mode
/// checks are not meaningful here: require the current user as owner, a
/// protected DACL, and non-inherited allow ACEs only for that owner.
pub fn validate_protected_credential_file(path: &Path) -> Result<(), PlatformError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| PlatformError::Io(format!("credential metadata: {error}")))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(PlatformError::Invalid(
            "credential path must be a regular non-reparse file".to_owned(),
        ));
    }
    let wide_path = wide_path(path)?;
    // Open and inspect the exact file handle before reading its descriptor.
    // `GetNamedSecurityInfoW(path)` alone would leave a path-replacement
    // window in which a reparse point or another file could be checked.
    let raw_file = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    let file = OwnedHandle::new(raw_file, "CreateFileW(credential)")?;
    validate_protected_file_handle(&file, "credential")
}

/// Read one owner-protected payload through a held Windows file handle.
///
/// Every directory between the local drive root and the target is opened with
/// `OPEN_REPARSE_POINT` and retained until the target read completes.  The
/// handles do not share delete access, so a caller cannot replace an approved
/// ancestor while the final path is being opened.  The target itself uses a
/// no-share handle and is checked for a regular, non-reparse file plus an
/// owner-only protected DACL before any bytes are read.
pub fn read_protected_payload_file(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, PlatformError> {
    if max_bytes == 0 || max_bytes > MAX_ADMIN_PIPE_FRAME {
        return Err(PlatformError::Invalid(
            "protected payload bound is outside the platform limit".to_owned(),
        ));
    }
    validate_local_protected_path(path)?;
    let _ancestors = open_protected_ancestors(path)?;
    let wide_path = wide_path(path)?;
    let raw_file = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_NONE,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    let file = OwnedHandle::new(raw_file, "CreateFileW(payload)")?;
    validate_protected_file_handle(&file, "payload")?;
    read_protected_file_handle(&file, max_bytes)
}

fn validate_local_protected_path(path: &Path) -> Result<(), PlatformError> {
    let components = path.components().collect::<Vec<_>>();
    if components.is_empty()
        || !path.is_absolute()
        || !matches!(components.last(), Some(Component::Normal(_)))
    {
        return Err(PlatformError::Invalid(
            "protected payload path must be an absolute local file".to_owned(),
        ));
    }
    if path.as_os_str().encode_wide().count() > 32_767 {
        return Err(PlatformError::Invalid(
            "protected payload path exceeds the Windows path bound".to_owned(),
        ));
    }
    for component in components {
        match component {
            Component::Prefix(prefix)
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) => {}
            Component::Prefix(_) => {
                return Err(PlatformError::Invalid(
                    "protected payload path must use a local drive prefix".to_owned(),
                ));
            }
            Component::CurDir | Component::ParentDir => {
                return Err(PlatformError::Invalid(
                    "protected payload path contains traversal".to_owned(),
                ));
            }
            Component::Normal(value)
                if value
                    .encode_wide()
                    .any(|unit| unit == u16::from(b':') || unit == 0) =>
            {
                return Err(PlatformError::Invalid(
                    "protected payload path contains an alternate data stream or NUL".to_owned(),
                ));
            }
            Component::RootDir | Component::Normal(_) => {}
        }
    }
    Ok(())
}

fn open_protected_ancestors(path: &Path) -> Result<Vec<OwnedHandle>, PlatformError> {
    let components = path.components().collect::<Vec<_>>();
    let mut current = PathBuf::new();
    let mut ancestors = Vec::new();
    for (index, component) in components.iter().enumerate() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                current.push(component.as_os_str());
            }
            std::path::Component::Normal(value) => {
                current.push(value);
                if index + 1 == components.len() {
                    continue;
                }
                let wide = wide_path(&current)?;
                let raw = unsafe {
                    CreateFileW(
                        wide.as_ptr(),
                        GENERIC_READ | READ_CONTROL,
                        // Retain read sharing only: write access could change
                        // reparse metadata after this ancestor was validated.
                        FILE_SHARE_READ,
                        null(),
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL
                            | FILE_FLAG_OPEN_REPARSE_POINT
                            | FILE_FLAG_BACKUP_SEMANTICS,
                        null_mut(),
                    )
                };
                let handle = OwnedHandle::new(raw, "CreateFileW(payload ancestor)")?;
                validate_directory_handle(&handle)?;
                ancestors.push(handle);
            }
            std::path::Component::CurDir | std::path::Component::ParentDir => {
                return Err(PlatformError::Invalid(
                    "protected payload path contains traversal".to_owned(),
                ));
            }
        }
    }
    Ok(ancestors)
}

fn open_worker_image_leaf(path: &Path) -> Result<OwnedHandle, PlatformError> {
    let wide = wide_path(path)?;
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    let handle = OwnedHandle::new(raw, "CreateFileW(worker image leaf)")?;
    let mut information =
        windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle.raw(), &raw mut information) } == 0 {
        return Err(last_error("GetFileInformationByHandle(worker image leaf)"));
    }
    if information.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
    {
        return Err(PlatformError::IdentityMismatch(
            "worker image leaf must be a regular non-reparse file".to_owned(),
        ));
    }
    Ok(handle)
}

fn validate_directory_handle(handle: &OwnedHandle) -> Result<(), PlatformError> {
    let mut information =
        windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle.raw(), &raw mut information) } == 0 {
        return Err(last_error("GetFileInformationByHandle(payload ancestor)"));
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PlatformError::IdentityMismatch(
            "protected payload ancestor must not be a reparse point".to_owned(),
        ));
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(PlatformError::Invalid(
            "protected payload ancestor must be a directory".to_owned(),
        ));
    }
    Ok(())
}

fn validate_protected_file_handle(file: &OwnedHandle, label: &str) -> Result<(), PlatformError> {
    let mut file_information =
        windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.raw(), &raw mut file_information) } == 0 {
        return Err(last_error(&format!("GetFileInformationByHandle({label})")));
    }
    if file_information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || file_information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
    {
        return Err(PlatformError::Invalid(format!(
            "{label} must be a regular non-reparse file"
        )));
    }
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.raw(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            &raw mut dacl,
            null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 {
        return Err(win32_error(&format!("GetSecurityInfo({label})"), status));
    }
    let result = validate_credential_acl(owner, dacl, descriptor);
    if !descriptor.is_null() {
        unsafe { LocalFree(descriptor) };
    }
    result
}

fn read_protected_file_handle(
    file: &OwnedHandle,
    max_bytes: usize,
) -> Result<Vec<u8>, PlatformError> {
    let mut bytes = Vec::with_capacity(max_bytes.min(16 * 1024));
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let remaining = max_bytes.saturating_add(1).saturating_sub(bytes.len());
        if remaining == 0 {
            return Err(PlatformError::Invalid(
                "protected payload file exceeds the payload bound".to_owned(),
            ));
        }
        let count = u32::try_from(remaining.min(buffer.len()))
            .map_err(|_| PlatformError::Invalid("payload read size overflow".to_owned()))?;
        let mut read = 0_u32;
        let ok = unsafe {
            ReadFile(
                file.raw(),
                buffer.as_mut_ptr().cast(),
                count,
                &raw mut read,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error("ReadFile(payload)"));
        }
        if read > count {
            return Err(PlatformError::Invalid(
                "payload read count exceeds requested buffer".to_owned(),
            ));
        }
        if read == 0 {
            break;
        }
        let read = usize::try_from(read)
            .map_err(|_| PlatformError::Invalid("payload read count overflow".to_owned()))?;
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() > max_bytes {
            return Err(PlatformError::Invalid(
                "protected payload file exceeds the payload bound".to_owned(),
            ));
        }
    }
    Ok(bytes)
}

#[allow(clippy::too_many_lines)]
fn validate_credential_acl(
    owner: *mut c_void,
    dacl: *mut windows_sys::Win32::Security::ACL,
    descriptor: *mut c_void,
) -> Result<(), PlatformError> {
    if owner.is_null() || unsafe { IsValidSid(owner) } == 0 {
        return Err(PlatformError::Invalid(
            "credential owner SID is invalid".to_owned(),
        ));
    }
    let expected_sid = current_user_sid()?;
    if sid_string(owner)? != expected_sid {
        return Err(PlatformError::IdentityMismatch(
            "credential owner is not the service user".to_owned(),
        ));
    }
    if descriptor.is_null() {
        return Err(PlatformError::Invalid(
            "credential security descriptor is missing".to_owned(),
        ));
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) } == 0
    {
        return Err(last_error("GetSecurityDescriptorControl"));
    }
    if control & SE_DACL_PROTECTED == 0 || dacl.is_null() {
        return Err(PlatformError::IdentityMismatch(
            "credential DACL must be present and protected".to_owned(),
        ));
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    let info_size = u32::try_from(size_of::<ACL_SIZE_INFORMATION>())
        .map_err(|_| PlatformError::Invalid("ACL size overflow".to_owned()))?;
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut info).cast::<c_void>(),
            info_size,
            windows_sys::Win32::Security::AclSizeInformation,
        )
    } == 0
    {
        return Err(last_error("GetAclInformation"));
    }
    if info.AceCount == 0 {
        return Err(PlatformError::IdentityMismatch(
            "credential DACL has no owner allow entry".to_owned(),
        ));
    }
    let dacl_address = dacl.cast::<u8>() as usize;
    let dacl_capacity = usize::from(unsafe { (*dacl).AclSize });
    let acl_used = usize::try_from(info.AclBytesInUse)
        .map_err(|_| PlatformError::Invalid("ACL byte count overflow".to_owned()))?;
    if dacl_capacity < size_of::<windows_sys::Win32::Security::ACL>()
        || acl_used < size_of::<windows_sys::Win32::Security::ACL>()
        || acl_used > dacl_capacity
    {
        return Err(PlatformError::Invalid(
            "credential DACL byte bounds are invalid".to_owned(),
        ));
    }
    let dacl_end = dacl_address
        .checked_add(acl_used)
        .ok_or_else(|| PlatformError::Invalid("ACL address range overflow".to_owned()))?;
    for index in 0..info.AceCount {
        let mut raw_ace = null_mut();
        if unsafe { GetAce(dacl, index, &raw mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(last_error("GetAce"));
        }
        // GetAce returns an untrusted descriptor-provided pointer.  Read the
        // fixed header without assuming alignment, then prove the complete
        // ACE and SID fit inside the ACL before any typed cast or dereference.
        let entry_address = raw_ace as usize;
        let header_end = entry_address
            .checked_add(size_of::<windows_sys::Win32::Security::ACE_HEADER>())
            .ok_or_else(|| PlatformError::Invalid("ACE header address overflow".to_owned()))?;
        if entry_address < dacl_address || header_end > dacl_end {
            return Err(PlatformError::Invalid(
                "credential ACE header lies outside its ACL".to_owned(),
            ));
        }
        let header = unsafe {
            std::ptr::read_unaligned(raw_ace.cast::<windows_sys::Win32::Security::ACE_HEADER>())
        };
        let entry_size = usize::from(header.AceSize);
        let entry_end = entry_address
            .checked_add(entry_size)
            .ok_or_else(|| PlatformError::Invalid("ACE address range overflow".to_owned()))?;
        if entry_address < dacl_address
            || entry_end > dacl_end
            || entry_size < size_of::<windows_sys::Win32::Security::ACE_HEADER>()
            || u32::from(header.AceFlags) & windows_sys::Win32::Security::INHERITED_ACE != 0
            || header.AceType != 0
        {
            return Err(PlatformError::IdentityMismatch(
                "credential DACL contains inherited or non-allow ACE".to_owned(),
            ));
        }
        let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        let sid_minimum_end = sid_offset
            .checked_add(size_of::<u32>())
            .ok_or_else(|| PlatformError::Invalid("ACE SID offset overflow".to_owned()))?;
        if entry_size < sid_minimum_end {
            return Err(PlatformError::Invalid(
                "credential allow ACE is truncated before its SID".to_owned(),
            ));
        }
        let sid = unsafe { raw_ace.cast::<u8>().add(sid_offset).cast::<c_void>() };
        let sid_length = usize::try_from(unsafe { GetLengthSid(sid) })
            .map_err(|_| PlatformError::Invalid("credential SID length overflow".to_owned()))?;
        if sid_length == 0
            || sid_length > entry_size.saturating_sub(sid_offset)
            || sid_length > dacl_end.saturating_sub(sid.cast::<u8>() as usize)
        {
            return Err(PlatformError::Invalid(
                "credential allow ACE SID exceeds its bounded ACE".to_owned(),
            ));
        }
        if unsafe { IsValidSid(sid) } == 0 || sid_string(sid)? != expected_sid {
            return Err(PlatformError::IdentityMismatch(
                "credential DACL grants a different SID".to_owned(),
            ));
        }
    }
    Ok(())
}

fn set_message_nonblocking(handle: HANDLE) -> Result<(), PlatformError> {
    let mode = NONBLOCKING_MESSAGE_MODE;
    if unsafe { SetNamedPipeHandleState(handle, &raw const mode, null(), null()) } == 0 {
        return Err(last_error("SetNamedPipeHandleState"));
    }
    Ok(())
}

fn query_pipe_local_information(handle: HANDLE) -> Result<FilePipeLocalInformation, PlatformError> {
    let expected_size = size_of::<FilePipeLocalInformation>();
    if expected_size != 40 {
        return Err(PlatformError::Unsupported(
            "Windows named-pipe local information layout is not 40 bytes".to_owned(),
        ));
    }
    let length = u32::try_from(expected_size)
        .map_err(|_| PlatformError::Invalid("pipe information size overflow".to_owned()))?;
    let mut status = IoStatusBlock {
        status: 0,
        information: 0,
    };
    let mut information = FilePipeLocalInformation {
        named_pipe_type: 0,
        named_pipe_configuration: 0,
        maximum_instances: 0,
        current_instances: 0,
        inbound_quota: 0,
        read_data_available: 0,
        outbound_quota: 0,
        write_quota_available: 0,
        named_pipe_state: 0,
        named_pipe_end: 0,
    };
    let result = unsafe {
        NtQueryInformationFile(
            handle,
            &raw mut status,
            (&raw mut information).cast(),
            length,
            FILE_PIPE_LOCAL_INFORMATION_CLASS,
        )
    };
    if result != 0 || status.status != 0 || status.information != expected_size {
        return Err(PlatformError::Unavailable(format!(
            "NtQueryInformationFile did not prove pipe state (status=0x{:08X}, io_status=0x{:08X}, bytes={})",
            result.cast_unsigned(),
            status.status.cast_unsigned(),
            status.information,
        )));
    }
    Ok(information)
}

fn read_exact_poll(
    handle: HANDLE,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), PlatformError> {
    let mut offset = 0_usize;
    while offset < buffer.len() {
        ensure_io_deadline(handle, deadline, "admin pipe read deadline elapsed")?;
        let remaining = &mut buffer[offset..];
        let count = u32::try_from(remaining.len())
            .map_err(|_| PlatformError::Invalid("admin read exceeds frame bound".to_owned()))?;
        let mut read = 0_u32;
        let ok = unsafe {
            ReadFile(
                handle,
                remaining.as_mut_ptr().cast(),
                count,
                &raw mut read,
                null_mut(),
            )
        };
        let code = unsafe { GetLastError() };
        if read > count {
            return Err(PlatformError::Invalid(
                "admin read count exceeds requested buffer".to_owned(),
            ));
        }
        if ok != 0 || (code == ERROR_MORE_DATA && read != 0) {
            if read == 0 {
                return Err(PlatformError::Unavailable(
                    "admin pipe returned no read progress".to_owned(),
                ));
            }
            offset = offset.saturating_add(
                usize::try_from(read)
                    .map_err(|_| PlatformError::Invalid("admin read count overflow".to_owned()))?,
            );
            ensure_io_deadline(handle, deadline, "admin pipe read deadline elapsed")?;
            continue;
        }
        if is_pending_io_error(code) {
            ensure_io_deadline(handle, deadline, "admin pipe read deadline elapsed")?;
            thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
            continue;
        }
        if code == ERROR_BROKEN_PIPE || code == ERROR_PIPE_NOT_CONNECTED {
            return Err(PlatformError::Unavailable(
                "admin pipe peer closed before frame completion".to_owned(),
            ));
        }
        return Err(win32_error("ReadFile(admin pipe)", code));
    }
    Ok(())
}

fn write_all_poll(handle: HANDLE, buffer: &[u8], deadline: Instant) -> Result<(), PlatformError> {
    let mut offset = 0_usize;
    while offset < buffer.len() {
        ensure_io_deadline(handle, deadline, "admin pipe write deadline elapsed")?;
        let remaining = &buffer[offset..];
        let count = u32::try_from(remaining.len())
            .map_err(|_| PlatformError::Invalid("admin write exceeds frame bound".to_owned()))?;
        let mut written = 0_u32;
        let ok = unsafe {
            WriteFile(
                handle,
                remaining.as_ptr().cast(),
                count,
                &raw mut written,
                null_mut(),
            )
        };
        if written > count {
            return Err(PlatformError::Invalid(
                "admin write count exceeds requested buffer".to_owned(),
            ));
        }
        if ok != 0 {
            if written == 0 {
                ensure_io_deadline(handle, deadline, "admin pipe write deadline elapsed")?;
                thread::sleep(
                    POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                );
                continue;
            }
            offset = offset
                .saturating_add(usize::try_from(written).map_err(|_| {
                    PlatformError::Invalid("admin write count overflow".to_owned())
                })?);
            ensure_io_deadline(handle, deadline, "admin pipe write deadline elapsed")?;
            continue;
        }
        let code = unsafe { GetLastError() };
        if written != 0 && is_pending_io_error(code) {
            offset = offset
                .saturating_add(usize::try_from(written).map_err(|_| {
                    PlatformError::Invalid("admin write count overflow".to_owned())
                })?);
            ensure_io_deadline(handle, deadline, "admin pipe write deadline elapsed")?;
            continue;
        }
        if is_pending_io_error(code) {
            ensure_io_deadline(handle, deadline, "admin pipe write deadline elapsed")?;
            thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
            continue;
        }
        if code == ERROR_BROKEN_PIPE || code == ERROR_PIPE_NOT_CONNECTED {
            return Err(PlatformError::Unavailable(
                "admin pipe peer closed during frame write".to_owned(),
            ));
        }
        return Err(win32_error("WriteFile(admin pipe)", code));
    }
    Ok(())
}

fn ensure_io_deadline(
    handle: HANDLE,
    deadline: Instant,
    message: &str,
) -> Result<(), PlatformError> {
    if Instant::now() >= deadline {
        let _ = unsafe { CancelIoEx(handle, null()) };
        return Err(PlatformError::Timeout(message.to_owned()));
    }
    Ok(())
}

fn is_pending_pipe_error(code: u32) -> bool {
    code == ERROR_PIPE_LISTENING
}

fn is_pending_io_error(code: u32) -> bool {
    code == ERROR_NO_DATA || code == ERROR_PIPE_LISTENING
}

fn deadline(timeout: Duration) -> Instant {
    Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now)
}

fn timeout_millis(timeout: Duration) -> Result<u32, PlatformError> {
    validate_timeout(timeout)?;
    let millis = timeout.as_millis();
    u32::try_from(millis)
        .map_err(|_| PlatformError::Invalid("admin timeout does not fit Win32".to_owned()))
}

fn validate_pipe_name(name: &str) -> Result<(), PlatformError> {
    let prefix = r"\\.\pipe\ascension-watchdog-";
    let valid_suffix = name.strip_prefix(prefix).is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    });
    if name.len() > MAX_PIPE_NAME_BYTES || !valid_suffix || name.contains(['\0', '\r', '\n']) {
        return Err(PlatformError::Invalid(
            "admin pipe name is outside the fixed local namespace".to_owned(),
        ));
    }
    Ok(())
}

fn validate_worker_pipe_name(name: &str) -> Result<(), PlatformError> {
    let valid = name
        .strip_prefix(r"\\.\pipe\ascension-worker-")
        .is_some_and(|nonce| {
            let bytes = nonce.as_bytes();
            bytes.len() == 36
                && bytes.iter().enumerate().all(|(index, byte)| {
                    if matches!(index, 8 | 13 | 18 | 23) {
                        *byte == b'-'
                    } else {
                        byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
                    }
                })
                && bytes[14] == b'4'
                && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        });
    if !valid || name.len() > MAX_PIPE_NAME_BYTES {
        return Err(PlatformError::Invalid(
            "worker pipe name is not a bounded local launch nonce".to_owned(),
        ));
    }
    Ok(())
}

fn validate_timeout(timeout: Duration) -> Result<(), PlatformError> {
    if timeout.is_zero() || timeout > Duration::from_secs(30) {
        return Err(PlatformError::Invalid(
            "admin timeout must be between 1ms and 30s".to_owned(),
        ));
    }
    Ok(())
}

fn validate_sid(sid: &str) -> Result<(), PlatformError> {
    let mut components = sid.split('-');
    let valid = components.next() == Some("S")
        && components.next().is_some_and(|revision| {
            !revision.is_empty() && revision.bytes().all(|b| b.is_ascii_digit())
        })
        && components.next().is_some_and(|authority| {
            !authority.is_empty() && authority.bytes().all(|b| b.is_ascii_digit())
        })
        && components.all(|subauthority| {
            !subauthority.is_empty() && subauthority.bytes().all(|b| b.is_ascii_digit())
        });
    if sid.len() > MAX_SID_BYTES || !valid {
        return Err(PlatformError::Invalid(
            "authorized peer SID is outside the bounded syntax".to_owned(),
        ));
    }
    Ok(())
}

fn current_user_sid() -> Result<String, PlatformError> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(last_error("OpenProcessToken(current user)"));
    }
    let token = OwnedHandle::new(token, "OpenProcessToken(current user)")?;
    token_user_sid(token.raw())
}

pub(crate) fn process_user_sid(process: HANDLE) -> Result<String, PlatformError> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(last_error("OpenProcessToken(pipe peer)"));
    }
    let token = OwnedHandle::new(token, "OpenProcessToken(pipe peer)")?;
    token_user_sid(token.raw())
}

fn token_user_sid(token: HANDLE) -> Result<String, PlatformError> {
    let mut required = 0_u32;
    let _ = unsafe {
        windows_sys::Win32::Security::GetTokenInformation(
            token,
            windows_sys::Win32::Security::TokenUser,
            null_mut(),
            0,
            &raw mut required,
        )
    };
    if required == 0
        || usize::try_from(required).unwrap_or(usize::MAX) > MAX_SID_BYTES.saturating_mul(4)
    {
        return Err(last_error("GetTokenInformation(size)"));
    }
    let required_bytes = usize::try_from(required)
        .map_err(|_| PlatformError::Invalid("token SID size overflow".to_owned()))?;
    let word_size = size_of::<usize>();
    let words = required_bytes
        .checked_add(word_size - 1)
        .ok_or_else(|| PlatformError::Invalid("token SID allocation overflow".to_owned()))?
        / word_size;
    let mut words = vec![0_usize; words];
    let buffer_size = words
        .len()
        .checked_mul(word_size)
        .ok_or_else(|| PlatformError::Invalid("token SID buffer overflow".to_owned()))?;
    let buffer_size = u32::try_from(buffer_size)
        .map_err(|_| PlatformError::Invalid("token SID buffer size overflow".to_owned()))?;
    let mut returned = buffer_size;
    if unsafe {
        windows_sys::Win32::Security::GetTokenInformation(
            token,
            windows_sys::Win32::Security::TokenUser,
            words.as_mut_ptr().cast(),
            buffer_size,
            &raw mut returned,
        )
    } == 0
    {
        return Err(last_error("GetTokenInformation(TokenUser)"));
    }
    let user = unsafe { &*words.as_ptr().cast::<TOKEN_USER>() };
    let sid = user.User.Sid;
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(PlatformError::IdentityMismatch(
            "token user SID is invalid".to_owned(),
        ));
    }
    sid_string(sid)
}

fn sid_string(sid: *mut c_void) -> Result<String, PlatformError> {
    let length = unsafe { GetLengthSid(sid) };
    if length == 0 || usize::try_from(length).unwrap_or(usize::MAX) > MAX_SID_BYTES {
        return Err(PlatformError::Invalid(
            "Windows SID exceeds the fixed bound".to_owned(),
        ));
    }
    let mut string_sid = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &raw mut string_sid) } == 0 || string_sid.is_null() {
        return Err(last_error("ConvertSidToStringSidW"));
    }
    let result = unsafe {
        let mut length = 0_usize;
        while *string_sid.add(length) != 0 {
            length = length.saturating_add(1);
            if length > MAX_SID_BYTES {
                LocalFree(string_sid.cast());
                return Err(PlatformError::Invalid(
                    "Windows SID string exceeds the fixed bound".to_owned(),
                ));
            }
        }
        let result = String::from_utf16(slice::from_raw_parts(string_sid, length))
            .map_err(|_| PlatformError::IdentityMismatch("Windows SID is not UTF-16".to_owned()));
        LocalFree(string_sid.cast());
        result
    }?;
    validate_sid(&result)?;
    Ok(result)
}

fn query_image_path(process: HANDLE) -> Result<PathBuf, PlatformError> {
    let mut buffer = vec![0_u16; 32_768];
    let mut length = u32::try_from(buffer.len())
        .map_err(|_| PlatformError::Invalid("image path buffer overflow".to_owned()))?;
    if unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            buffer.as_mut_ptr(),
            &raw mut length,
        )
    } == 0
    {
        return Err(last_error("QueryFullProcessImageNameW"));
    }
    buffer.truncate(
        usize::try_from(length)
            .map_err(|_| PlatformError::Invalid("image path length overflow".to_owned()))?,
    );
    if buffer.is_empty() {
        return Err(PlatformError::IdentityMismatch(
            "peer image path is empty".to_owned(),
        ));
    }
    Ok(PathBuf::from(String::from_utf16_lossy(&buffer)))
}

fn process_creation_time(process: HANDLE) -> Result<u64, PlatformError> {
    let mut creation = windows_sys::Win32::Foundation::FILETIME::default();
    let mut exit = windows_sys::Win32::Foundation::FILETIME::default();
    let mut kernel = windows_sys::Win32::Foundation::FILETIME::default();
    let mut user = windows_sys::Win32::Foundation::FILETIME::default();
    if unsafe {
        GetProcessTimes(
            process,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    } == 0
    {
        return Err(last_error("GetProcessTimes"));
    }
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

fn canonicalize_executable(path: &Path) -> Result<PathBuf, PlatformError> {
    if !path.is_absolute() {
        return Err(PlatformError::Invalid(
            "expected server executable must be absolute".to_owned(),
        ));
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| PlatformError::Io(format!("server executable: {error}")))?;
    if !canonical.is_file() {
        return Err(PlatformError::Invalid(
            "expected server executable is not a regular file".to_owned(),
        ));
    }
    Ok(canonical)
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy()
        .trim_start_matches(r"\\?\")
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn wide(value: &str) -> Result<Vec<u16>, PlatformError> {
    if value.contains('\0') {
        return Err(PlatformError::Invalid(
            "Windows name contains NUL".to_owned(),
        ));
    }
    Ok(value.encode_utf16().chain(std::iter::once(0)).collect())
}

fn wide_path(path: &Path) -> Result<Vec<u16>, PlatformError> {
    let value = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if value.contains(&0) {
        return Err(PlatformError::Invalid(
            "Windows path contains NUL".to_owned(),
        ));
    }
    Ok(value.into_iter().chain(std::iter::once(0)).collect())
}

fn last_error(operation: &str) -> PlatformError {
    win32_error(operation, unsafe { GetLastError() })
}

fn win32_error(operation: &str, code: u32) -> PlatformError {
    PlatformError::Win32 {
        operation: operation.to_owned(),
        code,
    }
}

struct OwnedHandle(HANDLE);

// A HANDLE is an opaque kernel-owned value.  Each wrapper has unique
// ownership and is moved, never aliased, into exactly one worker thread.
unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    fn new(raw: HANDLE, operation: &str) -> Result<Self, PlatformError> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(last_error(operation));
        }
        Ok(Self(raw))
    }

    const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct SecurityDescriptor(*mut c_void);

impl SecurityDescriptor {
    fn for_sid(allowed_sid: &str) -> Result<Self, PlatformError> {
        validate_sid(allowed_sid)?;
        let descriptor = format!("D:P(A;;GA;;;{allowed_sid})");
        let descriptor = wide(&descriptor)?;
        let mut raw = null_mut();
        let mut size = 0_u32;
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor.as_ptr(),
                1,
                &raw mut raw,
                &raw mut size,
            )
        } == 0
            || raw.is_null()
            || size == 0
        {
            return Err(last_error(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            ));
        }
        Ok(Self(raw))
    }

    const fn raw(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

#[cfg(test)]
mod ancestor_lock_tests {
    use super::*;

    struct TestDirectory(PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    fn open_writer(path: &Path) -> Result<OwnedHandle, PlatformError> {
        let path = wide_path(path)?;
        let raw = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                null_mut(),
            )
        };
        OwnedHandle::new(raw, "open test ancestor writer")
    }

    #[test]
    fn retained_ancestor_prevents_write_open_until_release()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("watchdog-ancestor-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&path)?;
        let directory = TestDirectory(path);
        drop(open_writer(&directory.0)?);
        let guards = open_protected_ancestors(&directory.0.join("payload.json"))?;
        assert!(
            open_writer(&directory.0).is_err(),
            "validated ancestor remained writable"
        );
        drop(guards);
        drop(open_writer(&directory.0)?);
        Ok(())
    }
}
