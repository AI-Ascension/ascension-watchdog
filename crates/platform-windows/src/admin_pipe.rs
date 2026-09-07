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
use std::path::{Path, PathBuf};
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
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_NONE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFileInformationByHandle, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, READ_CONTROL, ReadFile,
    WriteFile,
};
use windows_sys::Win32::System::IO::CancelIoEx;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeClientSessionId, GetNamedPipeServerProcessId, PIPE_NOWAIT, PIPE_READMODE_MESSAGE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES,
    SetNamedPipeHandleState,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessId, GetProcessTimes, OpenProcess,
    OpenProcessToken, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    QueryFullProcessImageNameW,
};

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
    /// Create one fixed worker instance.  Multiple workers may create the same
    /// name; the watchdog controls the number of instances and never grows it
    /// from client input.
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
                PIPE_ACCESS_DUPLEX,
                LOCAL_ONLY_PIPE_MODE,
                PIPE_UNLIMITED_INSTANCES,
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
                let peer = match self.capture_peer() {
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
    /// partial-write retries.  The receiver reads the prefix then body
    /// exactly; no arbitrary stream is exposed above this boundary.
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
        write_all_poll(self.handle.raw(), &length.to_be_bytes(), deadline)?;
        write_all_poll(self.handle.raw(), payload, deadline)?;
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
        Ok(())
    }

    fn capture_peer(&self) -> Result<AdminPipePeer, PlatformError> {
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
        Ok(AdminPipePeer {
            process_id,
            session_id,
            user_sid,
            executable,
        })
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
}

/// A client-side admin pipe handle with server PID/creation/image checks.
pub struct AdminPipeClient {
    handle: OwnedHandle,
    _name: String,
    server_process: OwnedHandle,
    server_process_id: u32,
    server_creation_time: u64,
    server_executable: PathBuf,
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
    /// Connect to a local named pipe and verify the exact server process.  If
    /// `expected_server_executable` is supplied, its canonical path must match
    /// the path observed through the held server process handle.
    pub fn connect(
        name: impl Into<String>,
        expected_server_executable: Option<&Path>,
        timeout: Duration,
    ) -> Result<Self, PlatformError> {
        validate_timeout(timeout)?;
        let name = name.into();
        validate_pipe_name(&name)?;
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
        set_message_nonblocking(handle.raw())?;
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
        if let Some(expected) = expected_server_executable {
            let expected = canonicalize_executable(expected)?;
            if normalize_path(&expected) != normalize_path(&server_executable) {
                return Err(PlatformError::IdentityMismatch(
                    "admin pipe server executable is not approved".to_owned(),
                ));
            }
        }
        let server_creation_time = process_creation_time(server_process.raw())?;
        Ok(Self {
            handle,
            _name: name,
            server_process,
            server_process_id,
            server_creation_time,
            server_executable,
        })
    }

    /// Process ID observed from the named-pipe server end.
    #[must_use]
    pub const fn server_process_id(&self) -> u32 {
        self.server_process_id
    }

    /// Exact image path observed while the server process handle was held.
    #[must_use]
    pub fn server_executable(&self) -> &Path {
        &self.server_executable
    }

    /// Read one complete bounded admin frame.
    pub fn read_frame(&mut self, timeout: Duration) -> Result<Vec<u8>, PlatformError> {
        validate_timeout(timeout)?;
        self.verify_server_identity()?;
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
    let mut file_information =
        windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.raw(), &raw mut file_information) } == 0 {
        return Err(last_error("GetFileInformationByHandle(credential)"));
    }
    if file_information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || file_information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
    {
        return Err(PlatformError::Invalid(
            "credential path must be a regular non-reparse file".to_owned(),
        ));
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
        return Err(win32_error("GetSecurityInfo(credential)", status));
    }
    let result = validate_credential_acl(owner, dacl, descriptor);
    if !descriptor.is_null() {
        unsafe { LocalFree(descriptor) };
    }
    result
}

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
    for index in 0..info.AceCount {
        let mut raw_ace = null_mut();
        if unsafe { GetAce(dacl, index, &raw mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(last_error("GetAce"));
        }
        let header = unsafe { &*raw_ace.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
        if u32::from(header.AceFlags) & windows_sys::Win32::Security::INHERITED_ACE != 0
            || header.AceType != 0
        {
            return Err(PlatformError::IdentityMismatch(
                "credential DACL contains inherited or non-allow ACE".to_owned(),
            ));
        }
        let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = (&raw const ace.SidStart).cast::<c_void>().cast_mut();
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

fn read_exact_poll(
    handle: HANDLE,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), PlatformError> {
    let mut offset = 0_usize;
    while offset < buffer.len() {
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
            continue;
        }
        if is_pending_io_error(code) {
            if Instant::now() >= deadline {
                return Err(PlatformError::Timeout(
                    "admin pipe read deadline elapsed".to_owned(),
                ));
            }
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
                return Err(PlatformError::Unavailable(
                    "admin pipe returned no write progress".to_owned(),
                ));
            }
            offset = offset
                .saturating_add(usize::try_from(written).map_err(|_| {
                    PlatformError::Invalid("admin write count overflow".to_owned())
                })?);
            continue;
        }
        let code = unsafe { GetLastError() };
        if written != 0 && is_pending_io_error(code) {
            offset = offset
                .saturating_add(usize::try_from(written).map_err(|_| {
                    PlatformError::Invalid("admin write count overflow".to_owned())
                })?);
            continue;
        }
        if is_pending_io_error(code) {
            if Instant::now() >= deadline {
                return Err(PlatformError::Timeout(
                    "admin pipe write deadline elapsed".to_owned(),
                ));
            }
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

fn process_user_sid(process: HANDLE) -> Result<String, PlatformError> {
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
    let value = path.as_os_str().to_string_lossy();
    if value.contains('\0') {
        return Err(PlatformError::Invalid(
            "Windows path contains NUL".to_owned(),
        ));
    }
    Ok(value.encode_utf16().chain(std::iter::once(0)).collect())
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
