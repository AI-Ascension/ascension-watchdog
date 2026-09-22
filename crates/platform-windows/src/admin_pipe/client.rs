//! Client side of the bounded Windows admin and worker pipe transports.
//!
//! This module owns the client handle, the admin `connect` and worker
//! `connect_worker` entry points, the mandatory expected-server-executable
//! binding, the server account/session/image verification against launch
//! policy, the immutable worker image digest guard, and the bounded request
//! read/write and cancel paths.  The expected server SID/session/image binding,
//! the worker endpoint rules and the worker image digest are unchanged from
//! the pre-split file.

use super::{
    MAX_ADMIN_PIPE_FRAME, OwnedHandle, canonicalize_executable, deadline, last_error,
    normalize_path, open_protected_ancestors, open_worker_image_leaf, process_creation_time,
    process_user_sid, query_image_path, read_exact_poll, set_message_nonblocking, timeout_millis,
    validate_local_protected_path, validate_pipe_name, validate_sid, validate_timeout,
    validate_worker_pipe_name, wide, win32_error, write_all_poll,
};
use crate::PlatformError;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    ERROR_NOT_FOUND, ERROR_OPERATION_ABORTED, ERROR_PIPE_NOT_CONNECTED, ERROR_SEM_TIMEOUT,
    GENERIC_READ, GENERIC_WRITE, GetLastError,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::CancelIoEx;
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeServerProcessId, PIPE_NOWAIT, SetNamedPipeHandleState,
};
use windows_sys::Win32::System::Threading::{
    GetProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};
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
