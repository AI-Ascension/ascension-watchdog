//! Bounded Win32 pipe transport primitives for the admin endpoint.
//!
//! This module owns the low-level pieces every admin and worker pipe exchange
//! is built from: the unique-ownership handle and security-descriptor
//! wrappers, the bounded-frame, timeout and endpoint-name validators, the
//! polling read/write helpers and their pending-I/O classification, the
//! pipe-local-information query, and the SID, token, process-image and
//! creation-time identity queries.
//!
//! Nothing here decides authorization or protocol framing.  The server and
//! client modules keep applying exactly the checks they applied before the
//! split; this module only supplies the primitives they share.

use crate::PlatformError;
use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::slice;
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_MORE_DATA, ERROR_NO_DATA, ERROR_PIPE_LISTENING,
    ERROR_PIPE_NOT_CONNECTED, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::{GetLengthSid, IsValidSid, TOKEN_QUERY, TOKEN_USER};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::IO::CancelIoEx;
use windows_sys::Win32::System::Pipes::{
    PIPE_NOWAIT, PIPE_READMODE_MESSAGE, SetNamedPipeHandleState,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcessToken, PROCESS_NAME_WIN32,
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
pub(super) struct FilePipeLocalInformation {
    pub(super) named_pipe_type: u32,
    pub(super) named_pipe_configuration: u32,
    pub(super) maximum_instances: u32,
    pub(super) current_instances: u32,
    pub(super) inbound_quota: u32,
    pub(super) read_data_available: u32,
    pub(super) outbound_quota: u32,
    pub(super) write_quota_available: u32,
    pub(super) named_pipe_state: u32,
    pub(super) named_pipe_end: u32,
}

const FILE_PIPE_LOCAL_INFORMATION_CLASS: u32 = 24;
pub(super) const FILE_PIPE_CONNECTED_STATE: u32 = 3;
pub(super) const FILE_PIPE_SERVER_END: u32 = 1;

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
pub(super) const MAX_PIPE_NAME_BYTES: usize = 192;
const MAX_SID_BYTES: usize = 184;
pub(super) const POLL_INTERVAL: Duration = Duration::from_millis(2);
const NONBLOCKING_MESSAGE_MODE: u32 = PIPE_READMODE_MESSAGE | PIPE_NOWAIT;
pub(super) fn set_message_nonblocking(handle: HANDLE) -> Result<(), PlatformError> {
    let mode = NONBLOCKING_MESSAGE_MODE;
    if unsafe { SetNamedPipeHandleState(handle, &raw const mode, null(), null()) } == 0 {
        return Err(last_error("SetNamedPipeHandleState"));
    }
    Ok(())
}

pub(super) fn query_pipe_local_information(
    handle: HANDLE,
) -> Result<FilePipeLocalInformation, PlatformError> {
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

pub(super) fn read_exact_poll(
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

pub(super) fn write_all_poll(
    handle: HANDLE,
    buffer: &[u8],
    deadline: Instant,
) -> Result<(), PlatformError> {
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

pub(super) fn is_pending_pipe_error(code: u32) -> bool {
    code == ERROR_PIPE_LISTENING
}

fn is_pending_io_error(code: u32) -> bool {
    code == ERROR_NO_DATA || code == ERROR_PIPE_LISTENING
}

pub(super) fn deadline(timeout: Duration) -> Instant {
    Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now)
}

pub(super) fn timeout_millis(timeout: Duration) -> Result<u32, PlatformError> {
    validate_timeout(timeout)?;
    let millis = timeout.as_millis();
    u32::try_from(millis)
        .map_err(|_| PlatformError::Invalid("admin timeout does not fit Win32".to_owned()))
}

pub(super) fn validate_pipe_name(name: &str) -> Result<(), PlatformError> {
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

pub(super) fn validate_worker_pipe_name(name: &str) -> Result<(), PlatformError> {
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

pub(super) fn validate_timeout(timeout: Duration) -> Result<(), PlatformError> {
    if timeout.is_zero() || timeout > Duration::from_secs(30) {
        return Err(PlatformError::Invalid(
            "admin timeout must be between 1ms and 30s".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_sid(sid: &str) -> Result<(), PlatformError> {
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

pub(super) fn current_user_sid() -> Result<String, PlatformError> {
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

pub(super) fn sid_string(sid: *mut c_void) -> Result<String, PlatformError> {
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

pub(super) fn query_image_path(process: HANDLE) -> Result<PathBuf, PlatformError> {
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

pub(super) fn process_creation_time(process: HANDLE) -> Result<u64, PlatformError> {
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

pub(super) fn canonicalize_executable(path: &Path) -> Result<PathBuf, PlatformError> {
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

pub(super) fn normalize_path(path: &Path) -> String {
    path.to_string_lossy()
        .trim_start_matches(r"\\?\")
        .replace('/', "\\")
        .to_ascii_lowercase()
}

pub(super) fn wide(value: &str) -> Result<Vec<u16>, PlatformError> {
    if value.contains('\0') {
        return Err(PlatformError::Invalid(
            "Windows name contains NUL".to_owned(),
        ));
    }
    Ok(value.encode_utf16().chain(std::iter::once(0)).collect())
}

pub(super) fn wide_path(path: &Path) -> Result<Vec<u16>, PlatformError> {
    let value = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if value.contains(&0) {
        return Err(PlatformError::Invalid(
            "Windows path contains NUL".to_owned(),
        ));
    }
    Ok(value.into_iter().chain(std::iter::once(0)).collect())
}

pub(super) fn last_error(operation: &str) -> PlatformError {
    win32_error(operation, unsafe { GetLastError() })
}

pub(super) fn win32_error(operation: &str, code: u32) -> PlatformError {
    PlatformError::Win32 {
        operation: operation.to_owned(),
        code,
    }
}

pub(super) struct OwnedHandle(HANDLE);

// A HANDLE is an opaque kernel-owned value.  Each wrapper has unique
// ownership and is moved, never aliased, into exactly one worker thread.
unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    pub(super) fn new(raw: HANDLE, operation: &str) -> Result<Self, PlatformError> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(last_error(operation));
        }
        Ok(Self(raw))
    }

    pub(super) const fn raw(&self) -> HANDLE {
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

pub(super) struct SecurityDescriptor(*mut c_void);

impl SecurityDescriptor {
    pub(super) fn for_sid(allowed_sid: &str) -> Result<Self, PlatformError> {
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

    pub(super) const fn raw(&self) -> *mut c_void {
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
