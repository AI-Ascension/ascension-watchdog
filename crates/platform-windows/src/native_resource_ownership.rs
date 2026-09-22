//! Win32 resource ownership and identity primitives.
//!
//! Owns the immediate RAII wrappers (`OwnedHandle`,
//! `ProtectedDirectoryHandle`, `SecurityDescriptor`) that close kernel
//! objects exactly once, the process creation-time/image-path identity
//! reads used to bind a contained process to its executable, and the
//! UTF-16/Win32 error helpers shared by the reviewed native boundary.
//!
//! This module was extracted verbatim from `native.rs`; cleanup ordering,
//! restricted unsafe boundaries, error semantics and visibility are
//! unchanged.  Items that remain shared by sibling native modules are
//! re-exported from `native` at `pub(crate)`/`pub` exactly as before.

use super::{
    CloseHandle, ConvertStringSecurityDescriptorToSecurityDescriptorW, CreateFileW,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILETIME,
    GetCurrentProcess, GetFileInformationByHandle, GetLastError, GetProcessTimes, HANDLE,
    INVALID_HANDLE_VALUE, LocalFree, MAX_IMAGE_PATH, OPEN_EXISTING, PROCESS_NAME_WIN32,
    PSECURITY_DESCRIPTOR, Path, PathBuf, PlatformError, QueryFullProcessImageNameW, c_void, null,
    null_mut,
};
use std::os::windows::ffi::{OsStrExt, OsStringExt};

#[derive(Debug)]
pub(crate) struct OwnedHandle(HANDLE);

/// A retained handle to an owner-local directory. The watchdog storage layer
/// keeps this opaque value alive while its lock file is authoritative.
#[derive(Debug)]
#[allow(dead_code)]
pub struct ProtectedDirectoryHandle(OwnedHandle);

/// Open one exact local directory and validate its identity for the owner
/// lifetime.  Child files still need to be created and atomically renamed
/// beneath this directory during restore/release publication, so the directory
/// handle shares child mutation and delete access.  The authoritative lock file
/// itself remains opened without delete sharing; that handle is what prevents
/// replacement/removal of the owner namespace while this guard is alive.
pub fn open_protected_directory(path: &Path) -> Result<ProtectedDirectoryHandle, PlatformError> {
    let wide_path = wide_path(path)?;
    let raw = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    let handle = OwnedHandle::new(raw, "CreateFileW(owner directory)")?;
    let mut information =
        windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle.raw(), &raw mut information) } == 0 {
        return Err(last_error("GetFileInformationByHandle(owner directory)"));
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(PlatformError::Invalid(
            "owner lock parent must be a directory".to_owned(),
        ));
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PlatformError::IdentityMismatch(
            "owner lock parent must not be a reparse point".to_owned(),
        ));
    }
    Ok(ProtectedDirectoryHandle(handle))
}

impl OwnedHandle {
    pub(crate) fn new(raw: HANDLE, operation: &str) -> Result<Self, PlatformError> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(last_error(operation));
        }
        Ok(Self(raw))
    }

    pub(crate) fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

pub(crate) fn close_raw_handle(handle: HANDLE) {
    if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
        unsafe { CloseHandle(handle) };
    }
}

// A Windows kernel handle is an OS-managed reference that may be used by any
// thread in the owning process.  `OwnedHandle` never exposes a borrowed raw
// handle and closes it exactly once, so transferring the wrapper through the
// service callback is safe.
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

pub(crate) struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    pub(crate) fn from_raw(
        raw: PSECURITY_DESCRIPTOR,
        operation: &str,
    ) -> Result<Self, PlatformError> {
        if raw.is_null() {
            return Err(last_error(operation));
        }
        Ok(Self(raw))
    }

    pub(crate) fn owner_only() -> Result<Self, PlatformError> {
        // `OW` in the protected DACL grants access to the security
        // descriptor owner, but omitting the descriptor owner lets Windows
        // choose the token's default-owner SID. Bind it explicitly to the
        // current token user so reopened named objects retain exact owner
        // authority even when the service token is elevated.
        let owner_sid = crate::admin_pipe::process_user_sid(unsafe { GetCurrentProcess() })?;
        let descriptor = wide(&format!("O:{owner_sid}D:P(A;;GA;;;OW)"))?;
        let mut raw = null_mut();
        let mut size = 0_u32;
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor.as_ptr(),
                1,
                &raw mut raw,
                &raw mut size,
            )
        };
        if ok == 0 || raw.is_null() || size == 0 {
            return Err(last_error(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            ));
        }
        Ok(Self(raw))
    }

    pub(crate) fn raw(&self) -> *mut c_void {
        self.0
    }

    pub(crate) fn raw_security_descriptor(&self) -> PSECURITY_DESCRIPTOR {
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

pub(crate) fn process_creation_time(handle: HANDLE) -> Result<u64, PlatformError> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let ok = unsafe {
        GetProcessTimes(
            handle,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    };
    if ok == 0 {
        return Err(last_error("GetProcessTimes"));
    }
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

pub(crate) fn query_image_path(handle: HANDLE) -> Result<PathBuf, PlatformError> {
    let mut buffer = vec![0_u16; MAX_IMAGE_PATH];
    let mut size = u32::try_from(buffer.len())
        .map_err(|_| PlatformError::Invalid("image path buffer size overflow".to_owned()))?;
    let ok = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            buffer.as_mut_ptr(),
            &raw mut size,
        )
    };
    if ok == 0 {
        return Err(last_error("QueryFullProcessImageNameW"));
    }
    buffer.truncate(
        usize::try_from(size)
            .map_err(|_| PlatformError::Invalid("image path size overflow".to_owned()))?,
    );
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer)))
}

pub(crate) fn wide(value: &str) -> Result<Vec<u16>, PlatformError> {
    if value.contains('\0') {
        return Err(PlatformError::Invalid(
            "Windows string contains NUL".to_owned(),
        ));
    }
    Ok(value.encode_utf16().chain(std::iter::once(0)).collect())
}

pub(crate) fn wide_path(path: &Path) -> Result<Vec<u16>, PlatformError> {
    if path.as_os_str().encode_wide().any(|unit| unit == 0) {
        return Err(PlatformError::Invalid(
            "Windows path contains NUL".to_owned(),
        ));
    }
    Ok(path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect())
}

pub(crate) fn last_error(operation: &str) -> PlatformError {
    PlatformError::Win32 {
        operation: operation.to_owned(),
        code: unsafe { GetLastError() },
    }
}

pub(crate) fn win32_error(operation: &str, code: u32) -> PlatformError {
    PlatformError::Win32 {
        operation: operation.to_owned(),
        code,
    }
}
