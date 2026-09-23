//! Protected Windows files, path traversal and DACL validation.
//!
//! This module owns the owner-protected credential, payload and service-config
//! readers, the local-path and no-reparse ancestor traversal, the retained
//! ancestor handles, `ProtectedFileAcl` and `validate_protected_acl`.  The
//! owner/DACL requirements, the bounded reads, the distinct packaged
//! service-config policy and the no-reparse traversal are unchanged from the
//! pre-split file.

use super::win32::{
    MAX_ADMIN_PIPE_FRAME, OwnedHandle, current_user_sid, last_error, sid_string, wide_path,
    win32_error,
};
use crate::PlatformError;
use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{GENERIC_READ, LocalFree};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, GetAce, GetAclInformation,
    GetLengthSid, GetSecurityDescriptorControl, IsValidSid, OWNER_SECURITY_INFORMATION,
    SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_NONE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFileInformationByHandle, OPEN_EXISTING, READ_CONTROL, ReadFile,
};
const SYSTEM_SID: &str = "S-1-5-18";
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

// The packaged service account receives `(R)` on the configuration file. The
// mask below is the set of file/security rights that would let that account
// change, delete, or re-permission the config. SYSTEM and Administrators are
// intentionally allowed full control by the deployment boundary.
const SERVICE_CONFIG_WRITE_MASK: u32 = 0x0000_0002 // FILE_WRITE_DATA
    | 0x0000_0004 // FILE_APPEND_DATA
    | 0x0000_0010 // FILE_WRITE_EA
    | 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0000_0100 // FILE_WRITE_ATTRIBUTES
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x0100_0000 // ACCESS_SYSTEM_SECURITY
    | 0x4000_0000 // GENERIC_WRITE
    | 0x1000_0000; // GENERIC_ALL

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

/// Read the owner-local watchdog configuration through a held Windows file
/// handle. Credentials and job payloads continue to use
/// [`read_protected_payload_file`], whose owner-only policy is intentionally
/// stricter. A packaged config is SYSTEM-owned, has a protected DACL, grants
/// SYSTEM/Administrators full control, and grants a virtual service SID read
/// access only. The current-user owner-only ACL remains accepted for local
/// development and synthetic Windows tests.
pub fn read_protected_service_config_file(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, PlatformError> {
    if max_bytes == 0 || max_bytes > MAX_ADMIN_PIPE_FRAME {
        return Err(PlatformError::Invalid(
            "protected configuration bound is outside the platform limit".to_owned(),
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
    let file = OwnedHandle::new(raw_file, "CreateFileW(service configuration)")?;
    validate_service_config_file_handle(&file, "service configuration")?;
    read_protected_file_handle(&file, max_bytes)
}
pub(super) fn validate_local_protected_path(path: &Path) -> Result<(), PlatformError> {
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
pub(super) fn open_protected_ancestors(path: &Path) -> Result<Vec<OwnedHandle>, PlatformError> {
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
pub(super) fn open_worker_image_leaf(path: &Path) -> Result<OwnedHandle, PlatformError> {
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
    validate_protected_file_handle_with_policy(file, label, ProtectedFileAcl::Credential)
}
fn validate_service_config_file_handle(
    file: &OwnedHandle,
    label: &str,
) -> Result<(), PlatformError> {
    let packaged =
        validate_protected_file_handle_with_policy(file, label, ProtectedFileAcl::ServiceConfig);
    if packaged.is_ok() {
        return Ok(());
    }
    // Developer and synthetic Windows tests deliberately use the older
    // owner-only ACL. Keep that narrow policy as a compatibility path; it
    // still requires the current token as owner and every explicit ACE to be
    // an allow entry for that exact SID.
    validate_protected_file_handle_with_policy(file, label, ProtectedFileAcl::Credential)
}
#[derive(Clone, Copy)]
enum ProtectedFileAcl {
    Credential,
    ServiceConfig,
}
fn validate_protected_file_handle_with_policy(
    file: &OwnedHandle,
    label: &str,
    policy: ProtectedFileAcl,
) -> Result<(), PlatformError> {
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
    let result = validate_protected_acl(owner, dacl, descriptor, policy);
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
fn validate_protected_acl(
    owner: *mut c_void,
    dacl: *mut windows_sys::Win32::Security::ACL,
    descriptor: *mut c_void,
    policy: ProtectedFileAcl,
) -> Result<(), PlatformError> {
    if owner.is_null() || unsafe { IsValidSid(owner) } == 0 {
        return Err(PlatformError::Invalid(
            "protected file owner SID is invalid".to_owned(),
        ));
    }
    let owner_sid = sid_string(owner)?;
    let expected_sid = match policy {
        ProtectedFileAcl::Credential => Some(current_user_sid()?),
        ProtectedFileAcl::ServiceConfig => None,
    };
    if let Some(expected_sid) = expected_sid.as_deref() {
        if owner_sid != expected_sid {
            return Err(PlatformError::IdentityMismatch(
                "credential owner is not the service user".to_owned(),
            ));
        }
    } else if owner_sid != SYSTEM_SID {
        return Err(PlatformError::IdentityMismatch(
            "packaged service configuration owner is not SYSTEM".to_owned(),
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
            "protected file DACL has no allow entry".to_owned(),
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
    let mut has_system = false;
    let mut has_administrators = false;
    let mut has_service = false;
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
                "protected file allow ACE SID exceeds its bounded ACE".to_owned(),
            ));
        }
        if unsafe { IsValidSid(sid) } == 0 {
            return Err(PlatformError::IdentityMismatch(
                "protected file DACL grants an invalid SID".to_owned(),
            ));
        }
        let sid = sid_string(sid)?;
        match policy {
            ProtectedFileAcl::Credential => {
                if Some(sid.as_str()) != expected_sid.as_deref() {
                    return Err(PlatformError::IdentityMismatch(
                        "credential DACL grants a different SID".to_owned(),
                    ));
                }
            }
            ProtectedFileAcl::ServiceConfig => {
                let mask =
                    unsafe { std::ptr::read_unaligned(raw_ace.cast::<ACCESS_ALLOWED_ACE>()) }.Mask;
                if sid == SYSTEM_SID {
                    has_system = true;
                    continue;
                }
                if sid == ADMINISTRATORS_SID {
                    has_administrators = true;
                    continue;
                }
                if !is_virtual_service_sid(&sid) {
                    return Err(PlatformError::IdentityMismatch(
                        "packaged service configuration DACL grants an unapproved SID".to_owned(),
                    ));
                }
                has_service = true;
                if mask & SERVICE_CONFIG_WRITE_MASK != 0 {
                    return Err(PlatformError::IdentityMismatch(
                        "packaged service configuration grants service write access".to_owned(),
                    ));
                }
            }
        }
    }
    if matches!(policy, ProtectedFileAcl::ServiceConfig) {
        // Require all three roles. SYSTEM and Administrators are the recovery
        // and operator authorities; a virtual service SID is the sole runtime
        // reader. A DACL containing only broad operator access must not be
        // accepted as an installable service configuration.
        if !has_system || !has_administrators || !has_service {
            return Err(PlatformError::IdentityMismatch(
                "packaged service configuration DACL must include SYSTEM, Administrators, and a virtual service SID".to_owned(),
            ));
        }
    }
    Ok(())
}
fn is_virtual_service_sid(sid: &str) -> bool {
    let Some(suffix) = sid.strip_prefix("S-1-5-80-") else {
        return false;
    };
    let parts = suffix.split('-').collect::<Vec<_>>();
    parts.len() == 5
        && parts
            .into_iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}
