//! Windows-only implementation.
//!
//! All raw handles are wrapped immediately and all process operations are
//! preceded by creation-time and executable identity checks.  The Job Object
//! is named with the persisted launch nonce and has a protected DACL, so a
//! restarted watchdog can reopen the exact authority rather than searching by
//! process name.  The `PROC_THREAD_ATTRIBUTE_JOB_LIST` attribute is used with
//! `CREATE_SUSPENDED`; the child cannot execute before assignment.

use crate::contract::{
    LifecycleFrame, LifecycleRequest, PlatformError, ProcessIdentity, SessionSelector,
    WindowsLaunchSpec, WindowsPlatformConfig,
};
use crate::native_gateway_health_bootstrap::{
    GATEWAY_HEALTH_BOOTSTRAP_FRAME_BYTES, GatewayHealthBootstrapLaunch,
};
use crate::native_worker_bootstrap::{MAX_WORKER_BOOTSTRAP_FRAME_BYTES, WorkerBootstrapLaunch};
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::mem::{align_of, size_of};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceErrorControl,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND,
    ERROR_INVALID_PARAMETER, ERROR_MORE_DATA, ERROR_NO_DATA, ERROR_NOT_FOUND,
    ERROR_OPERATION_ABORTED, ERROR_PATH_NOT_FOUND, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING,
    ERROR_PIPE_NOT_CONNECTED, ERROR_SERVICE_EXISTS, ERROR_SERVICE_NOT_ACTIVE, ERROR_SUCCESS,
    FILETIME, GENERIC_READ, GetLastError, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    LocalFree, SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{
    EqualSid, GetSecurityDescriptorOwner, GetTokenInformation, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, GetFileInformationByHandle, GetFileSizeEx, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    READ_CONTROL, ReadFile, WriteFile,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, CreatePipe, DisconnectNamedPipe,
    GetNamedPipeClientProcessId, GetNamedPipeClientSessionId, PIPE_NOWAIT, PIPE_READMODE_MESSAGE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, SetNamedPipeHandleState,
};
use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSGetActiveConsoleSessionId, WTSQueryUserToken,
};
use windows_sys::Win32::System::SystemServices::{JOB_OBJECT_QUERY, JOB_OBJECT_TERMINATE};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetProcessId, GetProcessTimes, InitializeProcThreadAttributeList, OpenProcess,
    OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    QueryFullProcessImageNameW, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

#[path = "native_current_process.rs"]
mod native_current_process;
pub use native_current_process::{CurrentControllerIdentity, capture_current_controller};

#[path = "native_launch.rs"]
mod native_launch;
pub use native_launch::{
    ActiveSession, WindowsLaunchError, WindowsProcessLauncher, select_active_session,
};
#[cfg(test)]
pub(crate) use native_launch::{SpawnFailure, wrap_created_process_handles};
pub(crate) use native_launch::{duration_to_millis, validate_stop_timeouts};

#[path = "native_resource_ownership.rs"]
mod native_resource_ownership;
pub(crate) use native_resource_ownership::{
    OwnedHandle, SecurityDescriptor, close_raw_handle, last_error, process_creation_time,
    query_image_path, wide, wide_path, win32_error,
};
pub use native_resource_ownership::{ProtectedDirectoryHandle, open_protected_directory};

#[path = "native_integrity.rs"]
mod native_integrity;
#[cfg(test)]
pub(crate) use native_integrity::Sha256;
pub use native_integrity::executable_sha256;
pub(crate) use native_integrity::{IntegrityGuards, canonicalize_executable, check_image_deadline};

#[path = "native_job.rs"]
mod native_job;
#[cfg(test)]
pub(crate) use native_job::PLANNED_JOB_PREFIX;
pub use native_job::{JobOwnedProcess, StopOutcome};
pub(crate) use native_job::{
    create_job, job_name, open_planned_job, terminate_job_and_wait,
    validate_planned_job_cleanup_timeout,
};
#[path = "native_named_pipe.rs"]
mod native_named_pipe;
pub use native_named_pipe::{NamedPipePeer, NamedPipeServer};

#[path = "native_service.rs"]
mod native_service;
pub use native_service::{
    ScmHealthChecker, ServiceBinding, ServiceInstallPlan, ServiceRuntime, StoppedServiceWitness,
};
#[cfg(test)]
pub(crate) use native_service::{
    canonicalize_service_config_path, service_missing, service_not_active,
    validate_installed_service_config,
};

const MAX_IMAGE_PATH: usize = 32_768;
const PIPE_NAME_PREFIX: &str = r"\\.\pipe\ascension-watchdog-";
const SERVICE_NAME: &str = "ascension-watchdog";

fn process_session(pid: u32) -> Result<u32, PlatformError> {
    let mut session = 0_u32;
    let ok = unsafe { ProcessIdToSessionId(pid, &raw mut session) };
    if ok == 0 {
        return Err(last_error("ProcessIdToSessionId"));
    }
    Ok(session)
}

fn canonicalize_directory(path: &Path) -> Result<PathBuf, PlatformError> {
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| PlatformError::Io(format!("working directory: {error}")))?;
    if !canonical.is_dir() {
        return Err(PlatformError::Invalid(
            "working directory is not a directory".to_owned(),
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

fn validate_nonce(value: &str) -> Result<(), PlatformError> {
    if value.is_empty()
        || value.len() > 96
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(PlatformError::Invalid(
            "launch nonce is outside the named-object bounds".to_owned(),
        ));
    }
    Ok(())
}

fn validate_pipe_name(name: &str) -> Result<(), PlatformError> {
    if !name.starts_with(PIPE_NAME_PREFIX)
        || name.len() > 192
        || name.contains(['\0', '\r', '\n'])
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"\\._-".contains(&byte))
    {
        return Err(PlatformError::Invalid(
            "pipe name is outside the fixed local namespace".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_service::service::ServiceConfig;

    fn create_unverified_job(name: &str, max_processes: u32) -> Result<OwnedHandle, PlatformError> {
        let wide_name = wide(name)?;
        let raw = unsafe { CreateJobObjectW(null(), wide_name.as_ptr()) };
        let job = OwnedHandle::new(raw, "CreateJobObjectW(test fixture)")?;
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            return Err(PlatformError::Unavailable(
                "test Job Object unexpectedly already exists".to_owned(),
            ));
        }
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = max_processes;
        let length =
            u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).map_err(|_| {
                PlatformError::Invalid("test Job Object limit size overflow".to_owned())
            })?;
        if unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast::<c_void>(),
                length,
            )
        } == 0
        {
            return Err(last_error("SetInformationJobObject(test fixture)"));
        }
        Ok(job)
    }

    #[test]
    fn invalid_nonce_and_pipe_namespace_are_rejected() {
        assert!(validate_nonce("../old").is_err());
        assert!(validate_pipe_name(r"\\.\pipe\other").is_err());
    }

    #[test]
    fn service_binding_rejects_a_different_existing_config() -> Result<(), PlatformError> {
        let directory = std::env::temp_dir().join(format!(
            "ascension-service-binding-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        std::fs::create_dir(&directory)
            .map_err(|error| PlatformError::Io(format!("test directory: {error}")))?;
        let expected_config = directory.join("expected.json");
        let other_config = directory.join("other.json");
        std::fs::write(&expected_config, b"expected")
            .map_err(|error| PlatformError::Io(format!("expected config: {error}")))?;
        std::fs::write(&other_config, b"other")
            .map_err(|error| PlatformError::Io(format!("other config: {error}")))?;
        let executable = canonicalize_executable(
            &std::env::current_exe()
                .map_err(|error| PlatformError::Io(format!("test executable: {error}")))?,
        )?;
        let command_line = crate::service_command::render_service_command_line(
            executable.to_string_lossy().as_ref(),
            other_config.to_string_lossy().as_ref(),
        );
        let service_config = ServiceConfig {
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: PathBuf::from(command_line),
            load_order_group: None,
            tag_id: 0,
            dependencies: Vec::new(),
            account_name: None,
            display_name: "test".into(),
        };
        let expected_canonical = canonicalize_service_config_path(&expected_config)?;
        let result =
            validate_installed_service_config(&service_config, &executable, &expected_canonical);
        assert!(matches!(result, Err(PlatformError::IdentityMismatch(_))));
        let mut service_config = service_config;
        service_config.executable_path = crate::service_command::render_service_command_line(
            executable.to_string_lossy().as_ref(),
            expected_canonical.to_string_lossy().as_ref(),
        )
        .into();
        for start_type in [ServiceStartType::OnDemand, ServiceStartType::Disabled] {
            service_config.start_type = start_type;
            assert!(
                validate_installed_service_config(
                    &service_config,
                    &executable,
                    &expected_canonical,
                )
                .is_ok()
            );
        }
        let _ = std::fs::remove_dir_all(directory);
        Ok(())
    }

    #[test]
    fn missing_service_is_an_idempotent_probe_result() {
        let error = windows_service::Error::Winapi(std::io::Error::from_raw_os_error(
            windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST.cast_signed(),
        ));
        assert!(service_missing(&error));
        assert!(!service_not_active(&error));
    }

    #[test]
    fn immutable_hash_matches_sha256_reference_vectors() {
        let mut digest = Sha256::new();
        digest.update(b"abc");
        assert_eq!(
            digest.hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        let mut digest = Sha256::new();
        digest.update(vec![b'a'; 1_000_000].as_slice());
        assert_eq!(
            digest.hex(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn executable_barrier_can_reopen_a_read_shared_guard() -> Result<(), PlatformError> {
        let executable = std::env::current_exe()
            .map_err(|error| PlatformError::Io(format!("current test executable: {error}")))?;
        let guard = IntegrityGuards::open(&executable)?;
        guard.verify_path_barrier()
    }

    #[test]
    fn created_handle_wrap_failure_is_typed_as_post_creation() {
        let result = wrap_created_process_handles(
            windows_sys::Win32::System::Threading::PROCESS_INFORMATION::default(),
        );
        assert!(matches!(result, Err(SpawnFailure::Created(_))));
    }

    #[test]
    fn replay_policy_cannot_reset_after_disconnect_without_a_new_epoch() -> Result<(), PlatformError>
    {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let name = format!(
            r"\\.\pipe\ascension-watchdog-replay-policy-{}-{nonce}",
            std::process::id()
        );
        let mut server = NamedPipeServer::create(name)?;
        server.configure_replay_policy(7, "epoch-seven")?;
        server.last_sequence = 4;
        server.reset_listener()?;

        assert!(server.configure_replay_policy(7, "epoch-seven").is_err());
        assert!(server.configure_replay_policy(6, "older").is_err());
        server.configure_replay_policy(8, "epoch-eight")?;
        assert_eq!(server.last_sequence, 0);
        Ok(())
    }

    #[test]
    fn planned_job_recovery_rejects_an_unrelated_job_limit() -> Result<(), PlatformError> {
        let executable = std::env::current_exe()
            .map_err(|error| PlatformError::Io(format!("current test executable: {error}")))?;
        let nonce = format!(
            "planned-limits-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        );
        let name = job_name(&nonce)?;
        // This fixture is deliberately not created by the owner-verified
        // production helper: recovery must reject a same-name object whose
        // owner or configured process limit is not the current authority.
        let job = create_unverified_job(&name, 7)?;
        let mut allowlisted_executables = BTreeMap::new();
        allowlisted_executables.insert(
            crate::contract::ComponentKind::Synthetic,
            executable.clone(),
        );
        let mut approved_executable_sha256 = BTreeMap::new();
        approved_executable_sha256.insert(
            crate::contract::ComponentKind::Synthetic,
            executable_sha256(&executable)?,
        );
        let launcher = WindowsProcessLauncher::new(WindowsPlatformConfig {
            service_name: SERVICE_NAME.to_owned(),
            pipe_name: format!(r"\\.\pipe\ascension-watchdog-test-{nonce}"),
            allowlisted_executables,
            approved_executable_sha256,
            authorized_peer_executable: executable,
            max_arguments: 8,
            max_environment: 8,
            max_processes: 8,
        })?;
        let planned = format!("{PLANNED_JOB_PREFIX}{nonce}");
        assert!(matches!(
            launcher.force_cleanup_planned_containment(&planned, Duration::from_secs(1)),
            Err(PlatformError::IdentityMismatch(_))
        ));
        drop(job);
        assert_eq!(
            launcher.force_cleanup_planned_containment(&planned, Duration::from_secs(1))?,
            StopOutcome::AlreadyExited
        );
        Ok(())
    }

    #[test]
    fn planned_job_recovery_does_not_open_unrelated_allowlist_entries() -> Result<(), PlatformError>
    {
        let executable = std::env::current_exe()
            .map_err(|error| PlatformError::Io(format!("current test executable: {error}")))?;
        let nonce = format!(
            "planned-missing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        );
        let missing = std::env::temp_dir().join(format!("ascension-watchdog-missing-{nonce}.exe"));
        assert!(!missing.exists(), "test fixture path unexpectedly exists");
        let mut allowlisted_executables = BTreeMap::new();
        allowlisted_executables.insert(
            crate::contract::ComponentKind::Synthetic,
            executable.clone(),
        );
        allowlisted_executables.insert(crate::contract::ComponentKind::Gateway, missing);
        let mut approved_executable_sha256 = BTreeMap::new();
        approved_executable_sha256.insert(
            crate::contract::ComponentKind::Synthetic,
            executable_sha256(&executable)?,
        );
        approved_executable_sha256.insert(crate::contract::ComponentKind::Gateway, "0".repeat(64));
        let launcher = WindowsProcessLauncher::new(WindowsPlatformConfig {
            service_name: SERVICE_NAME.to_owned(),
            pipe_name: format!(r"\\.\pipe\ascension-watchdog-test-{nonce}"),
            allowlisted_executables,
            approved_executable_sha256,
            authorized_peer_executable: executable,
            max_arguments: 8,
            max_environment: 8,
            max_processes: 8,
        })?;

        // No named object exists for this fresh nonce. The exact planned-job
        // recovery path must be independently idempotent; an unrelated
        // missing executable must not be opened or block that conclusion.
        assert_eq!(
            launcher.force_cleanup_planned_containment(
                &format!("{PLANNED_JOB_PREFIX}{nonce}"),
                Duration::from_secs(1),
            )?,
            StopOutcome::AlreadyExited
        );
        Ok(())
    }
}
