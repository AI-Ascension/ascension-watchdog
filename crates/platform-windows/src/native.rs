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
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::mem::{align_of, size_of};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU32, Ordering};
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
    FILETIME, GENERIC_READ, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{
    EqualSid, GetSecurityDescriptorOwner, GetTokenInformation, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_FIRST_PIPE_INSTANCE,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, GetFileInformationByHandle,
    GetFileSizeEx, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, READ_CONTROL, ReadFile, WriteFile,
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
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeClientSessionId, PIPE_NOWAIT, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_MESSAGE,
};
use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSGetActiveConsoleSessionId, WTSQueryUserToken,
};
use windows_sys::Win32::System::SystemServices::{JOB_OBJECT_QUERY, JOB_OBJECT_TERMINATE};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetProcessId, GetProcessTimes, InitializeProcThreadAttributeList, OpenProcess,
    OpenProcessToken, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, QueryFullProcessImageNameW,
    ResumeThread, STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
};

const MAX_PIPE_FRAME: usize = 8 * 1024;
const MAX_IMAGE_PATH: usize = 32_768;
const JOB_NAME_PREFIX: &str = r"Local\ascension-watchdog-";
const PIPE_NAME_PREFIX: &str = r"\\.\pipe\ascension-watchdog-";
const SERVICE_NAME: &str = "ascension-watchdog";
const SERVICE_CONFIG_ARGUMENT: &str = "--config";
const SERVICE_SWITCH_ARGUMENT: &str = "--service";
const DEFAULT_SERVICE_CONFIG: &str = r"C:\ProgramData\Ascension\Watchdog\watchdog.json";
const HEALTH_STALE_AFTER: Duration = Duration::from_secs(90);
const SERVICE_READY_TIMEOUT: Duration = Duration::from_mins(2);
const SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(30);
const PLANNED_JOB_PREFIX: &str = "windows-job:";
const MAX_PLANNED_JOB_CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;
const HASH_READ_BYTES: usize = 64 * 1024;
const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

type ReconcileCallback =
    dyn Fn(Arc<Mutex<bool>>) -> Result<(), PlatformError> + Send + Sync + 'static;
type ReadinessCallback = dyn Fn() -> Result<(), PlatformError> + Send + Sync + 'static;

static SERVICE_RECONCILE: OnceLock<Arc<ReconcileCallback>> = OnceLock::new();
static SERVICE_READINESS: OnceLock<Arc<ReadinessCallback>> = OnceLock::new();

/// A process launched in an ACL-protected named Job Object.
pub struct JobOwnedProcess {
    identity: ProcessIdentity,
    process: OwnedHandle,
    job: OwnedHandle,
    integrity: Arc<IntegrityGuards>,
    graceful_timeout: Duration,
    force_timeout: Duration,
}

/// Classification for failures after Windows has created a child in the
/// exact named Job Object.  The caller must retain the durable launch intent
/// when the Job cannot be proven empty before returning the error.
#[derive(Debug)]
pub enum WindowsLaunchError {
    /// No child was created, or the exact Job was proven empty after cleanup.
    Ordinary(PlatformError),
    /// A child may still be owned by the exact Job and cleanup was not proven.
    CleanupUncertain(PlatformError),
}

impl std::fmt::Display for WindowsLaunchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ordinary(error) => write!(formatter, "Windows launch failed: {error}"),
            Self::CleanupUncertain(error) => {
                write!(formatter, "Windows launch cleanup is uncertain: {error}")
            }
        }
    }
}

impl std::error::Error for WindowsLaunchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ordinary(error) | Self::CleanupUncertain(error) => Some(error),
        }
    }
}

impl From<PlatformError> for WindowsLaunchError {
    fn from(error: PlatformError) -> Self {
        Self::Ordinary(error)
    }
}

/// Handles held for the complete owner lifetime so the approved executable
/// file object and its release directory cannot be replaced underneath a
/// running process.  The directory handle protects the directory object from
/// removal or rename; it does not hash or pin dependent DLL contents.
#[derive(Debug)]
struct IntegrityGuards {
    // These handles are retained for their no-share lifetime; the fields are
    // intentionally not otherwise read after the initial hash.
    #[allow(dead_code)]
    executable: OwnedHandle,
    #[allow(dead_code)]
    release_directory: OwnedHandle,
    path: PathBuf,
    digest: String,
    file_identity: FileIdentity,
}

/// Kernel file identity captured from the same handle that is hashed.  A
/// canonical path is only a lookup; this tuple proves that the path still
/// resolves to the protected file object before a suspended child is resumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    volume_serial: u32,
    file_index: u64,
    size: u64,
}

impl IntegrityGuards {
    fn open(path: &Path) -> Result<Self, PlatformError> {
        let parent = path.parent().ok_or_else(|| {
            PlatformError::Invalid("approved executable has no release directory".to_owned())
        })?;
        let release_directory = open_immutable_path(
            parent,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_FLAG_BACKUP_SEMANTICS,
            "CreateFileW(release directory)",
        )?;
        let executable = open_immutable_path(
            path,
            GENERIC_READ,
            FILE_ATTRIBUTE_NORMAL,
            "CreateFileW(executable)",
        )?;
        let protected_identity = file_identity(&executable)?;
        let digest = hash_immutable_file(&executable)?;
        if file_identity(&executable)? != protected_identity {
            return Err(PlatformError::IdentityMismatch(
                "approved executable changed while its protected handle was opened".to_owned(),
            ));
        }
        Ok(Self {
            executable,
            release_directory,
            path: path.to_owned(),
            digest,
            file_identity: protected_identity,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn digest(&self) -> &str {
        &self.digest
    }

    /// Reopen the exact launch path under the same no-share policy and verify
    /// both kernel file identity and bytes.  This check is intentionally made
    /// while the child is still suspended; a path-only comparison is not a
    /// sufficient process-creation barrier.
    fn verify_path_barrier(&self) -> Result<(), PlatformError> {
        let candidate = open_immutable_path(
            self.path(),
            GENERIC_READ,
            FILE_ATTRIBUTE_NORMAL,
            "CreateFileW(approved executable barrier)",
        )?;
        if file_identity(&candidate)? != self.file_identity {
            return Err(PlatformError::IdentityMismatch(
                "launch path resolves to a different executable file object".to_owned(),
            ));
        }
        if hash_immutable_file(&candidate)? != self.digest {
            return Err(PlatformError::IdentityMismatch(
                "launch path executable bytes differ from the protected release".to_owned(),
            ));
        }
        Ok(())
    }
}

impl std::fmt::Debug for JobOwnedProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JobOwnedProcess")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl JobOwnedProcess {
    /// Return the immutable creation identity.
    #[must_use]
    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    /// Check the exact process handle and creation token without a PID search.
    pub fn is_running(&self) -> Result<bool, PlatformError> {
        self.verify_identity()?;
        let result = unsafe { WaitForSingleObject(self.process.raw(), 0) };
        match result {
            WAIT_TIMEOUT => Ok(true),
            WAIT_OBJECT_0 => Ok(false),
            code => Err(PlatformError::Win32 {
                operation: "WaitForSingleObject".to_owned(),
                code,
            }),
        }
    }

    /// Check whether a PID currently belongs to this exact Job Object.
    ///
    /// This is an observation helper for descendant tests and diagnostics;
    /// callers must not use a PID alone as a termination authority.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::Win32`] when the process cannot be opened or
    /// the Job Object membership query fails.
    pub fn is_member_running(&self, pid: u32) -> Result<bool, PlatformError> {
        if pid == 0 {
            return Err(PlatformError::Invalid(
                "Job Object member PID must be non-zero".to_owned(),
            ));
        }
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        };
        if process.is_null() {
            if unsafe { GetLastError() } == ERROR_INVALID_PARAMETER {
                return Ok(false);
            }
            return Err(last_error("OpenProcess(Job Object member)"));
        }
        let process = OwnedHandle::new(process, "OpenProcess(Job Object member)")?;
        let mut member = 0;
        let ok = unsafe { IsProcessInJob(process.raw(), self.job.raw(), &raw mut member) };
        if ok == 0 {
            return Err(last_error("IsProcessInJob"));
        }
        Ok(member != 0)
    }

    /// Request graceful shutdown only when the component protocol is owned by
    /// the caller.  Generic Windows processes have no safe portable TERM
    /// equivalent, so this boundary refuses to fake graceful completion.
    pub fn graceful_stop(&self) -> Result<StopOutcome, PlatformError> {
        self.verify_identity()?;
        if self.active_processes()? == 0 {
            return Ok(StopOutcome::AlreadyExited);
        }
        Err(PlatformError::Unsupported(format!(
            "generic Windows graceful stop requires the component lifecycle protocol before the {} ms deadline",
            self.graceful_timeout.as_millis()
        )))
    }

    /// Terminate the verified Job Object and wait for all owned descendants.
    pub fn force_stop(&self) -> Result<StopOutcome, PlatformError> {
        self.verify_identity()?;
        terminate_job_and_wait(&self.job, self.force_timeout)
    }

    /// Reopen a named job after watchdog restart and verify its recorded
    /// leader.  This method never enumerates by process name.
    pub fn reopen(
        identity: ProcessIdentity,
        max_processes: u32,
        graceful_timeout: Duration,
        force_timeout: Duration,
    ) -> Result<Self, PlatformError> {
        identity.validate()?;
        validate_nonce(&identity.launch_nonce)?;
        validate_stop_timeouts(graceful_timeout, force_timeout)?;
        if max_processes == 0 || max_processes > 128 {
            return Err(PlatformError::Invalid(
                "Job Object process limit is outside bounds".to_owned(),
            ));
        }
        let name = job_name(&identity.launch_nonce)?;
        let wide_name = wide(&name)?;
        let job = unsafe {
            windows_sys::Win32::System::JobObjects::OpenJobObjectW(
                JOB_OBJECT_QUERY | JOB_OBJECT_TERMINATE | READ_CONTROL,
                0,
                wide_name.as_ptr(),
            )
        };
        let job = OwnedHandle::new(job, "OpenJobObjectW")?;
        verify_job_owner(&job)?;
        verify_job_limits(&job, max_processes)?;
        let executable = canonicalize_executable(&identity.executable)?;
        if normalize_path(&executable) != normalize_path(&identity.executable) {
            return Err(PlatformError::IdentityMismatch(
                "persisted executable path no longer resolves to the same release".to_owned(),
            ));
        }
        let integrity = Arc::new(IntegrityGuards::open(&executable)?);
        if integrity.digest() != identity.executable_sha256 {
            return Err(PlatformError::IdentityMismatch(
                "persisted executable digest differs from the immutable release handle".to_owned(),
            ));
        }
        integrity.verify_path_barrier()?;
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                identity.pid,
            )
        };
        let process = OwnedHandle::new(process, "OpenProcess")?;
        let owner = Self {
            identity,
            process,
            job,
            integrity,
            graceful_timeout,
            force_timeout,
        };
        owner.verify_identity()?;
        if owner.is_running()? {
            if process_session(owner.identity.pid)? != owner.identity.session_id {
                return Err(PlatformError::IdentityMismatch(
                    "reopened process session differs from persisted session".to_owned(),
                ));
            }
            if !owner.is_member_running(owner.identity.pid)? {
                return Err(PlatformError::IdentityMismatch(
                    "reopened process is not a member of its named Job Object".to_owned(),
                ));
            }
        }
        Ok(owner)
    }

    fn verify_identity(&self) -> Result<(), PlatformError> {
        let pid = unsafe { GetProcessId(self.process.raw()) };
        if pid == 0 || pid != self.identity.pid {
            return Err(PlatformError::IdentityMismatch(
                "process handle PID differs from recorded identity".to_owned(),
            ));
        }
        let creation = process_creation_time(self.process.raw())?;
        if creation != self.identity.creation_time_100ns {
            return Err(PlatformError::IdentityMismatch(
                "process creation time differs from recorded identity".to_owned(),
            ));
        }
        let executable = query_image_path(self.process.raw())?;
        if normalize_path(&executable) != normalize_path(&self.identity.executable) {
            return Err(PlatformError::IdentityMismatch(
                "process executable differs from recorded identity".to_owned(),
            ));
        }
        if self.identity.executable_sha256 != self.integrity.digest() {
            return Err(PlatformError::IdentityMismatch(
                "recorded executable digest differs from the immutable release handle".to_owned(),
            ));
        }
        let process_state = unsafe { WaitForSingleObject(self.process.raw(), 0) };
        if process_state == WAIT_TIMEOUT {
            if process_session(pid)? != self.identity.session_id {
                return Err(PlatformError::IdentityMismatch(
                    "process session differs from recorded identity".to_owned(),
                ));
            }
            let mut member = 0;
            let ok = unsafe { IsProcessInJob(self.process.raw(), self.job.raw(), &raw mut member) };
            if ok == 0 {
                return Err(last_error("IsProcessInJob(identity)"));
            }
            if member == 0 {
                return Err(PlatformError::IdentityMismatch(
                    "process is not a member of its named Job Object".to_owned(),
                ));
            }
        } else if process_state != WAIT_OBJECT_0 {
            return Err(PlatformError::Win32 {
                operation: "WaitForSingleObject(identity)".to_owned(),
                code: process_state,
            });
        }
        Ok(())
    }

    fn active_processes(&self) -> Result<u32, PlatformError> {
        active_processes(&self.job)
    }
}

/// Result of an exact Job Object termination request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopOutcome {
    Exited,
    AlreadyExited,
    TimedOut,
}

/// Launcher for fixed, role-allowlisted executables.
#[derive(Debug)]
pub struct WindowsProcessLauncher {
    config: WindowsPlatformConfig,
}

impl WindowsProcessLauncher {
    /// Validate configuration before any SCM, token, or process call.
    pub fn new(config: WindowsPlatformConfig) -> Result<Self, PlatformError> {
        config.validate()?;
        // Integrity guards are opened at launch time for the selected role.
        // Recovery of a prepared named Job has no executable identity yet and
        // must remain available when an unrelated configured role is absent.
        Ok(Self { config })
    }

    /// Reopen and terminate one exact planned Job Object without a process
    /// identity.  This is the recovery authority for a durable launch intent
    /// that was persisted before a child identity was returned.  The caller
    /// must supply the persisted `windows-job:<launch_nonce>` containment; the
    /// native boundary validates that closed namespace, derives only its
    /// nonce-based local name, and never searches by PID or process name.
    ///
    /// An absent exact object is conclusive only when `OpenJobObjectW` reports
    /// `ERROR_FILE_NOT_FOUND` or `ERROR_PATH_NOT_FOUND`.  Other open failures
    /// remain errors, because they do not prove that the authority is gone.
    pub fn force_cleanup_planned_containment(
        &self,
        planned_containment: &str,
        force_timeout: Duration,
    ) -> Result<StopOutcome, PlatformError> {
        self.config.validate()?;
        validate_planned_job_cleanup_timeout(force_timeout)?;
        let Some(job) = open_planned_job(planned_containment, self.config.max_processes)? else {
            return Ok(StopOutcome::AlreadyExited);
        };
        terminate_job_and_wait(&job, force_timeout)
    }

    /// Launch a direct executable with Job Object assignment before resume.
    #[allow(clippy::too_many_lines)]
    pub fn launch(
        &self,
        specification: &WindowsLaunchSpec,
    ) -> Result<JobOwnedProcess, WindowsLaunchError> {
        specification
            .validate(&self.config)
            .map_err(WindowsLaunchError::Ordinary)?;
        validate_nonce(&specification.launch_nonce).map_err(WindowsLaunchError::Ordinary)?;
        let approved = self
            .config
            .allowlisted_executables
            .get(&specification.component)
            .ok_or_else(|| PlatformError::Unsupported("component is not allowlisted".to_owned()))
            .map_err(WindowsLaunchError::Ordinary)?;
        let approved_digest = self
            .config
            .approved_executable_sha256
            .get(&specification.component)
            .ok_or_else(|| {
                PlatformError::Unsupported("component has no approved executable digest".to_owned())
            })
            .map_err(WindowsLaunchError::Ordinary)?;
        let executable = canonicalize_executable(&specification.executable)
            .map_err(WindowsLaunchError::Ordinary)?;
        let approved = canonicalize_executable(approved).map_err(WindowsLaunchError::Ordinary)?;
        if normalize_path(&executable) != normalize_path(&approved) {
            return Err(WindowsLaunchError::Ordinary(
                PlatformError::IdentityMismatch(
                    "requested executable is outside the role allowlist".to_owned(),
                ),
            ));
        }
        let integrity =
            Arc::new(IntegrityGuards::open(&executable).map_err(WindowsLaunchError::Ordinary)?);
        if integrity.digest() != approved_digest {
            return Err(WindowsLaunchError::Ordinary(
                PlatformError::IdentityMismatch(
                    "approved executable bytes differ from the configured release digest"
                        .to_owned(),
                ),
            ));
        }
        if normalize_path(integrity.path()) != normalize_path(&executable) {
            return Err(WindowsLaunchError::Ordinary(
                PlatformError::IdentityMismatch(
                    "integrity guard path differs from requested executable".to_owned(),
                ),
            ));
        }
        integrity
            .verify_path_barrier()
            .map_err(WindowsLaunchError::Ordinary)?;
        let session_id = match specification.session {
            SessionSelector::ActiveUser => match select_active_session() {
                ActiveSession::Available(session) => session,
                ActiveSession::WaitingForSession => {
                    return Err(WindowsLaunchError::Ordinary(PlatformError::Unavailable(
                        "WAITING_FOR_SESSION: no active interactive user session".to_owned(),
                    )));
                }
            },
            SessionSelector::CurrentService | SessionSelector::Explicit(0) => {
                current_process_session().map_err(WindowsLaunchError::Ordinary)?
            }
            SessionSelector::Explicit(session) => session,
        };
        let job_name =
            job_name(&specification.launch_nonce).map_err(WindowsLaunchError::Ordinary)?;
        let job = create_job(&job_name, self.config.max_processes)
            .map_err(WindowsLaunchError::Ordinary)?;
        // A service normally runs in session 0.  Use the current token only
        // when the selected session is the caller's session (which keeps
        // unprivileged synthetic tests useful); otherwise obtain the target
        // interactive user's token through WTS.  HostBroker always follows
        // the same explicit session policy.
        let caller_session = current_process_session().map_err(WindowsLaunchError::Ordinary)?;
        let token = if caller_session == session_id {
            None
        } else {
            Some(query_user_token(session_id).map_err(WindowsLaunchError::Ordinary)?)
        };
        let process = spawn_suspended_with_job(
            token.as_ref().map(OwnedHandle::raw),
            &job,
            &executable,
            specification,
        );
        let process = match process {
            Ok(process) => process,
            Err(SpawnFailure::BeforeCreate(error)) => {
                return Err(WindowsLaunchError::Ordinary(error));
            }
            Err(SpawnFailure::Created(error)) => {
                return Err(classify_spawn_cleanup(
                    &job,
                    launch_force_timeout(specification),
                    error,
                ));
            }
        };
        let (process_handle, thread_handle, pid) = process;
        if let Err(error) = integrity.verify_path_barrier() {
            return Err(classify_spawn_cleanup(
                &job,
                launch_force_timeout(specification),
                error,
            ));
        }
        let resumed = unsafe { ResumeThread(thread_handle.raw()) };
        if resumed == u32::MAX {
            return Err(classify_spawn_cleanup(
                &job,
                launch_force_timeout(specification),
                last_error("ResumeThread"),
            ));
        }
        let creation_time = match process_creation_time(process_handle.raw()) {
            Ok(value) => value,
            Err(error) => {
                return Err(classify_spawn_cleanup(
                    &job,
                    launch_force_timeout(specification),
                    error,
                ));
            }
        };
        let force_timeout = launch_force_timeout(specification);
        let identity = ProcessIdentity {
            pid,
            creation_time_100ns: creation_time,
            launch_nonce: specification.launch_nonce.clone(),
            executable,
            executable_sha256: integrity.digest().to_owned(),
            session_id,
        };
        let owner = JobOwnedProcess {
            identity,
            process: process_handle,
            job,
            integrity: Arc::clone(&integrity),
            graceful_timeout: Duration::from_millis(u64::from(specification.graceful_timeout_ms)),
            force_timeout: Duration::from_millis(u64::from(specification.force_timeout_ms)),
        };
        if let Err(error) = owner.verify_identity() {
            return Err(classify_spawn_cleanup(&owner.job, force_timeout, error));
        }
        let observed_session = match process_session(pid) {
            Ok(value) => value,
            Err(error) => {
                return Err(classify_spawn_cleanup(&owner.job, force_timeout, error));
            }
        };
        if observed_session != session_id {
            return Err(classify_spawn_cleanup(
                &owner.job,
                force_timeout,
                PlatformError::IdentityMismatch(
                    "spawned process session differs from the selected session".to_owned(),
                ),
            ));
        }
        let member = match owner.is_member_running(pid) {
            Ok(value) => value,
            Err(error) => {
                return Err(classify_spawn_cleanup(&owner.job, force_timeout, error));
            }
        };
        if !member {
            return Err(classify_spawn_cleanup(
                &owner.job,
                force_timeout,
                PlatformError::IdentityMismatch(
                    "spawned process is not a member of its Job Object".to_owned(),
                ),
            ));
        }
        Ok(owner)
    }
}

fn launch_force_timeout(specification: &WindowsLaunchSpec) -> Duration {
    Duration::from_millis(u64::from(specification.force_timeout_ms))
}

/// Keep the exact Job handle authoritative while translating a post-spawn
/// failure.  A failed terminate request or an unproved wait is explicitly
/// uncertain; callers must retain the durable launch intent for reconciliation.
fn classify_spawn_cleanup(
    job: &OwnedHandle,
    force_timeout: Duration,
    launch_error: PlatformError,
) -> WindowsLaunchError {
    match terminate_job_and_wait(job, force_timeout) {
        Ok(StopOutcome::Exited | StopOutcome::AlreadyExited) => {
            WindowsLaunchError::Ordinary(launch_error)
        }
        Ok(StopOutcome::TimedOut) => {
            WindowsLaunchError::CleanupUncertain(PlatformError::Timeout(format!(
                "post-spawn launch validation failed ({launch_error}); exact Job cleanup timed out"
            )))
        }
        Err(cleanup_error) => {
            WindowsLaunchError::CleanupUncertain(PlatformError::Unavailable(format!(
                "post-spawn launch validation failed ({launch_error}); exact Job cleanup failed: {cleanup_error}"
            )))
        }
    }
}

/// A process creation call can succeed before one of its returned native
/// handles can be wrapped.  Keep that distinction typed so the caller cannot
/// accidentally report a created child as an ordinary pre-spawn rejection.
#[derive(Debug)]
enum SpawnFailure {
    BeforeCreate(PlatformError),
    Created(PlatformError),
}

impl From<PlatformError> for SpawnFailure {
    fn from(error: PlatformError) -> Self {
        Self::BeforeCreate(error)
    }
}

fn create_job(name: &str, max_processes: u32) -> Result<OwnedHandle, PlatformError> {
    let security = SecurityDescriptor::owner_only()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| PlatformError::Invalid("SECURITY_ATTRIBUTES size overflow".to_owned()))?,
        lpSecurityDescriptor: security.raw(),
        bInheritHandle: 0,
    };
    let wide_name = wide(name)?;
    let raw = unsafe { CreateJobObjectW(&raw const attributes, wide_name.as_ptr()) };
    let job = OwnedHandle::new(raw, "CreateJobObjectW")?;
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        return Err(PlatformError::Unavailable(
            "named Job Object already exists; refusing to attach to an old launch".to_owned(),
        ));
    }
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.BasicLimitInformation.ActiveProcessLimit = max_processes;
    let ok = unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast::<c_void>(),
            u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                .map_err(|_| PlatformError::Invalid("Job Object limit size overflow".to_owned()))?,
        )
    };
    if ok == 0 {
        return Err(last_error("SetInformationJobObject"));
    }
    verify_job_owner(&job)?;
    verify_job_limits(&job, max_processes)?;
    Ok(job)
}

fn query_job_limits(
    job: &OwnedHandle,
) -> Result<JOBOBJECT_EXTENDED_LIMIT_INFORMATION, PlatformError> {
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    let mut returned = 0_u32;
    let length = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
        .map_err(|_| PlatformError::Invalid("Job Object limit size overflow".to_owned()))?;
    let ok = unsafe {
        QueryInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&raw mut limits).cast(),
            length,
            &raw mut returned,
        )
    };
    if ok == 0 {
        return Err(last_error("QueryInformationJobObject(limits)"));
    }
    if returned < length {
        return Err(PlatformError::Unavailable(
            "Job Object returned a truncated limit descriptor".to_owned(),
        ));
    }
    Ok(limits)
}

fn verify_job_limits(job: &OwnedHandle, max_processes: u32) -> Result<(), PlatformError> {
    let limits = query_job_limits(job)?;
    let flags = limits.BasicLimitInformation.LimitFlags;
    let required = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if flags & required != required {
        return Err(PlatformError::IdentityMismatch(
            "Job Object lacks the required active-process and kill-on-close limits".to_owned(),
        ));
    }
    if flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) != 0 {
        return Err(PlatformError::IdentityMismatch(
            "Job Object permits descendants to break away".to_owned(),
        ));
    }
    if limits.BasicLimitInformation.ActiveProcessLimit != max_processes {
        return Err(PlatformError::IdentityMismatch(
            "Job Object active-process limit differs from the persisted configuration".to_owned(),
        ));
    }
    Ok(())
}

fn open_planned_job(
    planned_containment: &str,
    max_processes: u32,
) -> Result<Option<OwnedHandle>, PlatformError> {
    if max_processes == 0 || max_processes > 128 {
        return Err(PlatformError::Invalid(
            "planned Job Object process limit is outside bounds".to_owned(),
        ));
    }
    let nonce = planned_job_nonce(planned_containment)?;
    let name = job_name(nonce)?;
    let wide_name = wide(&name)?;
    let raw = unsafe {
        windows_sys::Win32::System::JobObjects::OpenJobObjectW(
            JOB_OBJECT_QUERY | JOB_OBJECT_TERMINATE | READ_CONTROL,
            0,
            wide_name.as_ptr(),
        )
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        let code = unsafe { GetLastError() };
        if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND {
            return Ok(None);
        }
        return Err(win32_error("OpenJobObjectW(planned containment)", code));
    }
    let job = OwnedHandle::new(raw, "OpenJobObjectW(planned containment)")?;
    // The name is necessary but not sufficient authority.  Reopened jobs
    // must still be owned by this service identity and carry the configured
    // containment limit; an unrelated same-user object is rejected before
    // any termination request is attempted.
    verify_job_owner(&job)?;
    verify_job_limits(&job, max_processes)?;
    Ok(Some(job))
}

fn terminate_job_and_wait(
    job: &OwnedHandle,
    force_timeout: Duration,
) -> Result<StopOutcome, PlatformError> {
    let active = active_processes(job)?;
    if active == 0 {
        return Ok(StopOutcome::AlreadyExited);
    }
    let terminated = unsafe { TerminateJobObject(job.raw(), 1) };
    if terminated == 0 {
        return Err(last_error("TerminateJobObject"));
    }
    if wait_for_job_empty(job, force_timeout)? {
        Ok(StopOutcome::Exited)
    } else {
        Ok(StopOutcome::TimedOut)
    }
}

fn active_processes(job: &OwnedHandle) -> Result<u32, PlatformError> {
    let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    let mut returned = 0_u32;
    let ok = unsafe {
        QueryInformationJobObject(
            job.raw(),
            JobObjectBasicAccountingInformation,
            (&raw mut accounting).cast(),
            u32::try_from(size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>()).map_err(|_| {
                PlatformError::Invalid("Job Object accounting size overflow".to_owned())
            })?,
            &raw mut returned,
        )
    };
    if ok == 0 {
        return Err(last_error("QueryInformationJobObject"));
    }
    Ok(accounting.ActiveProcesses)
}

fn wait_for_job_empty(job: &OwnedHandle, timeout: Duration) -> Result<bool, PlatformError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    loop {
        if active_processes(job)? == 0 {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(
            Duration::from_millis(25).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

fn verify_job_owner(job: &OwnedHandle) -> Result<(), PlatformError> {
    let mut owner_sid: PSID = null_mut();
    let mut group_sid: PSID = null_mut();
    let mut dacl = null_mut();
    let mut sacl = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let result = unsafe {
        windows_sys::Win32::Security::Authorization::GetSecurityInfo(
            job.raw(),
            windows_sys::Win32::Security::Authorization::SE_KERNEL_OBJECT,
            windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION,
            &raw mut owner_sid,
            &raw mut group_sid,
            &raw mut dacl,
            &raw mut sacl,
            &raw mut descriptor,
        )
    };
    if result != ERROR_SUCCESS {
        return Err(PlatformError::Win32 {
            operation: "GetSecurityInfo(Job Object owner)".to_owned(),
            code: result,
        });
    }
    let descriptor = SecurityDescriptor::from_raw(descriptor, "GetSecurityInfo")?;
    let mut descriptor_owner: PSID = null_mut();
    let mut owner_defaulted = 0;
    let owner_ok = unsafe {
        GetSecurityDescriptorOwner(
            descriptor.raw_security_descriptor(),
            &raw mut descriptor_owner,
            &raw mut owner_defaulted,
        )
    };
    if owner_ok == 0 || descriptor_owner.is_null() || owner_sid.is_null() {
        return Err(last_error("GetSecurityDescriptorOwner"));
    }
    let mut token_raw = null_mut();
    let token = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token_raw) };
    if token == 0 {
        return Err(last_error("OpenProcessToken(owner)"));
    }
    let token = OwnedHandle::new(token_raw, "OpenProcessToken(owner)")?;
    let mut required = 0_u32;
    let _ =
        unsafe { GetTokenInformation(token.raw(), TokenUser, null_mut(), 0, &raw mut required) };
    if required == 0 {
        return Err(last_error("GetTokenInformation(owner size)"));
    }
    let word_size = size_of::<usize>();
    let word_count = usize::try_from(required)
        .ok()
        .and_then(|bytes| bytes.checked_add(word_size.saturating_sub(1)))
        .map(|bytes| bytes / word_size)
        .ok_or_else(|| PlatformError::Invalid("token owner size overflow".to_owned()))?;
    let mut storage = vec![0_usize; word_count];
    let storage_bytes = u32::try_from(storage.len().saturating_mul(word_size))
        .map_err(|_| PlatformError::Invalid("token owner storage size overflow".to_owned()))?;
    let ok = unsafe {
        GetTokenInformation(
            token.raw(),
            TokenUser,
            storage.as_mut_ptr().cast(),
            storage_bytes,
            &raw mut required,
        )
    };
    if ok == 0 {
        return Err(last_error("GetTokenInformation(owner)"));
    }
    let token_user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    let equal = unsafe { EqualSid(descriptor_owner, token_user.User.Sid) };
    if equal == 0 {
        return Err(PlatformError::IdentityMismatch(
            "named Job Object owner differs from the current service token".to_owned(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn spawn_suspended_with_job(
    token: Option<HANDLE>,
    job: &OwnedHandle,
    executable: &Path,
    specification: &WindowsLaunchSpec,
) -> Result<(OwnedHandle, OwnedHandle, u32), SpawnFailure> {
    let mut command_line = command_line(executable, &specification.arguments)?;
    let mut environment = environment_block(&specification.environment)?;
    let current_directory = specification
        .working_directory
        .as_deref()
        .map(canonicalize_directory)
        .transpose()?;
    let executable_wide = wide_path(executable)?;
    let current_directory_wide = current_directory.as_deref().map(wide_path).transpose()?;
    let desktop = (specification.component == crate::contract::ComponentKind::HostBroker)
        .then(|| wide("winsta0\\default"))
        .transpose()?;
    let mut attribute_size = 0_usize;
    let _ = unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &raw mut attribute_size) };
    if attribute_size == 0 {
        return Err(last_error("InitializeProcThreadAttributeList(size)").into());
    }
    // `PROC_THREAD_ATTRIBUTE_LIST` is an opaque native structure whose
    // alignment is not guaranteed by `Vec<u8>`.  Allocate whole `usize`
    // words so the pointer passed to every attribute API is explicitly
    // pointer-aligned and the backing storage outlives the CreateProcess call.
    let attribute_words = attribute_size
        .checked_add(align_of::<usize>().saturating_sub(1))
        .ok_or_else(|| PlatformError::Invalid("attribute list size overflow".to_owned()))?
        / align_of::<usize>();
    let mut attribute_storage = vec![0_usize; attribute_words];
    let attribute_bytes = attribute_storage
        .len()
        .checked_mul(size_of::<usize>())
        .ok_or_else(|| PlatformError::Invalid("attribute list allocation overflow".to_owned()))?;
    if attribute_bytes < attribute_size
        || !(attribute_storage.as_ptr() as usize).is_multiple_of(align_of::<usize>())
    {
        return Err(PlatformError::Invalid(
            "attribute list storage does not satisfy alignment/size invariants".to_owned(),
        )
        .into());
    }
    let attribute_list = attribute_storage.as_mut_ptr().cast();
    let initialized =
        unsafe { InitializeProcThreadAttributeList(attribute_list, 1, 0, &raw mut attribute_size) };
    if initialized == 0 {
        return Err(last_error("InitializeProcThreadAttributeList").into());
    }
    let jobs = [job.raw()];
    let updated = unsafe {
        UpdateProcThreadAttribute(
            attribute_list,
            0,
            usize::try_from(PROC_THREAD_ATTRIBUTE_JOB_LIST)
                .map_err(|_| PlatformError::Invalid("job attribute value overflow".to_owned()))?,
            jobs.as_ptr().cast::<c_void>(),
            size_of::<HANDLE>(),
            null_mut(),
            null_mut(),
        )
    };
    if updated == 0 {
        unsafe { DeleteProcThreadAttributeList(attribute_list) };
        return Err(last_error("UpdateProcThreadAttribute(JOB_LIST)").into());
    }
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>())
        .map_err(|_| PlatformError::Invalid("STARTUPINFOEXW size overflow".to_owned()))?;
    startup.StartupInfo.lpDesktop = desktop
        .as_ref()
        .map_or(null_mut(), |value| value.as_ptr().cast_mut());
    startup.lpAttributeList = attribute_list;
    let mut information = windows_sys::Win32::System::Threading::PROCESS_INFORMATION::default();
    let flags = CREATE_SUSPENDED
        | EXTENDED_STARTUPINFO_PRESENT
        | CREATE_UNICODE_ENVIRONMENT
        | CREATE_NEW_PROCESS_GROUP;
    // A non-null empty block gives the child a deliberately minimal
    // environment.  A null pointer would inherit the service environment.
    let environment_ptr = environment.as_mut_ptr().cast::<c_void>().cast_const();
    let current_directory_ptr = current_directory_wide.as_ref().map_or(null(), Vec::as_ptr);
    let result = unsafe {
        match token {
            Some(token) => CreateProcessAsUserW(
                token,
                executable_wide.as_ptr(),
                command_line.as_mut_ptr(),
                null(),
                null(),
                0,
                flags,
                environment_ptr,
                current_directory_ptr,
                (&raw const startup).cast(),
                &raw mut information,
            ),
            None => CreateProcessW(
                executable_wide.as_ptr(),
                command_line.as_mut_ptr(),
                null(),
                null(),
                0,
                flags,
                environment_ptr,
                current_directory_ptr,
                (&raw const startup).cast(),
                &raw mut information,
            ),
        }
    };
    unsafe { DeleteProcThreadAttributeList(attribute_list) };
    if result == 0 {
        return Err(last_error("CreateProcess").into());
    }
    let pid = information.dwProcessId;
    let (process, thread) = wrap_created_process_handles(information)?;
    Ok((process, thread, pid))
}

fn wrap_created_process_handles(
    information: windows_sys::Win32::System::Threading::PROCESS_INFORMATION,
) -> Result<(OwnedHandle, OwnedHandle), SpawnFailure> {
    let process = match OwnedHandle::new(information.hProcess, "CreateProcess process handle") {
        Ok(handle) => handle,
        Err(error) => {
            close_raw_handle(information.hProcess);
            close_raw_handle(information.hThread);
            return Err(SpawnFailure::Created(error));
        }
    };
    let thread = match OwnedHandle::new(information.hThread, "CreateProcess thread handle") {
        Ok(handle) => handle,
        Err(error) => {
            close_raw_handle(information.hThread);
            return Err(SpawnFailure::Created(error));
        }
    };
    Ok((process, thread))
}

fn query_user_token(session_id: u32) -> Result<OwnedHandle, PlatformError> {
    let mut token = null_mut();
    let result = unsafe { WTSQueryUserToken(session_id, &raw mut token) };
    if result == 0 {
        return Err(last_error("WTSQueryUserToken"));
    }
    OwnedHandle::new(token, "WTSQueryUserToken")
}

fn current_process_session() -> Result<u32, PlatformError> {
    process_session(std::process::id())
}

fn process_session(pid: u32) -> Result<u32, PlatformError> {
    let mut session = 0_u32;
    let ok = unsafe { ProcessIdToSessionId(pid, &raw mut session) };
    if ok == 0 {
        return Err(last_error("ProcessIdToSessionId"));
    }
    Ok(session)
}

/// Interactive session availability is an explicit state, not a relaunch loop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveSession {
    Available(u32),
    WaitingForSession,
}

#[must_use]
pub fn select_active_session() -> ActiveSession {
    let session = unsafe { WTSGetActiveConsoleSessionId() };
    if session == u32::MAX {
        ActiveSession::WaitingForSession
    } else {
        ActiveSession::Available(session)
    }
}

/// Peer identity captured from the local named pipe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedPipePeer {
    pub process_id: u32,
    pub creation_time_100ns: u64,
    pub session_id: u32,
    pub executable: PathBuf,
}

/// One-message local IPC server.  The object ACL is owner-only and remote
/// clients are rejected by the pipe mode.  Reads require both peer
/// authentication and a configured nonce/epoch replay window.
pub struct NamedPipeServer {
    handle: OwnedHandle,
    name: String,
    connected: bool,
    peer: Option<NamedPipePeer>,
    peer_process: Option<OwnedHandle>,
    expected_session: Option<u32>,
    expected_executable: Option<PathBuf>,
    expected_epoch: Option<u64>,
    expected_nonce: Option<String>,
    authenticated: bool,
    last_sequence: u64,
    last_frame: Option<LifecycleFrame>,
}

impl std::fmt::Debug for NamedPipeServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NamedPipeServer")
            .field("name", &self.name)
            .field("connected", &self.connected)
            .field("authenticated", &self.authenticated)
            .finish_non_exhaustive()
    }
}

impl NamedPipeServer {
    /// Create a one-instance owner-only named pipe.  Callers must supply an
    /// explicit peer policy with [`Self::authenticate_peer`] and
    /// [`Self::configure_replay_policy`] before reading a request.
    pub fn create(name: impl Into<String>) -> Result<Self, PlatformError> {
        Self::create_inner(name.into(), None, None, None, None)
    }

    /// Create a lifecycle pipe bound to the configured executable and a
    /// durable epoch/nonce.  This is the preferred production constructor;
    /// it prevents a caller from forgetting to bind
    /// `WindowsPlatformConfig::authorized_peer_executable`.
    pub fn create_for_config(
        config: &WindowsPlatformConfig,
        expected_session: Option<u32>,
        epoch: u64,
        nonce: impl Into<String>,
    ) -> Result<Self, PlatformError> {
        config.validate()?;
        Self::create_with_policy(
            config.pipe_name.clone(),
            expected_session,
            &config.authorized_peer_executable,
            epoch,
            nonce,
        )
    }

    /// Create a lifecycle pipe with an explicit authenticated peer policy.
    pub fn create_with_policy(
        name: impl Into<String>,
        expected_session: Option<u32>,
        expected_executable: &Path,
        epoch: u64,
        nonce: impl Into<String>,
    ) -> Result<Self, PlatformError> {
        let expected_executable = canonicalize_executable(expected_executable)?;
        let nonce = nonce.into();
        validate_replay_policy(epoch, &nonce)?;
        Self::create_inner(
            name.into(),
            expected_session,
            Some(expected_executable),
            Some(epoch),
            Some(nonce),
        )
    }

    fn create_inner(
        name: String,
        expected_session: Option<u32>,
        expected_executable: Option<PathBuf>,
        expected_epoch: Option<u64>,
        expected_nonce: Option<String>,
    ) -> Result<Self, PlatformError> {
        validate_pipe_name(&name)?;
        if expected_executable.is_some() != expected_epoch.is_some()
            || expected_epoch.is_some() != expected_nonce.is_some()
        {
            return Err(PlatformError::Invalid(
                "lifecycle peer and replay policy must be configured together".to_owned(),
            ));
        }
        let security = SecurityDescriptor::owner_only()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).map_err(|_| {
                PlatformError::Invalid("SECURITY_ATTRIBUTES size overflow".to_owned())
            })?,
            lpSecurityDescriptor: security.raw(),
            bInheritHandle: 0,
        };
        let wide_name = wide(&name)?;
        let raw = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE
                    | PIPE_READMODE_MESSAGE
                    | PIPE_NOWAIT
                    | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                u32::try_from(MAX_PIPE_FRAME)
                    .map_err(|_| PlatformError::Invalid("pipe frame size overflow".to_owned()))?,
                u32::try_from(MAX_PIPE_FRAME)
                    .map_err(|_| PlatformError::Invalid("pipe frame size overflow".to_owned()))?,
                2_000,
                &raw const attributes,
            )
        };
        let handle = OwnedHandle::new(raw, "CreateNamedPipeW")?;
        Ok(Self {
            handle,
            name,
            connected: false,
            peer: None,
            peer_process: None,
            expected_session,
            expected_executable,
            expected_epoch,
            expected_nonce,
            authenticated: false,
            last_sequence: 0,
            last_frame: None,
        })
    }

    /// Set the durable replay window for a pipe created with [`Self::create`].
    /// This must be done before a request is read.
    pub fn configure_replay_policy(
        &mut self,
        epoch: u64,
        nonce: impl Into<String>,
    ) -> Result<(), PlatformError> {
        if self.authenticated || self.last_frame.is_some() {
            return Err(PlatformError::Invalid(
                "lifecycle replay policy cannot change after authentication".to_owned(),
            ));
        }
        let nonce = nonce.into();
        validate_replay_policy(epoch, &nonce)?;
        if let Some(previous_epoch) = self.expected_epoch {
            if epoch <= previous_epoch {
                return Err(PlatformError::IdentityMismatch(
                    "lifecycle replay policy epoch must advance before its sequence can reset"
                        .to_owned(),
                ));
            }
        } else if self.expected_nonce.is_some() {
            return Err(PlatformError::Invalid(
                "lifecycle replay policy epoch is missing".to_owned(),
            ));
        }
        self.expected_epoch = Some(epoch);
        self.expected_nonce = Some(nonce);
        self.last_sequence = 0;
        self.last_frame = None;
        Ok(())
    }

    /// Poll for one local client for at most `timeout`, then capture its
    /// process handle, PID, creation time, session and executable.  Every
    /// post-connect metadata failure resets the pipe to listen state so a
    /// rejected peer cannot strand the one-instance endpoint.
    pub fn accept(&mut self, timeout: Duration) -> Result<Option<NamedPipePeer>, PlatformError> {
        validate_lifecycle_timeout(timeout)?;
        if self.connected {
            return Err(PlatformError::Invalid(
                "named pipe already has a connected client".to_owned(),
            ));
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        loop {
            let result = unsafe { ConnectNamedPipe(self.handle.raw(), null_mut()) };
            let code = if result == 0 {
                unsafe { GetLastError() }
            } else {
                ERROR_SUCCESS
            };
            if result != 0 || code == ERROR_PIPE_CONNECTED {
                self.connected = true;
                match self.capture_peer() {
                    Ok((peer, process)) => {
                        self.peer = Some(peer.clone());
                        self.peer_process = Some(process);
                        return Ok(Some(peer));
                    }
                    Err(error) => {
                        let _ = self.reset_listener();
                        return Err(error);
                    }
                }
            }
            if code == ERROR_NO_DATA || code == ERROR_PIPE_NOT_CONNECTED {
                self.reset_listener()?;
            } else if code != ERROR_PIPE_LISTENING && code != ERROR_OPERATION_ABORTED {
                return Err(win32_error("ConnectNamedPipe", code));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(
                Duration::from_millis(2).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }

    /// Verify peer session and exact executable, then authorize lifecycle
    /// reads.  The configured policy is preferred; explicit values are only
    /// available for the low-level constructor and are never optional at read
    /// time.
    pub fn authenticate_peer(
        &mut self,
        expected_session: Option<u32>,
        expected_executable: &Path,
    ) -> Result<&NamedPipePeer, PlatformError> {
        let expected = canonicalize_executable(expected_executable)?;
        if self.expected_executable.is_some() && self.expected_session != expected_session {
            return Err(PlatformError::IdentityMismatch(
                "named-pipe session policy differs from configured authority".to_owned(),
            ));
        }
        if self
            .expected_executable
            .as_ref()
            .is_some_and(|configured| normalize_path(configured) != normalize_path(&expected))
        {
            return Err(PlatformError::IdentityMismatch(
                "named-pipe executable policy differs from configured authority".to_owned(),
            ));
        }
        self.expected_executable = Some(expected);
        self.expected_session = expected_session;
        self.authenticate_configured_peer()
    }

    /// Apply the executable/session policy captured by `create_with_policy`.
    pub fn authenticate_configured_peer(&mut self) -> Result<&NamedPipePeer, PlatformError> {
        self.verify_peer_identity()?;
        let peer = self
            .peer
            .as_ref()
            .ok_or_else(|| PlatformError::Invalid("named pipe has no accepted peer".to_owned()))?;
        let expected = self.expected_executable.as_ref().ok_or_else(|| {
            PlatformError::Invalid(
                "named-pipe peer executable policy must be configured before reads".to_owned(),
            )
        })?;
        if self
            .expected_session
            .is_some_and(|session| session != peer.session_id)
        {
            return Err(PlatformError::IdentityMismatch(
                "named-pipe peer session is not approved".to_owned(),
            ));
        }
        if normalize_path(expected) != normalize_path(&peer.executable) {
            return Err(PlatformError::IdentityMismatch(
                "named-pipe peer executable is not approved".to_owned(),
            ));
        }
        self.authenticated = true;
        Ok(peer)
    }

    /// Read and replay-check one bounded lifecycle frame.
    pub fn read_frame(&mut self, timeout: Duration) -> Result<LifecycleFrame, PlatformError> {
        self.require_authenticated()?;
        self.verify_peer_identity()?;
        let payload = read_length_prefixed(self.handle.raw(), timeout)?;
        let frame = LifecycleFrame::decode_payload(&payload)?;
        self.verify_replay(&frame)?;
        self.last_sequence = frame.sequence;
        self.last_frame = Some(frame.clone());
        Ok(frame)
    }

    /// Read one request only after peer authentication and replay checks.
    pub fn read_request(&mut self, timeout: Duration) -> Result<LifecycleRequest, PlatformError> {
        Ok(self.read_frame(timeout)?.request)
    }

    /// Write a frame with a bounded deadline.  A response is bound to the
    /// current authenticated epoch/nonce and may acknowledge the last request
    /// sequence, but cannot introduce a new unauthenticated window.
    pub fn write_frame(
        &mut self,
        frame: &LifecycleFrame,
        timeout: Duration,
    ) -> Result<(), PlatformError> {
        self.require_authenticated()?;
        self.verify_peer_identity()?;
        frame.validate()?;
        if self.expected_epoch != Some(frame.epoch)
            || self.expected_nonce.as_deref() != Some(frame.nonce.as_str())
            || self.last_frame.as_ref().is_none_or(|last| {
                last.sequence != frame.sequence
                    || last.request.capability() != frame.request.capability()
            })
        {
            return Err(PlatformError::IdentityMismatch(
                "lifecycle response is outside the current authenticated frame".to_owned(),
            ));
        }
        write_length_prefixed(self.handle.raw(), &frame.encode_payload()?, timeout)
    }

    /// Write a response matching the most recently received request.
    pub fn write_request(
        &mut self,
        request: &LifecycleRequest,
        timeout: Duration,
    ) -> Result<(), PlatformError> {
        let last = self.last_frame.as_ref().ok_or_else(|| {
            PlatformError::Invalid("lifecycle response has no preceding request".to_owned())
        })?;
        let frame = LifecycleFrame::new(
            last.nonce.clone(),
            last.epoch,
            last.sequence,
            request.clone(),
        );
        self.write_frame(&frame, timeout)
    }

    /// Cancel pending native I/O and reset a connected peer.
    pub fn cancel(&mut self) -> Result<(), PlatformError> {
        let result =
            unsafe { windows_sys::Win32::System::IO::CancelIoEx(self.handle.raw(), null()) };
        if result == 0 {
            let code = unsafe { GetLastError() };
            if code != ERROR_NOT_FOUND
                && code != ERROR_OPERATION_ABORTED
                && code != ERROR_PIPE_NOT_CONNECTED
            {
                return Err(win32_error("CancelIoEx(lifecycle pipe)", code));
            }
        }
        Ok(())
    }

    /// Disconnect and make the one-instance endpoint available for the next
    /// bounded connection.
    pub fn disconnect(&mut self) -> Result<(), PlatformError> {
        self.reset_listener()
    }

    fn capture_peer(&self) -> Result<(NamedPipePeer, OwnedHandle), PlatformError> {
        let mut process_id = 0_u32;
        let ok = unsafe { GetNamedPipeClientProcessId(self.handle.raw(), &raw mut process_id) };
        if ok == 0 || process_id == 0 {
            return Err(last_error("GetNamedPipeClientProcessId"));
        }
        let mut session_id = 0_u32;
        let ok = unsafe { GetNamedPipeClientSessionId(self.handle.raw(), &raw mut session_id) };
        if ok == 0 {
            return Err(last_error("GetNamedPipeClientSessionId"));
        }
        let raw_process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                process_id,
            )
        };
        let process = OwnedHandle::new(raw_process, "OpenProcess(pipe peer)")?;
        let creation_time_100ns = process_creation_time(process.raw())?;
        let executable = query_image_path(process.raw())?;
        Ok((
            NamedPipePeer {
                process_id,
                creation_time_100ns,
                session_id,
                executable,
            },
            process,
        ))
    }

    fn verify_peer_identity(&self) -> Result<(), PlatformError> {
        if !self.connected {
            return Err(PlatformError::Invalid(
                "named pipe has no connected client".to_owned(),
            ));
        }
        let peer = self.peer.as_ref().ok_or_else(|| {
            PlatformError::Invalid("named pipe peer identity is missing".to_owned())
        })?;
        let process = self.peer_process.as_ref().ok_or_else(|| {
            PlatformError::Invalid("named pipe peer handle is missing".to_owned())
        })?;
        if unsafe { GetProcessId(process.raw()) } != peer.process_id
            || process_creation_time(process.raw())? != peer.creation_time_100ns
        {
            return Err(PlatformError::IdentityMismatch(
                "named-pipe peer process identity changed".to_owned(),
            ));
        }
        if process_session(peer.process_id)? != peer.session_id
            || normalize_path(&query_image_path(process.raw())?) != normalize_path(&peer.executable)
        {
            return Err(PlatformError::IdentityMismatch(
                "named-pipe peer session or executable changed".to_owned(),
            ));
        }
        Ok(())
    }

    fn verify_replay(&self, frame: &LifecycleFrame) -> Result<(), PlatformError> {
        if self.expected_epoch != Some(frame.epoch)
            || self.expected_nonce.as_deref() != Some(frame.nonce.as_str())
        {
            return Err(PlatformError::IdentityMismatch(
                "lifecycle frame belongs to a different nonce or epoch".to_owned(),
            ));
        }
        if frame.sequence <= self.last_sequence {
            return Err(PlatformError::IdentityMismatch(
                "lifecycle frame sequence was replayed or regressed".to_owned(),
            ));
        }
        Ok(())
    }

    fn require_authenticated(&self) -> Result<(), PlatformError> {
        if !self.authenticated {
            return Err(PlatformError::IdentityMismatch(
                "lifecycle peer must be authenticated before reading".to_owned(),
            ));
        }
        if self.expected_epoch.is_none() || self.expected_nonce.is_none() {
            return Err(PlatformError::IdentityMismatch(
                "lifecycle replay policy is not configured".to_owned(),
            ));
        }
        Ok(())
    }

    fn reset_listener(&mut self) -> Result<(), PlatformError> {
        if self.connected {
            let result = unsafe { DisconnectNamedPipe(self.handle.raw()) };
            if result == 0 {
                let code = unsafe { GetLastError() };
                if code != ERROR_NOT_FOUND
                    && code != ERROR_PIPE_NOT_CONNECTED
                    && code != ERROR_BROKEN_PIPE
                    && code != ERROR_NO_DATA
                {
                    return Err(win32_error("DisconnectNamedPipe", code));
                }
            }
        }
        self.connected = false;
        self.peer = None;
        self.peer_process = None;
        self.authenticated = false;
        // Keep the monotonic sequence across reconnects for the same durable
        // epoch.  Only an explicit new epoch/nonce policy resets it; otherwise
        // a captured old frame could be replayed after DisconnectNamedPipe.
        self.last_frame = None;
        Ok(())
    }
}

/// Idempotent SCM installation plan.  The caller must separately authorize
/// and perform this mutation; this method only uses SCM APIs, never a shell.
pub struct ServiceInstallPlan {
    pub service_name: String,
    pub executable: PathBuf,
}

impl ServiceInstallPlan {
    /// Refuse the legacy installer rather than silently registering as
    /// `LocalSystem`.  A service account is an authorization decision and
    /// must be supplied explicitly by the deployment owner.
    pub fn install(&self) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(
            "Windows service installation requires an explicit least-privilege service account"
                .to_owned(),
        ))
    }

    /// Install an automatic own-process service under an explicit account.
    /// `account_password` is passed only to SCM and is never included in an
    /// error or diagnostic value.  Virtual service accounts may use `None`.
    pub fn install_as(
        &self,
        account_name: &str,
        account_password: Option<&str>,
    ) -> Result<(), PlatformError> {
        self.install_as_with_config(
            account_name,
            account_password,
            Path::new(DEFAULT_SERVICE_CONFIG),
        )
    }

    /// Install with an explicit, non-secret configuration path. The service
    /// command line remains closed and bounded; credentials are never accepted
    /// as launch arguments.
    pub fn install_as_with_config(
        &self,
        account_name: &str,
        account_password: Option<&str>,
        config_path: &Path,
    ) -> Result<(), PlatformError> {
        if self.service_name != SERVICE_NAME {
            return Err(PlatformError::Invalid(
                "service name is not the fixed ascension-watchdog name".to_owned(),
            ));
        }
        validate_service_account(account_name)?;
        let config_path = canonicalize_service_config_path(config_path)?;
        let executable = canonicalize_executable(&self.executable)?;
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .map_err(service_error("OpenSCManager"))?;
        let info = ServiceInfo {
            name: self.service_name.clone().into(),
            display_name: "AI-Ascension deterministic deployment watchdog".into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: windows_service::service::ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: executable,
            launch_arguments: vec![
                "daemon".into(),
                SERVICE_SWITCH_ARGUMENT.into(),
                SERVICE_CONFIG_ARGUMENT.into(),
                config_path.as_os_str().to_owned(),
            ],
            dependencies: Vec::new(),
            account_name: Some(account_name.into()),
            account_password: account_password.map(Into::into),
        };
        let service_access = ServiceAccess::QUERY_STATUS
            | ServiceAccess::START
            | ServiceAccess::STOP
            | ServiceAccess::CHANGE_CONFIG
            | ServiceAccess::DELETE;
        let (service, created) = match manager.create_service(&info, service_access) {
            Ok(service) => (service, true),
            Err(error) if service_exists(&error) => manager
                .open_service(&self.service_name, service_access)
                .map(|service| (service, false))
                .map_err(service_error("OpenService(existing)"))?,
            Err(error) => return Err(service_error("CreateService")(error)),
        };
        let result = (|| {
            service
                .change_config(&info)
                .map_err(service_error("ChangeServiceConfig"))?;
            service
                .update_failure_actions(ServiceFailureActions {
                    reset_period: ServiceFailureResetPeriod::After(Duration::from_hours(24)),
                    reboot_msg: None,
                    command: None,
                    actions: Some(vec![
                        ServiceAction {
                            action_type: ServiceActionType::Restart,
                            delay: Duration::from_secs(5),
                        },
                        ServiceAction {
                            action_type: ServiceActionType::Restart,
                            delay: Duration::from_secs(30),
                        },
                        ServiceAction {
                            action_type: ServiceActionType::None,
                            delay: Duration::default(),
                        },
                    ]),
                })
                .map_err(service_error("ChangeServiceConfig2(failure actions)"))?;
            service
                .set_failure_actions_on_non_crash_failures(true)
                .map_err(service_error("ChangeServiceConfig2(failure actions flag)"))?;
            Ok::<(), PlatformError>(())
        })();
        if let Err(error) = result {
            if created {
                service
                    .delete()
                    .map_err(service_error("DeleteService(rollback)"))?;
            }
            return Err(error);
        }
        Ok(())
    }

    /// Refuse the legacy unbound removal path. The platform boundary cannot
    /// authenticate an owner-local deployment from a bare service name, so
    /// callers must bind SCM, stop that concrete binding, verify the owner
    /// store, and then use the bound deletion operation.
    pub fn uninstall(&self) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(
            "Windows service uninstall requires a durable owner-local Stopped intent".to_owned(),
        ))
    }

    /// Bind the fixed service's SCM command line before opening the owner
    /// store or writing a stop intent. A missing service is an idempotent
    /// no-op; an existing service returns an opaque concrete binding that must
    /// be supplied to both the bounded stop and deletion operations.
    pub fn bind_installed_service(
        &self,
        config_path: &Path,
    ) -> Result<Option<ServiceBinding>, PlatformError> {
        if self.service_name != SERVICE_NAME {
            return Err(PlatformError::Invalid(
                "service name is not the fixed ascension-watchdog name".to_owned(),
            ));
        }
        validate_service_config_path(config_path)?;
        let expected_executable = canonicalize_executable(&self.executable)?;
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(service_error("OpenSCManager(verify uninstall)"))?;
        let service = match manager.open_service(&self.service_name, ServiceAccess::QUERY_CONFIG) {
            Ok(service) => service,
            Err(error) if service_missing(&error) => return Ok(None),
            Err(error) => return Err(service_error("OpenService(verify uninstall)")(error)),
        };
        let expected_config = canonicalize_service_config_path(config_path)?;
        let service_config = service
            .query_config()
            .map_err(service_error("QueryServiceConfig(verify uninstall)"))?;
        validate_installed_service_config(&service_config, &expected_executable, &expected_config)?;
        Ok(Some(ServiceBinding {
            executable: expected_executable,
            config: expected_config,
        }))
    }

    /// Stop a previously bound service and wait for SCM's stopped state. This
    /// operation never deletes the service; the caller must verify the bound
    /// owner store after the service's authenticated stop callback completes.
    pub fn stop_bound_service(&self, binding: &ServiceBinding) -> Result<(), PlatformError> {
        if self.service_name != SERVICE_NAME {
            return Err(PlatformError::Invalid(
                "service name is not the fixed ascension-watchdog name".to_owned(),
            ));
        }
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(service_error("OpenSCManager(stop uninstall)"))?;
        let service = match manager.open_service(
            &self.service_name,
            ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
        ) {
            Ok(service) => service,
            Err(error) if service_missing(&error) => {
                return Err(PlatformError::IdentityMismatch(
                    "bound watchdog service disappeared before stop".to_owned(),
                ));
            }
            Err(error) => return Err(service_error("OpenService(stop uninstall)")(error)),
        };
        // Re-query immediately before the SCM stop. The initial bind occurs
        // before the owner store is opened; this closes the gap where another
        // deployment could rewrite the fixed service while state is settling.
        let service_config = service
            .query_config()
            .map_err(service_error("QueryServiceConfig(stop uninstall)"))?;
        validate_installed_service_config(&service_config, &binding.executable, &binding.config)?;
        let status = service
            .query_status()
            .map_err(service_error("QueryServiceStatus(stop uninstall)"))?;
        if status.current_state != ServiceState::Stopped
            && status.current_state != ServiceState::StopPending
            && let Err(error) = service.stop()
        {
            if !service_not_active(&error) {
                return Err(service_error("ControlService(stop uninstall)")(error));
            }
            // The service may have reached Stopped between the query and
            // ControlService. Re-query the authoritative SCM state before
            // deciding whether deletion is safe.
            let refreshed = service
                .query_status()
                .map_err(service_error("QueryServiceStatus(stop race)"))?;
            if refreshed.current_state != ServiceState::Stopped
                && refreshed.current_state != ServiceState::StopPending
            {
                return Err(PlatformError::Unavailable(
                    "SCM reported service-not-active but the service was not stopped".to_owned(),
                ));
            }
        }
        if status.current_state != ServiceState::Stopped {
            wait_for_service_state(&service, ServiceState::Stopped, SERVICE_STOP_TIMEOUT)?;
        }
        // The service can be reconfigured while it is stopping. Re-bind before
        // returning the stop witness so deletion cannot use stale authority.
        let service_config = service
            .query_config()
            .map_err(service_error("QueryServiceConfig(after stop)"))?;
        validate_installed_service_config(&service_config, &binding.executable, &binding.config)?;
        Ok(())
    }

    /// Delete a concrete bound service only after it is stopped and the
    /// command line has been re-queried. A missing service is idempotent once
    /// the earlier stop witness was established.
    pub fn delete_bound_stopped_service(
        &self,
        binding: &ServiceBinding,
    ) -> Result<(), PlatformError> {
        if self.service_name != SERVICE_NAME {
            return Err(PlatformError::Invalid(
                "service name is not the fixed ascension-watchdog name".to_owned(),
            ));
        }
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(service_error("OpenSCManager(delete uninstall)"))?;
        let service = match manager.open_service(
            &self.service_name,
            ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
        ) {
            Ok(service) => service,
            Err(error) if service_missing(&error) => return Ok(()),
            Err(error) => return Err(service_error("OpenService(delete uninstall)")(error)),
        };
        let service_config = service
            .query_config()
            .map_err(service_error("QueryServiceConfig(delete uninstall)"))?;
        validate_installed_service_config(&service_config, &binding.executable, &binding.config)?;
        let status = service
            .query_status()
            .map_err(service_error("QueryServiceStatus(delete uninstall)"))?;
        if status.current_state != ServiceState::Stopped {
            return Err(PlatformError::Unavailable(
                "SCM service was not stopped before deletion".to_owned(),
            ));
        }
        let service_config = service
            .query_config()
            .map_err(service_error("QueryServiceConfig(before delete)"))?;
        validate_installed_service_config(&service_config, &binding.executable, &binding.config)?;
        service
            .delete()
            .map_err(service_error("DeleteService(uninstall)"))
    }
}

/// A concrete SCM binding captured by querying the fixed service's installed
/// command line. Its fields remain private so callers cannot substitute a
/// different executable or owner config between stop and delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceBinding {
    executable: PathBuf,
    config: PathBuf,
}

impl ServiceBinding {
    /// Return the canonical owner-local config path captured from SCM. The
    /// caller must use this path for the post-stop store verification rather
    /// than resolving its original operator input again.
    #[must_use]
    pub fn config_path(&self) -> &Path {
        &self.config
    }
}

fn validate_service_config_path(path: &Path) -> Result<(), PlatformError> {
    let text = path.to_string_lossy();
    if !path.is_absolute()
        || text.is_empty()
        || text.len() > 512
        || text.contains('\0')
        || text.contains('"')
        || text.chars().any(char::is_control)
    {
        return Err(PlatformError::Invalid(
            "Windows service config must be an absolute bounded path".to_owned(),
        ));
    }
    Ok(())
}

fn canonicalize_service_config_path(path: &Path) -> Result<PathBuf, PlatformError> {
    validate_service_config_path(path)?;
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| PlatformError::Io(format!("service config path: {error}")))?;
    if !canonical.is_file() {
        return Err(PlatformError::Invalid(
            "Windows service config is not a regular file".to_owned(),
        ));
    }
    Ok(canonical)
}

fn validate_installed_service_config(
    service_config: &windows_service::service::ServiceConfig,
    expected_executable: &Path,
    expected_config: &Path,
) -> Result<(), PlatformError> {
    if service_config.service_type != ServiceType::OWN_PROCESS {
        return Err(PlatformError::IdentityMismatch(
            "SCM service type is not the fixed watchdog own-process deployment".to_owned(),
        ));
    }
    let removal_start_mode = match service_config.start_type {
        ServiceStartType::AutoStart => crate::service_command::RemovalStartMode::AutoStart,
        ServiceStartType::OnDemand => crate::service_command::RemovalStartMode::OnDemand,
        ServiceStartType::Disabled => crate::service_command::RemovalStartMode::Disabled,
        ServiceStartType::SystemStart | ServiceStartType::BootStart => {
            crate::service_command::RemovalStartMode::Unsupported
        }
    };
    crate::service_command::validate_removal_start_mode(removal_start_mode).map_err(|error| {
        PlatformError::IdentityMismatch(format!("invalid SCM removal start mode: {error}"))
    })?;
    let command_line = crate::service_command::parse_service_command_line(
        &service_config.executable_path.to_string_lossy(),
    )
    .map_err(|error| {
        PlatformError::IdentityMismatch(format!("invalid SCM service command line: {error}"))
    })?;
    let actual_executable = PathBuf::from(command_line.executable);
    let actual_config = PathBuf::from(command_line.config);
    let canonical_executable = canonicalize_executable(&actual_executable)?;
    let canonical_config = canonicalize_service_config_path(&actual_config)?;
    if normalize_path(&actual_executable) != normalize_path(&canonical_executable)
        || normalize_path(&canonical_executable) != normalize_path(expected_executable)
    {
        return Err(PlatformError::IdentityMismatch(
            "SCM service executable is not the approved canonical watchdog executable".to_owned(),
        ));
    }
    if normalize_path(&actual_config) != normalize_path(&canonical_config)
        || normalize_path(&canonical_config) != normalize_path(expected_config)
    {
        return Err(PlatformError::IdentityMismatch(
            "SCM service config is not the approved canonical owner-local config".to_owned(),
        ));
    }
    Ok(())
}

fn validate_service_account(account_name: &str) -> Result<(), PlatformError> {
    let normalized = account_name.to_ascii_lowercase();
    if account_name.is_empty()
        || account_name.len() > 256
        || account_name.contains('\0')
        || account_name.chars().any(char::is_control)
        || matches!(
            normalized.as_str(),
            "localsystem"
                | ".\\localsystem"
                | "localservice"
                | ".\\localservice"
                | "networkservice"
                | ".\\networkservice"
                | "nt authority\\system"
                | "nt authority\\localsystem"
        )
    {
        return Err(PlatformError::Invalid(
            "Windows service account must be an explicit least-privilege identity".to_owned(),
        ));
    }
    Ok(())
}

/// Minimal trusted health checker.  It can request SCM stop/recovery only
/// when an owner-local heartbeat file is stale; it never launches components.
pub struct ScmHealthChecker {
    pub service_name: String,
    pub heartbeat_file: PathBuf,
    pub stale_after: Duration,
}

impl ScmHealthChecker {
    /// Request SCM recovery when the bounded heartbeat age proves a hang.
    pub fn request_recovery_if_stale(
        &self,
        now: std::time::SystemTime,
    ) -> Result<bool, PlatformError> {
        if self.service_name != SERVICE_NAME {
            return Err(PlatformError::Invalid(
                "health checker service name is not fixed".to_owned(),
            ));
        }
        let metadata = std::fs::metadata(&self.heartbeat_file)
            .map_err(|error| PlatformError::Io(format!("heartbeat metadata: {error}")))?;
        let modified = metadata
            .modified()
            .map_err(|error| PlatformError::Io(format!("heartbeat timestamp: {error}")))?;
        let age = now.duration_since(modified).unwrap_or_default();
        if age <= self.stale_after.min(HEALTH_STALE_AFTER) {
            return Ok(false);
        }
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(service_error("OpenSCManager(health checker)"))?;
        let service = manager
            .open_service(
                &self.service_name,
                ServiceAccess::START | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
            )
            .map_err(service_error("OpenService(health checker)"))?;
        let status = service
            .query_status()
            .map_err(service_error("QueryServiceStatus(health checker)"))?;
        if status.current_state != ServiceState::Running {
            // Do not turn a deliberate stop or a pending transition into an
            // implicit start merely because an old heartbeat remains on disk.
            return Ok(false);
        }
        service
            .stop()
            .map_err(service_error("ControlService(stop)"))?;
        wait_for_service_state(&service, ServiceState::Stopped, HEALTH_STALE_AFTER)?;
        service
            .start::<&std::ffi::OsStr>(&[])
            .map_err(service_error("StartService(recovery)"))?;
        wait_for_service_state(&service, ServiceState::Running, HEALTH_STALE_AFTER)?;
        Ok(true)
    }
}

fn wait_for_service_state(
    service: &Service,
    expected: ServiceState,
    timeout: Duration,
) -> Result<(), PlatformError> {
    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(std::time::Instant::now);
    loop {
        let status = service
            .query_status()
            .map_err(service_error("QueryServiceStatus(recovery)"))?;
        if status.current_state == expected {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(PlatformError::Timeout(format!(
                "SCM service did not reach {expected:?} before the bounded recovery deadline"
            )));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Service runtime callback.  The callback must call its real reconciliation
/// loop and return when the SCM stop flag is observed.
pub struct ServiceRuntime;

impl ServiceRuntime {
    /// Enter the SCM dispatcher for the fixed service name.
    ///
    /// This compatibility entrypoint deliberately refuses to claim `Running`
    /// because it has no trusted readiness witness.  Call
    /// [`Self::run_with_readiness`] from the production daemon.
    pub fn run<F>(reconcile: F) -> Result<(), PlatformError>
    where
        F: Fn(Arc<Mutex<bool>>) -> Result<(), PlatformError> + Send + Sync + 'static,
    {
        Self::run_with_readiness(reconcile, || {
            Err(PlatformError::Unavailable(
                "service readiness witness was not supplied".to_owned(),
            ))
        })
    }

    /// Enter the SCM dispatcher and publish `Running` only after the caller's
    /// bounded, real readiness witness succeeds.  The witness should perform
    /// the same configuration, storage, IPC, and control-loop checks used by
    /// the daemon; a static boolean or process-alive probe is not sufficient.
    pub fn run_with_readiness<F, R>(reconcile: F, readiness: R) -> Result<(), PlatformError>
    where
        F: Fn(Arc<Mutex<bool>>) -> Result<(), PlatformError> + Send + Sync + 'static,
        R: Fn() -> Result<(), PlatformError> + Send + Sync + 'static,
    {
        SERVICE_RECONCILE.set(Arc::new(reconcile)).map_err(|_| {
            PlatformError::Unavailable("service runtime was already initialized".to_owned())
        })?;
        SERVICE_READINESS.set(Arc::new(readiness)).map_err(|_| {
            PlatformError::Unavailable("service readiness was already initialized".to_owned())
        })?;
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .map_err(service_error("service dispatcher"))
    }
}

windows_service::define_windows_service!(ffi_service_main, dispatch_service_main);

fn dispatch_service_main(arguments: Vec<std::ffi::OsString>) {
    if let (Some(reconcile), Some(readiness)) = (SERVICE_RECONCILE.get(), SERVICE_READINESS.get()) {
        if let Err(error) = service_entry(arguments, reconcile, readiness) {
            // The SCM callback cannot return a Rust error.  Do not silently
            // discard startup/status failures: this is the last diagnostic
            // path before SCM applies configured failure actions.
            eprintln!("ascension-watchdog service entry failed: {error}");
        }
    } else {
        eprintln!("ascension-watchdog service entry callbacks were not initialized");
    }
}

fn service_entry(
    _arguments: Vec<std::ffi::OsString>,
    reconcile: &Arc<ReconcileCallback>,
    readiness: &Arc<ReadinessCallback>,
) -> Result<(), PlatformError> {
    let stopping = Arc::new(Mutex::new(false));
    let stop_flag = Arc::clone(&stopping);
    let status_slot = Arc::new(Mutex::new(None::<ServiceStatusHandle>));
    let handler_status_slot = Arc::clone(&status_slot);
    let stop_checkpoint = Arc::new(AtomicU32::new(1));
    let handler_checkpoint = Arc::clone(&stop_checkpoint);
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            if let Ok(mut value) = stop_flag.lock() {
                *value = true;
            }
            let checkpoint = handler_checkpoint.fetch_add(1, Ordering::AcqRel);
            if let Ok(slot) = handler_status_slot.lock()
                && let Some(status) = *slot
                && let Err(error) = status.set_service_status(ServiceStatus {
                    service_type: ServiceType::OWN_PROCESS,
                    current_state: ServiceState::StopPending,
                    controls_accepted: windows_service::service::ServiceControlAccept::empty(),
                    exit_code: windows_service::service::ServiceExitCode::Win32(ERROR_SUCCESS),
                    checkpoint,
                    wait_hint: SERVICE_STOP_TIMEOUT,
                    process_id: None,
                })
            {
                eprintln!("ascension-watchdog failed to publish STOP_PENDING: {error}");
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(SERVICE_NAME, handler)
        .map_err(service_error("RegisterServiceCtrlHandler"))?;
    if let Ok(mut slot) = status_slot.lock() {
        *slot = Some(status);
    } else {
        return Err(PlatformError::Unavailable(
            "service status slot was poisoned before startup".to_owned(),
        ));
    }
    status
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StartPending,
            controls_accepted: windows_service::service::ServiceControlAccept::STOP
                | windows_service::service::ServiceControlAccept::PRESHUTDOWN,
            exit_code: windows_service::service::ServiceExitCode::Win32(ERROR_SUCCESS),
            checkpoint: 1,
            wait_hint: SERVICE_READY_TIMEOUT,
            process_id: None,
        })
        .map_err(service_error("SetServiceStatus(StartPending)"))?;
    if let Err(error) = readiness() {
        status
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Stopped,
                controls_accepted: windows_service::service::ServiceControlAccept::empty(),
                exit_code: windows_service::service::ServiceExitCode::ServiceSpecific(1),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .map_err(service_error(
                "SetServiceStatus(Stopped after readiness failure)",
            ))?;
        return Err(error);
    }
    status
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: windows_service::service::ServiceControlAccept::STOP
                | windows_service::service::ServiceControlAccept::PRESHUTDOWN,
            exit_code: windows_service::service::ServiceExitCode::Win32(ERROR_SUCCESS),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .map_err(service_error("SetServiceStatus(Running)"))?;
    let reconcile_error = reconcile(stopping).err();
    status
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: windows_service::service::ServiceControlAccept::empty(),
            // A failed/uncertain reconciliation is explicitly not a clean
            // stop. SCM receives a service-specific failure status, while the
            // durable stop intent prevents child relaunch on any recovery.
            exit_code: if reconcile_error.is_some() {
                windows_service::service::ServiceExitCode::ServiceSpecific(1)
            } else {
                windows_service::service::ServiceExitCode::Win32(ERROR_SUCCESS)
            },
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .map_err(service_error("SetServiceStatus(Stopped)"))?;
    if let Some(error) = reconcile_error {
        return Err(error);
    }
    Ok(())
}

#[derive(Debug)]
struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(raw: HANDLE, operation: &str) -> Result<Self, PlatformError> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(last_error(operation));
        }
        Ok(Self(raw))
    }

    fn raw(&self) -> HANDLE {
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

fn close_raw_handle(handle: HANDLE) {
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

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn from_raw(raw: PSECURITY_DESCRIPTOR, operation: &str) -> Result<Self, PlatformError> {
        if raw.is_null() {
            return Err(last_error(operation));
        }
        Ok(Self(raw))
    }

    fn owner_only() -> Result<Self, PlatformError> {
        let descriptor = wide("D:P(A;;GA;;;OW)")?;
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

    fn raw(&self) -> *mut c_void {
        self.0
    }

    fn raw_security_descriptor(&self) -> PSECURITY_DESCRIPTOR {
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

fn validate_lifecycle_timeout(timeout: Duration) -> Result<(), PlatformError> {
    if timeout.is_zero() || timeout > Duration::from_secs(30) {
        return Err(PlatformError::Invalid(
            "lifecycle pipe timeout must be between 1ms and 30s".to_owned(),
        ));
    }
    Ok(())
}

fn validate_replay_policy(epoch: u64, nonce: &str) -> Result<(), PlatformError> {
    let request = LifecycleRequest::Heartbeat {
        instance_id: "policy".to_owned(),
        incarnation: "policy".to_owned(),
        sequence: 1,
    };
    LifecycleFrame::new(nonce, epoch, 1, request).validate()
}

fn read_length_prefixed(handle: HANDLE, timeout: Duration) -> Result<Vec<u8>, PlatformError> {
    validate_lifecycle_timeout(timeout)?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let mut length_bytes = [0_u8; 4];
    read_exact_poll(handle, &mut length_bytes, deadline)?;
    let length = usize::try_from(u32::from_le_bytes(length_bytes))
        .map_err(|_| PlatformError::Invalid("lifecycle frame length overflow".to_owned()))?;
    if length == 0 || length > MAX_PIPE_FRAME {
        return Err(PlatformError::Invalid(
            "lifecycle frame exceeds bounds".to_owned(),
        ));
    }
    let mut payload = vec![0_u8; length];
    read_exact_poll(handle, &mut payload, deadline)?;
    Ok(payload)
}

fn write_length_prefixed(
    handle: HANDLE,
    payload: &[u8],
    timeout: Duration,
) -> Result<(), PlatformError> {
    validate_lifecycle_timeout(timeout)?;
    if payload.is_empty() || payload.len() > MAX_PIPE_FRAME {
        return Err(PlatformError::Invalid(
            "lifecycle frame exceeds bounds".to_owned(),
        ));
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let length = u32::try_from(payload.len())
        .map_err(|_| PlatformError::Invalid("lifecycle frame length overflow".to_owned()))?;
    write_all_poll(handle, &length.to_le_bytes(), deadline)?;
    write_all_poll(handle, payload, deadline)
}

fn read_exact_poll(
    handle: HANDLE,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), PlatformError> {
    let mut offset = 0_usize;
    while offset < buffer.len() {
        ensure_io_deadline(handle, deadline, "lifecycle pipe read deadline elapsed")?;
        let remaining = &mut buffer[offset..];
        let count = u32::try_from(remaining.len())
            .map_err(|_| PlatformError::Invalid("pipe read exceeds bounds".to_owned()))?;
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
                "lifecycle read count exceeds requested buffer".to_owned(),
            ));
        }
        if ok != 0 || (code == ERROR_MORE_DATA && read != 0) {
            if read == 0 {
                return Err(PlatformError::Unavailable(
                    "lifecycle pipe returned no read progress".to_owned(),
                ));
            }
            offset = offset.saturating_add(
                usize::try_from(read)
                    .map_err(|_| PlatformError::Invalid("pipe read count overflow".to_owned()))?,
            );
            ensure_io_deadline(handle, deadline, "lifecycle pipe read deadline elapsed")?;
            continue;
        }
        if code == ERROR_NO_DATA || code == ERROR_PIPE_LISTENING {
            ensure_io_deadline(handle, deadline, "lifecycle pipe read deadline elapsed")?;
            thread::sleep(
                Duration::from_millis(2).min(deadline.saturating_duration_since(Instant::now())),
            );
            continue;
        }
        if code == ERROR_BROKEN_PIPE || code == ERROR_PIPE_NOT_CONNECTED {
            return Err(PlatformError::Unavailable(
                "named pipe closed before frame completion".to_owned(),
            ));
        }
        return Err(win32_error("ReadFile(lifecycle pipe)", code));
    }
    Ok(())
}

fn write_all_poll(handle: HANDLE, buffer: &[u8], deadline: Instant) -> Result<(), PlatformError> {
    let mut offset = 0_usize;
    while offset < buffer.len() {
        ensure_io_deadline(handle, deadline, "lifecycle pipe write deadline elapsed")?;
        let remaining = &buffer[offset..];
        let count = u32::try_from(remaining.len())
            .map_err(|_| PlatformError::Invalid("pipe write exceeds bounds".to_owned()))?;
        let mut written = 0_u32;
        let ok = unsafe {
            WriteFile(
                handle,
                remaining.as_ptr(),
                count,
                &raw mut written,
                null_mut(),
            )
        };
        if written > count {
            return Err(PlatformError::Invalid(
                "lifecycle write count exceeds requested buffer".to_owned(),
            ));
        }
        if ok != 0 {
            if written == 0 {
                return Err(PlatformError::Unavailable(
                    "named pipe made no write progress".to_owned(),
                ));
            }
            offset = offset.saturating_add(
                usize::try_from(written)
                    .map_err(|_| PlatformError::Invalid("pipe write count overflow".to_owned()))?,
            );
            ensure_io_deadline(handle, deadline, "lifecycle pipe write deadline elapsed")?;
            continue;
        }
        let code = unsafe { GetLastError() };
        if code == ERROR_NO_DATA || code == ERROR_PIPE_LISTENING {
            ensure_io_deadline(handle, deadline, "lifecycle pipe write deadline elapsed")?;
            thread::sleep(
                Duration::from_millis(2).min(deadline.saturating_duration_since(Instant::now())),
            );
            continue;
        }
        if code == ERROR_BROKEN_PIPE || code == ERROR_PIPE_NOT_CONNECTED {
            return Err(PlatformError::Unavailable(
                "named pipe closed during frame write".to_owned(),
            ));
        }
        return Err(win32_error("WriteFile(lifecycle pipe)", code));
    }
    Ok(())
}

fn ensure_io_deadline(
    handle: HANDLE,
    deadline: Instant,
    message: &str,
) -> Result<(), PlatformError> {
    if Instant::now() >= deadline {
        let _ = unsafe { windows_sys::Win32::System::IO::CancelIoEx(handle, null()) };
        return Err(PlatformError::Timeout(message.to_owned()));
    }
    Ok(())
}

fn process_creation_time(handle: HANDLE) -> Result<u64, PlatformError> {
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

fn query_image_path(handle: HANDLE) -> Result<PathBuf, PlatformError> {
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

fn open_immutable_path(
    path: &Path,
    desired_access: u32,
    flags_and_attributes: u32,
    operation: &str,
) -> Result<OwnedHandle, PlatformError> {
    let wide_path = wide_path(path)?;
    // Share reads so the barrier and CreateProcessW can reopen the approved
    // object, while deliberately denying write and delete/rename access.
    // Holding the directory handle at the same boundary prevents the release
    // directory itself from being removed or renamed while a child is owned.
    let raw = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            desired_access,
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            flags_and_attributes,
            null_mut(),
        )
    };
    OwnedHandle::new(raw, operation)
}

/// Hash one canonical executable using the same bounded read path as launch.
///
/// This helper is intended for trusted configuration/test tooling.  It does
/// not reserve the path or replace the launch-time integrity guard; callers
/// must still pass the resulting digest as an approved configuration value.
pub fn executable_sha256(path: &Path) -> Result<String, PlatformError> {
    let executable = canonicalize_executable(path)?;
    Ok(IntegrityGuards::open(&executable)?.digest().to_owned())
}

fn file_identity(file: &OwnedHandle) -> Result<FileIdentity, PlatformError> {
    let mut information =
        windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.raw(), &raw mut information) } == 0 {
        return Err(last_error("GetFileInformationByHandle(executable)"));
    }
    Ok(FileIdentity {
        volume_serial: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
        size: (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow),
    })
}

fn hash_immutable_file(file: &OwnedHandle) -> Result<String, PlatformError> {
    let mut file_size = 0_i64;
    let ok = unsafe { GetFileSizeEx(file.raw(), &raw mut file_size) };
    if ok == 0 {
        return Err(last_error("GetFileSizeEx(immutable executable)"));
    }
    if file_size < 0 {
        return Err(PlatformError::Unavailable(
            "immutable executable has a negative file size".to_owned(),
        ));
    }
    let expected_size = u64::try_from(file_size)
        .map_err(|_| PlatformError::Invalid("immutable executable size overflow".to_owned()))?;
    if expected_size > MAX_HASH_BYTES {
        return Err(PlatformError::Invalid(
            "immutable executable exceeds the hash size bound".to_owned(),
        ));
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; HASH_READ_BYTES];
    let mut total = 0_u64;
    while total < expected_size {
        let remaining = expected_size.saturating_sub(total);
        let count = usize::try_from(remaining.min(u64::try_from(buffer.len()).map_err(|_| {
            PlatformError::Invalid("immutable hash buffer size overflow".to_owned())
        })?))
        .map_err(|_| PlatformError::Invalid("immutable hash read size overflow".to_owned()))?;
        let count = u32::try_from(count).map_err(|_| {
            PlatformError::Invalid("immutable hash read exceeds Win32 bounds".to_owned())
        })?;
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
            return Err(last_error("ReadFile(immutable executable)"));
        }
        if read == 0 || read > count {
            return Err(PlatformError::Unavailable(
                "immutable executable changed while it was being hashed".to_owned(),
            ));
        }
        digest.update(
            &buffer[..usize::try_from(read)
                .map_err(|_| PlatformError::Invalid("immutable hash count overflow".to_owned()))?],
        );
        total = total.saturating_add(u64::from(read));
    }
    let mut final_size = 0_i64;
    let ok = unsafe { GetFileSizeEx(file.raw(), &raw mut final_size) };
    if ok == 0 {
        return Err(last_error("GetFileSizeEx(immutable executable final)"));
    }
    if final_size < 0 || u64::try_from(final_size).ok() != Some(expected_size) {
        return Err(PlatformError::IdentityMismatch(
            "immutable executable changed while it was being hashed".to_owned(),
        ));
    }
    Ok(digest.hex())
}

#[derive(Clone, Debug)]
struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    length_bits: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            buffer: [0; 64],
            buffered: 0,
            length_bits: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.length_bits = self.length_bits.wrapping_add(
            u64::try_from(input.len())
                .unwrap_or(u64::MAX)
                .wrapping_mul(8),
        );
        if self.buffered != 0 {
            let needed = 64 - self.buffered;
            if input.len() < needed {
                self.buffer[self.buffered..self.buffered + input.len()].copy_from_slice(input);
                self.buffered += input.len();
                return;
            }
            self.buffer[self.buffered..].copy_from_slice(&input[..needed]);
            let block = self.buffer;
            self.compress(&block);
            self.buffered = 0;
            input = &input[needed..];
        }
        while input.len() >= 64 {
            self.compress(&input[..64]);
            input = &input[64..];
        }
        self.buffer[..input.len()].copy_from_slice(input);
        self.buffered = input.len();
    }

    fn finalize(mut self) -> [u8; 32] {
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > 56 {
            self.buffer[self.buffered..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffered = 0;
        }
        self.buffer[self.buffered..56].fill(0);
        self.buffer[56..].copy_from_slice(&self.length_bits.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut result = [0_u8; 32];
        for (index, word) in self.state.iter().enumerate() {
            result[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        result
    }

    fn compress(&mut self, block: &[u8]) {
        let mut words = [0_u32; 64];
        for (index, word) in words.iter_mut().enumerate().take(16) {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let mut state = self.state;
        for index in 0..64 {
            let choice = (state[4] & state[5]) ^ ((!state[4]) & state[6]);
            let majority = (state[0] & state[1]) ^ (state[0] & state[2]) ^ (state[1] & state[2]);
            let sigma0 =
                state[0].rotate_right(2) ^ state[0].rotate_right(13) ^ state[0].rotate_right(22);
            let sigma1 =
                state[4].rotate_right(6) ^ state[4].rotate_right(11) ^ state[4].rotate_right(25);
            let temp1 = state[7]
                .wrapping_add(sigma1)
                .wrapping_add(choice)
                .wrapping_add(SHA256_K[index])
                .wrapping_add(words[index]);
            let temp2 = sigma0.wrapping_add(majority);
            state[7] = state[6];
            state[6] = state[5];
            state[5] = state[4];
            state[4] = state[3].wrapping_add(temp1);
            state[3] = state[2];
            state[2] = state[1];
            state[1] = state[0];
            state[0] = temp1.wrapping_add(temp2);
        }
        for (slot, value) in self.state.iter_mut().zip(state) {
            *slot = slot.wrapping_add(value);
        }
    }
}

impl Sha256 {
    fn hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let digest = self.clone().finalize();
        let mut result = String::with_capacity(digest.len().saturating_mul(2));
        for byte in digest {
            result.push(char::from(HEX[usize::from(byte >> 4)]));
            result.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        result
    }
}

fn canonicalize_executable(path: &Path) -> Result<PathBuf, PlatformError> {
    if !path.is_absolute() {
        return Err(PlatformError::Invalid(
            "Windows executable must be absolute".to_owned(),
        ));
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| PlatformError::Io(format!("executable path: {error}")))?;
    if !canonical.is_file() {
        return Err(PlatformError::Invalid(
            "Windows executable is not a regular file".to_owned(),
        ));
    }
    Ok(canonical)
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

fn job_name(nonce: &str) -> Result<String, PlatformError> {
    validate_nonce(nonce)?;
    Ok(format!("{JOB_NAME_PREFIX}{nonce}"))
}

fn planned_job_nonce(planned_containment: &str) -> Result<&str, PlatformError> {
    let nonce = planned_containment
        .strip_prefix(PLANNED_JOB_PREFIX)
        .ok_or_else(|| {
            PlatformError::Invalid(
                "planned Windows containment must use the windows-job:<nonce> authority".to_owned(),
            )
        })?;
    validate_nonce(nonce)?;
    Ok(nonce)
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

fn wide(value: &str) -> Result<Vec<u16>, PlatformError> {
    if value.contains('\0') {
        return Err(PlatformError::Invalid(
            "Windows string contains NUL".to_owned(),
        ));
    }
    Ok(value.encode_utf16().chain(std::iter::once(0)).collect())
}

fn wide_path(path: &Path) -> Result<Vec<u16>, PlatformError> {
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

fn command_line(executable: &Path, arguments: &[String]) -> Result<Vec<u16>, PlatformError> {
    let mut line = crate::service_command::quote_windows(executable.to_string_lossy().as_ref());
    for argument in arguments {
        line.push(' ');
        line.push_str(&crate::service_command::quote_windows(argument));
    }
    let result = wide(&line)?;
    if result.len().saturating_sub(1) > 32_767 {
        return Err(PlatformError::Invalid(
            "Windows command line exceeds the CreateProcessW bound".to_owned(),
        ));
    }
    Ok(result)
}

fn environment_block(environment: &BTreeMap<String, String>) -> Result<Vec<u16>, PlatformError> {
    let mut block = Vec::new();
    for (name, value) in environment {
        if name.contains('=') || name.contains('\0') || value.contains('\0') {
            return Err(PlatformError::Invalid(
                "Windows environment contains an invalid name/value".to_owned(),
            ));
        }
        block.extend(name.encode_utf16());
        block.push('=' as u16);
        block.extend(value.encode_utf16());
        block.push(0);
    }
    if block.is_empty() {
        block.extend_from_slice(&[0, 0]);
    } else {
        block.push(0);
    }
    if block.len() > 32_767 {
        return Err(PlatformError::Invalid(
            "Windows environment block exceeds the CreateProcessW bound".to_owned(),
        ));
    }
    Ok(block)
}

fn duration_to_millis(duration: Duration) -> Result<u32, PlatformError> {
    let millis = duration.as_millis();
    if millis == 0 || millis > u128::from(u32::MAX) {
        return Err(PlatformError::Invalid(
            "Windows stop timeout is outside the Win32 wait bound".to_owned(),
        ));
    }
    u32::try_from(millis)
        .map_err(|_| PlatformError::Invalid("Windows stop timeout overflow".to_owned()))
}

fn validate_stop_timeouts(graceful: Duration, force: Duration) -> Result<(), PlatformError> {
    if graceful.is_zero() || force.is_zero() || force < graceful {
        return Err(PlatformError::Invalid(
            "Windows stop deadlines are invalid".to_owned(),
        ));
    }
    let _ = duration_to_millis(graceful)?;
    let _ = duration_to_millis(force)?;
    Ok(())
}

fn validate_planned_job_cleanup_timeout(timeout: Duration) -> Result<(), PlatformError> {
    if timeout.is_zero() || timeout > MAX_PLANNED_JOB_CLEANUP_TIMEOUT {
        return Err(PlatformError::Invalid(
            "planned Job Object cleanup deadline is outside the 1ms..=30s bound".to_owned(),
        ));
    }
    let _ = duration_to_millis(timeout)?;
    Ok(())
}

fn last_error(operation: &str) -> PlatformError {
    PlatformError::Win32 {
        operation: operation.to_owned(),
        code: unsafe { GetLastError() },
    }
}

fn win32_error(operation: &str, code: u32) -> PlatformError {
    PlatformError::Win32 {
        operation: operation.to_owned(),
        code,
    }
}

fn service_exists(error: &windows_service::Error) -> bool {
    matches!(
        error,
        windows_service::Error::Winapi(error)
            if error.raw_os_error() == Some(ERROR_SERVICE_EXISTS.cast_signed())
    )
}

fn service_missing(error: &windows_service::Error) -> bool {
    matches!(
        error,
        windows_service::Error::Winapi(error)
            if error.raw_os_error() == Some(
                windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST.cast_signed(),
            )
    )
}

fn service_not_active(error: &windows_service::Error) -> bool {
    matches!(
        error,
        windows_service::Error::Winapi(error)
            if error.raw_os_error() == Some(ERROR_SERVICE_NOT_ACTIVE.cast_signed())
    )
}

fn service_error(operation: &'static str) -> impl Fn(windows_service::Error) -> PlatformError {
    move |error| PlatformError::Io(format!("{operation}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_service::service::ServiceConfig;

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
            expected_config.to_string_lossy().as_ref(),
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
        let job = create_job(&name, 7)?;
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
