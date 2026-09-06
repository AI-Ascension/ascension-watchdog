//! Windows-only implementation.
//!
//! All raw handles are wrapped immediately and all process operations are
//! preceded by creation-time and executable identity checks.  The Job Object
//! is named with the persisted launch nonce and has a protected DACL, so a
//! restarted watchdog can reopen the exact authority rather than searching by
//! process name.  The `PROC_THREAD_ATTRIBUTE_JOB_LIST` attribute is used with
//! `CREATE_SUSPENDED`; the child cannot execute before assignment.

use crate::contract::{
    LifecycleRequest, PlatformError, ProcessIdentity, SessionSelector, WindowsLaunchSpec,
    WindowsPlatformConfig,
};
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceErrorControl,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_INVALID_PARAMETER, ERROR_PIPE_CONNECTED,
    ERROR_SERVICE_EXISTS, ERROR_SUCCESS, FILETIME, GetLastError, HANDLE, LocalFree, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FlushFileBuffers, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeClientSessionId, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_MESSAGE, PIPE_WAIT,
};
use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSGetActiveConsoleSessionId, WTSQueryUserToken,
};
use windows_sys::Win32::System::SystemServices::{JOB_OBJECT_QUERY, JOB_OBJECT_TERMINATE};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetProcessId,
    GetProcessTimes, InitializeProcThreadAttributeList, OpenProcess,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, QueryFullProcessImageNameW, ResumeThread, STARTUPINFOEXW,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

const MAX_PIPE_FRAME: usize = 8 * 1024;
const MAX_IMAGE_PATH: usize = 32_768;
const JOB_NAME_PREFIX: &str = r"Local\ascension-watchdog-";
const PIPE_NAME_PREFIX: &str = r"\\.\pipe\ascension-watchdog-";
const SERVICE_NAME: &str = "ascension-watchdog";
const HEALTH_STALE_AFTER: Duration = Duration::from_secs(90);

type ReconcileCallback = dyn Fn(Arc<Mutex<bool>>) + Send + Sync + 'static;

static SERVICE_RECONCILE: OnceLock<Arc<ReconcileCallback>> = OnceLock::new();

/// A process launched in an ACL-protected named Job Object.
pub struct JobOwnedProcess {
    identity: ProcessIdentity,
    process: OwnedHandle,
    job: OwnedHandle,
    graceful_timeout: Duration,
    force_timeout: Duration,
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
        if !self.is_running()? {
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
        let running = self.is_running()?;
        if self.active_processes()? == 0 {
            return Ok(StopOutcome::AlreadyExited);
        }
        let terminated = unsafe { TerminateJobObject(self.job.raw(), 1) };
        if terminated == 0 {
            return Err(last_error("TerminateJobObject"));
        }
        let deadline = std::time::Instant::now()
            .checked_add(self.force_timeout)
            .unwrap_or_else(std::time::Instant::now);
        loop {
            if self.active_processes()? == 0 {
                return Ok(if running {
                    StopOutcome::Exited
                } else {
                    StopOutcome::AlreadyExited
                });
            }
            if std::time::Instant::now() >= deadline {
                return Ok(StopOutcome::TimedOut);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// Reopen a named job after watchdog restart and verify its recorded
    /// leader.  This method never enumerates by process name.
    pub fn reopen(
        identity: ProcessIdentity,
        max_processes: u32,
        graceful_timeout: Duration,
        force_timeout: Duration,
    ) -> Result<Self, PlatformError> {
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
                JOB_OBJECT_QUERY | JOB_OBJECT_TERMINATE,
                0,
                wide_name.as_ptr(),
            )
        };
        let job = OwnedHandle::new(job, "OpenJobObjectW")?;
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
            graceful_timeout,
            force_timeout,
        };
        owner.verify_identity()?;
        if owner.active_processes()? > max_processes {
            return Err(PlatformError::IdentityMismatch(
                "reopened Job Object exceeds the persisted process limit".to_owned(),
            ));
        }
        if owner.is_running()? && !owner.is_member_running(owner.identity.pid)? {
            return Err(PlatformError::IdentityMismatch(
                "reopened process is not a member of its named Job Object".to_owned(),
            ));
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
        Ok(())
    }

    fn active_processes(&self) -> Result<u32, PlatformError> {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let mut returned = 0_u32;
        let ok = unsafe {
            QueryInformationJobObject(
                self.job.raw(),
                JobObjectBasicAccountingInformation,
                (&raw mut accounting).cast(),
                u32::try_from(size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>()).map_err(
                    |_| PlatformError::Invalid("Job Object accounting size overflow".to_owned()),
                )?,
                &raw mut returned,
            )
        };
        if ok == 0 {
            return Err(last_error("QueryInformationJobObject"));
        }
        Ok(accounting.ActiveProcesses)
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
        Ok(Self { config })
    }

    /// Launch a direct executable with Job Object assignment before resume.
    pub fn launch(
        &self,
        specification: &WindowsLaunchSpec,
    ) -> Result<JobOwnedProcess, PlatformError> {
        specification.validate(&self.config)?;
        validate_nonce(&specification.launch_nonce)?;
        let approved = self
            .config
            .allowlisted_executables
            .get(&specification.component)
            .ok_or_else(|| PlatformError::Unsupported("component is not allowlisted".to_owned()))?;
        let executable = canonicalize_executable(&specification.executable)?;
        let approved = canonicalize_executable(approved)?;
        if normalize_path(&executable) != normalize_path(&approved) {
            return Err(PlatformError::IdentityMismatch(
                "requested executable is outside the role allowlist".to_owned(),
            ));
        }
        let session_id = match specification.session {
            SessionSelector::ActiveUser => match select_active_session() {
                ActiveSession::Available(session) => session,
                ActiveSession::WaitingForSession => {
                    return Err(PlatformError::Unavailable(
                        "WAITING_FOR_SESSION: no active interactive user session".to_owned(),
                    ));
                }
            },
            SessionSelector::Explicit(session) => session,
        };
        let job_name = job_name(&specification.launch_nonce)?;
        let job = create_job(&job_name, self.config.max_processes)?;
        // A service normally runs in session 0.  Use the current token only
        // when the selected session is the caller's session (which keeps
        // unprivileged synthetic tests useful); otherwise obtain the target
        // interactive user's token through WTS.  HostBroker always follows
        // the same explicit session policy.
        let caller_session = current_process_session()?;
        let token = if caller_session == session_id {
            None
        } else {
            Some(query_user_token(session_id)?)
        };
        let process = spawn_suspended_with_job(
            token.as_ref().map(OwnedHandle::raw),
            &job,
            &executable,
            specification,
        )?;
        let (process_handle, thread_handle, pid) = process;
        let resumed = unsafe { ResumeThread(thread_handle.raw()) };
        if resumed == u32::MAX {
            let _ = unsafe { TerminateJobObject(job.raw(), 1) };
            return Err(last_error("ResumeThread"));
        }
        let creation_time = process_creation_time(process_handle.raw())?;
        let identity = ProcessIdentity {
            pid,
            creation_time_100ns: creation_time,
            launch_nonce: specification.launch_nonce.clone(),
            executable,
            session_id,
        };
        let owner = JobOwnedProcess {
            identity,
            process: process_handle,
            job,
            graceful_timeout: Duration::from_millis(u64::from(specification.graceful_timeout_ms)),
            force_timeout: Duration::from_millis(u64::from(specification.force_timeout_ms)),
        };
        if let Err(error) = owner.verify_identity() {
            let _ = owner.force_stop();
            return Err(error);
        }
        if process_session(pid)? != session_id {
            let _ = owner.force_stop();
            return Err(PlatformError::IdentityMismatch(
                "spawned process session differs from the selected session".to_owned(),
            ));
        }
        if !owner.is_member_running(pid)? {
            let _ = owner.force_stop();
            return Err(PlatformError::IdentityMismatch(
                "spawned process is not a member of its Job Object".to_owned(),
            ));
        }
        Ok(owner)
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
    Ok(job)
}

fn spawn_suspended_with_job(
    token: Option<HANDLE>,
    job: &OwnedHandle,
    executable: &Path,
    specification: &WindowsLaunchSpec,
) -> Result<(OwnedHandle, OwnedHandle, u32), PlatformError> {
    let mut command_line = command_line(executable, &specification.arguments)?;
    let mut environment = environment_block(&specification.environment)?;
    let current_directory = specification
        .working_directory
        .as_deref()
        .map(canonicalize_directory)
        .transpose()?;
    let executable_wide = wide_path(executable)?;
    let current_directory_wide = current_directory.as_deref().map(wide_path).transpose()?;
    let mut attribute_size = 0_usize;
    let _ = unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &raw mut attribute_size) };
    if attribute_size == 0 {
        return Err(last_error("InitializeProcThreadAttributeList(size)"));
    }
    let mut attribute_storage = vec![0_u8; attribute_size];
    let attribute_list = attribute_storage.as_mut_ptr().cast();
    let initialized =
        unsafe { InitializeProcThreadAttributeList(attribute_list, 1, 0, &raw mut attribute_size) };
    if initialized == 0 {
        return Err(last_error("InitializeProcThreadAttributeList"));
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
        return Err(last_error("UpdateProcThreadAttribute(JOB_LIST)"));
    }
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>())
        .map_err(|_| PlatformError::Invalid("STARTUPINFOEXW size overflow".to_owned()))?;
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
        return Err(last_error("CreateProcess"));
    }
    let process = OwnedHandle::new(information.hProcess, "CreateProcess process handle")?;
    let thread = OwnedHandle::new(information.hThread, "CreateProcess thread handle")?;
    Ok((process, thread, information.dwProcessId))
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
    pub session_id: u32,
    pub executable: PathBuf,
}

/// One-message local IPC server.  The object ACL is owner-only and remote
/// clients are rejected by the pipe mode; peer PID/session/image are checked
/// before a lifecycle frame is accepted.
pub struct NamedPipeServer {
    handle: OwnedHandle,
    name: String,
    connected: bool,
    peer: Option<NamedPipePeer>,
}

impl std::fmt::Debug for NamedPipeServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NamedPipeServer")
            .field("name", &self.name)
            .field("connected", &self.connected)
            .finish_non_exhaustive()
    }
}

impl NamedPipeServer {
    /// Create a one-instance owner-only named pipe.
    pub fn create(name: impl Into<String>) -> Result<Self, PlatformError> {
        let name = name.into();
        validate_pipe_name(&name)?;
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
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
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
        })
    }

    /// Block until one local client connects, then capture its PID/session and
    /// executable.  A later call must explicitly authenticate that peer.
    pub fn accept(&mut self) -> Result<NamedPipePeer, PlatformError> {
        if self.connected {
            return Err(PlatformError::Invalid(
                "named pipe already has a connected client".to_owned(),
            ));
        }
        let result = unsafe { ConnectNamedPipe(self.handle.raw(), null_mut()) };
        if result == 0 && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
            return Err(last_error("ConnectNamedPipe"));
        }
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
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                process_id,
            )
        };
        let process = OwnedHandle::new(process, "OpenProcess(pipe peer)")?;
        let executable = query_image_path(process.raw())?;
        let peer = NamedPipePeer {
            process_id,
            session_id,
            executable,
        };
        self.connected = true;
        self.peer = Some(peer.clone());
        Ok(peer)
    }

    /// Verify peer session and exact executable before consuming a lifecycle
    /// request.  The pipe ACL is the user boundary; PID is only a rechecked
    /// diagnostic identity and is never accepted as sole authorization.
    pub fn authenticate_peer(
        &self,
        expected_session: Option<u32>,
        expected_executable: &Path,
    ) -> Result<&NamedPipePeer, PlatformError> {
        let peer = self
            .peer
            .as_ref()
            .ok_or_else(|| PlatformError::Invalid("named pipe has no accepted peer".to_owned()))?;
        if expected_session.is_some_and(|session| session != peer.session_id) {
            return Err(PlatformError::IdentityMismatch(
                "named-pipe peer session is not approved".to_owned(),
            ));
        }
        let expected = canonicalize_executable(expected_executable)?;
        if normalize_path(&expected) != normalize_path(&peer.executable) {
            return Err(PlatformError::IdentityMismatch(
                "named-pipe peer executable is not approved".to_owned(),
            ));
        }
        Ok(peer)
    }

    /// Read one bounded lifecycle frame.  The protocol is closed and length
    /// prefixed; no arbitrary command text is accepted.
    pub fn read_request(&mut self) -> Result<LifecycleRequest, PlatformError> {
        if !self.connected {
            return Err(PlatformError::Invalid(
                "named pipe has no connected client".to_owned(),
            ));
        }
        let mut length = [0_u8; 4];
        read_exact(self.handle.raw(), &mut length)?;
        let length = usize::try_from(u32::from_le_bytes(length))
            .map_err(|_| PlatformError::Invalid("lifecycle frame length overflow".to_owned()))?;
        if length == 0 || length > MAX_PIPE_FRAME {
            return Err(PlatformError::Invalid(
                "lifecycle frame exceeds bounds".to_owned(),
            ));
        }
        let mut payload = vec![0_u8; length];
        read_exact(self.handle.raw(), &mut payload)?;
        LifecycleRequest::decode_payload(&payload)
    }

    /// Write one bounded acknowledgement payload.
    pub fn write_request(&mut self, request: &LifecycleRequest) -> Result<(), PlatformError> {
        if !self.connected {
            return Err(PlatformError::Invalid(
                "named pipe has no connected client".to_owned(),
            ));
        }
        let payload = request.encode_payload()?;
        let length = u32::try_from(payload.len())
            .map_err(|_| PlatformError::Invalid("lifecycle frame length overflow".to_owned()))?;
        write_all(self.handle.raw(), &length.to_le_bytes())?;
        write_all(self.handle.raw(), &payload)?;
        let flushed = unsafe { FlushFileBuffers(self.handle.raw()) };
        if flushed == 0 {
            return Err(last_error("FlushFileBuffers"));
        }
        Ok(())
    }

    /// Disconnect and make the one-instance endpoint available for the next
    /// bounded connection.
    pub fn disconnect(&mut self) -> Result<(), PlatformError> {
        if self.connected {
            let ok = unsafe { DisconnectNamedPipe(self.handle.raw()) };
            if ok == 0 {
                return Err(last_error("DisconnectNamedPipe"));
            }
        }
        self.connected = false;
        self.peer = None;
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
    /// Install an automatic own-process service and bounded restart actions.
    pub fn install(&self) -> Result<(), PlatformError> {
        if self.service_name != SERVICE_NAME {
            return Err(PlatformError::Invalid(
                "service name is not the fixed ascension-watchdog name".to_owned(),
            ));
        }
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
            launch_arguments: vec!["daemon".into()],
            dependencies: Vec::new(),
            account_name: None,
            account_password: None,
        };
        let service_access = ServiceAccess::QUERY_STATUS
            | ServiceAccess::START
            | ServiceAccess::STOP
            | ServiceAccess::CHANGE_CONFIG;
        let service = match manager.create_service(&info, service_access) {
            Ok(service) => service,
            Err(error) if service_exists(&error) => manager
                .open_service(&self.service_name, service_access)
                .map_err(service_error("OpenService(existing)"))?,
            Err(error) => return Err(service_error("CreateService")(error)),
        };
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
        Ok(())
    }
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
                ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
            )
            .map_err(service_error("OpenService(health checker)"))?;
        service
            .stop()
            .map_err(service_error("ControlService(stop)"))?;
        Ok(true)
    }
}

/// Service runtime callback.  The callback must call its real reconciliation
/// loop and return when the SCM stop flag is observed.
pub struct ServiceRuntime;

impl ServiceRuntime {
    /// Enter the SCM dispatcher for the fixed service name.
    pub fn run<F>(reconcile: F) -> Result<(), PlatformError>
    where
        F: Fn(Arc<Mutex<bool>>) + Send + Sync + 'static,
    {
        SERVICE_RECONCILE.set(Arc::new(reconcile)).map_err(|_| {
            PlatformError::Unavailable("service runtime was already initialized".to_owned())
        })?;
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .map_err(service_error("service dispatcher"))
    }
}

windows_service::define_windows_service!(ffi_service_main, dispatch_service_main);

fn dispatch_service_main(arguments: Vec<std::ffi::OsString>) {
    if let Some(reconcile) = SERVICE_RECONCILE.get() {
        let _ = service_entry(arguments, reconcile);
    }
}

fn service_entry<F>(
    _arguments: Vec<std::ffi::OsString>,
    reconcile: &Arc<F>,
) -> Result<(), PlatformError>
where
    F: Fn(Arc<Mutex<bool>>) + Send + Sync + 'static + ?Sized,
{
    let stopping = Arc::new(Mutex::new(false));
    let stop_flag = Arc::clone(&stopping);
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            if let Ok(mut value) = stop_flag.lock() {
                *value = true;
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(SERVICE_NAME, handler)
        .map_err(service_error("RegisterServiceCtrlHandler"))?;
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
    reconcile(stopping);
    status
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: windows_service::service::ServiceControlAccept::empty(),
            exit_code: windows_service::service::ServiceExitCode::Win32(ERROR_SUCCESS),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .map_err(service_error("SetServiceStatus(Stopped)"))?;
    Ok(())
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(raw: HANDLE, operation: &str) -> Result<Self, PlatformError> {
        if raw.is_null() {
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

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
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
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

fn read_exact(handle: HANDLE, buffer: &mut [u8]) -> Result<(), PlatformError> {
    let mut offset = 0_usize;
    while offset < buffer.len() {
        let remaining = &mut buffer[offset..];
        let count = u32::try_from(remaining.len())
            .map_err(|_| PlatformError::Invalid("pipe read exceeds bounds".to_owned()))?;
        let mut read = 0_u32;
        let ok = unsafe {
            ReadFile(
                handle,
                remaining.as_mut_ptr(),
                count,
                &raw mut read,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error("ReadFile"));
        }
        if read == 0 {
            return Err(PlatformError::Unavailable(
                "named pipe closed before frame completion".to_owned(),
            ));
        }
        offset = offset.saturating_add(
            usize::try_from(read)
                .map_err(|_| PlatformError::Invalid("pipe read count overflow".to_owned()))?,
        );
    }
    Ok(())
}

fn write_all(handle: HANDLE, buffer: &[u8]) -> Result<(), PlatformError> {
    let mut offset = 0_usize;
    while offset < buffer.len() {
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
        if ok == 0 {
            return Err(last_error("WriteFile"));
        }
        if written == 0 {
            return Err(PlatformError::Unavailable(
                "named pipe made no write progress".to_owned(),
            ));
        }
        offset = offset.saturating_add(
            usize::try_from(written)
                .map_err(|_| PlatformError::Invalid("pipe write count overflow".to_owned()))?,
        );
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
    let mut line = quote_windows(executable.to_string_lossy().as_ref());
    for argument in arguments {
        line.push(' ');
        line.push_str(&quote_windows(argument));
    }
    wide(&line)
}

fn quote_windows(value: &str) -> String {
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        let mut quoted = String::from('"');
        let mut slashes = 0_usize;
        for character in value.chars() {
            if character == '\\' {
                slashes += 1;
            } else if character == '"' {
                quoted.extend(std::iter::repeat_n(
                    '\\',
                    slashes.saturating_mul(2).saturating_add(1),
                ));
                quoted.push(character);
                slashes = 0;
            } else {
                quoted.extend(std::iter::repeat_n('\\', slashes));
                quoted.push(character);
                slashes = 0;
            }
        }
        quoted.extend(std::iter::repeat_n('\\', slashes.saturating_mul(2)));
        quoted.push('"');
        quoted
    } else {
        value.to_owned()
    }
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

fn last_error(operation: &str) -> PlatformError {
    PlatformError::Win32 {
        operation: operation.to_owned(),
        code: unsafe { GetLastError() },
    }
}

fn service_exists(error: &windows_service::Error) -> bool {
    matches!(
        error,
        windows_service::Error::Winapi(error)
            if error.raw_os_error() == Some(ERROR_SERVICE_EXISTS.cast_signed())
    )
}

fn service_error(operation: &'static str) -> impl Fn(windows_service::Error) -> PlatformError {
    move |error| PlatformError::Io(format!("{operation}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_quoting_preserves_backslashes_before_quotes() {
        assert_eq!(quote_windows("plain"), "plain");
        assert_eq!(quote_windows("a b"), "\"a b\"");
        assert_eq!(quote_windows(r#"a\\\"b"#), r#"\"a\\\\\\\"b\""#);
    }

    #[test]
    fn invalid_nonce_and_pipe_namespace_are_rejected() {
        assert!(validate_nonce("../old").is_err());
        assert!(validate_pipe_name(r"\\.\pipe\other").is_err());
    }
}
