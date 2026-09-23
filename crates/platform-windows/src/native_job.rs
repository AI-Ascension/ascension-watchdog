//! Job containment and process lifecycle.
//!
//! Owns the ACL-protected named Job Object boundary: the `JobOwnedProcess`
//! owner, job creation with an owner-only security descriptor, the exact
//! process/job limit queries and verification, prepared-job recovery, the
//! bounded terminate-and-wait stop path with its `StopOutcome`, and the
//! nonce-bound job naming helpers.
//!
//! Extracted verbatim from `native.rs`; process identity checks, nonce-bound
//! recovery, protected job ownership and the positive empty-containment
//! evidence are unchanged.  Items still used by the coordinator, the launcher
//! or the service runtime are re-exported from `native` under their original
//! names.

use super::{
    Arc, AtomicBool, CreateJobObjectW, Duration, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND,
    ERROR_INVALID_PARAMETER, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, EqualSid, GetCurrentProcess,
    GetLastError, GetProcessId, GetSecurityDescriptorOwner, GetTokenInformation, HANDLE,
    INVALID_HANDLE_VALUE, Instant, IntegrityGuards, IsProcessInJob,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, JOB_OBJECT_QUERY,
    JOB_OBJECT_TERMINATE, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, OpenProcess, OpenProcessToken, Ordering, OwnedHandle,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PSECURITY_DESCRIPTOR, PSID,
    PlatformError, ProcessIdentity, QueryInformationJobObject, READ_CONTROL, SECURITY_ATTRIBUTES,
    SecurityDescriptor, SetInformationJobObject, TOKEN_QUERY, TOKEN_USER, TerminateJobObject,
    TokenUser, WAIT_OBJECT_0, WAIT_TIMEOUT, WaitForSingleObject, c_void, canonicalize_executable,
    duration_to_millis, last_error, normalize_path, null_mut, process_creation_time,
    process_session, query_image_path, size_of, thread, validate_nonce, validate_stop_timeouts,
    wide, win32_error,
};

const JOB_NAME_PREFIX: &str = r"Local\ascension-watchdog-";

pub(crate) const PLANNED_JOB_PREFIX: &str = "windows-job:";
const MAX_PLANNED_JOB_CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
const JOB_EMPTY_SETTLE_DELAY: Duration = Duration::from_millis(25);

/// A process launched in an ACL-protected named Job Object.
pub struct JobOwnedProcess {
    pub(crate) identity: ProcessIdentity,
    pub(crate) process: OwnedHandle,
    pub(crate) job: OwnedHandle,
    pub(crate) integrity: Arc<IntegrityGuards>,
    pub(crate) graceful_timeout: Duration,
    pub(crate) force_timeout: Duration,
    pub(crate) live_identity_verified: AtomicBool,
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
    /// Capture account/session policy from this supervisor-owned process
    /// handle. This is not an observation of an untrusted IPC endpoint.
    pub fn account_identity(&self) -> Result<(String, u32), PlatformError> {
        self.verify_identity()?;
        let account = crate::admin_pipe::process_user_sid(self.process.raw())?;
        Ok((account, self.identity.session_id))
    }

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
        terminate_job_and_wait(&self.job, self.force_timeout, Some(self.process.raw()))
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
            live_identity_verified: AtomicBool::new(false),
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

    pub(crate) fn verify_identity(&self) -> Result<(), PlatformError> {
        let live_identity_verified = self.live_identity_verified.load(Ordering::Acquire);
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
        if self.identity.executable_sha256 != self.integrity.digest() {
            return Err(PlatformError::IdentityMismatch(
                "recorded executable digest differs from the immutable release handle".to_owned(),
            ));
        }
        let process_state = unsafe { WaitForSingleObject(self.process.raw(), 0) };
        if process_state != WAIT_TIMEOUT && process_state != WAIT_OBJECT_0 {
            return Err(PlatformError::Win32 {
                operation: "WaitForSingleObject(identity)".to_owned(),
                code: process_state,
            });
        }
        if live_identity_verified {
            // The witness is private to this held owner and is set only after
            // the live process passed the image, session, and Job membership
            // checks below. Keep validating the held handle's PID, creation
            // token, immutable digest, and wait state above on every call,
            // then avoid re-querying metadata that Windows may withdraw while
            // TerminateProcess is still making the same process object
            // signaled. A reopened owner starts with no witness and cannot
            // inherit this fast path from serialized identity fields.
            return Ok(());
        }
        if process_state == WAIT_OBJECT_0 {
            return Err(PlatformError::IdentityMismatch(
                "terminal process has no previously verified live ownership witness".to_owned(),
            ));
        }
        let executable = query_image_path(self.process.raw())?;
        if normalize_path(&executable) != normalize_path(&self.identity.executable) {
            return Err(PlatformError::IdentityMismatch(
                "process executable differs from recorded identity".to_owned(),
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
            self.live_identity_verified.store(true, Ordering::Release);
        } else if process_state == WAIT_OBJECT_0 && !live_identity_verified {
            return Err(PlatformError::IdentityMismatch(
                "process exited before its live ownership witness was verified".to_owned(),
            ));
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

pub(crate) fn create_job(name: &str, max_processes: u32) -> Result<OwnedHandle, PlatformError> {
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

pub(crate) fn open_planned_job(
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

pub(crate) fn terminate_job_and_wait(
    job: &OwnedHandle,
    force_timeout: Duration,
    leader: Option<HANDLE>,
) -> Result<StopOutcome, PlatformError> {
    let active = active_processes(job)?;
    if active == 0 {
        return Ok(StopOutcome::AlreadyExited);
    }
    let terminated = unsafe { TerminateJobObject(job.raw(), 1) };
    if terminated == 0 {
        return Err(last_error("TerminateJobObject"));
    }
    let deadline = Instant::now()
        .checked_add(force_timeout)
        .unwrap_or_else(Instant::now);
    let mut empty_since = None;
    loop {
        if active_processes(job)? == 0 {
            let observed_at = *empty_since.get_or_insert_with(Instant::now);
            let leader_exited = match leader {
                Some(process) => match unsafe { WaitForSingleObject(process, 0) } {
                    WAIT_OBJECT_0 => true,
                    WAIT_TIMEOUT => false,
                    code => {
                        return Err(PlatformError::Win32 {
                            operation: "WaitForSingleObject(job leader)".to_owned(),
                            code,
                        });
                    }
                },
                None => true,
            };
            if leader_exited
                && (leader.is_some() || observed_at.elapsed() >= JOB_EMPTY_SETTLE_DELAY)
            {
                return Ok(StopOutcome::Exited);
            }
        } else {
            empty_since = None;
        }
        if Instant::now() >= deadline {
            return Ok(StopOutcome::TimedOut);
        }
        thread::sleep(
            Duration::from_millis(25).min(deadline.saturating_duration_since(Instant::now())),
        );
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

pub(crate) fn job_name(nonce: &str) -> Result<String, PlatformError> {
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

pub(crate) fn validate_planned_job_cleanup_timeout(timeout: Duration) -> Result<(), PlatformError> {
    if timeout.is_zero() || timeout > MAX_PLANNED_JOB_CLEANUP_TIMEOUT {
        return Err(PlatformError::Invalid(
            "planned Job Object cleanup deadline is outside the 1ms..=30s bound".to_owned(),
        ));
    }
    let _ = duration_to_millis(timeout)?;
    Ok(())
}
