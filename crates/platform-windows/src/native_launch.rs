//! Suspended launch and bootstrap handoff.
//!
//! Owns the role-allowlisted launcher facade: canonical executable selection,
//! `CreateProcess` with `CREATE_SUSPENDED` and
//! `PROC_THREAD_ATTRIBUTE_JOB_LIST` assignment before `ResumeThread`, the
//! worker/Gateway bootstrap pipe handoff, the post-creation cleanup
//! classification that keeps the exact Job Object authoritative, and the
//! session/token selection used to pick the child's session.
//!
//! Extracted verbatim from `native.rs`; the guarantee that a child cannot
//! execute before Job assignment, the explicit inherited-handle list, the
//! bootstrap frame bounds, and the post-creation cleanup uncertainty are
//! unchanged.  Items still used by the coordinator are re-exported from
//! `native` under their original names.

use super::{
    Arc, AtomicBool, BTreeMap, CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, CreatePipe, CreateProcessAsUserW, CreateProcessW,
    DeleteProcThreadAttributeList, Duration, EXTENDED_STARTUPINFO_PRESENT,
    GATEWAY_HEALTH_BOOTSTRAP_FRAME_BYTES, GatewayHealthBootstrapLaunch, GetLastError, HANDLE,
    HANDLE_FLAG_INHERIT, InitializeProcThreadAttributeList, Instant, IntegrityGuards,
    JobOwnedProcess, MAX_WORKER_BOOTSTRAP_FRAME_BYTES, OwnedHandle, PIPE_NOWAIT,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, Path, PlatformError,
    ProcessIdentity, ResumeThread, SECURITY_ATTRIBUTES, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    SessionSelector, SetHandleInformation, SetNamedPipeHandleState, StopOutcome,
    UpdateProcThreadAttribute, WTSGetActiveConsoleSessionId, WTSQueryUserToken, WindowsLaunchSpec,
    WindowsPlatformConfig, WorkerBootstrapLaunch, WriteFile, align_of, c_void,
    canonicalize_directory, canonicalize_executable, close_raw_handle, create_job, job_name,
    last_error, normalize_path, null, null_mut, open_planned_job, process_creation_time,
    process_session, size_of, terminate_job_and_wait, validate_nonce,
    validate_planned_job_cleanup_timeout, wide, wide_path, win32_error,
};

const WORKER_BOOTSTRAP_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const GATEWAY_HEALTH_BOOTSTRAP_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
// CreatePipe's size is a requested buffer size, not a promise of overlapped
// I/O.  The worker frame is written once, while the child remains suspended,
// so the complete bounded frame fits in the requested pipe buffer.  See the
// evidence note for the resulting synchronous-call deadline limitation.
const WORKER_PIPE_BUFFER_BYTES: usize = MAX_WORKER_BOOTSTRAP_FRAME_BYTES;
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
/// Launcher for fixed, role-allowlisted executables.
#[derive(Debug)]
pub struct WindowsProcessLauncher {
    config: WindowsPlatformConfig,
}

/// Typed startup material selected by the role-specific launch method.
/// Worker and Gateway frames cannot cross each other's admission path.
enum LaunchBootstrap<'a> {
    Worker(&'a WorkerBootstrapLaunch),
    Gateway(&'a GatewayHealthBootstrapLaunch),
}

impl LaunchBootstrap<'_> {
    fn frame(&self) -> &[u8] {
        match self {
            Self::Worker(launch) => launch.frame(),
            Self::Gateway(launch) => launch.frame(),
        }
    }

    fn max_frame_bytes(&self) -> usize {
        match self {
            Self::Worker(_) => MAX_WORKER_BOOTSTRAP_FRAME_BYTES,
            Self::Gateway(_) => GATEWAY_HEALTH_BOOTSTRAP_FRAME_BYTES,
        }
    }

    fn write_timeout(&self) -> Duration {
        match self {
            Self::Worker(_) => WORKER_BOOTSTRAP_WRITE_TIMEOUT,
            Self::Gateway(_) => GATEWAY_HEALTH_BOOTSTRAP_WRITE_TIMEOUT,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Worker(_) => "worker bootstrap",
            Self::Gateway(_) => "Gateway health bootstrap",
        }
    }
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
        terminate_job_and_wait(&job, force_timeout, None)
    }

    /// Launch a direct executable with Job Object assignment before resume.
    pub fn launch(
        &self,
        specification: &WindowsLaunchSpec,
    ) -> Result<JobOwnedProcess, WindowsLaunchError> {
        self.launch_inner(specification, None, || Ok(()))
    }

    /// Launch a Harness worker and invoke the durable authorization barrier
    /// immediately before `ResumeThread`.
    ///
    /// The callback runs only after executable identity, Job Object
    /// assignment, and complete worker-frame handoff have succeeded.  A
    /// callback error is treated as a post-spawn failure and the exact Job is
    /// cleaned up before the error is returned. A successful callback's guard
    /// is retained through `ResumeThread`, then dropped to release admission.
    pub fn launch_with_worker_bootstrap_and_barrier<F, G>(
        &self,
        specification: &WindowsLaunchSpec,
        worker: &WorkerBootstrapLaunch,
        before_resume: F,
    ) -> Result<JobOwnedProcess, WindowsLaunchError>
    where
        F: FnOnce() -> Result<G, PlatformError>,
    {
        if specification.component != crate::contract::ComponentKind::Harness {
            return Err(WindowsLaunchError::Ordinary(PlatformError::Unsupported(
                "Windows worker bootstrap is only valid for the Harness role".to_owned(),
            )));
        }
        worker.validate().map_err(WindowsLaunchError::Ordinary)?;
        let bootstrap = LaunchBootstrap::Worker(worker);
        self.launch_inner(specification, Some(&bootstrap), before_resume)
    }

    /// Launch the exact Gateway executable with one fixed health frame and
    /// invoke the durable authorization barrier immediately before
    /// `ResumeThread`.
    ///
    /// The frame is handed over through a dedicated anonymous pipe while the
    /// child is suspended.  It is never copied into the launch specification,
    /// command line, or environment block.  Any post-spawn failure is cleaned
    /// up through the exact named Job Object before being returned.
    pub fn launch_with_gateway_health_bootstrap_and_barrier<F, G>(
        &self,
        specification: &WindowsLaunchSpec,
        gateway_health: &GatewayHealthBootstrapLaunch,
        before_resume: F,
    ) -> Result<JobOwnedProcess, WindowsLaunchError>
    where
        F: FnOnce() -> Result<G, PlatformError>,
    {
        gateway_health
            .validate_for_launch(specification)
            .map_err(WindowsLaunchError::Ordinary)?;
        let bootstrap = LaunchBootstrap::Gateway(gateway_health);
        self.launch_inner_with_pipe_buffer(
            specification,
            Some(&bootstrap),
            GATEWAY_HEALTH_BOOTSTRAP_FRAME_BYTES,
            before_resume,
        )
    }

    /// Exercise a deliberately undersized anonymous worker pipe in a native
    /// regression test.  This hook is compiled only with the private
    /// `native-worker-test-hooks` feature and is not part of the production
    /// launch surface.
    #[cfg(feature = "native-worker-test-hooks")]
    pub fn launch_with_worker_bootstrap_with_pipe_buffer_for_test<F>(
        &self,
        specification: &WindowsLaunchSpec,
        worker: &WorkerBootstrapLaunch,
        pipe_buffer_bytes: usize,
        before_resume: F,
    ) -> Result<JobOwnedProcess, WindowsLaunchError>
    where
        F: FnOnce() -> Result<(), PlatformError>,
    {
        if specification.component != crate::contract::ComponentKind::Harness {
            return Err(WindowsLaunchError::Ordinary(PlatformError::Unsupported(
                "Windows worker bootstrap is only valid for the Harness role".to_owned(),
            )));
        }
        worker.validate().map_err(WindowsLaunchError::Ordinary)?;
        let bootstrap = LaunchBootstrap::Worker(worker);
        self.launch_inner_with_pipe_buffer(
            specification,
            Some(&bootstrap),
            pipe_buffer_bytes,
            before_resume,
        )
    }

    fn launch_inner<F, G>(
        &self,
        specification: &WindowsLaunchSpec,
        bootstrap: Option<&LaunchBootstrap<'_>>,
        before_resume: F,
    ) -> Result<JobOwnedProcess, WindowsLaunchError>
    where
        F: FnOnce() -> Result<G, PlatformError>,
    {
        self.launch_inner_with_pipe_buffer(
            specification,
            bootstrap,
            WORKER_PIPE_BUFFER_BYTES,
            before_resume,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn launch_inner_with_pipe_buffer<F, G>(
        &self,
        specification: &WindowsLaunchSpec,
        bootstrap: Option<&LaunchBootstrap<'_>>,
        pipe_buffer_bytes: usize,
        before_resume: F,
    ) -> Result<JobOwnedProcess, WindowsLaunchError>
    where
        F: FnOnce() -> Result<G, PlatformError>,
    {
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
        let caller_session = current_process_session().map_err(WindowsLaunchError::Ordinary)?;
        let session_id = match specification.session {
            SessionSelector::ActiveUser => match select_active_session() {
                ActiveSession::Available(session) => session,
                ActiveSession::WaitingForSession => {
                    return Err(WindowsLaunchError::Ordinary(PlatformError::Unavailable(
                        "WAITING_FOR_SESSION: no active interactive user session".to_owned(),
                    )));
                }
            },
            SessionSelector::CurrentService => caller_session,
            SessionSelector::Explicit(0) if caller_session != 0 => {
                return Err(WindowsLaunchError::Ordinary(PlatformError::Unavailable(
                    "explicit service session 0 requires a session-0 controller".to_owned(),
                )));
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
            bootstrap,
            pipe_buffer_bytes,
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
        // Establish the live ownership witness while the child is still
        // suspended. A legitimate short-lived child must not race its first
        // image/session/membership verification after resumption.
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
            live_identity_verified: AtomicBool::new(false),
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
        // Retain the caller's admission reservation across ResumeThread. A
        // durable operator Stop cannot commit in the check-to-resume interval
        // when the caller returns its owner-local transaction guard here.
        let admission_guard = match before_resume() {
            Ok(guard) => guard,
            Err(error) => {
                return Err(classify_spawn_cleanup(&owner.job, force_timeout, error));
            }
        };
        let resumed = unsafe { ResumeThread(thread_handle.raw()) };
        let resume_error = (resumed == u32::MAX).then(|| last_error("ResumeThread"));
        drop(admission_guard);
        if let Some(error) = resume_error {
            return Err(classify_spawn_cleanup(&owner.job, force_timeout, error));
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
    match terminate_job_and_wait(job, force_timeout, None) {
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
pub(crate) enum SpawnFailure {
    BeforeCreate(PlatformError),
    Created(PlatformError),
}

impl From<PlatformError> for SpawnFailure {
    fn from(error: PlatformError) -> Self {
        Self::BeforeCreate(error)
    }
}

/// Dedicated anonymous bootstrap stdin endpoints.  The reader is inheritable
/// and appears in the explicit child handle list; the writer is parent-only.
struct BootstrapPipe {
    reader: OwnedHandle,
    writer: OwnedHandle,
}

impl BootstrapPipe {
    fn create(
        buffer_bytes: usize,
        label: &str,
        max_frame_bytes: usize,
    ) -> Result<Self, PlatformError> {
        if buffer_bytes == 0 || buffer_bytes > max_frame_bytes {
            return Err(PlatformError::Invalid(format!(
                "{label} pipe buffer is outside the fixed frame bound"
            )));
        }
        let mut reader = null_mut();
        let mut writer = null_mut();
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).map_err(|_| {
                PlatformError::Invalid("worker pipe SECURITY_ATTRIBUTES size overflow".to_owned())
            })?,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        let size = u32::try_from(buffer_bytes).map_err(|_| {
            PlatformError::Invalid(format!("{label} pipe buffer size exceeds Win32 bounds"))
        })?;
        let created = unsafe {
            CreatePipe(
                &raw mut reader,
                &raw mut writer,
                &raw const attributes,
                size,
            )
        };
        if created == 0 {
            return Err(last_error("CreatePipe(bootstrap)"));
        }
        let reader = match OwnedHandle::new(reader, "CreatePipe(bootstrap reader)") {
            Ok(handle) => handle,
            Err(error) => {
                close_raw_handle(writer);
                return Err(error);
            }
        };
        let writer = match OwnedHandle::new(writer, "CreatePipe(bootstrap writer)") {
            Ok(handle) => handle,
            Err(error) => {
                drop(reader);
                return Err(error);
            }
        };
        // `CreatePipe` marks both endpoints inheritable when requested.  Only
        // the reader is approved for the child; the parent writer must never
        // cross the CreateProcess boundary even if another launch path later
        // enables ordinary handle inheritance.
        let inherit_mask = HANDLE_FLAG_INHERIT;
        if unsafe { SetHandleInformation(writer.raw(), inherit_mask, 0) } == 0 {
            return Err(last_error("SetHandleInformation(bootstrap writer)"));
        }
        // Anonymous pipes are implemented by named-pipe handles and support
        // the documented PIPE_NOWAIT compatibility mode.  This is not
        // overlapped/asynchronous I/O, but it guarantees that WriteFile
        // returns immediately instead of waiting for the suspended child to
        // drain the pipe.
        let mode = PIPE_NOWAIT;
        if unsafe { SetNamedPipeHandleState(writer.raw(), &raw const mode, null(), null()) } == 0 {
            return Err(last_error("SetNamedPipeHandleState(bootstrap writer)"));
        }
        Ok(Self { reader, writer })
    }
}

/// Write one complete bootstrap frame through the `PIPE_NOWAIT` anonymous writer.
/// Because the child remains suspended, a partial write cannot make progress;
/// it fails closed and the caller retains the exact Job Object for cleanup.
fn write_bootstrap(
    pipe: BootstrapPipe,
    frame: &[u8],
    max_frame_bytes: usize,
    timeout: Duration,
    label: &str,
) -> Result<(), PlatformError> {
    let BootstrapPipe { reader, writer } = pipe;
    drop(reader);
    if frame.is_empty() || frame.len() > max_frame_bytes {
        drop(writer);
        return Err(PlatformError::Invalid(format!(
            "{label} frame exceeds bounds"
        )));
    }
    let count = u32::try_from(frame.len())
        .map_err(|_| PlatformError::Invalid(format!("{label} frame exceeds Win32 bounds")))?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    if Instant::now() >= deadline {
        return Err(PlatformError::Timeout(format!(
            "{label} pipe write deadline elapsed"
        )));
    }
    let mut written = 0_u32;
    let ok = unsafe {
        WriteFile(
            writer.raw(),
            frame.as_ptr().cast(),
            count,
            &raw mut written,
            null_mut(),
        )
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        if code == windows_sys::Win32::Foundation::ERROR_NO_DATA
            || code == windows_sys::Win32::Foundation::ERROR_PIPE_LISTENING
        {
            return Err(PlatformError::Timeout(format!(
                "{label} pipe cannot accept the complete frame without blocking"
            )));
        }
        return Err(win32_error("WriteFile(bootstrap)", code));
    }
    if written != count {
        return Err(PlatformError::Unavailable(format!(
            "{label} pipe accepted only a partial frame"
        )));
    }
    if Instant::now() >= deadline {
        return Err(PlatformError::Timeout(format!(
            "{label} pipe write exceeded its deadline"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn spawn_suspended_with_job(
    token: Option<HANDLE>,
    job: &OwnedHandle,
    executable: &Path,
    specification: &WindowsLaunchSpec,
    bootstrap: Option<&LaunchBootstrap<'_>>,
    pipe_buffer_bytes: usize,
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
    if let Some(LaunchBootstrap::Worker(worker)) = bootstrap {
        if specification.component != crate::contract::ComponentKind::Harness {
            return Err(PlatformError::Unsupported(
                "Windows worker bootstrap is only valid for the Harness role".to_owned(),
            )
            .into());
        }
        worker.validate()?;
    }
    if let Some(LaunchBootstrap::Gateway(gateway)) = bootstrap {
        if specification.component != crate::contract::ComponentKind::Gateway {
            return Err(PlatformError::Unsupported(
                "Gateway health bootstrap is only valid for the Gateway role".to_owned(),
            )
            .into());
        }
        gateway.validate_for_launch(specification)?;
    }
    let bootstrap_pipe = bootstrap
        .map(|launch| {
            BootstrapPipe::create(pipe_buffer_bytes, launch.label(), launch.max_frame_bytes())
        })
        .transpose()?;
    let mut attribute_size = 0_usize;
    let attribute_count = if bootstrap_pipe.is_some() { 2 } else { 1 };
    let _ = unsafe {
        InitializeProcThreadAttributeList(null_mut(), attribute_count, 0, &raw mut attribute_size)
    };
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
    let initialized = unsafe {
        InitializeProcThreadAttributeList(
            attribute_list,
            attribute_count,
            0,
            &raw mut attribute_size,
        )
    };
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
    let bootstrap_handle_list = bootstrap_pipe.as_ref().map(|pipe| [pipe.reader.raw()]);
    if let Some(handles) = bootstrap_handle_list.as_ref() {
        let updated = unsafe {
            UpdateProcThreadAttribute(
                attribute_list,
                0,
                usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST).map_err(|_| {
                    PlatformError::Invalid("bootstrap handle-list attribute overflow".to_owned())
                })?,
                handles.as_ptr().cast::<c_void>(),
                size_of::<HANDLE>(),
                null_mut(),
                null_mut(),
            )
        };
        if updated == 0 {
            unsafe { DeleteProcThreadAttributeList(attribute_list) };
            return Err(last_error("UpdateProcThreadAttribute(HANDLE_LIST)").into());
        }
    }
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>())
        .map_err(|_| PlatformError::Invalid("STARTUPINFOEXW size overflow".to_owned()))?;
    startup.StartupInfo.lpDesktop = desktop
        .as_ref()
        .map_or(null_mut(), |value| value.as_ptr().cast_mut());
    if let Some(pipe) = bootstrap_pipe.as_ref() {
        startup.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = pipe.reader.raw();
    }
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
    let inherit_handles = i32::from(bootstrap_pipe.is_some());
    let result = unsafe {
        match token {
            Some(token) => CreateProcessAsUserW(
                token,
                executable_wide.as_ptr(),
                command_line.as_mut_ptr(),
                null(),
                null(),
                inherit_handles,
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
                inherit_handles,
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
    if let Some(pipe) = bootstrap_pipe {
        let Some(bootstrap) = bootstrap else {
            drop(thread);
            drop(process);
            return Err(PlatformError::Invalid(
                "bootstrap pipe was created without frame bytes".to_owned(),
            )
            .into());
        };
        if let Err(error) = write_bootstrap(
            pipe,
            bootstrap.frame(),
            bootstrap.max_frame_bytes(),
            bootstrap.write_timeout(),
            bootstrap.label(),
        ) {
            drop(thread);
            drop(process);
            return Err(SpawnFailure::Created(error));
        }
    }
    Ok((process, thread, pid))
}

pub(crate) fn wrap_created_process_handles(
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

pub(crate) fn duration_to_millis(duration: Duration) -> Result<u32, PlatformError> {
    let millis = duration.as_millis();
    if millis == 0 || millis > u128::from(u32::MAX) {
        return Err(PlatformError::Invalid(
            "Windows stop timeout is outside the Win32 wait bound".to_owned(),
        ));
    }
    u32::try_from(millis)
        .map_err(|_| PlatformError::Invalid("Windows stop timeout overflow".to_owned()))
}

pub(crate) fn validate_stop_timeouts(
    graceful: Duration,
    force: Duration,
) -> Result<(), PlatformError> {
    if graceful.is_zero() || force.is_zero() || force < graceful {
        return Err(PlatformError::Invalid(
            "Windows stop deadlines are invalid".to_owned(),
        ));
    }
    let _ = duration_to_millis(graceful)?;
    let _ = duration_to_millis(force)?;
    Ok(())
}
