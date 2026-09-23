//! Lifecycle named-pipe transport.
//!
//! Owns the owner-only, one-instance lifecycle named pipe: peer capture and
//! identity verification, executable/session authentication, the durable
//! epoch/nonce replay window, the bounded length-prefixed frame reader and
//! writer, and the cancel/disconnect reset path.
//!
//! Extracted verbatim from `native.rs`; the owner-only ACL, the fixed local
//! pipe namespace, remote-client rejection, peer-identity revalidation and
//! the replay-window monotonicity are unchanged.  The public transport types
//! are re-exported from `native` under their original names.

use super::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, Duration, ERROR_BROKEN_PIPE,
    ERROR_MORE_DATA, ERROR_NO_DATA, ERROR_NOT_FOUND, ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED,
    ERROR_PIPE_LISTENING, ERROR_PIPE_NOT_CONNECTED, ERROR_SUCCESS, FILE_FLAG_FIRST_PIPE_INSTANCE,
    GetLastError, GetNamedPipeClientProcessId, GetNamedPipeClientSessionId, GetProcessId, HANDLE,
    Instant, LifecycleFrame, LifecycleRequest, OpenProcess, OwnedHandle, PIPE_ACCESS_DUPLEX,
    PIPE_NOWAIT, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, Path, PathBuf, PlatformError, ReadFile,
    SECURITY_ATTRIBUTES, SecurityDescriptor, WindowsPlatformConfig, WriteFile,
    canonicalize_executable, last_error, normalize_path, null, null_mut, process_creation_time,
    process_session, query_image_path, size_of, thread, validate_pipe_name, wide, win32_error,
};

const MAX_PIPE_FRAME: usize = 8 * 1024;

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
    pub(crate) last_sequence: u64,
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

    pub(crate) fn reset_listener(&mut self) -> Result<(), PlatformError> {
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
