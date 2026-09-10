//! Bounded local IPC server.

#![cfg_attr(
    not(unix),
    allow(
        dead_code,
        unused_imports,
        reason = "the worker implementation is intentionally disabled on other platforms"
    )
)]

use super::auth::AuthReferences;
use super::auth::{AuthStore, Authz};
#[cfg(unix)]
use super::endpoint::bind_endpoint;
use super::protocol::{AdminRequest, MainLoopHealth, reject_duplicate_fields};
use super::protocol::{AdminResponse, ReplyStatus};
use super::queue::AdminQueue;
use super::queue::{IdempotencyCache, QueueAdmission, now_unix_ms};
use super::{MAX_CLIENT_WORKERS, MAX_CLIENTS, MAX_FRAME_BYTES, MAX_IDEMPOTENCY_RECORDS};
use crate::error::{Result, WatchdogError};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

/// Server transport settings.  The endpoint and token references are explicit
/// and are never serialized into status replies.
#[derive(Clone)]
pub struct AdminServerConfig {
    endpoint: PathBuf,
    auth: AuthReferences,
    max_clients: usize,
    worker_count: usize,
    io_timeout: Duration,
    idempotency_capacity: usize,
    #[cfg(windows)]
    allowed_peer_sid: Option<String>,
}

impl std::fmt::Debug for AdminServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut builder = f.debug_struct("AdminServerConfig");
        builder
            .field("endpoint", &"<protected-endpoint>")
            .field("auth", &self.auth)
            .field("max_clients", &self.max_clients)
            .field("worker_count", &self.worker_count)
            .field("io_timeout", &self.io_timeout)
            .field("idempotency_capacity", &self.idempotency_capacity);
        #[cfg(windows)]
        builder.field(
            "allowed_peer_sid",
            &self.allowed_peer_sid.as_ref().map(|_| "<configured>"),
        );
        builder.finish()
    }
}

impl AdminServerConfig {
    /// Construct a conservative server configuration with fixed worker and
    /// retention bounds.
    pub fn new(endpoint: impl Into<PathBuf>, auth: AuthReferences) -> Result<Self> {
        let config = Self {
            endpoint: endpoint.into(),
            auth,
            max_clients: MAX_CLIENTS,
            worker_count: if cfg!(windows) { 1 } else { MAX_CLIENT_WORKERS },
            io_timeout: Duration::from_secs(5),
            idempotency_capacity: MAX_IDEMPOTENCY_RECORDS,
            #[cfg(windows)]
            allowed_peer_sid: None,
        };
        config.validate()
    }

    /// Endpoint path used for bind and exact cleanup.
    #[must_use]
    pub fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    /// Set the maximum simultaneously admitted clients.
    pub fn with_max_clients(mut self, max_clients: usize) -> Result<Self> {
        self.max_clients = max_clients;
        self.worker_count = self.worker_count.min(max_clients.max(1));
        self.validate()
    }

    /// Set a smaller fixed worker count for tests or constrained hosts.
    pub fn with_worker_count(mut self, worker_count: usize) -> Result<Self> {
        self.worker_count = worker_count;
        self.validate()
    }

    /// Set the bounded per-connection I/O deadline.
    pub fn with_io_timeout(mut self, timeout: Duration) -> Result<Self> {
        self.io_timeout = timeout;
        self.validate()
    }

    /// Set bounded in-memory idempotency retention.
    pub fn with_idempotency_capacity(mut self, capacity: usize) -> Result<Self> {
        self.idempotency_capacity = capacity;
        self.validate()
    }

    /// Restrict Windows named-pipe peers to this explicit operator SID.  When
    /// omitted, the native transport uses the service owner's SID and an
    /// owner-only pipe ACL.
    #[cfg(windows)]
    pub fn with_allowed_peer_sid(mut self, sid: impl Into<String>) -> Result<Self> {
        self.allowed_peer_sid = Some(sid.into());
        self.validate()
    }

    fn validate(self) -> Result<Self> {
        super::validate_endpoint_path(&self.endpoint)?;
        if cfg!(windows) && self.worker_count != 1 {
            return Err(WatchdogError::InvalidInput(
                "Windows admin transport requires exactly one exclusive pipe worker".to_string(),
            ));
        }
        if self.max_clients == 0 || self.max_clients > MAX_CLIENTS {
            return Err(WatchdogError::InvalidInput(format!(
                "max_clients must be 1..={MAX_CLIENTS}"
            )));
        }
        if self.worker_count == 0
            || self.worker_count > MAX_CLIENT_WORKERS
            || self.worker_count > self.max_clients
        {
            return Err(WatchdogError::InvalidInput(format!(
                "worker_count must be 1..={MAX_CLIENT_WORKERS} and <= max_clients"
            )));
        }
        if self.io_timeout.is_zero() || self.io_timeout > Duration::from_secs(30) {
            return Err(WatchdogError::InvalidInput(
                "admin I/O timeout must be between 1ms and 30s".to_string(),
            ));
        }
        if self.idempotency_capacity == 0 || self.idempotency_capacity > MAX_IDEMPOTENCY_RECORDS {
            return Err(WatchdogError::InvalidInput(format!(
                "idempotency capacity must be 1..={MAX_IDEMPOTENCY_RECORDS}"
            )));
        }
        Ok(self)
    }
}

/// Running admin server.  Dropping it joins the fixed I/O and worker threads
/// and then lets the endpoint guard perform exact identity-checked cleanup.
pub struct AdminServer {
    stop: Arc<AtomicBool>,
    client_count: Arc<AtomicUsize>,
    #[cfg(unix)]
    accept_thread: Option<JoinHandle<()>>,
    #[cfg(unix)]
    workers: Vec<WorkerHandle>,
    #[cfg(windows)]
    workers: Vec<JoinHandle<()>>,
    endpoint: Option<super::endpoint::EndpointGuard>,
}

#[cfg(unix)]
struct WorkerHandle {
    sender: SyncSender<std::os::unix::net::UnixStream>,
    join: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for AdminServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut builder = f.debug_struct("AdminServer");
        builder.field("client_count", &self.client_count.load(Ordering::Acquire));
        #[cfg(unix)]
        builder.field("workers", &self.workers.len());
        #[cfg(windows)]
        builder.field("workers", &self.workers.len());
        builder.finish_non_exhaustive()
    }
}

impl AdminServer {
    /// Start the server.  On Unix, binding an incumbent path returns `BUSY`
    /// and never unlinks it.  On Windows, fixed worker threads own isolated
    /// native named-pipe instances and hand the same queue contract to the
    /// reconciliation loop.
    #[cfg(unix)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn start(
        config: AdminServerConfig,
        queue: AdminQueue,
        health: MainLoopHealth,
    ) -> Result<Self> {
        let config = config.validate()?;
        let auth = config.auth.load()?;
        let (listener, endpoint) = bind_endpoint(&config.endpoint)?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let client_count = Arc::new(AtomicUsize::new(0));
        let cache = Arc::new(
            IdempotencyCache::new(config.idempotency_capacity)
                .map_err(WatchdogError::InvalidInput)?,
        );
        let mut workers = Vec::with_capacity(config.worker_count);
        for _ in 0..config.worker_count {
            let (sender, receiver) = mpsc::sync_channel::<std::os::unix::net::UnixStream>(1);
            let worker_stop = Arc::clone(&stop);
            let worker_auth = auth.clone();
            let worker_queue = queue.clone();
            let worker_health = health.clone();
            let worker_cache = Arc::clone(&cache);
            let worker_count = Arc::clone(&client_count);
            let io_timeout = config.io_timeout;
            let join = thread::Builder::new()
                .name("watchdog-admin-client".to_string())
                .spawn(move || {
                    worker_loop(
                        receiver,
                        worker_stop,
                        worker_auth,
                        worker_queue,
                        worker_health,
                        worker_cache,
                        worker_count,
                        io_timeout,
                    );
                })
                .map_err(WatchdogError::Io)?;
            workers.push(WorkerHandle {
                sender,
                join: Some(join),
            });
        }
        let accept_stop = Arc::clone(&stop);
        let accept_count = Arc::clone(&client_count);
        let accept_health = health.clone();
        let accept_workers = workers.iter().map(|worker| worker.sender.clone()).collect();
        let max_clients = config.max_clients;
        let accept_timeout = config.io_timeout;
        let accept_thread = thread::Builder::new()
            .name("watchdog-admin-accept".to_string())
            .spawn(move || {
                accept_loop(
                    listener,
                    accept_stop,
                    accept_count,
                    accept_health,
                    accept_workers,
                    max_clients,
                    accept_timeout,
                );
            })
            .map_err(WatchdogError::Io)?;
        Ok(Self {
            stop,
            client_count,
            accept_thread: Some(accept_thread),
            #[cfg(unix)]
            workers,
            endpoint: Some(endpoint),
        })
    }

    /// Start the authenticated Windows named-pipe transport.
    #[cfg(windows)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn start(
        config: AdminServerConfig,
        queue: AdminQueue,
        health: MainLoopHealth,
    ) -> Result<Self> {
        use ascension_platform_windows::AdminPipeServer;

        let config = config.validate()?;
        let auth = config.auth.load()?;
        let cache = Arc::new(
            IdempotencyCache::new(config.idempotency_capacity)
                .map_err(WatchdogError::InvalidInput)?,
        );
        let stop = Arc::new(AtomicBool::new(false));
        let client_count = Arc::new(AtomicUsize::new(0));
        let mut pipe_servers = Vec::with_capacity(config.worker_count);
        for _ in 0..config.worker_count {
            pipe_servers.push(
                AdminPipeServer::create(
                    config.endpoint.to_string_lossy().into_owned(),
                    config.allowed_peer_sid.as_deref(),
                )
                .map_err(|error| WatchdogError::Unsupported(error.to_string()))?,
            );
        }
        let mut workers = Vec::with_capacity(config.worker_count);
        for pipe_server in pipe_servers {
            let worker_stop = Arc::clone(&stop);
            let worker_auth = auth.clone();
            let worker_queue = queue.clone();
            let worker_health = health.clone();
            let worker_cache = Arc::clone(&cache);
            let worker_count = Arc::clone(&client_count);
            let io_timeout = config.io_timeout;
            let join = thread::Builder::new()
                .name("watchdog-admin-pipe".to_string())
                .spawn(move || {
                    windows_worker_loop(
                        pipe_server,
                        &worker_stop,
                        &worker_auth,
                        &worker_queue,
                        &worker_health,
                        &worker_cache,
                        &worker_count,
                        io_timeout,
                    );
                })
                .map_err(WatchdogError::Io)?;
            workers.push(join);
        }
        Ok(Self {
            stop,
            client_count,
            workers,
            endpoint: None,
        })
    }

    /// Other targets have no authenticated local transport.
    #[cfg(not(any(unix, windows)))]
    pub fn start(
        _config: AdminServerConfig,
        _queue: AdminQueue,
        _health: MainLoopHealth,
    ) -> Result<Self> {
        Err(WatchdogError::Unsupported(
            "admin transport is unsupported on this platform".to_string(),
        ))
    }

    /// Exact endpoint path while the server is live.
    #[must_use]
    pub fn endpoint(&self) -> Option<&Path> {
        self.endpoint
            .as_ref()
            .map(super::endpoint::EndpointGuard::path)
    }

    /// Request shutdown and join all fixed transport threads.
    pub fn shutdown(mut self) -> Result<()> {
        self.shutdown_inner();
        Ok(())
    }

    fn shutdown_inner(&mut self) {
        self.stop.store(true, Ordering::Release);
        #[cfg(unix)]
        if let Some(join) = self.accept_thread.take() {
            let _ = join.join();
        }
        #[cfg(unix)]
        {
            let mut workers = std::mem::take(&mut self.workers);
            for worker in &mut workers {
                if let Some(join) = worker.join.take() {
                    let _ = join.join();
                }
            }
        }
        #[cfg(windows)]
        {
            let mut workers = std::mem::take(&mut self.workers);
            for join in workers.drain(..) {
                let _ = join.join();
            }
        }
    }
}

impl Drop for AdminServer {
    fn drop(&mut self) {
        self.shutdown_inner();
        self.endpoint.take();
    }
}

#[cfg(unix)]
#[allow(clippy::needless_pass_by_value)]
fn accept_loop(
    listener: std::os::unix::net::UnixListener,
    stop: Arc<AtomicBool>,
    client_count: Arc<AtomicUsize>,
    health: MainLoopHealth,
    workers: Vec<SyncSender<std::os::unix::net::UnixStream>>,
    max_clients: usize,
    io_timeout: Duration,
) {
    let mut next_worker = 0usize;
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _address)) => {
                if !reserve_client(&client_count, max_clients) {
                    let mut stream = stream;
                    let _ = stream.set_write_timeout(Some(io_timeout));
                    let _ = send_error(&mut stream, ReplyStatus::Busy, &health);
                    continue;
                }
                let worker_index = next_worker % workers.len();
                next_worker = next_worker.wrapping_add(1);
                match workers[worker_index].try_send(stream) {
                    Ok(()) => {}
                    Err(TrySendError::Full(stream) | TrySendError::Disconnected(stream)) => {
                        client_count.fetch_sub(1, Ordering::AcqRel);
                        let mut stream = stream;
                        let _ = stream.set_write_timeout(Some(io_timeout));
                        let _ = send_error(&mut stream, ReplyStatus::Busy, &health);
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}

#[cfg(unix)]
#[allow(clippy::needless_pass_by_value)]
fn worker_loop(
    receiver: mpsc::Receiver<std::os::unix::net::UnixStream>,
    stop: Arc<AtomicBool>,
    auth: AuthStore,
    queue: AdminQueue,
    health: MainLoopHealth,
    cache: Arc<IdempotencyCache>,
    client_count: Arc<AtomicUsize>,
    io_timeout: Duration,
) {
    while !stop.load(Ordering::Acquire) {
        match receiver.recv_timeout(Duration::from_millis(25)) {
            Ok(stream) => {
                handle_connection(stream, &auth, &queue, &health, &cache, io_timeout);
                client_count.fetch_sub(1, Ordering::AcqRel);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

#[cfg(unix)]
fn handle_connection(
    mut stream: std::os::unix::net::UnixStream,
    auth: &AuthStore,
    queue: &AdminQueue,
    health: &MainLoopHealth,
    cache: &Arc<IdempotencyCache>,
    io_timeout: Duration,
) {
    let _ = stream.set_read_timeout(Some(io_timeout));
    let _ = stream.set_write_timeout(Some(io_timeout));
    let frame = match read_frame(&mut stream) {
        Ok(frame) => frame,
        Err(FrameReadError::TooLarge) => {
            let _ = send_error(&mut stream, ReplyStatus::BoundsExceeded, health);
            return;
        }
        Err(FrameReadError::Io) => return,
    };
    let Ok(request) = decode_request(&frame) else {
        let _ = send_error(&mut stream, ReplyStatus::Invalid, health);
        return;
    };
    let principal = match auth.authorize(&request) {
        Authz::Allowed(principal) => principal,
        Authz::Forbidden => {
            let _ = send_response(
                &mut stream,
                &AdminResponse::error(
                    request.request_id,
                    request.idempotency_key,
                    ReplyStatus::Forbidden,
                    health,
                ),
            );
            return;
        }
        Authz::Unauthorized => {
            let _ = send_response(
                &mut stream,
                &AdminResponse::error(
                    request.request_id,
                    request.idempotency_key,
                    ReplyStatus::Unauthorized,
                    health,
                ),
            );
            return;
        }
    };

    let Ok(context) = request.dispatch_context(principal) else {
        let _ = send_response(
            &mut stream,
            &AdminResponse::error(
                request.request_id,
                request.idempotency_key,
                ReplyStatus::Invalid,
                health,
            ),
        );
        return;
    };
    let fingerprint = context.command_fingerprint().to_owned();
    let cache_key = request.idempotency_key.clone();
    match cache.begin(&cache_key, &fingerprint) {
        super::queue::CacheLookup::Complete(response) => {
            let response = response.with_current_health(health);
            let _ = send_response(&mut stream, &response);
            return;
        }
        super::queue::CacheLookup::Pending => {
            let _ = send_response(
                &mut stream,
                &AdminResponse::error(
                    request.request_id,
                    request.idempotency_key,
                    ReplyStatus::InProgress,
                    health,
                ),
            );
            return;
        }
        super::queue::CacheLookup::Conflict => {
            let _ = send_response(
                &mut stream,
                &AdminResponse::error(
                    request.request_id,
                    request.idempotency_key,
                    ReplyStatus::Conflict,
                    health,
                ),
            );
            return;
        }
        super::queue::CacheLookup::New => {}
    }
    let (response_sender, response_receiver) = mpsc::sync_channel(1);
    let received_at_ms = now_unix_ms();
    let command = request.command.clone();
    let deadline_ms = request.deadline_ms;
    drop(request);
    if let Err(admission) = queue.enqueue(
        context.clone(),
        command,
        deadline_ms,
        response_sender,
        received_at_ms,
        Arc::clone(cache),
        cache_key.clone(),
    ) {
        cache.abandon(&cache_key, &fingerprint);
        let status = match admission {
            QueueAdmission::Full => ReplyStatus::Busy,
            QueueAdmission::Closed => ReplyStatus::PersistenceUnavailable,
        };
        let _ = send_response(
            &mut stream,
            &AdminResponse::context_error(&context, status, health),
        );
        return;
    }
    let deadline = Duration::from_millis(u64::from(deadline_ms));
    match response_receiver.recv_timeout(deadline) {
        Ok(response) => {
            let _ = send_response(&mut stream, &response);
        }
        Err(RecvTimeoutError::Timeout) => {
            // The item remains in the main-loop queue and its eventual outcome
            // is cached.  A retry with the same key receives that outcome rather
            // than invoking the command a second time.
            let _ = send_response(
                &mut stream,
                &AdminResponse::error(
                    context.request_id().to_string(),
                    context.idempotency_key().to_string(),
                    ReplyStatus::Timeout,
                    health,
                ),
            );
        }
        Err(RecvTimeoutError::Disconnected) => {}
    }
}

#[cfg(windows)]
fn windows_worker_loop(
    mut pipe: ascension_platform_windows::AdminPipeServer,
    stop: &Arc<AtomicBool>,
    auth: &AuthStore,
    queue: &AdminQueue,
    health: &MainLoopHealth,
    cache: &Arc<IdempotencyCache>,
    client_count: &Arc<AtomicUsize>,
    io_timeout: Duration,
) {
    // A short accept poll keeps shutdown bounded even when no client is
    // present.  Once connected, all reads/writes retain the configured
    // per-request deadline and are polled in the native boundary.
    let accept_poll = Duration::from_millis(50).min(io_timeout);
    while !stop.load(Ordering::Acquire) {
        match pipe.accept(accept_poll) {
            Ok(None) => {}
            Err(_) => {
                let _ = pipe.disconnect();
            }
            Ok(Some(_peer)) => {
                client_count.fetch_add(1, Ordering::AcqRel);
                windows_handle_connection(&mut pipe, auth, queue, health, cache, io_timeout, stop);
                let _ = pipe.cancel();
                let _ = pipe.disconnect();
                client_count.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }
    let _ = pipe.cancel();
    let _ = pipe.disconnect();
}

#[cfg(windows)]
fn windows_handle_connection(
    pipe: &mut ascension_platform_windows::AdminPipeServer,
    auth: &AuthStore,
    queue: &AdminQueue,
    health: &MainLoopHealth,
    cache: &Arc<IdempotencyCache>,
    io_timeout: Duration,
    stop: &AtomicBool,
) {
    let frame = match pipe.read_frame(io_timeout) {
        Ok(frame) => frame,
        Err(error) => {
            let status = if error.to_string().contains("frame exceeds") {
                ReplyStatus::BoundsExceeded
            } else {
                return;
            };
            let _ = send_pipe_error(pipe, status, health, io_timeout);
            return;
        }
    };
    let Ok(request) = decode_request(&frame) else {
        let _ = send_pipe_error(pipe, ReplyStatus::Invalid, health, io_timeout);
        return;
    };
    let principal = match auth.authorize(&request) {
        Authz::Allowed(_) => super::protocol::AuthenticatedPrincipalClass::WindowsOperator,
        Authz::Forbidden => {
            let response = AdminResponse::error(
                request.request_id,
                request.idempotency_key,
                ReplyStatus::Forbidden,
                health,
            );
            let _ = send_pipe_response(pipe, &response, io_timeout);
            return;
        }
        Authz::Unauthorized => {
            let response = AdminResponse::error(
                request.request_id,
                request.idempotency_key,
                ReplyStatus::Unauthorized,
                health,
            );
            let _ = send_pipe_response(pipe, &response, io_timeout);
            return;
        }
    };
    let Ok(context) = request.dispatch_context(principal) else {
        let response = AdminResponse::error(
            request.request_id,
            request.idempotency_key,
            ReplyStatus::Invalid,
            health,
        );
        let _ = send_pipe_response(pipe, &response, io_timeout);
        return;
    };
    let fingerprint = context.command_fingerprint().to_owned();
    let cache_key = context.idempotency_key().to_owned();
    match cache.begin(&cache_key, &fingerprint) {
        super::queue::CacheLookup::Complete(response) => {
            let response = response.with_current_health(health);
            let _ = send_pipe_response(pipe, &response, io_timeout);
            return;
        }
        super::queue::CacheLookup::Pending => {
            let response = AdminResponse::context_error(&context, ReplyStatus::InProgress, health);
            let _ = send_pipe_response(pipe, &response, io_timeout);
            return;
        }
        super::queue::CacheLookup::Conflict => {
            let response = AdminResponse::context_error(&context, ReplyStatus::Conflict, health);
            let _ = send_pipe_response(pipe, &response, io_timeout);
            return;
        }
        super::queue::CacheLookup::New => {}
    }
    let command = request.command.clone();
    let deadline_ms = request.deadline_ms;
    drop(request);
    let (response_sender, response_receiver) = mpsc::sync_channel(1);
    if let Err(admission) = queue.enqueue(
        context.clone(),
        command,
        deadline_ms,
        response_sender,
        now_unix_ms(),
        Arc::clone(cache),
        cache_key.clone(),
    ) {
        cache.abandon(&cache_key, &fingerprint);
        let status = match admission {
            QueueAdmission::Full => ReplyStatus::Busy,
            QueueAdmission::Closed => ReplyStatus::PersistenceUnavailable,
        };
        let response = AdminResponse::context_error(&context, status, health);
        let _ = send_pipe_response(pipe, &response, io_timeout);
        return;
    }
    let deadline = Duration::from_millis(u64::from(deadline_ms));
    let started = std::time::Instant::now();
    loop {
        let elapsed = started.elapsed();
        if elapsed >= deadline {
            let response = AdminResponse::context_error(&context, ReplyStatus::Timeout, health);
            let _ = send_pipe_response(pipe, &response, io_timeout);
            return;
        }
        let wait = Duration::from_millis(50).min(deadline.saturating_sub(elapsed));
        match response_receiver.recv_timeout(wait) {
            Ok(response) => {
                let _ = send_pipe_response(pipe, &response, io_timeout);
                return;
            }
            Err(RecvTimeoutError::Timeout) if !stop.load(Ordering::Acquire) => {}
            Err(RecvTimeoutError::Timeout) => return,
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

#[cfg(windows)]
fn send_pipe_error(
    pipe: &mut ascension_platform_windows::AdminPipeServer,
    status: ReplyStatus,
    health: &MainLoopHealth,
    timeout: Duration,
) -> Result<()> {
    let response = AdminResponse::error("", "", status, health);
    send_pipe_response(pipe, &response, timeout)
        .map_err(|error| WatchdogError::Io(std::io::Error::other(error)))
}

#[cfg(windows)]
fn send_pipe_response(
    pipe: &mut ascension_platform_windows::AdminPipeServer,
    response: &AdminResponse,
    timeout: Duration,
) -> std::result::Result<(), ascension_platform_windows::PlatformError> {
    let bytes = response
        .encode()
        .map_err(ascension_platform_windows::PlatformError::Invalid)?;
    pipe.write_frame(&bytes, timeout)
}

#[cfg(unix)]
fn reserve_client(count: &AtomicUsize, max_clients: usize) -> bool {
    let mut current = count.load(Ordering::Acquire);
    loop {
        if current >= max_clients {
            return false;
        }
        match count.compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

#[cfg(unix)]
enum FrameReadError {
    TooLarge,
    Io,
}

#[cfg(unix)]
fn read_frame(
    stream: &mut std::os::unix::net::UnixStream,
) -> std::result::Result<Vec<u8>, FrameReadError> {
    use std::io::Read;
    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|_| FrameReadError::Io)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(FrameReadError::TooLarge);
    }
    let mut frame = vec![0u8; length];
    stream
        .read_exact(&mut frame)
        .map_err(|_| FrameReadError::Io)?;
    Ok(frame)
}

#[cfg(all(test, windows))]
mod windows_config_tests {
    use super::*;

    #[test]
    fn exclusive_endpoint_defaults_to_one_worker_and_rejects_more() -> Result<()> {
        let executable = std::env::current_exe()?;
        let auth = AuthReferences::for_test(
            executable.with_file_name("read.token"),
            executable.with_file_name("admin.token"),
        );
        let config = AdminServerConfig::new(r"\\.\pipe\ascension-watchdog-config-test", auth)?;
        assert_eq!(config.worker_count, 1);
        assert!(config.with_worker_count(2).is_err());
        Ok(())
    }
}

fn decode_request(frame: &[u8]) -> std::result::Result<AdminRequest, String> {
    if frame.len() > MAX_FRAME_BYTES {
        return Err("request exceeds frame bound".to_string());
    }
    reject_duplicate_fields(frame)?;
    let request: AdminRequest = serde_json::from_slice(frame).map_err(|error| error.to_string())?;
    request.validate()?;
    let command_bytes = serde_json::to_vec(&request.command).map_err(|error| error.to_string())?;
    if !super::protocol::payload_within_bound(&command_bytes) {
        return Err("command payload exceeds payload bound".to_string());
    }
    if serde_json::to_vec(&request)
        .map_err(|error| error.to_string())?
        .len()
        > MAX_FRAME_BYTES
    {
        return Err("request exceeds encoded frame bound".to_string());
    }
    Ok(request)
}

#[cfg(unix)]
fn send_error(
    stream: &mut std::os::unix::net::UnixStream,
    status: ReplyStatus,
    health: &MainLoopHealth,
) -> std::io::Result<()> {
    let response = AdminResponse::error("", "", status, health);
    send_response(stream, &response)
}

#[cfg(unix)]
fn send_response(
    stream: &mut std::os::unix::net::UnixStream,
    response: &AdminResponse,
) -> std::io::Result<()> {
    use std::io::Write;
    let bytes = response.encode().map_err(std::io::Error::other)?;
    let length = u32::try_from(bytes.len()).map_err(|_| std::io::Error::other("frame bound"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()
}
