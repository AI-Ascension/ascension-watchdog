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
#[cfg(unix)]
use super::auth::{AuthStore, Authz};
#[cfg(unix)]
use super::endpoint::bind_endpoint;
use super::protocol::{AdminRequest, MainLoopHealth, reject_duplicate_fields};
#[cfg(unix)]
use super::protocol::{AdminResponse, ReplyStatus};
use super::queue::AdminQueue;
#[cfg(unix)]
use super::queue::{IdempotencyCache, QueueAdmission, now_unix_ms};
use super::{MAX_CLIENT_WORKERS, MAX_CLIENTS, MAX_FRAME_BYTES, MAX_IDEMPOTENCY_RECORDS};
use crate::error::{Result, WatchdogError};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(unix)]
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
#[cfg(unix)]
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
}

impl std::fmt::Debug for AdminServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminServerConfig")
            .field("endpoint", &"<protected-endpoint>")
            .field("auth", &self.auth)
            .field("max_clients", &self.max_clients)
            .field("worker_count", &self.worker_count)
            .field("io_timeout", &self.io_timeout)
            .field("idempotency_capacity", &self.idempotency_capacity)
            .finish()
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
            worker_count: MAX_CLIENT_WORKERS,
            io_timeout: Duration::from_secs(5),
            idempotency_capacity: MAX_IDEMPOTENCY_RECORDS,
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

    fn validate(self) -> Result<Self> {
        super::validate_endpoint_path(&self.endpoint)?;
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
    accept_thread: Option<JoinHandle<()>>,
    #[cfg(unix)]
    workers: Vec<WorkerHandle>,
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
        builder.finish_non_exhaustive()
    }
}

impl AdminServer {
    /// Start the server.  On Unix, binding an incumbent path returns `BUSY`
    /// and never unlinks it.  On Windows this returns `UNSUPPORTED` until the
    /// separately owned P2 named-pipe transport is integrated.
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

    /// Windows/non-Unix builds fail closed rather than pretending to have a
    /// local authenticated transport.
    #[cfg(not(unix))]
    pub fn start(
        _config: AdminServerConfig,
        _queue: AdminQueue,
        _health: MainLoopHealth,
    ) -> Result<Self> {
        Err(WatchdogError::Unsupported(
            "native Windows admin transport is owned by the P2 broker".to_string(),
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
    match auth.authorize(&request) {
        Authz::Allowed => {}
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
    }

    let fingerprint = request.fingerprint();
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
    if let Err(admission) = queue.enqueue(
        request.clone(),
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
            &AdminResponse::error(request.request_id, request.idempotency_key, status, health),
        );
        return;
    }
    let deadline = Duration::from_millis(u64::from(request.deadline_ms));
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
                    request.request_id,
                    request.idempotency_key,
                    ReplyStatus::Timeout,
                    health,
                ),
            );
        }
        Err(RecvTimeoutError::Disconnected) => {}
    }
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
