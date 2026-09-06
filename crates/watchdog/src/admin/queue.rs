//! Bounded handoff from local IPC workers to the real reconciliation loop.

#![cfg_attr(
    not(unix),
    allow(
        dead_code,
        unused_imports,
        reason = "queue admission is intentionally disabled with the unsupported transport"
    )
)]

use super::MAX_QUEUE;
use super::protocol::{AdminDispatcher, AdminRequest, AdminResponse, MainLoopHealth, ReplyStatus};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Maximum commands the main loop drains in one bounded pass by default.
pub const MAX_DRAIN_BATCH: usize = 16;

/// A bounded queue shared by the server workers and exactly one watchdog main
/// loop.  The receiver is never consumed by the I/O thread.
#[derive(Clone)]
pub struct AdminQueue {
    inner: Arc<QueueInner>,
}

struct QueueInner {
    sender: SyncSender<QueuedRequest>,
    receiver: Mutex<Receiver<QueuedRequest>>,
    gate: Mutex<()>,
    depth: AtomicUsize,
    capacity: usize,
}

struct QueuedRequest {
    request: AdminRequest,
    response: SyncSender<AdminResponse>,
    received_at_ms: u64,
    cache: Arc<IdempotencyCache>,
    cache_key: String,
    fingerprint: String,
}

impl std::fmt::Debug for AdminQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminQueue")
            .field("capacity", &self.inner.capacity)
            .field("depth", &self.depth())
            .finish()
    }
}

impl AdminQueue {
    /// Create a queue with a hard capacity; zero and over-bound capacities are
    /// rejected instead of silently selecting an unbounded channel.
    pub fn new(capacity: usize) -> std::result::Result<Self, String> {
        if capacity == 0 || capacity > MAX_QUEUE {
            return Err(format!("admin queue capacity must be 1..={MAX_QUEUE}"));
        }
        let (sender, receiver) = mpsc::sync_channel(capacity);
        Ok(Self {
            inner: Arc::new(QueueInner {
                sender,
                receiver: Mutex::new(receiver),
                gate: Mutex::new(()),
                depth: AtomicUsize::new(0),
                capacity,
            }),
        })
    }

    /// Current bounded depth.  This is a diagnostic count, not an authority
    /// proof and never drives readiness on its own.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.inner.depth.load(Ordering::Acquire)
    }

    /// Queue capacity selected at construction.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }

    /// Main-loop-only entry point.  Every accepted request is executed here;
    /// the transport workers do not call the dispatcher.
    pub(crate) fn enqueue(
        &self,
        request: AdminRequest,
        response: SyncSender<AdminResponse>,
        received_at_ms: u64,
        cache: Arc<IdempotencyCache>,
        cache_key: String,
    ) -> std::result::Result<(), QueueAdmission> {
        let _gate = self
            .inner
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fingerprint = request.fingerprint();
        let item = QueuedRequest {
            request,
            response,
            received_at_ms,
            cache,
            cache_key,
            fingerprint,
        };
        match self.inner.sender.try_send(item) {
            Ok(()) => {
                self.inner.depth.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }
            Err(TrySendError::Full(_)) => Err(QueueAdmission::Full),
            Err(TrySendError::Disconnected(_)) => Err(QueueAdmission::Closed),
        }
    }

    /// Drain at most `max_items` requests on the reconciliation thread.  A
    /// request whose caller deadline elapsed is completed as a timeout without
    /// invoking the dispatcher.  A response send failure does not roll back a
    /// durable dispatch; the idempotency cache still retains its outcome.
    pub fn drain(
        &self,
        dispatcher: &mut dyn AdminDispatcher,
        health: &MainLoopHealth,
        now_ms: u64,
        max_items: usize,
    ) -> usize {
        let limit = max_items.min(MAX_DRAIN_BATCH);
        if limit == 0 {
            return 0;
        }
        let mut drained = 0;
        while drained < limit {
            let item = {
                let _gate = self
                    .inner
                    .gate
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let receiver = self
                    .inner
                    .receiver
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match receiver.try_recv() {
                    Ok(item) => {
                        self.inner.depth.fetch_sub(1, Ordering::AcqRel);
                        item
                    }
                    Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
                }
            };
            drained += 1;

            let deadline = item
                .received_at_ms
                .saturating_add(u64::from(item.request.deadline_ms));
            let response = if now_ms > deadline {
                AdminResponse::error(
                    item.request.request_id.clone(),
                    item.request.idempotency_key.clone(),
                    ReplyStatus::Timeout,
                    health,
                )
            } else {
                match dispatcher.dispatch(&item.request.command) {
                    Ok(result) => match result.validate() {
                        Ok(()) => AdminResponse::success(&item.request, result, health),
                        Err(_) => AdminResponse::error(
                            item.request.request_id.clone(),
                            item.request.idempotency_key.clone(),
                            ReplyStatus::BoundsExceeded,
                            health,
                        ),
                    },
                    Err(error) => AdminResponse::error(
                        item.request.request_id.clone(),
                        item.request.idempotency_key.clone(),
                        error.status(),
                        health,
                    ),
                }
            };
            item.cache
                .complete(&item.cache_key, &item.fingerprint, response.clone());
            let _ = item.response.send(response);
        }
        drained
    }
}

/// Why a request could not be handed to the loop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QueueAdmission {
    Full,
    Closed,
}

/// Bounded replay/idempotency memory for the local exchange.  Durable command
/// identity and operation history remain the dispatcher's responsibility.
#[derive(Debug)]
pub(crate) struct IdempotencyCache {
    entries: Mutex<CacheState>,
    capacity: usize,
}

#[derive(Debug, Default)]
struct CacheState {
    records: HashMap<String, CacheRecord>,
    order: VecDeque<String>,
}

#[derive(Clone, Debug)]
enum CacheRecord {
    Pending {
        fingerprint: String,
    },
    Complete {
        fingerprint: String,
        response: Box<AdminResponse>,
    },
}

/// Lookup result used by server workers before queue admission.
#[derive(Clone, Debug)]
pub(crate) enum CacheLookup {
    New,
    Pending,
    Complete(Box<AdminResponse>),
    Conflict,
}

impl IdempotencyCache {
    pub(crate) fn new(capacity: usize) -> std::result::Result<Self, String> {
        if capacity == 0 || capacity > super::MAX_IDEMPOTENCY_RECORDS {
            return Err(format!(
                "idempotency capacity must be 1..={}",
                super::MAX_IDEMPOTENCY_RECORDS
            ));
        }
        Ok(Self {
            entries: Mutex::new(CacheState::default()),
            capacity,
        })
    }

    pub(crate) fn begin(&self, key: &str, fingerprint: &str) -> CacheLookup {
        let mut state = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(record) = state.records.get(key) {
            return match record {
                CacheRecord::Pending {
                    fingerprint: current,
                } if current == fingerprint => CacheLookup::Pending,
                CacheRecord::Complete {
                    fingerprint: current,
                    response,
                } if current == fingerprint => CacheLookup::Complete(response.clone()),
                _ => CacheLookup::Conflict,
            };
        }
        if !reserve_slot(&mut state, self.capacity) {
            return CacheLookup::Conflict;
        }
        state.records.insert(
            key.to_string(),
            CacheRecord::Pending {
                fingerprint: fingerprint.to_string(),
            },
        );
        state.order.push_back(key.to_string());
        CacheLookup::New
    }

    pub(crate) fn abandon(&self, key: &str, fingerprint: &str) {
        let mut state = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let remove = matches!(
            state.records.get(key),
            Some(CacheRecord::Pending { fingerprint: current }) if current == fingerprint
        );
        if remove {
            state.records.remove(key);
            state.order.retain(|current| current != key);
        }
    }

    pub(crate) fn complete(&self, key: &str, fingerprint: &str, response: AdminResponse) {
        let mut state = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(record) = state.records.get_mut(key) {
            if let CacheRecord::Pending {
                fingerprint: current,
            } = record
            {
                if current == fingerprint {
                    *record = CacheRecord::Complete {
                        fingerprint: fingerprint.to_string(),
                        response: Box::new(response),
                    };
                }
            }
        }
    }
}

fn reserve_slot(state: &mut CacheState, capacity: usize) -> bool {
    while state.records.len() >= capacity {
        let Some(oldest) = state.order.pop_front() else {
            return false;
        };
        match state.records.get(&oldest) {
            Some(CacheRecord::Complete { .. }) => {
                state.records.remove(&oldest);
            }
            Some(CacheRecord::Pending { .. }) => {
                state.order.push_back(oldest);
                return false;
            }
            None => {}
        }
    }
    true
}

/// Wall clock used only for queue age/deadline accounting.  The main loop may
/// pass an injected deterministic timestamp in tests.
#[must_use]
pub(crate) fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
