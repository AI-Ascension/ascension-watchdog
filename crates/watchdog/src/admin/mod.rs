//! Authenticated, local administrative control for the watchdog.
//!
//! The admin sideband is deliberately narrower than the watchdog's runtime
//! implementation.  It owns framing, authentication, bounded admission,
//! idempotency and transport lifecycle.  A server I/O thread never opens a
//! database and never invokes a process or game operation: accepted requests
//! are handed to [`AdminQueue::drain`] on the actual reconciliation thread.
//!
//! Windows uses the isolated platform crate's named-pipe boundary while
//! sharing this module's closed command, capability, queue, and idempotency
//! contract with the Unix transport.

mod auth;
mod client;
mod endpoint;
mod protocol;
mod queue;
mod server;

pub use auth::{AuthReferences, AuthStore, Authz};
pub use client::{AdminClient, AdminClientConfig};
pub use endpoint::{EndpointGuard, validate_endpoint_path};
pub(crate) use protocol::command_fingerprint;
pub use protocol::{
    AcceptedView, AdminCommand, AdminDispatchError, AdminDispatcher, AdminMode, AdminRequest,
    AdminResponse, AdminResult, AttemptRequest, AttemptStatus, AttemptView,
    AuthenticatedPrincipalClass, BackupRequest, BackupView, Capability, CommandName,
    ContractVersion, DispatchContext, EmptyParams, HealthSnapshot, JobFilter, JobStatus,
    JobSubmitRequest, JobSubmitView, JobSubmittedView, JobView, JobsRequest, JobsView,
    MainLoopHealth, MainLoopPhase, QuarantineRequest, ReconcileRequest, ReconcileTarget,
    ReleaseActivateRequest, ReleaseInspectRequest, ReleaseInspection, ReplyStatus, RestoreRequest,
    RestoreView, RetryPolicy, RetryRequest, StatusView,
};
pub use queue::{AdminQueue, MAX_DRAIN_BATCH};
pub use server::{AdminServer, AdminServerConfig};

/// Contract name carried by every request and response.
pub const CONTRACT: &str = "watchdog-admin-v1";

/// Maximum complete request/response frame, including only the JSON body.  A
/// four-byte big-endian body length prefix is outside this limit.
pub const MAX_FRAME_BYTES: usize = 256 * 1024;

/// Maximum command payload after decoding.  This is intentionally smaller
/// than the frame bound so framing overhead and authentication stay bounded.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// Maximum number of simultaneously accepted client connections.
pub const MAX_CLIENTS: usize = 16;

/// Maximum requests waiting for the reconciliation thread.
pub const MAX_QUEUE: usize = 64;

/// Maximum retained idempotency records.  The durable job/attempt store owns
/// operation retention; this cache only protects the local control exchange.
pub const MAX_IDEMPOTENCY_RECORDS: usize = 256;

/// Maximum client-supplied deadline.  A shorter configured server deadline may
/// reduce this value, but no caller can hold a worker indefinitely.
pub const MAX_DEADLINE_MS: u32 = 30_000;

/// Maximum serialized payload carried by an authenticated job submission.
pub use protocol::MAX_JOB_PAYLOAD_BYTES;

/// Maximum workers used to serve local clients.  Workers are fixed at startup;
/// no request may create an unbounded thread.
pub const MAX_CLIENT_WORKERS: usize = 8;
