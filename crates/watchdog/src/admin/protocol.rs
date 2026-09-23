//! Closed, bounded admin request and response types.
//!
//! The original single-file module is split along its cohesive seams:
//! contract identity (`identity`), closed command payloads (`commands`), the
//! authenticated request envelope (`request`), bounded wire views (`views`),
//! the response envelope and dispatcher contract (`response`), strict
//! duplicate-member rejection (`duplicate`) and the bounded validation
//! helpers (`validation`).  Every public item is re-exported here, so
//! `admin::protocol` stays the single entrypoint and no wire contract, error
//! semantic, bound or caller changes.

#![cfg_attr(
    not(unix),
    allow(
        dead_code,
        unused_imports,
        reason = "duplicate-key and payload helpers are used only by the Unix transport"
    )
)]

mod commands;
mod duplicate;
mod identity;
mod request;
mod response;
mod validation;
mod views;

use super::MAX_PAYLOAD_BYTES;

const MAX_ID_BYTES: usize = 128;
const MAX_REASON_BYTES: usize = 512;
const MAX_TOKEN_BYTES: usize = 4 * 1024;
const MAX_RELEASE_BYTES: usize = 128;
const MAX_RESULT_ITEMS: usize = 256;
const MAX_JOB_KIND_BYTES: usize = 128;
/// Maximum serialized JSON payload accepted by authenticated job submission.
/// The complete command is also checked against `MAX_PAYLOAD_BYTES`, so the
/// envelope and framing overhead remain bounded.
pub const MAX_JOB_PAYLOAD_BYTES: usize = MAX_PAYLOAD_BYTES;

pub use commands::{
    AdminCommand, AttemptRequest, BackupRequest, EmptyParams, JobFilter, JobSubmitRequest,
    JobsRequest, QuarantineRequest, ReconcileRequest, ReconcileTarget, ReleaseActivateRequest,
    ReleaseInspectRequest, RestoreRequest, RetryPolicy, RetryRequest,
};
pub(crate) use duplicate::reject_duplicate_fields;
pub use identity::{AuthenticatedPrincipalClass, Capability, CommandName};
pub use request::{AdminRequest, DispatchContext};
pub use response::{AdminDispatchError, AdminDispatcher, AdminResponse};
pub(crate) use validation::{command_fingerprint, payload_within_bound};
pub use views::{
    AcceptedView, AdminMode, AdminResult, AttemptStatus, AttemptView, BackupView, ContractVersion,
    HealthSnapshot, JobStatus, JobSubmitView, JobSubmittedView, JobView, JobsView, MainLoopHealth,
    MainLoopPhase, ReleaseActivationView, ReleaseInspection, ReplyStatus, RestoreView, StatusView,
};
