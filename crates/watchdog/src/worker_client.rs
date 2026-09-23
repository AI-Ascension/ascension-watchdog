//! Authenticated watchdog-to-harness worker client.
//!
//! This module is the first production consumer of the frozen
//! `ascension-watchdog-worker-handoff-v1` frames.  It owns no worker database
//! and never retries an uncertain dispatch.  The owner-local
//! [`crate::storage::Store`] is updated before a dispatch send and after a
//! matching terminal response.
//!
//! The implementation is split into cohesive child modules; this file stays
//! the `worker_client` coordinator so every existing path into the module
//! keeps working:
//!
//! - `config` owns [`WorkerClientConfig`], its binding validation and the
//!   protected endpoint/credential references.
//! - `session` owns [`WorkerClient`] session lifecycle, the phase deadline and
//!   request header construction.
//! - `exchange` owns the bounded authenticated request/response exchanges
//!   (probe, control, dispatch, lookup, acknowledge).
//! - `orchestration` owns the store-backed claim/dispatch and reconciliation
//!   paths plus their result types.
//! - `validation` owns response, handoff and witness validation plus the
//!   protocol/storage tuple conversions.
//!
//! Every resulting module is below the 1,000-line target, so no exception has
//! to be documented.

#[path = "worker_client_auth.rs"]
mod auth;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
pub(crate) use auth::capture_linux_controller;
#[path = "worker_client_transport.rs"]
mod transport;

#[path = "worker_client_config.rs"]
mod config;
#[path = "worker_client_exchange.rs"]
mod exchange;
#[path = "worker_client_orchestration.rs"]
mod orchestration;
#[path = "worker_client_session.rs"]
mod session;
#[path = "worker_client_validation.rs"]
mod validation;

pub use auth::WorkerPeerIdentity;
pub use config::WorkerClientConfig;
pub use orchestration::{WorkerDispatchResult, WorkerReconcileResult};
pub use session::WorkerClient;
pub(crate) use session::WorkerPhaseError;
pub(crate) use validation::storage_receipt;
