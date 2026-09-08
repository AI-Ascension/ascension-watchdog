#![doc = "Deterministic crash-resilient supervision for AI-Ascension."]
// The package has intentionally small, dependency-free public APIs around
// SQLite and process adapters.  These targeted allows keep the strict
// workspace `all`/`pedantic` policy useful without requiring every Result
// wrapper to repeat the same generated error prose or replacing checked,
// bounded timestamp conversions with lossy casts.
#![allow(
    clippy::collapsible_if,
    clippy::doc_markdown,
    clippy::format_collect,
    clippy::map_unwrap_or,
    clippy::match_same_arms,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::needless_as_bytes,
    clippy::ptr_arg,
    clippy::semicolon_if_nothing_returned,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity
)]

pub mod admin;
pub mod cli;
pub mod config;
pub mod error;
pub mod platform;
pub mod policy;
pub mod preflight;
pub mod process;
pub mod release;
pub mod runtime;
pub mod service;
pub mod storage;
#[cfg(windows)]
pub mod windows_service;
pub mod worker_bootstrap;
pub mod worker_client;
pub mod worker_protocol;

pub use config::{ComponentConfig, DesiredMode, WatchdogConfig};
pub use error::{Result, WatchdogError};
pub use policy::{
    ComponentObservation, ComponentState, ReconcileAction, ReconcileDecision, SupervisorPolicy,
};
pub use process::{OutputSnapshot, OwnedChild, ProcessIdentity};
pub use runtime::{DirectRuntimeAdapter, ReconcileReport, RuntimeAdapter, Supervisor};
pub use storage::{
    Completion, ComponentRecord, DurabilityPragmas, JobClaim, JobRecord, JobStatus, SingletonLock,
    Store, StoreStatus,
};
