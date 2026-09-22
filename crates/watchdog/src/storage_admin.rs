//! Durable, owner-authenticated operator command admission.
//!
//! This module deliberately sits below the transport.  A transport may
//! authenticate a request, but only the reconciliation owner can turn its
//! token-free context into a durable command admission.  The command ledger
//! stores request identity, capability class, a command digest, and a bounded
//! response; it never stores credentials or command payloads.
//!
//! The implementation is split into cohesive child modules; this file stays
//! the `storage_admin` coordinator so every existing path into the module
//! keeps working:
//!
//! - `types` owns the ledger value types, the closed command vocabulary, the
//!   retention constants and the bounded field validators.
//! - `admission` owns read-only, mutation and job-submission admission plus
//!   the bounded read projections.
//! - `receipt` owns receipt/replay lookups, ledger capacity enforcement,
//!   response validation and strict row decoding.
//! - `migrations` owns the owner-locked additive ledger upgrade, the
//!   v1-to-v2 command-constraint rebuild and the table-shape validation.
//!
//! Every resulting module is below the 1,000-line target, so no exception has
//! to be documented.  The functional acceptance tests live in `storage` and
//! exercise the child modules through the preserved re-exports below.

#[path = "storage_backup_admin.rs"]
mod storage_backup_admin;

// `storage` is itself declared with `#[path]`, so this coordinator must name
// the child files explicitly instead of relying on directory derivation.
#[path = "storage_admin/admission.rs"]
mod admission;
#[path = "storage_admin/migrations.rs"]
mod migrations;
#[path = "storage_admin/receipt.rs"]
mod receipt;
#[path = "storage_admin/types.rs"]
mod types;

// Re-exported for the sibling `storage_backup_admin` child module, which
// reaches these through `super::`.
use super::{SingletonLock, insert_audit_tx, metadata_from_conn};

pub use migrations::migrate_operator_ledger_for_owner;
pub(crate) use receipt::{
    enforce_ledger_capacity, find_operator_by_key, find_operator_by_request, validate_response,
};
pub use types::{
    MAX_OPERATOR_COMMANDS, MAX_OPERATOR_COMMANDS_WITH_STOP_RESERVE, MAX_OPERATOR_RESPONSE_BYTES,
    OPERATOR_LEDGER_SCHEMA_VERSION, OperatorCapability, OperatorCommand, OperatorCommandContext,
    OperatorCommandOutcome, OperatorCommandReceipt, RESERVED_LIFECYCLE_COMMANDS,
    RESERVED_STOP_COMMANDS,
};
