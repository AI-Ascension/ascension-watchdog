//! Owner-local durable watchdog state.
//!
//! The store is intentionally separate from gateway and harness databases.  A
//! missing path is never opened by read-only commands, and an existing but
//! malformed path is reported as corruption instead of being recreated.
//!
//! `Store` is the facade type; the cohesive slices of its lifecycle live in
//! sibling modules, each owning one concern:
//!
//! - `storage_metadata` owns the status projection, desired mode / restart
//!   generation transitions, the bounded audit ledger, metadata access,
//!   reconciliation progress and the shared SQLite value guards (issue #101).
//! - `storage_jobs` owns the durable job queue, claims, completions and
//!   failures (issue #98).
//! - `storage_components` owns component records, persisted process identity
//!   and restart accounting (issue #99).
//! - `storage_launch_intents` owns pre-spawn launch admission and recovery
//!   records (issue #100).

use crate::config::validate_digest;
use crate::error::{Result, WatchdogError};
use rusqlite::{Connection, Transaction, TransactionBehavior};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[path = "storage_admin.rs"]
mod storage_admin;
#[path = "storage_backup.rs"]
mod storage_backup;
#[path = "storage_components.rs"]
mod storage_components;
#[path = "storage_gateway_health.rs"]
mod storage_gateway_health;
#[path = "storage_jobs.rs"]
mod storage_jobs;
#[path = "storage_launch_intents.rs"]
mod storage_launch_intents;
#[path = "storage_metadata.rs"]
mod storage_metadata;
#[path = "storage_ownership.rs"]
mod storage_ownership;
#[path = "storage_quarantine_admin.rs"]
mod storage_quarantine_admin;
#[path = "storage_queries.rs"]
mod storage_queries;
#[path = "storage_release.rs"]
mod storage_release;
#[path = "storage_retry_admin.rs"]
mod storage_retry_admin;
#[path = "storage_schema.rs"]
mod storage_schema;
#[path = "storage_worker_bootstrap.rs"]
mod storage_worker_bootstrap;
#[path = "storage_worker_handoff.rs"]
mod storage_worker_handoff;
pub use storage_admin::{
    MAX_OPERATOR_COMMANDS, MAX_OPERATOR_COMMANDS_WITH_STOP_RESERVE, MAX_OPERATOR_RESPONSE_BYTES,
    OPERATOR_LEDGER_SCHEMA_VERSION, OperatorCapability, OperatorCommand, OperatorCommandContext,
    OperatorCommandOutcome, OperatorCommandReceipt, RESERVED_LIFECYCLE_COMMANDS,
    RESERVED_STOP_COMMANDS, migrate_operator_ledger_for_owner,
};
pub use storage_components::ComponentRecord;
pub use storage_gateway_health::GatewayHealthBootstrapBinding;
pub use storage_jobs::{Completion, JobClaim, JobRecord, JobStatus};
pub(crate) use storage_jobs::{insert_job_tx, validate_claim_payload};
pub use storage_launch_intents::{LaunchIntent, LaunchIntentState};
pub(crate) use storage_launch_intents::{launch_intent_from_row, require_running_launch_intent};
pub use storage_metadata::{
    MAX_AUDIT_RECORDS, RESERVED_CRITICAL_AUDIT_RECORDS, RESERVED_STOP_AUDIT_RECORDS, StoreStatus,
};
pub(crate) use storage_metadata::{
    insert_audit_tx, metadata_from_conn, mode_as_str, parse_metadata_i64, parse_mode,
    sqlite_optional_u32, sqlite_optional_u64, sqlite_timestamp, sqlite_u32, sqlite_u64,
    to_sqlite_error, update_metadata_tx, upsert_metadata_tx, validate_detail,
    validate_metadata_identifier, validate_name, validate_name_sqlite,
};
pub use storage_ownership::SingletonLock;
use storage_ownership::{canonical_owner_path, ensure_owner_lock, reject_link_or_reparse};
pub use storage_queries::{AttemptSummary, JobSummary, JobSummaryPage};
pub use storage_release::{
    PendingReleaseActivation, ReleaseIdentity, ReleaseSelection, ReleaseSelectionState,
};
pub use storage_schema::DurabilityPragmas;
pub(crate) use storage_schema::table_exists;
use storage_schema::{
    config_compatibility_digest, connection_pragmas, open_connection, open_connection_with_flags,
    validate_local_storage_path,
};
pub use storage_worker_bootstrap::WorkerBootstrapBinding;
pub use storage_worker_handoff::{
    MAX_WORKER_WIRE_INTEGER, WORKER_HANDOFF_CONTRACT, WORKER_HANDOFF_OPERATION,
    WORKER_HANDOFF_PAYLOAD_DIGEST, WORKER_HANDOFF_SCHEMA_DIGEST, WORKER_HANDOFF_SCHEMA_VERSION,
    WorkerAcknowledgment, WorkerBinding, WorkerClaimWitness, WorkerCompletion, WorkerControlMode,
    WorkerControlWitness, WorkerHandoff, WorkerHandoffState, WorkerHandoffTuple,
    WorkerTerminalReceipt, WorkerTerminalRecord, WorkerTerminalStatus,
};

const SCHEMA_VERSION: i64 = 2;
const PREVIOUS_SCHEMA_VERSION: i64 = 1;

/// Return wall-clock milliseconds for audit records.  Scheduling uses the
/// explicit timestamp passed to policy/runtime methods instead.
#[must_use]
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Durable deployment and job store.
pub struct Store {
    conn: Connection,
    path: PathBuf,
    max_jobs: u64,
    max_payload_bytes: usize,
    restart_clock_epoch: String,
    restart_clock_started: Instant,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("path", &self.path)
            .field("max_jobs", &self.max_jobs)
            .field("max_payload_bytes", &self.max_payload_bytes)
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Open the store's SQLite connection without changing its state.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Run SQLite's integrity check without attempting repair.
    pub fn integrity_check(&self) -> Result<bool> {
        let result: String = self
            .conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        Ok(result.eq_ignore_ascii_case("ok"))
    }
}
