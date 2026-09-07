//! Owner-local worker handoff storage seam.
//!
//! The implementation is intentionally split by boundary: schema migration,
//! public identity types, claim/control admission, completion/acknowledgment,
//! and read-side projections each live in their own focused module.

mod storage_worker_claims;
mod storage_worker_completion;
mod storage_worker_queries;
mod storage_worker_schema;
mod storage_worker_types;

pub use storage_worker_schema::{
    MAX_WORKER_WIRE_INTEGER, WORKER_HANDOFF_CONTRACT, WORKER_HANDOFF_OPERATION,
    WORKER_HANDOFF_PAYLOAD_DIGEST, WORKER_HANDOFF_SCHEMA_DIGEST, WORKER_HANDOFF_SCHEMA_VERSION,
};
pub use storage_worker_types::{
    WorkerAcknowledgment, WorkerBinding, WorkerClaimWitness, WorkerCompletion, WorkerControlMode,
    WorkerControlWitness, WorkerHandoff, WorkerHandoffState, WorkerHandoffTuple,
    WorkerTerminalReceipt, WorkerTerminalRecord, WorkerTerminalStatus,
};

// The child modules use these owner-store primitives without widening their
// visibility beyond this storage module.
pub(crate) use super::{
    Store, insert_audit_tx, metadata_from_conn, now_unix_ms, parse_mode, sqlite_timestamp,
    sqlite_u32, sqlite_u64, table_exists, to_sqlite_error, validate_claim_payload, validate_name,
};

pub(crate) use storage_worker_schema::{
    create_worker_handoff_schema, insert_worker_handoff_metadata, migrate_worker_handoff_for_owner,
};
