//! Additive owner-local worker schema and migration.

use super::{insert_audit_tx, metadata_from_conn};
use crate::error::{Result, WatchdogError};
use rusqlite::{Connection, Transaction, TransactionBehavior, params};

pub const WORKER_HANDOFF_SCHEMA_VERSION: i64 = 1;
pub const MAX_WORKER_WIRE_INTEGER: u64 = 9_007_199_254_740_991;
pub const WORKER_HANDOFF_CONTRACT: &str = "ascension-watchdog-worker-handoff-v1";
pub const WORKER_HANDOFF_SCHEMA_DIGEST: &str =
    "bb13d15f6c0e4b8d0f58f7391fe4ba319ebc57a0a09effc06d73ea718bbff4cf";
pub const WORKER_HANDOFF_OPERATION: &str = "runtime_v3_episode";
pub const WORKER_HANDOFF_PAYLOAD_DIGEST: &str =
    "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

const WORKER_SCHEMA_METADATA_KEY: &str = "worker_handoff_schema_version";

/// Create the additive worker tables for a brand-new store.
pub(crate) fn create_worker_handoff_schema(conn: &mut Connection) -> Result<()> {
    conn.execute_batch(WORKER_SCHEMA_SQL)?;
    Ok(())
}

/// Insert the worker schema marker in the same initialization transaction as
/// the core metadata.  The migration path uses the same marker only after all
/// tables have been created successfully.
pub(crate) fn insert_worker_handoff_metadata(tx: &Transaction<'_>) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata (key, value) VALUES (?, ?)",
        params![
            WORKER_SCHEMA_METADATA_KEY,
            WORKER_HANDOFF_SCHEMA_VERSION.to_string()
        ],
    )?;
    Ok(())
}

/// Upgrade an existing owner-local core store under the already-held owner
/// lock.  A missing worker marker is migrated only when all worker tables are
/// absent; a partially created set fails closed and is never completed by a
/// read-only open.
pub(crate) fn migrate_worker_handoff_for_owner(conn: &mut Connection) -> Result<()> {
    let marker = metadata_from_conn(conn, WORKER_SCHEMA_METADATA_KEY)?;
    if let Some(value) = marker {
        let version = value.parse::<i64>().map_err(|_| {
            WatchdogError::Conflict(
                "worker handoff schema marker is not a valid SQLite integer".to_owned(),
            )
        })?;
        if version != WORKER_HANDOFF_SCHEMA_VERSION {
            return Err(WatchdogError::Unsupported(format!(
                "worker handoff schema {version} requires an explicit migration"
            )));
        }
        validate_worker_handoff_schema(conn)
    } else {
        let table_names = ["worker_bindings", "worker_control", "worker_handoffs"];
        let present = table_names
            .iter()
            .map(|name| super::table_exists(conn, name))
            .collect::<Result<Vec<_>>>()?;
        if present.iter().any(|exists| *exists) {
            return Err(WatchdogError::Conflict(
                "worker handoff schema is partially present without its version marker".to_owned(),
            ));
        }
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(WORKER_SCHEMA_SQL)?;
        insert_worker_handoff_metadata(&tx)?;
        insert_audit_tx(
            &tx,
            "worker_handoff_schema_migrated",
            &format!("schema={WORKER_HANDOFF_SCHEMA_VERSION}"),
            super::now_unix_ms(),
        )?;
        tx.commit()?;
        validate_worker_handoff_schema(conn)
    }
}

fn validate_worker_handoff_schema(conn: &Connection) -> Result<()> {
    for name in ["worker_bindings", "worker_control", "worker_handoffs"] {
        if !super::table_exists(conn, name)? {
            return Err(WatchdogError::Conflict(format!(
                "worker handoff table {name} is missing"
            )));
        }
    }
    for (table, required) in [
        (
            "worker_bindings",
            [
                "singleton",
                "deployment_id",
                "worker_owner_id",
                "worker_profile_digest",
                "release_digest",
                "config_digest",
                "schema_digest",
                "updated_at_ms",
            ]
            .as_slice(),
        ),
        (
            "worker_control",
            [
                "singleton",
                "deployment_id",
                "worker_owner_id",
                "worker_profile_digest",
                "watchdog_boot_id",
                "worker_boot_id",
                "mode",
                "mode_sequence",
                "updated_at_ms",
            ]
            .as_slice(),
        ),
        (
            "worker_handoffs",
            [
                "handoff_id",
                "deployment_id",
                "job_id",
                "attempt_id",
                "attempt_number",
                "worker_owner_id",
                "worker_profile_digest",
                "run_id",
                "episode_id",
                "trajectory_id",
                "payload_digest",
                "watchdog_boot_id",
                "worker_boot_id",
                "mode_sequence",
                "operation",
                "parameters",
                "state",
                "terminal_status",
                "checkpoint_sequence",
                "terminal_ref",
                "result_digest",
                "terminal_digest",
                "terminal_result",
                "ack_intent",
                "created_at_ms",
                "updated_at_ms",
                "dispatched_at_ms",
                "admitted_at_ms",
                "terminal_at_ms",
                "acknowledged_at_ms",
            ]
            .as_slice(),
        ),
    ] {
        let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for column in required {
            if !columns.iter().any(|value| value == column) {
                return Err(WatchdogError::Conflict(format!(
                    "{table} table is missing {column}"
                )));
            }
        }
    }
    Ok(())
}

const WORKER_SCHEMA_SQL: &str = r"
CREATE TABLE IF NOT EXISTS worker_bindings (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    deployment_id TEXT NOT NULL,
    worker_owner_id TEXT NOT NULL,
    worker_profile_digest TEXT NOT NULL,
    release_digest TEXT NOT NULL,
    config_digest TEXT NOT NULL,
    schema_digest TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS worker_control (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    deployment_id TEXT NOT NULL,
    worker_owner_id TEXT NOT NULL,
    worker_profile_digest TEXT NOT NULL,
    watchdog_boot_id TEXT NOT NULL,
    worker_boot_id TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN ('running','paused','draining','stopped')),
    mode_sequence INTEGER NOT NULL CHECK(mode_sequence > 0),
    updated_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS worker_handoffs (
    handoff_id TEXT PRIMARY KEY NOT NULL,
    deployment_id TEXT NOT NULL,
    job_id TEXT NOT NULL REFERENCES jobs(id),
    attempt_id TEXT NOT NULL REFERENCES attempts(id),
    attempt_number INTEGER NOT NULL CHECK(attempt_number > 0),
    worker_owner_id TEXT NOT NULL,
    worker_profile_digest TEXT NOT NULL,
    run_id TEXT NOT NULL,
    episode_id TEXT NOT NULL,
    trajectory_id TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    watchdog_boot_id TEXT NOT NULL,
    worker_boot_id TEXT NOT NULL,
    mode_sequence INTEGER NOT NULL CHECK(mode_sequence > 0),
    operation TEXT NOT NULL CHECK(operation = 'runtime_v3_episode'),
    parameters TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('prepared','may_have_been_dispatched','admitted','completed','failed','acknowledged','rejected')),
    terminal_status TEXT CHECK(terminal_status IS NULL OR terminal_status IN ('completed','failed')),
    checkpoint_sequence INTEGER CHECK(checkpoint_sequence IS NULL OR checkpoint_sequence >= 0),
    terminal_ref TEXT,
    result_digest TEXT,
    terminal_digest TEXT,
    terminal_result TEXT,
    ack_intent INTEGER NOT NULL DEFAULT 0 CHECK(ack_intent IN (0,1)),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    dispatched_at_ms INTEGER,
    admitted_at_ms INTEGER,
    terminal_at_ms INTEGER,
    acknowledged_at_ms INTEGER,
    UNIQUE(attempt_id),
    UNIQUE(episode_id),
    UNIQUE(run_id),
    UNIQUE(trajectory_id)
);
CREATE INDEX IF NOT EXISTS worker_handoffs_state_idx ON worker_handoffs(state, created_at_ms, handoff_id);
CREATE INDEX IF NOT EXISTS worker_handoffs_job_idx ON worker_handoffs(job_id, attempt_id);
";
