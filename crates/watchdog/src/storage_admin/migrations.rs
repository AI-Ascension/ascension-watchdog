//! Additive operator-ledger migrations.
//!
//! This module owns the durable schema work for the operator ledger: the
//! owner-locked upgrade entrypoint, the v1-to-v2 command-constraint rebuild,
//! the bootstrap DDL and the strict table-shape validation.  It never opens a
//! missing database and never runs from read-only status/doctor paths.

use super::super::{
    SCHEMA_VERSION, SingletonLock, Transaction, TransactionBehavior, WatchdogError,
    ensure_owner_lock, metadata_from_conn, open_connection_with_flags, validate_local_storage_path,
};
use super::types::OPERATOR_LEDGER_SCHEMA_VERSION;
use crate::error::Result;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::path::Path;

/// Upgrade only the additive operator-ledger table while the exact owner lock
/// is held.  This never creates a missing watchdog database and never runs
/// from read-only status/doctor paths.
pub fn migrate_operator_ledger_for_owner(
    path: impl AsRef<Path>,
    owner: &SingletonLock,
) -> Result<()> {
    let path = path.as_ref();
    ensure_owner_lock(path, owner)?;
    validate_local_storage_path(path, "operator ledger database")?;
    if !path.is_file() {
        return Err(WatchdogError::MissingState(path.to_path_buf()));
    }
    let mut conn = open_connection_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let schema = metadata_from_conn(&conn, "schema_version")?.ok_or_else(|| {
        WatchdogError::Conflict("watchdog schema_version metadata is missing".to_string())
    })?;
    let schema = schema.parse::<i64>().map_err(|_| {
        WatchdogError::Conflict("watchdog schema_version metadata is invalid".to_string())
    })?;
    if schema != SCHEMA_VERSION {
        return Err(WatchdogError::Unsupported(format!(
            "store schema {schema} requires an explicit migration"
        )));
    }
    let table_present = table_exists(&conn, "operator_commands")?;
    let supports_job_submit = if table_present {
        validate_operator_table(&conn)?;
        operator_table_supports_job_submit(&conn)?
    } else {
        false
    };
    let existing_version: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key='operator_ledger_schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let existing_version = existing_version
        .map(|version| {
            version.parse::<i64>().map_err(|_| {
                WatchdogError::Conflict(
                    "operator ledger schema version metadata is invalid".to_string(),
                )
            })
        })
        .transpose()?;
    if existing_version
        .is_some_and(|version| !(1..=OPERATOR_LEDGER_SCHEMA_VERSION).contains(&version))
    {
        return Err(WatchdogError::Unsupported(format!(
            "operator ledger schema {} requires an explicit migration",
            existing_version.unwrap_or_default()
        )));
    }
    if existing_version == Some(OPERATOR_LEDGER_SCHEMA_VERSION) && !table_present {
        return Err(WatchdogError::Conflict(
            "operator ledger schema marker exists but operator_commands is missing".to_string(),
        ));
    }
    if existing_version == Some(1) && !table_present {
        return Err(WatchdogError::Conflict(
            "operator ledger schema v1 marker exists but operator_commands is missing".to_string(),
        ));
    }
    if existing_version == Some(OPERATOR_LEDGER_SCHEMA_VERSION) && !supports_job_submit {
        return Err(WatchdogError::Conflict(
            "operator ledger schema v2 marker is paired with a v1 command constraint".to_string(),
        ));
    }

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if !table_present {
        // A missing marker and missing operator table is the only recognized
        // bootstrap case. A marker that already claimed a ledger was handled
        // above as corruption, so receipts can never be silently discarded.
        tx.execute_batch(OPERATOR_TABLE_SQL)?;
    } else if !supports_job_submit {
        migrate_operator_table_v1_to_v2(&tx)?;
    } else {
        tx.execute_batch(OPERATOR_INDEX_SQL)?;
    }
    let existing_version: Option<String> = tx
        .query_row(
            "SELECT value FROM metadata WHERE key='operator_ledger_schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match existing_version {
        Some(version) if version != "1" && version != "2" => {
            return Err(WatchdogError::Unsupported(format!(
                "operator ledger schema {version} requires an explicit migration"
            )));
        }
        Some(_) => {
            tx.execute(
                "UPDATE metadata SET value=? WHERE key='operator_ledger_schema_version'",
                params![OPERATOR_LEDGER_SCHEMA_VERSION.to_string()],
            )?;
        }
        None => {
            tx.execute(
                "INSERT INTO metadata (key, value) VALUES ('operator_ledger_schema_version', ?)",
                params![OPERATOR_LEDGER_SCHEMA_VERSION.to_string()],
            )?;
        }
    }
    tx.commit()?;
    Ok(())
}

const OPERATOR_INDEX_SQL: &str = "
    CREATE INDEX IF NOT EXISTS operator_commands_order_idx ON operator_commands(sequence);
    CREATE INDEX IF NOT EXISTS operator_commands_principal_idx ON operator_commands(principal, sequence);
";

const OPERATOR_TABLE_V2_REBUILD_SQL: &str = "
    CREATE TABLE operator_commands_v2 (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id TEXT NOT NULL UNIQUE,
        idempotency_key TEXT NOT NULL UNIQUE,
        principal TEXT NOT NULL,
        capability TEXT NOT NULL CHECK(capability IN ('read','admin')),
        command TEXT NOT NULL CHECK(command IN (
            'status','jobs','attempt','release_inspect','start','pause',
            'resume','drain','stop','quarantine','retry','reconcile',
            'backup','restore','release_activate','job_submit'
        )),
        command_fingerprint TEXT NOT NULL,
        desired_mode TEXT CHECK(desired_mode IS NULL OR desired_mode IN ('stopped','paused','running','draining')),
        response_json TEXT NOT NULL,
        recorded_at_ms INTEGER NOT NULL
    );
";

fn operator_table_supports_job_submit(conn: &Connection) -> Result<bool> {
    let ddl: String = conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='operator_commands'",
        [],
        |row| row.get(0),
    )?;
    Ok(ddl.to_ascii_lowercase().contains("'job_submit'"))
}

fn migrate_operator_table_v1_to_v2(tx: &Transaction<'_>) -> Result<()> {
    let high_water: Option<i64> = tx
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name='operator_commands'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let retained_max: i64 = tx.query_row(
        "SELECT COALESCE(MAX(sequence), 0) FROM operator_commands",
        [],
        |row| row.get(0),
    )?;
    if high_water.unwrap_or(0) < retained_max || high_water.is_some_and(|value| value < 0) {
        return Err(WatchdogError::Conflict(
            "operator sequence high-water mark is inconsistent with retained receipts".to_owned(),
        ));
    }
    tx.execute_batch(OPERATOR_TABLE_V2_REBUILD_SQL)?;
    tx.execute(
        "INSERT INTO operator_commands_v2 (sequence, request_id, idempotency_key, principal, capability, command, command_fingerprint, desired_mode, response_json, recorded_at_ms) SELECT sequence, request_id, idempotency_key, principal, capability, command, command_fingerprint, desired_mode, response_json, recorded_at_ms FROM operator_commands ORDER BY sequence",
        [],
    )?;
    tx.execute_batch(
        "DROP INDEX IF EXISTS operator_commands_order_idx;
         DROP INDEX IF EXISTS operator_commands_principal_idx;
         DROP TABLE operator_commands;
         ALTER TABLE operator_commands_v2 RENAME TO operator_commands;",
    )?;
    tx.execute_batch(OPERATOR_INDEX_SQL)?;
    if let Some(high_water) = high_water {
        let updated = tx.execute(
            "UPDATE sqlite_sequence SET seq=MAX(seq, ?) WHERE name='operator_commands'",
            params![high_water],
        )?;
        if updated == 0 {
            tx.execute(
                "INSERT INTO sqlite_sequence(name, seq) VALUES ('operator_commands', ?)",
                params![high_water],
            )?;
        }
    }
    Ok(())
}

const OPERATOR_TABLE_SQL: &str = "
    CREATE TABLE IF NOT EXISTS operator_commands (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id TEXT NOT NULL UNIQUE,
        idempotency_key TEXT NOT NULL UNIQUE,
        principal TEXT NOT NULL,
        capability TEXT NOT NULL CHECK(capability IN ('read','admin')),
        command TEXT NOT NULL CHECK(command IN (
            'status','jobs','attempt','release_inspect','start','pause',
            'resume','drain','stop','quarantine','retry','reconcile',
            'backup','restore','release_activate','job_submit'
        )),
        command_fingerprint TEXT NOT NULL,
        desired_mode TEXT CHECK(desired_mode IS NULL OR desired_mode IN ('stopped','paused','running','draining')),
        response_json TEXT NOT NULL,
        recorded_at_ms INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS operator_commands_order_idx ON operator_commands(sequence);
    CREATE INDEX IF NOT EXISTS operator_commands_principal_idx ON operator_commands(principal, sequence);
";

fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let value: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            params![name],
            |row| row.get(0),
        )
        .optional()?;
    Ok(value.is_some())
}

fn validate_operator_table(conn: &Connection) -> Result<()> {
    let mut statement = conn.prepare("PRAGMA table_info(operator_commands)")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?,
        ))
    })?;
    let columns = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    let expected = [
        ("sequence", "INTEGER", 0, 1),
        ("request_id", "TEXT", 1, 0),
        ("idempotency_key", "TEXT", 1, 0),
        ("principal", "TEXT", 1, 0),
        ("capability", "TEXT", 1, 0),
        ("command", "TEXT", 1, 0),
        ("command_fingerprint", "TEXT", 1, 0),
        ("desired_mode", "TEXT", 0, 0),
        ("response_json", "TEXT", 1, 0),
        ("recorded_at_ms", "INTEGER", 1, 0),
    ];
    if columns.len() != expected.len()
        || columns
            .iter()
            .zip(expected)
            .any(|((name, kind, not_null, primary_key), expected)| {
                name != expected.0
                    || !kind.eq_ignore_ascii_case(expected.1)
                    || *not_null != expected.2
                    || *primary_key != expected.3
            })
    {
        return Err(WatchdogError::Conflict(
            "operator_commands table has an incompatible schema".to_string(),
        ));
    }
    let ddl: String = conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='operator_commands'",
        [],
        |row| row.get(0),
    )?;
    let normalized_ddl = ddl
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    for required in [
        "request_id text not null unique",
        "idempotency_key text not null unique",
        "capability text not null check",
        "command text not null check",
        "response_json text not null",
    ] {
        if !normalized_ddl.contains(required) {
            return Err(WatchdogError::Conflict(
                "operator_commands table constraints are incomplete".to_string(),
            ));
        }
    }
    Ok(())
}
