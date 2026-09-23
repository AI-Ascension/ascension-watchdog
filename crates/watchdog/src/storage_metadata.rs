//! Desired mode, audit ledger, metadata and shared SQLite value validation.
//!
//! Extracted from `storage.rs` (issue #101) without behavior change: the
//! status projection, desired-mode and restart-generation transitions, the
//! bounded audit ledger, the metadata accessors, reconciliation progress and
//! the shared SQLite conversion guards used by every storage child module.

use super::{DurabilityPragmas, JobStatus, SCHEMA_VERSION, Store, now_unix_ms};
use crate::config::DesiredMode;
use crate::error::{Result, WatchdogError};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::Serialize;
use std::path::PathBuf;

const MAX_AUDIT_DETAIL_BYTES: usize = 16 * 1024;

/// Hard upper bound for retained audit rows.  Audit is intentionally
/// backpressured rather than silently evicted: deleting an old audit row can
/// make an operator replay indistinguishable from a new command.
pub const MAX_AUDIT_RECORDS: i64 = 4096;

/// Keep a small audit reserve for lifecycle commands when ordinary diagnostic
/// events have consumed the normal retention budget.
pub const RESERVED_CRITICAL_AUDIT_RECORDS: i64 = 8;

/// One bounded emergency slot keeps a fresh operator stop admissible after
/// ordinary and lifecycle ledger capacity is exhausted.
pub const RESERVED_STOP_AUDIT_RECORDS: i64 = 1;

/// Side-effect-free status snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StoreStatus {
    pub database: PathBuf,
    pub deployment_id: String,
    pub desired_mode: DesiredMode,
    pub schema_version: i64,
    pub restart_generation: i64,
    pub config_digest: String,
    pub approved_release_digest: Option<String>,
    pub jobs_queued: u64,
    pub jobs_running: u64,
    pub jobs_completed: u64,
    pub jobs_quarantined: u64,
    pub durability: DurabilityPragmas,
}

pub(crate) fn metadata_from_conn(conn: &Connection, key: &str) -> Result<Option<String>> {
    conn.query_row(
        "SELECT value FROM metadata WHERE key=?",
        params![key],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

pub(crate) fn update_metadata_tx(tx: &Transaction<'_>, key: &str, value: &str) -> Result<()> {
    let changed = tx.execute(
        "UPDATE metadata SET value=? WHERE key=?",
        params![value, key],
    )?;
    if changed != 1 {
        return Err(WatchdogError::Conflict(format!(
            "metadata key {key} is missing"
        )));
    }
    Ok(())
}

pub(crate) fn upsert_metadata_tx(tx: &Transaction<'_>, key: &str, value: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value],
    )?;
    Ok(())
}

pub(crate) fn insert_audit_tx(
    tx: &Transaction<'_>,
    action: &str,
    detail: &str,
    now_ms: u64,
) -> Result<()> {
    validate_name(action, "audit action", 128)?;
    validate_detail(detail, "audit detail")?;
    let retained: i64 = tx.query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0))?;
    let limit = if is_emergency_stop_audit_action(action) {
        MAX_AUDIT_RECORDS + RESERVED_STOP_AUDIT_RECORDS
    } else if is_critical_audit_action(action) {
        MAX_AUDIT_RECORDS
    } else {
        MAX_AUDIT_RECORDS - RESERVED_CRITICAL_AUDIT_RECORDS
    };
    if retained >= limit {
        return Err(WatchdogError::Conflict(
            "audit retention bound is full; explicit archival is required".to_string(),
        ));
    }
    tx.execute(
        "INSERT INTO audit (action, detail, occurred_at_ms) VALUES (?, ?, ?)",
        params![action, detail, sqlite_timestamp(now_ms)?],
    )?;
    Ok(())
}

fn is_critical_audit_action(action: &str) -> bool {
    action == "desired_mode_changed"
        || action.starts_with("operator_command_")
        || action == "store_restored_new_watchdog_namespace"
}

fn is_emergency_stop_audit_action(action: &str) -> bool {
    action == "operator_command_stop_accepted"
}

pub(crate) fn validate_name_sqlite(value: &str, field: &str, bound: usize) -> rusqlite::Result<()> {
    if value.is_empty() || value.len() > bound || value.chars().any(char::is_control) {
        return Err(to_sqlite_error(format!(
            "{field} is invalid or exceeds its bound"
        )));
    }
    Ok(())
}

pub(crate) fn to_sqlite_error<E: std::fmt::Display>(error: E) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error.to_string(),
        )),
    )
}

pub(crate) fn sqlite_u64(value: i64, field: &str) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| {
        to_sqlite_error(format!(
            "{field} contains a negative or out-of-range integer"
        ))
    })
}

pub(crate) fn sqlite_u32(value: i64, field: &str) -> rusqlite::Result<u32> {
    u32::try_from(value).map_err(|_| {
        to_sqlite_error(format!(
            "{field} contains a negative or out-of-range integer"
        ))
    })
}

pub(crate) fn sqlite_optional_u64(
    value: Option<i64>,
    field: &str,
) -> rusqlite::Result<Option<u64>> {
    value.map(|value| sqlite_u64(value, field)).transpose()
}

pub(crate) fn sqlite_optional_u32(
    value: Option<i64>,
    field: &str,
) -> rusqlite::Result<Option<u32>> {
    value.map(|value| sqlite_u32(value, field)).transpose()
}

pub(crate) fn validate_name(value: &str, name: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.as_bytes().contains(&0)
        || value.chars().any(char::is_control)
    {
        return Err(WatchdogError::InvalidInput(format!(
            "{name} must be non-empty, bounded, and free of control characters"
        )));
    }
    Ok(())
}

pub(crate) fn parse_metadata_i64(key: &str, value: &str) -> Result<i64> {
    value.parse::<i64>().map_err(|_| {
        WatchdogError::Conflict(format!("{key} metadata is not a valid SQLite integer"))
    })
}

pub(crate) fn validate_metadata_identifier(key: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || value.as_bytes().contains(&0)
        || value.chars().any(char::is_control)
    {
        return Err(WatchdogError::Conflict(format!(
            "{key} metadata is invalid"
        )));
    }
    Ok(())
}

pub(crate) fn sqlite_timestamp(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| {
        WatchdogError::InvalidInput("timestamp exceeds SQLite integer range".to_string())
    })
}

pub(crate) fn validate_detail(value: &str, name: &str) -> Result<()> {
    if value.len() > MAX_AUDIT_DETAIL_BYTES || value.as_bytes().contains(&0) {
        return Err(WatchdogError::InvalidInput(format!(
            "{name} exceeds its size bound"
        )));
    }
    Ok(())
}

pub(crate) fn mode_as_str(mode: DesiredMode) -> &'static str {
    match mode {
        DesiredMode::Stopped => "stopped",
        DesiredMode::Paused => "paused",
        DesiredMode::Running => "running",
        DesiredMode::Draining => "draining",
    }
}

pub(crate) fn parse_mode(value: &str) -> Result<DesiredMode> {
    match value {
        "stopped" => Ok(DesiredMode::Stopped),
        "paused" => Ok(DesiredMode::Paused),
        "running" => Ok(DesiredMode::Running),
        "draining" => Ok(DesiredMode::Draining),
        other => Err(WatchdogError::Conflict(format!(
            "unknown desired mode {other}"
        ))),
    }
}

impl Store {
    /// Produce a bounded status view suitable for the CLI/API.
    pub fn status(&self) -> Result<StoreStatus> {
        let deployment_id = self.metadata("deployment_id")?.ok_or_else(|| {
            WatchdogError::Conflict("deployment_id metadata is missing".to_string())
        })?;
        validate_metadata_identifier("deployment_id", &deployment_id)?;
        let desired_mode = parse_mode(&self.metadata("desired_mode")?.ok_or_else(|| {
            WatchdogError::Conflict("desired mode metadata is missing".to_string())
        })?)?;
        let schema_version = parse_metadata_i64(
            "schema_version",
            &self.metadata("schema_version")?.ok_or_else(|| {
                WatchdogError::Conflict("schema_version metadata is missing".to_string())
            })?,
        )?;
        if schema_version != SCHEMA_VERSION {
            return Err(WatchdogError::Unsupported(format!(
                "store schema {schema_version} requires an explicit migration"
            )));
        }
        let restart_generation = parse_metadata_i64(
            "restart_generation",
            &self.metadata("restart_generation")?.ok_or_else(|| {
                WatchdogError::Conflict("restart_generation metadata is missing".to_string())
            })?,
        )?;
        if restart_generation <= 0 {
            return Err(WatchdogError::Conflict(
                "restart_generation metadata must be positive".to_string(),
            ));
        }
        let config_digest = self.metadata("config_digest")?.ok_or_else(|| {
            WatchdogError::Conflict("config_digest metadata is missing".to_string())
        })?;
        crate::config::validate_digest(&config_digest).map_err(|message| {
            WatchdogError::Conflict(format!("config_digest metadata is invalid: {message}"))
        })?;
        let approved_release_digest = self.metadata("approved_release_digest")?;
        if let Some(digest) = &approved_release_digest {
            crate::config::validate_digest(digest).map_err(|message| {
                WatchdogError::Conflict(format!(
                    "approved_release_digest metadata is invalid: {message}"
                ))
            })?;
        }
        let jobs_queued = self.job_count(JobStatus::Queued)?;
        let jobs_running = self.job_count(JobStatus::Running)?;
        let jobs_completed = self.job_count(JobStatus::Completed)?;
        let jobs_quarantined = self.job_count(JobStatus::Quarantined)?;
        Ok(StoreStatus {
            database: self.path.clone(),
            deployment_id,
            desired_mode,
            schema_version,
            restart_generation,
            config_digest,
            approved_release_digest,
            jobs_queued,
            jobs_running,
            jobs_completed,
            jobs_quarantined,
            durability: self.durability()?,
        })
    }

    /// Read-only desired intent.
    pub fn desired_mode(&self) -> Result<DesiredMode> {
        let value = self.metadata("desired_mode")?.ok_or_else(|| {
            WatchdogError::Conflict("desired mode metadata is missing".to_string())
        })?;
        parse_mode(&value)
    }

    /// Persist operator intent and audit it before the runtime performs any
    /// corresponding effect.
    pub fn set_desired_mode(&mut self, mode: DesiredMode) -> Result<()> {
        self.set_desired_mode_at(mode, now_unix_ms())
    }

    /// Deterministic timestamp variant used by tests and replay.
    pub fn set_desired_mode_at(&mut self, mode: DesiredMode, now_ms: u64) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        update_metadata_tx(&tx, "desired_mode", mode_as_str(mode))?;
        update_metadata_tx(&tx, "updated_at_ms", &now_ms.to_string())?;
        insert_audit_tx(&tx, "desired_mode_changed", mode_as_str(mode), now_ms)?;
        tx.commit()?;
        Ok(())
    }

    /// Increment the durable generation when a daemon establishes a fresh
    /// reconciliation context.  Historical generation values never grant
    /// authority by themselves.
    pub fn establish_new_generation(&mut self, now_ms: u64) -> Result<i64> {
        let current = parse_metadata_i64(
            "restart_generation",
            &self.metadata("restart_generation")?.ok_or_else(|| {
                WatchdogError::Conflict("restart_generation metadata is missing".to_string())
            })?,
        )?;
        if current <= 0 {
            return Err(WatchdogError::Conflict(
                "restart_generation metadata must be positive".to_string(),
            ));
        }
        let next = current
            .checked_add(1)
            .ok_or_else(|| WatchdogError::Conflict("restart generation exhausted".to_string()))?;
        let tx = self.conn.transaction()?;
        update_metadata_tx(&tx, "restart_generation", &next.to_string())?;
        update_metadata_tx(&tx, "updated_at_ms", &now_ms.to_string())?;
        insert_audit_tx(
            &tx,
            "fresh_reconciliation_generation",
            &next.to_string(),
            now_ms,
        )?;
        tx.commit()?;
        Ok(next)
    }

    /// Retain an audit event with a bounded detail string.
    pub fn audit(&mut self, action: &str, detail: &str, now_ms: u64) -> Result<()> {
        validate_name(action, "audit action", 128)?;
        validate_detail(detail, "audit detail")?;
        let tx = self.conn.transaction()?;
        insert_audit_tx(&tx, action, detail, now_ms)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn metadata(&self, key: &str) -> Result<Option<String>> {
        metadata_from_conn(&self.conn, key)
    }

    /// Commit a fixed-size loop-progress projection without consuming the
    /// retention budget for historical state transitions and operator actions.
    pub fn record_reconciliation_progress(&mut self, now_ms: u64) -> Result<()> {
        let timestamp = sqlite_timestamp(now_ms)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let sequence = metadata_from_conn(&tx, "reconciliation_sequence")?;
        let previous_time = metadata_from_conn(&tx, "last_reconciled_at_ms")?;
        if sequence.is_some() != previous_time.is_some() {
            return Err(WatchdogError::Conflict(
                "incomplete reconciliation progress marker".to_owned(),
            ));
        }
        if let Some(value) = previous_time {
            let value = value.parse::<u64>().map_err(|_| {
                WatchdogError::Conflict("invalid reconciliation timestamp".to_owned())
            })?;
            sqlite_timestamp(value)?;
        }
        let initialized = sequence.is_some();
        let previous = sequence
            .map(|value| value.parse::<u64>())
            .transpose()
            .map_err(|_| WatchdogError::Conflict("invalid reconciliation sequence".to_owned()))?
            .unwrap_or(0);
        if initialized && previous == 0 {
            return Err(WatchdogError::Conflict(
                "invalid zero reconciliation sequence".to_owned(),
            ));
        }
        let next = previous
            .checked_add(1)
            .filter(|value| i64::try_from(*value).is_ok())
            .ok_or_else(|| {
                WatchdogError::Conflict("reconciliation sequence exhausted".to_owned())
            })?;
        upsert_metadata_tx(&tx, "reconciliation_sequence", &next.to_string())?;
        upsert_metadata_tx(&tx, "last_reconciled_at_ms", &timestamp.to_string())?;
        tx.commit()?;
        Ok(())
    }
}
