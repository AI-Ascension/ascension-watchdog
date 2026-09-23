//! Durable component records, persisted identity and restart accounting.
//!
//! Extracted from `storage.rs` (issue #99) without behavior change: the
//! component observation record and row decoder, the component state string
//! conversions, the persisted process identity, and the monotonic-epoch
//! restart budget accounting.  `Store` remains the facade type; this module
//! owns only the component/restart inherent methods.

use super::{
    Store, insert_audit_tx, sqlite_optional_u32, sqlite_optional_u64, sqlite_timestamp, sqlite_u32,
    to_sqlite_error, validate_detail, validate_name,
};
use crate::error::{Result, WatchdogError};
use crate::policy::ComponentState;
use crate::process::ProcessIdentity;
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::Serialize;

/// A persisted process observation used by reconciliation and status.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ComponentRecord {
    pub id: String,
    pub state: ComponentState,
    pub launch_nonce: Option<String>,
    pub pid: Option<u32>,
    pub executable_digest: Option<String>,
    pub started_at_ms: Option<u64>,
    pub restart_attempts: u32,
    pub last_restart_at_ms: Option<u64>,
    pub last_error: Option<String>,
}

fn component_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ComponentRecord> {
    let state: String = row.get(1)?;
    Ok(ComponentRecord {
        id: row.get(0)?,
        state: component_state_parse(&state).map_err(to_sqlite_error)?,
        launch_nonce: row.get(2)?,
        pid: sqlite_optional_u32(row.get::<_, Option<i64>>(3)?, "component pid")?,
        executable_digest: row.get(4)?,
        started_at_ms: sqlite_optional_u64(
            row.get::<_, Option<i64>>(5)?,
            "component started_at_ms",
        )?,
        restart_attempts: sqlite_u32(row.get::<_, i64>(6)?, "component restart_attempts")?,
        last_restart_at_ms: sqlite_optional_u64(
            row.get::<_, Option<i64>>(7)?,
            "component last_restart_at_ms",
        )?,
        last_error: row.get(8)?,
    })
}

fn component_state_as_str(state: ComponentState) -> &'static str {
    match state {
        ComponentState::Stopped => "stopped",
        ComponentState::Starting => "starting",
        ComponentState::Running => "running",
        ComponentState::Suspect => "suspect",
        ComponentState::Backoff => "backoff",
        ComponentState::Paused => "paused",
        ComponentState::Blocked => "blocked",
        ComponentState::Quarantined => "quarantined",
    }
}

fn component_state_parse(value: &str) -> Result<ComponentState> {
    match value {
        "stopped" => Ok(ComponentState::Stopped),
        "starting" => Ok(ComponentState::Starting),
        "running" => Ok(ComponentState::Running),
        "suspect" => Ok(ComponentState::Suspect),
        "backoff" => Ok(ComponentState::Backoff),
        "paused" => Ok(ComponentState::Paused),
        "blocked" => Ok(ComponentState::Blocked),
        "quarantined" => Ok(ComponentState::Quarantined),
        other => Err(WatchdogError::Conflict(format!(
            "unknown component state {other}"
        ))),
    }
}

impl Store {
    /// Return the restart count in a rolling window without resetting it on
    /// daemon restart.  Wall-clock input is retained only for the audit
    /// surface; aging uses the store instance's monotonic observation. Events
    /// from prior controller instances remain counted conservatively because a
    /// Rust `Instant` cannot be restored across a process restart.
    pub fn restart_count(&self, component_id: &str, now_ms: u64, window_ms: u64) -> Result<u32> {
        let _ = now_ms;
        self.restart_count_with_elapsed(component_id, self.restart_elapsed_ms(), window_ms)
    }

    /// Count restart events using an explicitly observed monotonic elapsed
    /// value. This deterministic hook is used by clock/fault tests and by a
    /// native adapter that can supply a trusted monotonic source.
    pub fn restart_count_with_elapsed(
        &self,
        component_id: &str,
        elapsed_ms: u64,
        window_ms: u64,
    ) -> Result<u32> {
        validate_name(component_id, "component id", 128)?;
        let clock_epoch = self.restart_clock_epoch.as_str();
        let cutoff = elapsed_ms.saturating_sub(window_ms);
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM restart_events WHERE component_id=? AND (clock_epoch <> ? OR clock_elapsed_ms >= ?)",
            params![
                component_id,
                clock_epoch,
                sqlite_timestamp(cutoff)?
            ],
            |row| row.get(0),
        )?;
        u32::try_from(count)
            .map_err(|_| WatchdogError::Conflict("restart count overflow".to_string()))
    }

    /// Record a restart decision and prune old events only after they leave the
    /// configured window according to the current monotonic clock epoch.
    pub fn record_restart(
        &mut self,
        component_id: &str,
        now_ms: u64,
        window_ms: u64,
    ) -> Result<u32> {
        let elapsed_ms = self.restart_elapsed_ms();
        self.record_restart_with_elapsed(component_id, now_ms, elapsed_ms, window_ms)
    }

    /// Record a restart with a trusted monotonic elapsed observation. Wall
    /// time is persisted for audit only; it cannot age or reset the budget.
    pub fn record_restart_with_elapsed(
        &mut self,
        component_id: &str,
        now_ms: u64,
        elapsed_ms: u64,
        window_ms: u64,
    ) -> Result<u32> {
        validate_name(component_id, "component id", 128)?;
        let clock_epoch = self.restart_clock_epoch.clone();
        let current_max: Option<i64> = self
            .conn
            .query_row(
                "SELECT MAX(clock_elapsed_ms) FROM restart_events WHERE component_id=? AND clock_epoch=?",
                params![component_id, clock_epoch],
                |row| row.get(0),
            )?;
        let observed_elapsed = current_max
            .and_then(|value| u64::try_from(value).ok())
            .map_or(elapsed_ms, |previous| previous.max(elapsed_ms));
        let cutoff = observed_elapsed.saturating_sub(window_ms);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM restart_events WHERE component_id=? AND clock_epoch=? AND clock_elapsed_ms < ?",
            params![
                component_id,
                &clock_epoch,
                sqlite_timestamp(cutoff)?
            ],
        )?;
        tx.execute(
            "INSERT INTO restart_events (component_id, occurred_at_ms, clock_epoch, clock_elapsed_ms) VALUES (?, ?, ?, ?)",
            params![
                component_id,
                sqlite_timestamp(now_ms)?,
                &clock_epoch,
                sqlite_timestamp(observed_elapsed)?
            ],
        )?;
        insert_audit_tx(&tx, "component_restart_recorded", component_id, now_ms)?;
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM restart_events WHERE component_id=? AND (clock_epoch <> ? OR clock_elapsed_ms >= ?)",
            params![
                component_id,
                &clock_epoch,
                sqlite_timestamp(cutoff)?
            ],
            |row| row.get(0),
        )?;
        tx.commit()?;
        u32::try_from(count)
            .map_err(|_| WatchdogError::Conflict("restart count overflow".to_string()))
    }

    fn restart_elapsed_ms(&self) -> u64 {
        self.restart_clock_started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    /// Persist a component state/identity observation.
    pub fn upsert_component(&mut self, record: &ComponentRecord, now_ms: u64) -> Result<()> {
        validate_name(&record.id, "component id", 128)?;
        if let Some(error) = &record.last_error {
            validate_detail(error, "component error")?;
        }
        let state = component_state_as_str(record.state);
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO components (id, state, launch_nonce, pid, executable_digest, started_at_ms, restart_attempts, last_restart_at_ms, last_error, updated_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET state=excluded.state, launch_nonce=excluded.launch_nonce, pid=excluded.pid, executable_digest=excluded.executable_digest, started_at_ms=excluded.started_at_ms, restart_attempts=excluded.restart_attempts, last_restart_at_ms=excluded.last_restart_at_ms, last_error=excluded.last_error, identity_json=CASE WHEN excluded.launch_nonce IS NULL THEN NULL ELSE components.identity_json END, updated_at_ms=excluded.updated_at_ms",
            params![record.id, state, record.launch_nonce, record.pid.map(i64::from), record.executable_digest, record.started_at_ms.map(sqlite_timestamp).transpose()?, i64::from(record.restart_attempts), record.last_restart_at_ms.map(sqlite_timestamp).transpose()?, record.last_error, sqlite_timestamp(now_ms)?],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Read one persisted component state.
    pub fn component(&self, id: &str) -> Result<Option<ComponentRecord>> {
        self.conn
            .query_row(
                "SELECT id, state, launch_nonce, pid, executable_digest, started_at_ms, restart_attempts, last_restart_at_ms, last_error FROM components WHERE id=?",
                params![id],
                component_record_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Durable component records in stable identifier order.  This is
    /// read-only reporting state (including restart attempts and backoff
    /// errors) and never grants launch authority.
    pub fn components(&self) -> Result<Vec<ComponentRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id, state, launch_nonce, pid, executable_digest, started_at_ms, restart_attempts, last_restart_at_ms, last_error FROM components ORDER BY id",
        )?;
        let rows = statement.query_map([], component_record_from_row)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    /// Persist the complete launch identity, including the OS creation
    /// fingerprint.  It is separate from the human-readable component row so
    /// status code cannot accidentally reduce identity to a PID.
    pub fn persist_component_identity(
        &mut self,
        component_id: &str,
        identity: &ProcessIdentity,
        now_ms: u64,
    ) -> Result<()> {
        validate_name(component_id, "component id", 128)?;
        let encoded = serde_json::to_string(identity)?;
        if encoded.len() > 4 * 1024 {
            return Err(WatchdogError::InvalidInput(
                "process identity exceeds its bound".to_string(),
            ));
        }
        let tx = self.conn.transaction()?;
        let changed = tx.execute(
            "UPDATE components SET identity_json=?, launch_nonce=?, pid=?, executable_digest=?, updated_at_ms=? WHERE id=?",
            params![encoded, identity.launch_nonce, i64::from(identity.pid), identity.executable_digest, sqlite_timestamp(now_ms)?, component_id],
        )?;
        if changed != 1 {
            tx.rollback()?;
            return Err(WatchdogError::NotFound(format!("component {component_id}")));
        }
        tx.commit()?;
        Ok(())
    }

    /// Read the complete persisted launch identity for diagnostics and future
    /// process-authority reconciliation.
    pub fn component_identity(&self, component_id: &str) -> Result<Option<ProcessIdentity>> {
        let encoded: Option<String> = self
            .conn
            .query_row(
                "SELECT identity_json FROM components WHERE id=?",
                params![component_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        encoded
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(Into::into)
    }

    /// Remove an identity after the exact child has been stopped.
    pub fn clear_component_identity(&mut self, component_id: &str, now_ms: u64) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE components SET identity_json=NULL, launch_nonce=NULL, pid=NULL, executable_digest=NULL, updated_at_ms=? WHERE id=?",
            params![sqlite_timestamp(now_ms)?, component_id],
        )?;
        tx.commit()?;
        Ok(())
    }
}
