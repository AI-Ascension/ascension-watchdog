//! Immutable dynamic bootstrap binding, separate from release configuration.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::{Store, insert_audit_tx, require_running_launch_intent};
use crate::config::hex_digest;
use crate::error::{Result, WatchdogError};
use crate::worker_bootstrap::{WorkerBootstrap, encode_frame};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerBootstrapBinding {
    pub watchdog_boot_id: String,
    pub frame_sha256: String,
}

const TABLE_SQL: &str = "CREATE TABLE worker_bootstrap_bindings (
            intent_id TEXT PRIMARY KEY NOT NULL REFERENCES launch_intents(id),
            version INTEGER NOT NULL CHECK(version=1),
            watchdog_boot_id TEXT NOT NULL CHECK(length(watchdog_boot_id)=36),
            frame_sha256 TEXT NOT NULL CHECK(length(frame_sha256)=64)
        )";
const TRIGGER_SQL: &str = "CREATE TRIGGER worker_bootstrap_binding_immutable
        BEFORE UPDATE ON worker_bootstrap_bindings
        BEGIN SELECT RAISE(ABORT, 'worker bootstrap binding is immutable'); END";

pub(super) fn create_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(TABLE_SQL)?;
    conn.execute_batch(TRIGGER_SQL)?;
    conn.execute(
        "INSERT INTO metadata(key,value) VALUES ('worker_bootstrap_schema','1')",
        [],
    )?;
    Ok(())
}

impl Store {
    /// Explicit owner-authorized schema installation. Requires durable stop;
    /// missing or inconsistent pieces of an installed schema are not repaired.
    pub fn migrate_worker_bootstrap(&mut self, owner: &super::SingletonLock) -> Result<()> {
        super::ensure_owner_lock(&self.path, owner)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mode = super::metadata_from_conn(&tx, "desired_mode")?;
        if mode.as_deref() != Some("stopped") {
            return Err(WatchdogError::Conflict(
                "bootstrap migration requires durable stop".to_owned(),
            ));
        }
        let marker = super::metadata_from_conn(&tx, "worker_bootstrap_schema")?;
        let exists = super::table_exists(&tx, "worker_bootstrap_bindings")?;
        if marker.is_none() && !exists {
            create_schema(&tx)?;
            insert_audit_tx(
                &tx,
                "worker_bootstrap_schema_installed",
                "version=1",
                super::now_unix_ms(),
            )?;
        } else {
            validate_schema(&tx)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Bind validated frame bytes before launching. Missing extension schema
    /// fails closed; ordinary reads and startup never create it implicitly.
    /// No credential, executable path, or frame payload is retained here.
    pub fn bind_worker_bootstrap(
        &mut self,
        intent_id: &str,
        bootstrap: &WorkerBootstrap,
        now_ms: u64,
    ) -> Result<WorkerBootstrapBinding> {
        let frame = encode_frame(bootstrap)
            .map_err(|_| WatchdogError::InvalidInput("invalid worker bootstrap".to_owned()))?;
        let binding = WorkerBootstrapBinding {
            watchdog_boot_id: bootstrap.watchdog_boot_id.to_string(),
            frame_sha256: hex_digest(&frame),
        };
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_schema(&tx)?;
        require_running_launch_intent(&tx)?;
        let intent: Option<(String, String, String)> = tx
            .query_row(
                "SELECT component_id, launch_nonce, state FROM launch_intents WHERE id=?",
                [intent_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((component, nonce, state)) = intent else {
            return Err(WatchdogError::NotFound(
                "bootstrap launch intent".to_owned(),
            ));
        };
        if component != bootstrap.component_id
            || nonce != bootstrap.launch_nonce.to_string()
            || state != "prepared"
        {
            return Err(WatchdogError::Conflict(
                "bootstrap differs from prepared launch intent".to_owned(),
            ));
        }
        let existing = read_binding(&tx, intent_id)?;
        if let Some(existing) = existing {
            if existing != binding {
                return Err(WatchdogError::Conflict(
                    "bootstrap binding cannot be replaced".to_owned(),
                ));
            }
        } else {
            tx.execute(
                "INSERT INTO worker_bootstrap_bindings VALUES (?, 1, ?, ?)",
                params![intent_id, binding.watchdog_boot_id, binding.frame_sha256],
            )?;
            insert_audit_tx(&tx, "worker_bootstrap_bound", intent_id, now_ms)?;
        }
        tx.commit()?;
        Ok(binding)
    }

    /// Read-only bootstrap identity lookup. Missing state is never reconstructed.
    pub fn worker_bootstrap_binding(
        &self,
        intent_id: &str,
    ) -> Result<Option<WorkerBootstrapBinding>> {
        read_binding(&self.conn, intent_id)
    }
}

fn read_binding(conn: &Connection, intent_id: &str) -> Result<Option<WorkerBootstrapBinding>> {
    validate_schema(conn)?;
    let row: Option<(i64, String, String)> = conn.query_row(
        "SELECT version, watchdog_boot_id, frame_sha256 FROM worker_bootstrap_bindings WHERE intent_id=?",
        [intent_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional()?;
    row.map(|(version, boot, digest)| {
        let valid_boot = uuid::Uuid::parse_str(&boot).is_ok_and(|id| {
            id.get_version_num() == 4
                && id.get_variant() == uuid::Variant::RFC4122
                && id.to_string() == boot
        });
        if version != 1 || !valid_boot || crate::config::validate_digest(&digest).is_err() {
            return Err(WatchdogError::Conflict(
                "invalid persisted worker bootstrap binding".to_owned(),
            ));
        }
        Ok(WorkerBootstrapBinding {
            watchdog_boot_id: boot,
            frame_sha256: digest,
        })
    })
    .transpose()
}

fn validate_schema(conn: &Connection) -> Result<()> {
    if super::metadata_from_conn(conn, "worker_bootstrap_schema")?.as_deref() != Some("1")
        || !super::table_exists(conn, "worker_bootstrap_bindings")?
    {
        return Err(WatchdogError::Conflict(
            "worker bootstrap schema missing or incompatible; explicit migration required"
                .to_owned(),
        ));
    }
    // This extension has one frozen DDL shape. Column/name presence alone
    // would accept a replacement table without constraints or a no-op guard.
    for (kind, name, expected) in [
        ("table", "worker_bootstrap_bindings", TABLE_SQL),
        ("trigger", "worker_bootstrap_binding_immutable", TRIGGER_SQL),
    ] {
        let actual: Option<String> = conn.query_row(
            "SELECT sql FROM sqlite_master WHERE type=? AND name=? AND tbl_name='worker_bootstrap_bindings'",
            params![kind, name], |row| row.get(0),
        ).optional()?;
        if actual.as_deref() != Some(expected) {
            return Err(WatchdogError::Conflict(
                "worker bootstrap schema definition differs from version 1".to_owned(),
            ));
        }
    }
    Ok(())
}
