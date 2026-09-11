//! Immutable, non-secret health bootstrap binding for one prepared launch.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use uuid::{Uuid, Variant, Version};

use super::{Store, insert_audit_tx, require_running_launch_intent};
use crate::error::{Result, WatchdogError};
use crate::platform::gateway_health::GatewayHealthBootstrap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayHealthBootstrapBinding {
    pub watchdog_boot_id: String,
    pub frame_sha256: String,
}

const TABLE_SQL: &str = "CREATE TABLE gateway_health_bindings (
            intent_id TEXT PRIMARY KEY NOT NULL REFERENCES launch_intents(id),
            version INTEGER NOT NULL CHECK(version=1),
            watchdog_boot_id TEXT NOT NULL CHECK(length(watchdog_boot_id)=36),
            frame_sha256 TEXT NOT NULL CHECK(length(frame_sha256)=64)
        )";
const TRIGGER_SQL: &str = "CREATE TRIGGER gateway_health_binding_immutable
        BEFORE UPDATE ON gateway_health_bindings
        BEGIN SELECT RAISE(ABORT, 'gateway health binding is immutable'); END";

pub(super) fn create_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(TABLE_SQL)?;
    conn.execute_batch(TRIGGER_SQL)?;
    conn.execute(
        "INSERT INTO metadata(key,value) VALUES ('gateway_health_schema','1')",
        [],
    )?;
    Ok(())
}

impl Store {
    /// Explicit stopped-owner migration, never an ordinary-startup repair.
    pub fn migrate_gateway_health(&mut self, owner: &super::SingletonLock) -> Result<()> {
        super::ensure_owner_lock(&self.path, owner)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if super::metadata_from_conn(&tx, "desired_mode")?.as_deref() != Some("stopped") {
            return invalid("gateway health migration requires durable stop");
        }
        let marker = super::metadata_from_conn(&tx, "gateway_health_schema")?;
        let table = super::table_exists(&tx, "gateway_health_bindings")?;
        let trigger: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='gateway_health_binding_immutable')",
            [], |row| row.get(0),
        )?;
        if marker.is_none() && !table && !trigger {
            create_schema(&tx)?;
            insert_audit_tx(
                &tx,
                "gateway_health_schema_installed",
                "version=1",
                super::now_unix_ms(),
            )?;
        } else {
            validate_schema(&tx)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Persist a digest, never a key/frame, before the launcher receives it.
    /// Repeating the same prepared binding is idempotent; changing it fails.
    pub fn bind_gateway_health(
        &mut self,
        intent_id: &str,
        watchdog_boot_id: Uuid,
        bootstrap: &GatewayHealthBootstrap,
        now_ms: u64,
    ) -> Result<GatewayHealthBootstrapBinding> {
        if watchdog_boot_id.get_variant() != Variant::RFC4122
            || watchdog_boot_id.get_version() != Some(Version::Random)
        {
            return invalid("gateway health requires a fresh watchdog boot identity");
        }
        let binding = GatewayHealthBootstrapBinding {
            watchdog_boot_id: watchdog_boot_id.to_string(),
            frame_sha256: bootstrap.frame_sha256(),
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
                "gateway health launch intent".to_owned(),
            ));
        };
        if component != "gateway"
            || nonce != bootstrap.launch_nonce().to_string()
            || state != "prepared"
        {
            return invalid("gateway health differs from the prepared gateway launch");
        }
        if let Some(existing) = read_binding(&tx, intent_id)? {
            if existing != binding {
                return invalid("gateway health binding cannot be replaced");
            }
        } else {
            tx.execute(
                "INSERT INTO gateway_health_bindings VALUES (?, 1, ?, ?)",
                params![intent_id, binding.watchdog_boot_id, binding.frame_sha256],
            )?;
            insert_audit_tx(&tx, "gateway_health_bound", intent_id, now_ms)?;
        }
        tx.commit()?;
        Ok(binding)
    }

    /// Side-effect-free binding lookup; missing schema fails closed.
    pub fn gateway_health_binding(
        &self,
        intent_id: &str,
    ) -> Result<Option<GatewayHealthBootstrapBinding>> {
        read_binding(&self.conn, intent_id)
    }
}

fn read_binding(
    conn: &Connection,
    intent_id: &str,
) -> Result<Option<GatewayHealthBootstrapBinding>> {
    validate_schema(conn)?;
    let row: Option<(i64, String, String)> = conn.query_row(
        "SELECT version, watchdog_boot_id, frame_sha256 FROM gateway_health_bindings WHERE intent_id=?",
        [intent_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional()?;
    row.map(|(version, boot, digest)| {
        let valid_boot = Uuid::parse_str(&boot).is_ok_and(|id| {
            id.get_variant() == Variant::RFC4122
                && id.get_version() == Some(Version::Random)
                && id.to_string() == boot
        });
        if version != 1 || !valid_boot || crate::config::validate_digest(&digest).is_err() {
            return invalid("invalid persisted gateway health binding");
        }
        Ok(GatewayHealthBootstrapBinding {
            watchdog_boot_id: boot,
            frame_sha256: digest,
        })
    })
    .transpose()
}

fn validate_schema(conn: &Connection) -> Result<()> {
    if super::metadata_from_conn(conn, "gateway_health_schema")?.as_deref() != Some("1")
        || !super::table_exists(conn, "gateway_health_bindings")?
    {
        return invalid(
            "gateway health schema missing or incompatible; explicit migration required",
        );
    }
    for (kind, name, expected) in [
        ("table", "gateway_health_bindings", TABLE_SQL),
        ("trigger", "gateway_health_binding_immutable", TRIGGER_SQL),
    ] {
        let actual: Option<String> = conn.query_row(
            "SELECT sql FROM sqlite_master WHERE type=? AND name=? AND tbl_name='gateway_health_bindings'",
            params![kind, name], |row| row.get(0),
        ).optional()?;
        if actual.as_deref() != Some(expected) {
            return invalid("gateway health schema definition differs from version 1");
        }
    }
    Ok(())
}

fn invalid<T>(message: &str) -> Result<T> {
    Err(WatchdogError::Conflict(message.to_owned()))
}
