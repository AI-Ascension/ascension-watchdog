//! Authenticated, owner-local backup admission and completion.
//!
//! The command ledger is the durable intent record.  A backup is never
//! selected by a client path: its identifier is resolved below the fixed
//! `backups` directory next to the owner-local database.

use super::{
    OperatorCommand, OperatorCommandContext, OperatorCommandOutcome, OperatorCommandReceipt,
    SingletonLock, insert_audit_tx, validate_response,
};
use crate::config::validate_digest;
use crate::error::{Result, WatchdogError};
use fs2::available_space;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use std::fs::{self, File};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const BACKUP_NAMESPACE: &str = "backups";
const BACKUP_SUFFIX: &str = ".sqlite3";
const MAX_BACKUP_BYTES: u64 = 512 * 1024 * 1024;
const BACKUP_HEADROOM_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
struct BackupBinding {
    schema_version: i64,
    deployment_id: String,
    config_digest: String,
    config_compat_digest: String,
    approved_release_digest: Option<String>,
}

impl crate::storage::Store {
    /// Admit and execute one authenticated backup.  The ledger row is
    /// committed with `durable=false` before the namespace or destination is
    /// created.  A failed snapshot therefore remains a replayable, uncertain
    /// command rather than becoming an implicit retry with a new identity.
    pub(crate) fn perform_operator_backup(
        &mut self,
        owner: &SingletonLock,
        context: &OperatorCommandContext,
        backup_id: &str,
        pending_response: &Value,
        now_ms: u64,
    ) -> Result<bool> {
        validate_backup_id(backup_id)?;
        let outcome = self.admit_operator_command(
            owner,
            context,
            OperatorCommand::Backup,
            pending_response,
            now_ms,
        )?;
        let (receipt, replayed) = match outcome {
            OperatorCommandOutcome::Accepted(receipt) => (receipt, false),
            OperatorCommandOutcome::Replayed(receipt) => (receipt, true),
            OperatorCommandOutcome::ReadOnly => {
                return Err(WatchdogError::Conflict(
                    "backup admission unexpectedly became read-only".to_owned(),
                ));
            }
        };
        let already_durable = backup_response_durable(&receipt.response, backup_id)?;
        let binding = self.backup_binding()?;
        let namespace = self.backup_namespace()?;
        let destination = backup_destination(&namespace, backup_id)?;

        if already_durable {
            validate_backup_namespace(&namespace)?;
            verify_backup(&destination, &binding, &receipt, backup_id)?;
            return Ok(true);
        }

        ensure_backup_namespace(&namespace)?;
        let destination = backup_destination(&namespace, backup_id)?;
        if destination.exists() {
            if !replayed {
                return Err(WatchdogError::Conflict(
                    "backup identifier already has a retained destination".to_owned(),
                ));
            }
            // A prior attempt may have completed the filesystem effect but
            // lost the ledger completion.  Verify it and finalize the same
            // request; never truncate or replace an existing destination.
            verify_backup(&destination, &binding, &receipt, backup_id)?;
        } else {
            check_backup_capacity(self, &namespace)?;
            self.backup_to(&destination)?;
            verify_backup(&destination, &binding, &receipt, backup_id)?;
        }

        let completed_response = durable_backup_response(&receipt.response, backup_id)?;
        self.complete_operator_backup(owner, &receipt, &completed_response, backup_id, now_ms)?;
        Ok(true)
    }

    fn backup_binding(&self) -> Result<BackupBinding> {
        read_binding(&self.conn)
    }

    fn backup_namespace(&self) -> Result<PathBuf> {
        let database = super::super::canonical_owner_path(&self.path, "database")?;
        let parent = database.parent().ok_or_else(|| {
            WatchdogError::InvalidInput("database has no owner-local parent".to_owned())
        })?;
        Ok(parent.join(BACKUP_NAMESPACE))
    }

    fn complete_operator_backup(
        &mut self,
        owner: &SingletonLock,
        receipt: &OperatorCommandReceipt,
        response: &Value,
        backup_id: &str,
        now_ms: u64,
    ) -> Result<()> {
        super::super::ensure_owner_lock(&self.path, owner)?;
        validate_response(response)?;
        let response_text = serde_json::to_string(response)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (request_id, key, command, fingerprint, existing_text): (String, String, String, String, String) = tx
            .query_row(
                "SELECT request_id, idempotency_key, command, command_fingerprint, response_json FROM operator_commands WHERE sequence=?",
                params![i64::try_from(receipt.sequence).map_err(|_| {
                    WatchdogError::Conflict("operator sequence exceeds SQLite range".to_owned())
                })?],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?
            .ok_or_else(|| WatchdogError::Conflict("backup intent receipt disappeared".to_owned()))?;
        if request_id != receipt.request_id
            || key != receipt.idempotency_key
            || command != "backup"
            || fingerprint != receipt.command_fingerprint
        {
            return Err(WatchdogError::Conflict(
                "backup intent receipt changed before completion".to_owned(),
            ));
        }
        let existing: Value = serde_json::from_str(&existing_text)?;
        if backup_response_durable(&existing, backup_id)? {
            tx.rollback()?;
            return Ok(());
        }
        let changed = tx.execute(
            "UPDATE operator_commands SET response_json=? WHERE sequence=?",
            params![
                response_text,
                i64::try_from(receipt.sequence).map_err(|_| {
                    WatchdogError::Conflict("operator sequence exceeds SQLite range".to_owned())
                })?
            ],
        )?;
        if changed != 1 {
            return Err(WatchdogError::Conflict(
                "backup completion updated no ledger row".to_owned(),
            ));
        }
        insert_audit_tx(
            &tx,
            "operator_command_backup_completed",
            &format!(
                "sequence={};key={};backup_id={backup_id}",
                receipt.sequence, receipt.idempotency_key
            ),
            now_ms,
        )?;
        tx.commit()?;
        Ok(())
    }
}

fn validate_backup_id(backup_id: &str) -> Result<()> {
    if backup_id.is_empty()
        || backup_id.len() > 128
        || !backup_id.is_ascii()
        || backup_id == "."
        || backup_id == ".."
        || backup_id
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')))
    {
        return Err(WatchdogError::InvalidInput(
            "backup_id must be one bounded owner-local path component".to_owned(),
        ));
    }
    Ok(())
}

fn backup_destination(namespace: &Path, backup_id: &str) -> Result<PathBuf> {
    validate_backup_id(backup_id)?;
    let mut filename = backup_id.to_owned();
    filename.push_str(BACKUP_SUFFIX);
    super::super::canonical_owner_path(&namespace.join(filename), "backup")
}

fn ensure_backup_namespace(namespace: &Path) -> Result<()> {
    if let Some(parent) = namespace.parent() {
        validate_owner_directory(parent, "backup owner directory")?;
    }
    match fs::symlink_metadata(namespace) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(namespace)?;
            #[cfg(unix)]
            fs::set_permissions(namespace, fs::Permissions::from_mode(0o700))?;
            #[cfg(unix)]
            if let Some(parent) = namespace.parent() {
                File::open(parent)?.sync_all()?;
            }
        }
        Err(error) => return Err(WatchdogError::Io(error)),
    }
    validate_backup_namespace(namespace)
}

fn validate_backup_namespace(namespace: &Path) -> Result<()> {
    if let Some(parent) = namespace.parent() {
        validate_owner_directory(parent, "backup owner directory")?;
    }
    validate_owner_directory(namespace, "backup namespace")
}

fn validate_owner_directory(path: &Path, name: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    super::super::reject_link_or_reparse(&metadata, name)?;
    if !metadata.is_dir() {
        return Err(WatchdogError::Conflict(format!(
            "{name} is not a directory"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(WatchdogError::Unauthorized(format!(
                "{name} must be owner-only"
            )));
        }
    }
    Ok(())
}

fn check_backup_capacity(store: &crate::storage::Store, namespace: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(store.path())?;
    super::super::reject_link_or_reparse(&metadata, "database")?;
    let page_count: i64 = store
        .conn
        .query_row("PRAGMA page_count", [], |row| row.get(0))?;
    let page_size: i64 = store
        .conn
        .query_row("PRAGMA page_size", [], |row| row.get(0))?;
    let page_count = u64::try_from(page_count).map_err(|_| {
        WatchdogError::Conflict("SQLite reported a negative logical page count".to_owned())
    })?;
    let page_size = u64::try_from(page_size)
        .map_err(|_| WatchdogError::Conflict("SQLite reported a negative page size".to_owned()))?;
    let size = page_count.checked_mul(page_size).ok_or_else(|| {
        WatchdogError::Conflict("SQLite logical database size overflowed".to_owned())
    })?;
    if size > MAX_BACKUP_BYTES {
        return Err(WatchdogError::Conflict(
            "database exceeds the bounded backup size".to_owned(),
        ));
    }
    let required = size
        .checked_mul(2)
        .and_then(|value| value.checked_add(BACKUP_HEADROOM_BYTES))
        .ok_or_else(|| {
            WatchdogError::Conflict("backup capacity calculation overflowed".to_owned())
        })?;
    let parent = namespace.parent().ok_or_else(|| {
        WatchdogError::InvalidInput("backup namespace has no owner-local parent".to_owned())
    })?;
    let available = available_space(parent)?;
    if available < required {
        return Err(WatchdogError::Conflict(
            "backup headroom is below the bounded database allowance".to_owned(),
        ));
    }
    Ok(())
}

fn verify_backup(
    destination: &Path,
    expected: &BackupBinding,
    receipt: &OperatorCommandReceipt,
    backup_id: &str,
) -> Result<()> {
    let metadata = fs::symlink_metadata(destination)?;
    super::super::reject_link_or_reparse(&metadata, "backup")?;
    if !metadata.is_file() {
        return Err(WatchdogError::Conflict(
            "backup destination is not a regular file".to_owned(),
        ));
    }
    if metadata.len() == 0 || metadata.len() > MAX_BACKUP_BYTES {
        return Err(WatchdogError::Conflict(
            "backup destination is outside the bounded size".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(WatchdogError::Unauthorized(
                "backup destination must be owner-only".to_owned(),
            ));
        }
    }
    let conn =
        super::super::open_connection_with_flags(destination, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let integrity: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if !integrity.eq_ignore_ascii_case("ok") {
        return Err(WatchdogError::Conflict(
            "backup integrity check did not return ok".to_owned(),
        ));
    }
    if read_binding(&conn)? != *expected {
        return Err(WatchdogError::Conflict(
            "backup binding differs from the current deployment".to_owned(),
        ));
    }
    verify_backup_receipt(&conn, receipt, backup_id)?;
    Ok(())
}

fn verify_backup_receipt(
    conn: &Connection,
    expected: &OperatorCommandReceipt,
    backup_id: &str,
) -> Result<()> {
    let sequence = i64::try_from(expected.sequence).map_err(|_| {
        WatchdogError::Conflict("operator sequence exceeds SQLite range".to_owned())
    })?;
    let (request_id, idempotency_key, principal, capability, command, fingerprint, response_text):
        (String, String, String, String, String, String, String) = conn
        .query_row(
            "SELECT request_id, idempotency_key, principal, capability, command, command_fingerprint, response_json FROM operator_commands WHERE sequence=?",
            params![sequence],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            WatchdogError::Conflict(
                "backup snapshot does not contain the admitted command receipt".to_owned(),
            )
        })?;
    if request_id != expected.request_id
        || idempotency_key != expected.idempotency_key
        || principal != expected.principal
        || capability != expected.capability.as_str()
        || command != expected.command.as_str()
        || fingerprint != expected.command_fingerprint
    {
        return Err(WatchdogError::Conflict(
            "backup snapshot command receipt differs from the admitted request".to_owned(),
        ));
    }
    let response: Value = serde_json::from_str(&response_text)?;
    backup_response_durable(&response, backup_id)?;
    Ok(())
}

fn read_binding(conn: &Connection) -> Result<BackupBinding> {
    let schema_text = super::metadata_from_conn(conn, "schema_version")?
        .ok_or_else(|| WatchdogError::Conflict("backup schema metadata is missing".to_owned()))?;
    let schema_version = super::super::parse_metadata_i64("schema_version", &schema_text)?;
    let deployment_id = super::metadata_from_conn(conn, "deployment_id")?.ok_or_else(|| {
        WatchdogError::Conflict("backup deployment metadata is missing".to_owned())
    })?;
    super::super::validate_metadata_identifier("deployment_id", &deployment_id)?;
    let config_digest = super::metadata_from_conn(conn, "config_digest")?
        .ok_or_else(|| WatchdogError::Conflict("backup config digest is missing".to_owned()))?;
    validate_digest(&config_digest).map_err(WatchdogError::Conflict)?;
    let config_compat_digest = super::metadata_from_conn(conn, "config_compat_digest")?
        .ok_or_else(|| {
            WatchdogError::Conflict("backup compatibility digest is missing".to_owned())
        })?;
    validate_digest(&config_compat_digest).map_err(WatchdogError::Conflict)?;
    let approved_release_digest = super::metadata_from_conn(conn, "approved_release_digest")?;
    if let Some(digest) = &approved_release_digest {
        validate_digest(digest).map_err(WatchdogError::Conflict)?;
    }
    Ok(BackupBinding {
        schema_version,
        deployment_id,
        config_digest,
        config_compat_digest,
        approved_release_digest,
    })
}

fn backup_response_durable(response: &Value, backup_id: &str) -> Result<bool> {
    let object = response.as_object().ok_or_else(|| {
        WatchdogError::Conflict("backup ledger response is not an object".to_owned())
    })?;
    if object.get("kind").and_then(Value::as_str) != Some("Backup") {
        return Err(WatchdogError::Conflict(
            "backup ledger response has an incompatible result kind".to_owned(),
        ));
    }
    let value = object
        .get("value")
        .and_then(Value::as_object)
        .ok_or_else(|| WatchdogError::Conflict("backup ledger response has no value".to_owned()))?;
    if value.get("backup_id").and_then(Value::as_str) != Some(backup_id) {
        return Err(WatchdogError::Conflict(
            "backup ledger response does not match the requested id".to_owned(),
        ));
    }
    value
        .get("durable")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            WatchdogError::Conflict("backup ledger response lacks durability state".to_owned())
        })
}

fn durable_backup_response(response: &Value, backup_id: &str) -> Result<Value> {
    if backup_response_durable(response, backup_id)? {
        return Ok(response.clone());
    }
    let mut result = response.clone();
    let value = result
        .as_object_mut()
        .and_then(|object| object.get_mut("value"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            WatchdogError::Conflict("backup ledger response has no mutable value".to_owned())
        })?;
    value.insert("durable".to_owned(), json!(true));
    validate_response(&result)?;
    Ok(result)
}
