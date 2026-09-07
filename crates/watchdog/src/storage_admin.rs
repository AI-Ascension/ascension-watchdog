//! Durable, owner-authenticated operator command admission.
//!
//! This module deliberately sits below the transport.  A transport may
//! authenticate a request, but only the reconciliation owner can turn its
//! token-free context into a durable command admission.  The command ledger
//! stores request identity, capability class, a command digest, and a bounded
//! response; it never stores credentials or command payloads.

#[path = "storage_backup_admin.rs"]
mod storage_backup_admin;

use super::{
    SCHEMA_VERSION, SingletonLock, Store, Transaction, TransactionBehavior, WatchdogError,
    ensure_owner_lock, insert_audit_tx, metadata_from_conn, mode_as_str,
    open_connection_with_flags, parse_mode, sqlite_u64, to_sqlite_error, update_metadata_tx,
    validate_local_storage_path, validate_name,
};
use crate::config::{DesiredMode, hex_digest, validate_digest};
use crate::error::Result;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;
use uuid::Uuid;

/// Version of the additive operator-ledger table.  It is intentionally kept
/// separate from the watchdog core schema version so old owner stores can be
/// upgraded under the singleton lock without pretending to migrate unrelated
/// state.
pub const OPERATOR_LEDGER_SCHEMA_VERSION: i64 = 2;

/// Maximum rows retained in the durable command ledger.  Rows are never
/// evicted: a full ledger backpressures a new command until an explicit,
/// separately reviewed archival operation exists.
pub const MAX_OPERATOR_COMMANDS: i64 = 256;

/// One dedicated, bounded stop slot remains available after the normal
/// ledger and lifecycle reserve are exhausted. It is never used for start,
/// resume, or any other command.
pub const RESERVED_STOP_COMMANDS: i64 = 1;

/// Maximum retained rows including the explicit emergency stop slot.
pub const MAX_OPERATOR_COMMANDS_WITH_STOP_RESERVE: i64 =
    MAX_OPERATOR_COMMANDS + RESERVED_STOP_COMMANDS;

/// Reserve for lifecycle commands when ordinary administrative commands have
/// filled the normal ledger budget.  The reserve is capacity, not a deletion
/// policy; every retained idempotency key remains replayable.
pub const RESERVED_LIFECYCLE_COMMANDS: i64 = 8;

/// Maximum serialized response retained for a durable command admission.
pub const MAX_OPERATOR_RESPONSE_BYTES: usize = 8 * 1024;

/// Capability class supplied after transport authentication.  Raw credentials
/// never enter this type or the durable ledger.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorCapability {
    /// May execute only commands classified as read-only.
    Read,
    /// May execute lifecycle and administrative mutations.
    Admin,
}

impl OperatorCapability {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Admin => "admin",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "read" => Ok(Self::Read),
            "admin" => Ok(Self::Admin),
            other => Err(WatchdogError::Conflict(format!(
                "unknown operator capability class {other}"
            ))),
        }
    }
}

/// Closed command names mirrored by the admin transport without importing the
/// transport module into storage.  Command arguments are represented only by
/// the context's SHA-256 fingerprint.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorCommand {
    Status,
    Jobs,
    Attempt,
    ReleaseInspect,
    Start,
    Pause,
    Resume,
    Drain,
    Stop,
    Quarantine,
    Retry,
    Reconcile,
    Backup,
    Restore,
    ReleaseActivate,
    JobSubmit,
}

impl OperatorCommand {
    fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Jobs => "jobs",
            Self::Attempt => "attempt",
            Self::ReleaseInspect => "release_inspect",
            Self::Start => "start",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Drain => "drain",
            Self::Stop => "stop",
            Self::Quarantine => "quarantine",
            Self::Retry => "retry",
            Self::Reconcile => "reconcile",
            Self::Backup => "backup",
            Self::Restore => "restore",
            Self::ReleaseActivate => "release_activate",
            Self::JobSubmit => "job_submit",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "status" => Ok(Self::Status),
            "jobs" => Ok(Self::Jobs),
            "attempt" => Ok(Self::Attempt),
            "release_inspect" => Ok(Self::ReleaseInspect),
            "start" => Ok(Self::Start),
            "pause" => Ok(Self::Pause),
            "resume" => Ok(Self::Resume),
            "drain" => Ok(Self::Drain),
            "stop" => Ok(Self::Stop),
            "quarantine" => Ok(Self::Quarantine),
            "retry" => Ok(Self::Retry),
            "reconcile" => Ok(Self::Reconcile),
            "backup" => Ok(Self::Backup),
            "restore" => Ok(Self::Restore),
            "release_activate" => Ok(Self::ReleaseActivate),
            "job_submit" => Ok(Self::JobSubmit),
            other => Err(WatchdogError::Conflict(format!(
                "unknown operator command {other}"
            ))),
        }
    }

    /// Whether dispatching this command must leave the durable store
    /// byte-for-byte unchanged.
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        matches!(
            self,
            Self::Status | Self::Jobs | Self::Attempt | Self::ReleaseInspect
        )
    }

    /// Desired mode, if this command carries a lifecycle transition.
    #[must_use]
    pub const fn desired_mode(self) -> Option<DesiredMode> {
        match self {
            Self::Start | Self::Resume => Some(DesiredMode::Running),
            Self::Pause => Some(DesiredMode::Paused),
            Self::Drain => Some(DesiredMode::Draining),
            Self::Stop => Some(DesiredMode::Stopped),
            _ => None,
        }
    }

    fn is_lifecycle(self) -> bool {
        self.desired_mode().is_some()
    }
}

/// Token-free authenticated context supplied by the transport's auth layer.
/// The caller must compute `command_fingerprint` over the closed command
/// envelope without credentials, request transport identity, or deadlines.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperatorCommandContext {
    pub request_id: String,
    pub idempotency_key: String,
    pub principal: String,
    pub capability: OperatorCapability,
    pub command_fingerprint: String,
}

impl OperatorCommandContext {
    /// Construct and validate a context without accepting a raw credential.
    pub fn new(
        request_id: impl Into<String>,
        idempotency_key: impl Into<String>,
        principal: impl Into<String>,
        capability: OperatorCapability,
        command_fingerprint: impl Into<String>,
    ) -> Result<Self> {
        let context = Self {
            request_id: request_id.into(),
            idempotency_key: idempotency_key.into(),
            principal: principal.into(),
            capability,
            command_fingerprint: command_fingerprint.into(),
        };
        context.validate()?;
        Ok(context)
    }

    /// Validate bounded identity and digest fields.
    pub fn validate(&self) -> Result<()> {
        validate_uuid_v4(&self.request_id, "request id")?;
        validate_name(&self.idempotency_key, "idempotency key", 128)?;
        validate_name(&self.principal, "operator principal", 128)?;
        validate_digest(&self.command_fingerprint).map_err(WatchdogError::InvalidInput)
    }
}

/// Durable receipt retained for an accepted mutation.  `replayed` is a
/// response-local marker and is not persisted as authority state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperatorCommandReceipt {
    pub sequence: u64,
    pub request_id: String,
    pub idempotency_key: String,
    pub principal: String,
    pub capability: OperatorCapability,
    pub command: OperatorCommand,
    pub command_fingerprint: String,
    pub desired_mode: Option<DesiredMode>,
    pub response: Value,
    pub recorded_at_ms: u64,
    pub replayed: bool,
}

/// Result of owner admission.  Read-only commands intentionally have no
/// receipt and perform no SQL write; accepted/replayed mutations carry the
/// durable response the transport may acknowledge or replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperatorCommandOutcome {
    ReadOnly,
    Accepted(OperatorCommandReceipt),
    Replayed(OperatorCommandReceipt),
}

impl Store {
    /// Validate a read-only operator command without requiring a singleton
    /// lock or opening a write transaction.  Callers with a read-only SQLite
    /// connection can use this path for status/inspection admission.
    pub fn admit_operator_read(
        &self,
        context: &OperatorCommandContext,
        command: OperatorCommand,
    ) -> Result<()> {
        context.validate()?;
        if !command.is_read_only() {
            return Err(WatchdogError::InvalidInput(
                "operator read admission requires a read-only command".to_string(),
            ));
        }
        if !matches!(
            context.capability,
            OperatorCapability::Read | OperatorCapability::Admin
        ) {
            return Err(WatchdogError::Unauthorized(
                "operator capability class is not recognized".to_string(),
            ));
        }
        Ok(())
    }

    /// Atomically admit one authenticated operator mutation under the
    /// singleton owner.  The transaction records the mode intent, ledger row,
    /// and audit event together before this method returns.  A duplicate key
    /// returns its original response and never reapplies the stored mode.
    ///
    /// `response` must be a bounded, transport-redacted response prepared by
    /// the caller.  Credentials and command payloads are intentionally absent
    /// from the context and are never written by this API.
    pub fn admit_operator_command(
        &mut self,
        owner: &SingletonLock,
        context: &OperatorCommandContext,
        command: OperatorCommand,
        response: &Value,
        now_ms: u64,
    ) -> Result<OperatorCommandOutcome> {
        ensure_owner_lock(&self.path, owner)?;
        context.validate()?;
        if command.is_read_only() {
            self.admit_operator_read(context, command)?;
            return Ok(OperatorCommandOutcome::ReadOnly);
        }
        if context.capability != OperatorCapability::Admin {
            return Err(WatchdogError::Unauthorized(
                "read capability cannot admit a mutating operator command".to_string(),
            ));
        }
        let desired_mode = command.desired_mode();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(existing) = find_operator_by_key(&tx, &context.idempotency_key)? {
            if existing.principal != context.principal || existing.capability != context.capability
            {
                return Err(WatchdogError::Unauthorized(
                    "idempotency key belongs to another operator context".to_string(),
                ));
            }
            if existing.command_fingerprint != context.command_fingerprint
                || existing.command != command
            {
                return Err(WatchdogError::Conflict(
                    "idempotency key was reused with a different command fingerprint".to_string(),
                ));
            }
            tx.rollback()?;
            return Ok(OperatorCommandOutcome::Replayed(
                existing.with_replayed(true),
            ));
        }
        if let Some(existing) = find_operator_by_request(&tx, &context.request_id)? {
            return Err(WatchdogError::Conflict(format!(
                "request id already belongs to idempotency key {}",
                existing.idempotency_key
            )));
        }
        enforce_ledger_capacity(&tx, command)?;
        // Validate and encode only a new admission.  A replay returns the
        // retained response above and must not be rejected because a caller
        // supplied a different (or oversized) transient response.
        validate_response(response)?;
        let response_text = serde_json::to_string(response)?;

        // All three writes share this transaction.  In particular, a mode
        // transition can never become visible without its replayable receipt
        // and audit record, and a receipt cannot exist without the intent.
        if let Some(mode) = desired_mode {
            update_metadata_tx(&tx, "desired_mode", mode_as_str(mode))?;
            update_metadata_tx(&tx, "updated_at_ms", &now_ms.to_string())?;
        }
        tx.execute(
            "INSERT INTO operator_commands (request_id, idempotency_key, principal, capability, command, command_fingerprint, desired_mode, response_json, recorded_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                context.request_id,
                context.idempotency_key,
                context.principal,
                context.capability.as_str(),
                command.as_str(),
                context.command_fingerprint,
                desired_mode.map(mode_as_str),
                response_text,
                super::sqlite_timestamp(now_ms)?,
            ],
        )?;
        let sequence_i64 = tx.last_insert_rowid();
        let detail = format!(
            "sequence={};request_id={};key={};principal={};capability={};command={};fingerprint={}",
            sequence_i64,
            context.request_id,
            context.idempotency_key,
            context.principal,
            context.capability.as_str(),
            command.as_str(),
            context.command_fingerprint,
        );
        let audit_action = if command == OperatorCommand::Stop {
            "operator_command_stop_accepted"
        } else {
            "operator_command_accepted"
        };
        insert_audit_tx(&tx, audit_action, &detail, now_ms)?;
        let sequence = u64::try_from(sequence_i64).map_err(|_| {
            WatchdogError::Conflict("operator command sequence overflow".to_string())
        })?;
        tx.commit()?;
        Ok(OperatorCommandOutcome::Accepted(OperatorCommandReceipt {
            sequence,
            request_id: context.request_id.clone(),
            idempotency_key: context.idempotency_key.clone(),
            principal: context.principal.clone(),
            capability: context.capability,
            command,
            command_fingerprint: context.command_fingerprint.clone(),
            desired_mode,
            response: response.clone(),
            recorded_at_ms: now_ms,
            replayed: false,
        }))
    }

    /// Atomically admit one authenticated job submission. The job row, the
    /// replayable operator receipt, and both audit records share one SQLite
    /// transaction. A replay is accepted even when the original job is
    /// completed or the deployment is stopped; it never changes desired mode
    /// and therefore cannot revive the scheduler.
    pub fn admit_operator_job_submission(
        &mut self,
        owner: &SingletonLock,
        context: &OperatorCommandContext,
        kind: &str,
        payload: &Value,
        now_ms: u64,
    ) -> Result<OperatorCommandOutcome> {
        ensure_owner_lock(&self.path, owner)?;
        context.validate()?;
        if context.capability != OperatorCapability::Admin {
            return Err(WatchdogError::Unauthorized(
                "read capability cannot admit a job submission".to_string(),
            ));
        }
        validate_name(kind, "job kind", 128)?;
        let encoded = serde_json::to_vec(payload)?;
        if encoded.len() > self.max_payload_bytes {
            return Err(WatchdogError::InvalidInput(format!(
                "job payload exceeds {} bytes",
                self.max_payload_bytes
            )));
        }
        let payload_digest = hex_digest(&encoded);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(existing) = find_operator_by_key(&tx, &context.idempotency_key)? {
            if existing.principal != context.principal || existing.capability != context.capability
            {
                return Err(WatchdogError::Unauthorized(
                    "idempotency key belongs to another operator context".to_string(),
                ));
            }
            if existing.command_fingerprint != context.command_fingerprint
                || existing.command != OperatorCommand::JobSubmit
            {
                return Err(WatchdogError::Conflict(
                    "idempotency key was reused with a different command fingerprint".to_string(),
                ));
            }
            let job_id = job_id_from_response(&existing.response)?;
            let stored: Option<(String, String)> = tx
                .query_row(
                    "SELECT kind, payload_digest FROM jobs WHERE id=?",
                    params![job_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let Some((stored_kind, stored_digest)) = stored else {
                return Err(WatchdogError::Conflict(
                    "job submission receipt has no durable job row".to_string(),
                ));
            };
            if stored_kind != kind || stored_digest != payload_digest {
                return Err(WatchdogError::Conflict(
                    "idempotency key was reused with a different job payload".to_string(),
                ));
            }
            tx.rollback()?;
            return Ok(OperatorCommandOutcome::Replayed(
                existing.with_replayed(true),
            ));
        }
        if let Some(existing) = find_operator_by_request(&tx, &context.request_id)? {
            return Err(WatchdogError::Conflict(format!(
                "request id already belongs to idempotency key {}",
                existing.idempotency_key
            )));
        }
        enforce_ledger_capacity(&tx, OperatorCommand::JobSubmit)?;

        let job_id = Uuid::new_v4().to_string();
        let response = json!({
            "kind": "JobSubmitted",
            "value": {"job_id": job_id},
        });
        validate_response(&response)?;
        let response_text = serde_json::to_string(&response)?;
        super::insert_job_tx(
            &tx,
            &job_id,
            kind,
            &encoded,
            &payload_digest,
            self.max_jobs,
            now_ms,
        )?;
        tx.execute(
            "INSERT INTO operator_commands (request_id, idempotency_key, principal, capability, command, command_fingerprint, desired_mode, response_json, recorded_at_ms) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)",
            params![
                context.request_id,
                context.idempotency_key,
                context.principal,
                context.capability.as_str(),
                OperatorCommand::JobSubmit.as_str(),
                context.command_fingerprint,
                response_text,
                super::sqlite_timestamp(now_ms)?,
            ],
        )?;
        let sequence_i64 = tx.last_insert_rowid();
        let detail = format!(
            "sequence={};request_id={};key={};principal={};capability={};command={};fingerprint={}",
            sequence_i64,
            context.request_id,
            context.idempotency_key,
            context.principal,
            context.capability.as_str(),
            OperatorCommand::JobSubmit.as_str(),
            context.command_fingerprint,
        );
        insert_audit_tx(&tx, "operator_command_accepted", &detail, now_ms)?;
        let sequence = u64::try_from(sequence_i64).map_err(|_| {
            WatchdogError::Conflict("operator command sequence overflow".to_string())
        })?;
        tx.commit()?;
        Ok(OperatorCommandOutcome::Accepted(OperatorCommandReceipt {
            sequence,
            request_id: context.request_id.clone(),
            idempotency_key: context.idempotency_key.clone(),
            principal: context.principal.clone(),
            capability: context.capability,
            command: OperatorCommand::JobSubmit,
            command_fingerprint: context.command_fingerprint.clone(),
            desired_mode: None,
            response,
            recorded_at_ms: now_ms,
            replayed: false,
        }))
    }

    /// Compatibility spelling for callers that mirror the wire command name.
    pub fn admit_operator_job_submit(
        &mut self,
        owner: &SingletonLock,
        context: &OperatorCommandContext,
        kind: &str,
        payload: &Value,
        now_ms: u64,
    ) -> Result<OperatorCommandOutcome> {
        self.admit_operator_job_submission(owner, context, kind, payload, now_ms)
    }

    /// Read one retained mutation receipt without changing the database.
    pub fn operator_command(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<OperatorCommandReceipt>> {
        validate_name(idempotency_key, "idempotency key", 128)?;
        self.conn
            .query_row(
                OPERATOR_SELECT,
                params![idempotency_key],
                operator_receipt_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// List retained mutation receipts in durable sequence order.  The limit
    /// is bounded even if a future caller supplies an untrusted value.
    pub fn list_operator_commands(&self, limit: u64) -> Result<Vec<OperatorCommandReceipt>> {
        let limit = limit.min(MAX_OPERATOR_COMMANDS_WITH_STOP_RESERVE as u64);
        let mut statement = self.conn.prepare(
            "SELECT sequence, request_id, idempotency_key, principal, capability, command, command_fingerprint, desired_mode, response_json, recorded_at_ms FROM operator_commands ORDER BY sequence LIMIT ?",
        )?;
        let rows = statement
            .query_map(params![i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
                operator_receipt_from_row(row)
            })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Number of retained command receipts, used for bounded diagnostics and
    /// fault tests.
    pub fn operator_command_count(&self) -> Result<u64> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM operator_commands", [], |row| {
                    row.get(0)
                })?;
        Ok(sqlite_u64(count, "operator command count")?)
    }
}

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

const OPERATOR_SELECT: &str = "SELECT sequence, request_id, idempotency_key, principal, capability, command, command_fingerprint, desired_mode, response_json, recorded_at_ms FROM operator_commands WHERE idempotency_key=?";

fn find_operator_by_key(tx: &Transaction<'_>, key: &str) -> Result<Option<OperatorCommandReceipt>> {
    tx.query_row(OPERATOR_SELECT, params![key], operator_receipt_from_row)
        .optional()
        .map_err(Into::into)
}

fn find_operator_by_request(
    tx: &Transaction<'_>,
    request_id: &str,
) -> Result<Option<OperatorCommandReceipt>> {
    tx.query_row(
        "SELECT sequence, request_id, idempotency_key, principal, capability, command, command_fingerprint, desired_mode, response_json, recorded_at_ms FROM operator_commands WHERE request_id=?",
        params![request_id],
        operator_receipt_from_row,
    )
    .optional()
    .map_err(Into::into)
}

fn enforce_ledger_capacity(tx: &Transaction<'_>, command: OperatorCommand) -> Result<()> {
    let count: i64 = tx.query_row("SELECT COUNT(*) FROM operator_commands", [], |row| {
        row.get(0)
    })?;
    let limit = if command == OperatorCommand::Stop {
        MAX_OPERATOR_COMMANDS_WITH_STOP_RESERVE
    } else if command.is_lifecycle() {
        MAX_OPERATOR_COMMANDS
    } else {
        MAX_OPERATOR_COMMANDS - RESERVED_LIFECYCLE_COMMANDS
    };
    if count >= limit {
        return Err(WatchdogError::Busy(
            "operator command ledger retention bound is full".into(),
        ));
    }
    Ok(())
}

fn validate_response(response: &Value) -> Result<()> {
    if response.is_null() {
        return Err(WatchdogError::InvalidInput(
            "operator response must not be null".to_string(),
        ));
    }
    let bytes = serde_json::to_vec(response)?;
    if bytes.len() > MAX_OPERATOR_RESPONSE_BYTES {
        return Err(WatchdogError::InvalidInput(format!(
            "operator response exceeds {MAX_OPERATOR_RESPONSE_BYTES} bytes"
        )));
    }
    if bytes.contains(&0) {
        return Err(WatchdogError::InvalidInput(
            "operator response contains NUL".to_string(),
        ));
    }
    Ok(())
}

fn job_id_from_response(response: &Value) -> Result<String> {
    let job_id = response
        .get("value")
        .and_then(Value::as_object)
        .and_then(|value| value.get("job_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            WatchdogError::Conflict("job submission receipt has no job id".to_string())
        })?;
    validate_name(job_id, "job id", 128)?;
    Ok(job_id.to_string())
}

fn operator_receipt_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<OperatorCommandReceipt> {
    let request_id: String = row.get(1)?;
    validate_uuid_v4(&request_id, "operator request id").map_err(to_sqlite_error)?;
    let idempotency_key: String = row.get(2)?;
    validate_name(&idempotency_key, "operator idempotency key", 128).map_err(to_sqlite_error)?;
    let principal: String = row.get(3)?;
    validate_name(&principal, "operator principal", 128).map_err(to_sqlite_error)?;
    let capability_text: String = row.get(4)?;
    let capability = OperatorCapability::parse(&capability_text).map_err(to_sqlite_error)?;
    if capability != OperatorCapability::Admin {
        return Err(to_sqlite_error(
            "operator ledger contains a non-mutating capability",
        ));
    }
    let command_text: String = row.get(5)?;
    let command = OperatorCommand::parse(&command_text).map_err(to_sqlite_error)?;
    if command.is_read_only() {
        return Err(to_sqlite_error(
            "operator ledger contains a read-only command",
        ));
    }
    let response_text: String = row.get(8)?;
    if response_text.len() > MAX_OPERATOR_RESPONSE_BYTES {
        return Err(to_sqlite_error(
            "operator response exceeds its persisted bound",
        ));
    }
    let command_fingerprint: String = row.get(6)?;
    validate_digest(&command_fingerprint).map_err(to_sqlite_error)?;
    let desired_mode_text: Option<String> = row.get(7)?;
    let desired_mode = desired_mode_text
        .as_deref()
        .map(parse_mode)
        .transpose()
        .map_err(to_sqlite_error)?;
    if desired_mode != command.desired_mode() {
        return Err(to_sqlite_error(
            "operator ledger desired mode does not match its command",
        ));
    }
    let response: Value = serde_json::from_str(&response_text).map_err(to_sqlite_error)?;
    if response.is_null() {
        return Err(to_sqlite_error("operator response must not be null"));
    }
    let sequence = sqlite_u64(row.get::<_, i64>(0)?, "operator command sequence")?;
    if sequence == 0 {
        return Err(to_sqlite_error(
            "operator command sequence must be positive",
        ));
    }
    let recorded_at_ms = sqlite_u64(row.get::<_, i64>(9)?, "operator recorded_at_ms")?;
    Ok(OperatorCommandReceipt {
        sequence,
        request_id,
        idempotency_key,
        principal,
        capability,
        command,
        command_fingerprint,
        desired_mode,
        response,
        recorded_at_ms,
        replayed: false,
    })
}

impl OperatorCommandReceipt {
    fn with_replayed(mut self, replayed: bool) -> Self {
        self.replayed = replayed;
        self
    }
}

fn validate_uuid_v4(value: &str, name: &str) -> Result<()> {
    let parsed = Uuid::parse_str(value)
        .map_err(|_| WatchdogError::InvalidInput(format!("{name} must be a UUIDv4")))?;
    if parsed.get_version_num() != 4 {
        return Err(WatchdogError::InvalidInput(format!(
            "{name} must be a UUIDv4"
        )));
    }
    Ok(())
}

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
