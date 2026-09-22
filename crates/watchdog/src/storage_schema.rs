//! Store connection lifecycle, schema creation, migrations and durability.
//!
//! Extracted from `storage.rs` (issue #96) without behavior change: store
//! initialization/open variants, the durability pragma projection, and the
//! schema/migration/compatibility machinery that establishes and validates the
//! owner-local database layout.  `Store` itself remains the facade type; this
//! module only owns its connection-establishing inherent methods.
use super::{
    LaunchIntent, OPERATOR_LEDGER_SCHEMA_VERSION, PREVIOUS_SCHEMA_VERSION, SCHEMA_VERSION,
    SingletonLock, Store, canonical_owner_path, ensure_owner_lock, insert_audit_tx,
    launch_intent_from_row, metadata_from_conn, mode_as_str, now_unix_ms, parse_metadata_i64,
    storage_admin, storage_gateway_health, storage_worker_bootstrap, storage_worker_handoff,
    update_metadata_tx, validate_metadata_identifier,
};
use crate::config::{DesiredMode, WatchdogConfig};
use crate::error::{Result, WatchdogError};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// SQLite durability settings observed from a live connection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DurabilityPragmas {
    pub journal_mode: String,
    pub synchronous: i64,
    pub foreign_keys: i64,
}

impl DurabilityPragmas {
    /// FULL is SQLite's numeric synchronous value 2.
    #[must_use]
    pub fn is_wal_full(&self) -> bool {
        self.journal_mode.eq_ignore_ascii_case("wal")
            && self.synchronous == 2
            && self.foreign_keys == 1
    }
}

impl Store {
    /// Initialize a new database and its schema.  Existing initialized state is
    /// never overwritten.  The compatibility entrypoint acquires the
    /// owner-local lock for the full bootstrap; production code that already
    /// owns the controller lock should use [`Self::initialize_for_owner`] to
    /// make that admission explicit without a second OS lock attempt.
    pub fn initialize(path: impl AsRef<Path>, config: &WatchdogConfig) -> Result<Self> {
        config.validate()?;
        let path = canonical_owner_path(path.as_ref(), "database")?;
        let _admission = match SingletonLock::current_for_path(&path) {
            Some(lock) => lock,
            None => SingletonLock::acquire(&path)?,
        };
        Self::initialize_impl(path, config)
    }

    /// Initialize a new store under an already-held singleton admission.
    /// The lock path must match the database exactly; this method never
    /// acquires a second OS lock and keeps the caller's lock authoritative.
    pub fn initialize_for_owner(
        path: impl AsRef<Path>,
        config: &WatchdogConfig,
        owner: &SingletonLock,
    ) -> Result<Self> {
        config.validate()?;
        let path = canonical_owner_path(path.as_ref(), "database")?;
        ensure_owner_lock(&path, owner)?;
        Self::initialize_impl(path, config)
    }

    fn initialize_impl(path: PathBuf, config: &WatchdogConfig) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let stable_path = canonical_owner_path(&path, "database")?;
        if stable_path != path {
            return Err(WatchdogError::Conflict(
                "database path changed while preparing initialization".to_string(),
            ));
        }
        let existed = path.exists();
        let mut conn = open_connection(&path)?;
        if existed {
            let marker: Option<String> = if table_exists(&conn, "metadata")? {
                conn.query_row(
                    "SELECT value FROM metadata WHERE key = 'schema_version'",
                    [],
                    |row| row.get(0),
                )
                .optional()?
            } else {
                None
            };
            if marker.is_some() {
                return Err(WatchdogError::Conflict(format!(
                    "store is already initialized: {}",
                    path.display()
                )));
            }
            if has_any_user_tables(&conn)? {
                return Err(WatchdogError::Conflict(format!(
                    "existing database is not a recognized watchdog store: {}",
                    path.display()
                )));
            }
        }
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        if !connection_pragmas(&conn)?.is_wal_full() {
            return Err(WatchdogError::Conflict(
                "required SQLite durability was not established".to_string(),
            ));
        }
        create_schema(&mut conn)?;
        let config_digest = config.digest()?;
        let config_compat_digest = config_compatibility_digest(config)?;
        let now = now_unix_ms();
        let tx = conn.transaction()?;
        insert_metadata(&tx, "schema_version", &SCHEMA_VERSION.to_string())?;
        insert_metadata(&tx, "deployment_id", &config.deployment_id)?;
        insert_metadata(&tx, "desired_mode", mode_as_str(config.desired_mode))?;
        insert_metadata(&tx, "restart_generation", "1")?;
        insert_metadata(&tx, "config_digest", &config_digest)?;
        insert_metadata(&tx, "config_compat_digest", &config_compat_digest)?;
        insert_metadata(
            &tx,
            "operator_ledger_schema_version",
            &OPERATOR_LEDGER_SCHEMA_VERSION.to_string(),
        )?;
        storage_worker_handoff::insert_worker_handoff_metadata(&tx)?;
        insert_metadata(&tx, "initialized_at_ms", &now.to_string())?;
        insert_metadata(&tx, "updated_at_ms", &now.to_string())?;
        insert_audit_tx(
            &tx,
            "store_initialized",
            &format!("schema={SCHEMA_VERSION};config_digest={config_digest}"),
            now,
        )?;
        tx.commit()?;
        let store = Self {
            conn,
            path,
            max_jobs: config.max_jobs,
            max_payload_bytes: config.max_payload_bytes,
            restart_clock_epoch: Uuid::new_v4().to_string(),
            restart_clock_started: Instant::now(),
        };
        store.validate_release_selection_metadata()?;
        Ok(store)
    }

    /// Open an existing initialized store without creating or migrating it.
    /// Schema upgrades are owner-authorized state transitions and must go
    /// through [`Self::open_for_owner`].
    pub fn open(path: impl AsRef<Path>, config: &WatchdogConfig) -> Result<Self> {
        config.validate()?;
        let path = canonical_owner_path(path.as_ref(), "database")?;
        Self::open_impl(path, config, OpenFlags::SQLITE_OPEN_READ_WRITE, false)
    }

    /// Open existing state through a true SQLite read-only, non-creating
    /// connection.  Status, doctor, and inspection paths should use this
    /// method so an unlink/create race cannot bootstrap or mutate state.
    pub fn open_read_only(path: impl AsRef<Path>, config: &WatchdogConfig) -> Result<Self> {
        config.validate()?;
        let path = canonical_owner_path(path.as_ref(), "database")?;
        Self::open_impl(path, config, OpenFlags::SQLITE_OPEN_READ_ONLY, false)
    }

    /// Hold SQLite's writer reservation while a native child is authorized
    /// and resumed/executed. No rows are changed. Dropping this connection
    /// rolls back the transaction and releases the reservation, so an operator
    /// Stop either commits before admission is checked or after resumption.
    pub(crate) fn reserve_launch_admission(self) -> Result<Self> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        Ok(self)
    }

    /// Compatibility alias retained for the worker-specific admission tests.
    /// Both worker and gateway-health launchers use the same owner-local
    /// reservation and therefore share the exact transaction boundary.
    #[allow(dead_code)]
    #[cfg(any(windows, test))]
    pub(crate) fn reserve_worker_admission(self) -> Result<Self> {
        self.reserve_launch_admission()
    }

    /// Admission needs at most two rows: one exact intent, or evidence of a
    /// conflicting unsettled launch. Never collect an unbounded history here.
    pub(crate) fn launch_admission_intents(&self, component: &str) -> Result<Vec<LaunchIntent>> {
        let mut statement = self.conn.prepare(
            "SELECT id, deployment_id, component_id, launch_nonce, expected_incarnation, expected_launch_spec_digest, planned_containment_id, state, ownership_proof_json, created_at_ms, updated_at_ms FROM launch_intents WHERE component_id=? AND state <> 'cleaned' LIMIT 2",
        )?;
        let rows = statement.query_map([component], launch_intent_from_row)?;
        rows.collect::<rusqlite::Result<Vec<LaunchIntent>>>()
            .map_err(Into::into)
    }

    /// Compatibility alias retained for the worker-specific admission tests.
    #[allow(dead_code)]
    #[cfg(any(windows, test))]
    pub(crate) fn worker_admission_intents(&self, component: &str) -> Result<Vec<LaunchIntent>> {
        self.launch_admission_intents(component)
    }

    /// Open existing state for a controller that already holds the matching
    /// singleton lock.  No migration, schema creation, or second lock attempt
    /// occurs in this method.
    pub fn open_for_owner(
        path: impl AsRef<Path>,
        config: &WatchdogConfig,
        owner: &SingletonLock,
    ) -> Result<Self> {
        config.validate()?;
        let path = canonical_owner_path(path.as_ref(), "database")?;
        ensure_owner_lock(&path, owner)?;
        let mut store = Self::open_impl(
            path.clone(),
            config,
            OpenFlags::SQLITE_OPEN_READ_WRITE,
            true,
        )?;
        storage_admin::migrate_operator_ledger_for_owner(&path, owner)?;
        storage_worker_handoff::migrate_worker_handoff_for_owner(&mut store.conn)?;
        Ok(store)
    }

    fn open_impl(
        path: PathBuf,
        config: &WatchdogConfig,
        flags: OpenFlags,
        allow_core_migration: bool,
    ) -> Result<Self> {
        if !path.is_file() {
            return Err(WatchdogError::MissingState(path));
        }
        let mut conn = open_connection_with_flags(&path, flags)?;
        let version: Option<String> = conn
            .query_row(
                "SELECT value FROM metadata WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let schema_version = version
            .as_deref()
            .map(|value| parse_metadata_i64("schema_version", value))
            .transpose()?;
        let needs_core_migration = match schema_version {
            Some(SCHEMA_VERSION) => {
                validate_launch_intent_schema(&conn)?;
                false
            }
            Some(PREVIOUS_SCHEMA_VERSION) if allow_core_migration => {
                validate_legacy_launch_intent_schema(&conn)?;
                true
            }
            Some(PREVIOUS_SCHEMA_VERSION) => {
                return Err(WatchdogError::Unsupported(
                    "store schema 1 requires an owner-authorized explicit migration".to_string(),
                ));
            }
            Some(other) => {
                return Err(WatchdogError::Unsupported(format!(
                    "store schema {other} requires an explicit migration"
                )));
            }
            None => {
                return Err(WatchdogError::Conflict(format!(
                    "database is not an initialized watchdog store: {}",
                    path.display()
                )));
            }
        };
        let pragmas = connection_pragmas(&conn)?;
        if !pragmas.is_wal_full() {
            return Err(WatchdogError::Conflict(format!(
                "required SQLite durability is not active: {pragmas:?}"
            )));
        }
        let stored_deployment_id: Option<String> = conn
            .query_row(
                "SELECT value FROM metadata WHERE key='deployment_id'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let Some(stored_deployment_id) = stored_deployment_id else {
            return Err(WatchdogError::Conflict(
                "deployment_id metadata is missing".to_string(),
            ));
        };
        validate_metadata_identifier("deployment_id", &stored_deployment_id)?;
        if stored_deployment_id != config.deployment_id {
            return Err(WatchdogError::Conflict(
                "deployment identity differs from initialized owner-local state; explicit restore is required"
                    .to_string(),
            ));
        }
        let stored_config_digest: Option<String> = conn
            .query_row(
                "SELECT value FROM metadata WHERE key='config_digest'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let Some(stored_config_digest) = stored_config_digest else {
            return Err(WatchdogError::Conflict(
                "config_digest metadata is missing".to_string(),
            ));
        };
        crate::config::validate_digest(&stored_config_digest).map_err(|message| {
            WatchdogError::Conflict(format!("config_digest metadata is invalid: {message}"))
        })?;
        let expected_config_digest = config.digest()?;
        if stored_config_digest != expected_config_digest {
            return Err(WatchdogError::Conflict(
                "configuration digest differs from initialized owner-local state; explicit migration is required"
                    .to_string(),
            ));
        }
        let stored_config_compat_digest = metadata_from_conn(&conn, "config_compat_digest")?
            .ok_or_else(|| {
                WatchdogError::Conflict("config_compat_digest metadata is missing".to_string())
            })?;
        crate::config::validate_digest(&stored_config_compat_digest).map_err(|message| {
            WatchdogError::Conflict(format!(
                "config_compat_digest metadata is invalid: {message}"
            ))
        })?;
        let expected_config_compat_digest = config_compatibility_digest(config)?;
        if stored_config_compat_digest != expected_config_compat_digest {
            return Err(WatchdogError::Conflict(
                "configuration compatibility identity differs from initialized owner-local state; explicit restore is required"
                    .to_string(),
            ));
        }
        if needs_core_migration {
            migrate_launch_intent_schema(&mut conn)?;
        }
        let store = Self {
            conn,
            path,
            max_jobs: config.max_jobs,
            max_payload_bytes: config.max_payload_bytes,
            restart_clock_epoch: Uuid::new_v4().to_string(),
            restart_clock_started: Instant::now(),
        };
        store.validate_release_selection_metadata()?;
        Ok(store)
    }

    /// Verify WAL/FULL/foreign-key settings on this connection.
    pub fn durability(&self) -> Result<DurabilityPragmas> {
        connection_pragmas(&self.conn)
    }
}

pub(super) fn open_connection(path: &Path) -> Result<Connection> {
    open_connection_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )
}

pub(super) fn open_connection_with_flags(path: &Path, flags: OpenFlags) -> Result<Connection> {
    let conn = Connection::open_with_flags(path, flags)?;
    conn.busy_timeout(Duration::from_millis(750))?;
    // Foreign-key and temp-store settings are connection-local.  Opening a
    // store for `status` does not switch journal mode or create state.
    conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY;")?;
    Ok(conn)
}

pub(super) fn connection_pragmas(conn: &Connection) -> Result<DurabilityPragmas> {
    let journal_mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    let synchronous: i64 = conn.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let foreign_keys: i64 = conn.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    Ok(DurabilityPragmas {
        journal_mode,
        synchronous,
        foreign_keys,
    })
}

pub(crate) fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let value: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            params![name],
            |row| row.get(0),
        )
        .optional()?;
    Ok(value.is_some())
}

pub(super) fn validate_local_storage_path(path: &Path, name: &str) -> Result<()> {
    if path.as_os_str().is_empty() || path.to_string_lossy().contains('\0') {
        return Err(WatchdogError::InvalidInput(format!(
            "{name} path is empty or contains NUL"
        )));
    }
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if normalized.starts_with("/mnt/") || normalized.starts_with("//wsl") {
        return Err(WatchdogError::InvalidInput(format!(
            "{name} must remain on an owner-local filesystem"
        )));
    }
    Ok(())
}

fn has_any_user_tables(conn: &Connection) -> Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

fn create_schema(conn: &mut Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY NOT NULL,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            detail TEXT NOT NULL,
            occurred_at_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY NOT NULL,
            kind TEXT NOT NULL,
            payload TEXT NOT NULL,
            payload_digest TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed','quarantined')),
            created_at_ms INTEGER NOT NULL,
            claimed_at_ms INTEGER,
            completed_at_ms INTEGER,
            attempt_count INTEGER NOT NULL CHECK(attempt_count >= 0),
            next_retry_at_ms INTEGER,
            last_error TEXT,
            result TEXT,
            completion_digest TEXT,
            worker_id TEXT
        );
        CREATE INDEX IF NOT EXISTS jobs_ready_idx ON jobs(status, next_retry_at_ms, created_at_ms, id);
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
        CREATE TABLE IF NOT EXISTS launch_intents (
            id TEXT PRIMARY KEY NOT NULL,
            deployment_id TEXT NOT NULL,
            component_id TEXT NOT NULL,
            launch_nonce TEXT NOT NULL,
            expected_incarnation TEXT NOT NULL,
            expected_launch_spec_digest TEXT NOT NULL,
            planned_containment_id TEXT,
            state TEXT NOT NULL CHECK(state IN ('prepared','proof_recorded','active','cleaned')),
            ownership_proof_json TEXT,
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS launch_intents_one_unsettled_component_idx ON launch_intents(component_id) WHERE state <> 'cleaned';
        CREATE INDEX IF NOT EXISTS launch_intents_component_idx ON launch_intents(component_id, state, created_at_ms);
        CREATE TABLE IF NOT EXISTS attempts (
            id TEXT PRIMARY KEY NOT NULL,
            job_id TEXT NOT NULL REFERENCES jobs(id),
            sequence INTEGER NOT NULL CHECK(sequence > 0),
            lineage TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('running','completed','failed','unknown')),
            started_at_ms INTEGER NOT NULL,
            finished_at_ms INTEGER,
            worker_id TEXT,
            outcome TEXT,
            UNIQUE(job_id, sequence)
        );
        CREATE TABLE IF NOT EXISTS restart_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            component_id TEXT NOT NULL,
            occurred_at_ms INTEGER NOT NULL,
            clock_epoch TEXT NOT NULL,
            clock_elapsed_ms INTEGER NOT NULL CHECK(clock_elapsed_ms >= 0)
        );
        CREATE INDEX IF NOT EXISTS restart_events_component_idx ON restart_events(component_id, clock_epoch, clock_elapsed_ms);
        CREATE TABLE IF NOT EXISTS components (
            id TEXT PRIMARY KEY NOT NULL,
            state TEXT NOT NULL,
            launch_nonce TEXT,
            pid INTEGER,
            executable_digest TEXT,
            started_at_ms INTEGER,
            restart_attempts INTEGER NOT NULL CHECK(restart_attempts >= 0),
            last_restart_at_ms INTEGER,
            last_error TEXT,
            identity_json TEXT,
            updated_at_ms INTEGER NOT NULL
        );
        ",
    )?;
    storage_worker_handoff::create_worker_handoff_schema(conn)?;
    storage_worker_bootstrap::create_schema(conn)?;
    storage_gateway_health::create_schema(conn)?;
    Ok(())
}

fn insert_metadata(tx: &Transaction<'_>, key: &str, value: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata (key, value) VALUES (?, ?)",
        params![key, value],
    )?;
    Ok(())
}

fn validate_legacy_launch_intent_schema(conn: &Connection) -> Result<()> {
    if !table_exists(conn, "launch_intents")? {
        return Err(WatchdogError::Conflict(
            "launch_intents table is missing from the initialized store".to_owned(),
        ));
    }
    let mut statement = conn.prepare("PRAGMA table_info(launch_intents)")?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for required in [
        "id",
        "deployment_id",
        "component_id",
        "launch_nonce",
        "planned_containment_id",
        "state",
        "ownership_proof_json",
        "created_at_ms",
        "updated_at_ms",
    ] {
        if !columns.iter().any(|column| column == required) {
            return Err(WatchdogError::Conflict(format!(
                "launch_intents table is missing {required}"
            )));
        }
    }
    Ok(())
}

fn validate_launch_intent_schema(conn: &Connection) -> Result<()> {
    if !table_exists(conn, "launch_intents")? {
        return Err(WatchdogError::Conflict(
            "launch_intents table is missing from the initialized store".to_owned(),
        ));
    }
    let mut statement = conn.prepare("PRAGMA table_info(launch_intents)")?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for required in ["expected_incarnation", "expected_launch_spec_digest"] {
        if !columns.iter().any(|column| column == required) {
            return Err(WatchdogError::Conflict(format!(
                "launch_intents table is missing {required}"
            )));
        }
    }
    Ok(())
}

/// Add the immutable launch binding columns without manufacturing values for
/// old rows.  A null binding is deliberate legacy evidence; runtime recovery
/// quarantines such an intent instead of deriving an expected value from its
/// proof or from the current restart generation.
fn migrate_launch_intent_schema(conn: &mut Connection) -> Result<()> {
    if !table_exists(conn, "metadata")? || !table_exists(conn, "launch_intents")? {
        return Err(WatchdogError::Conflict(
            "schema 1 store lacks the launch-intent migration boundary".to_owned(),
        ));
    }
    let columns = {
        let mut statement = conn.prepare("PRAGMA table_info(launch_intents)")?;
        statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let has_incarnation = columns
        .iter()
        .any(|column| column == "expected_incarnation");
    let has_digest = columns
        .iter()
        .any(|column| column == "expected_launch_spec_digest");
    if has_incarnation != has_digest {
        return Err(WatchdogError::Conflict(
            "launch-intent binding columns are only partially present".to_owned(),
        ));
    }
    if has_incarnation {
        validate_launch_intent_schema(conn)?;
        return Err(WatchdogError::Conflict(
            "schema 1 marker has already applied its launch-intent migration".to_owned(),
        ));
    }

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "ALTER TABLE launch_intents ADD COLUMN expected_incarnation TEXT",
        [],
    )?;
    tx.execute(
        "ALTER TABLE launch_intents ADD COLUMN expected_launch_spec_digest TEXT",
        [],
    )?;
    update_metadata_tx(&tx, "schema_version", &SCHEMA_VERSION.to_string())?;
    let now = now_unix_ms();
    insert_audit_tx(
        &tx,
        "store_schema_migrated",
        "schema=1->2;legacy_launch_intents_unbound",
        now,
    )?;
    tx.commit()?;
    validate_launch_intent_schema(conn)
}

pub(super) fn config_compatibility_digest(config: &WatchdogConfig) -> Result<String> {
    config.validate()?;
    let mut normalized = config.clone();
    normalized.deployment_id = "watchdog-compatibility-identity".to_string();
    normalized.database = PathBuf::from("/owner-local/watchdog.sqlite3");
    normalized.desired_mode = DesiredMode::Stopped;
    if let Some(health) = &normalized.gateway_health {
        for component in &mut normalized.components {
            if component.id == health.component_id {
                component.environment.insert(
                    "STS2_DEPLOYMENT_ID".to_owned(),
                    normalized.deployment_id.clone(),
                );
            }
        }
    }
    // This is a fingerprint projection, not an executable configuration. Its
    // fixed namespace/path placeholders intentionally are not platform-valid
    // launch identities. Validate the real input above, never the projection.
    Ok(crate::config::hex_digest(&serde_json::to_vec(&normalized)?))
}
