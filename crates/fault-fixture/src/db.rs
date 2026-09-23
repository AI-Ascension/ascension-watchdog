//! Durable fixture database and ownership.
//!
//! Owns the singleton sidecar lock and its in-process registry, the additive
//! column migrations, the database/lock path safety checks, the `SQLite`
//! integrity check, the operation row projection type and `DurableHost::open`.
//! Extracted verbatim from `lib.rs` by the durable-fixture-database-and-
//! ownership split (issue #74); the crate root keeps the `DurableHost` struct
//! definition and imports the row type and lock guard from here.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use fs2::FileExt;
use rusqlite::{Connection, params};

use crate::{DurableHost, FIXTURE_TIMESTAMP, FIXTURE_TOKEN, FixtureError, digest};

/// `fs2` uses the operating system's advisory lock, but Windows permits
/// multiple handles from one process to acquire the same byte-range lock.
/// Keep a small in-process registry as well so the fixture's ownership
/// contract is identical on every supported platform.  The OS lock remains
/// authoritative for competing processes.
pub(crate) struct SidecarLock {
    file: File,
    path: PathBuf,
}

impl Drop for SidecarLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
        if let Ok(mut registry) = sidecar_lock_registry().lock() {
            registry.remove(&self.path);
        }
    }
}

fn sidecar_lock_registry() -> &'static Mutex<HashSet<PathBuf>> {
    static REGISTRY: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashSet::new()))
}

pub(crate) type OperationRow = (
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    String,
    String,
    Option<String>,
);

fn migrate_columns(connection: &Connection) -> Result<(), FixtureError> {
    // The fixture is deliberately disposable, but retaining these additive
    // migrations makes a crash/restart against a database created by the
    // earlier fixture fail closed instead of silently dropping authority.
    let migrations = [
        (
            "fence",
            "deployment_id",
            "TEXT NOT NULL DEFAULT '00000000-0000-4000-8000-000000000000'",
        ),
        (
            "fence",
            "instance_id",
            "TEXT NOT NULL DEFAULT '00000000-0000-4000-8000-000000000000'",
        ),
        ("fence", "authority_state", "TEXT NOT NULL DEFAULT 'READY'"),
        ("fence", "lease_epoch_counter", "INTEGER NOT NULL DEFAULT 0"),
        ("fence", "lease_ttl_seconds", "INTEGER NOT NULL DEFAULT 30"),
        (
            "fence",
            "lease_renewal_interval_seconds",
            "INTEGER NOT NULL DEFAULT 10",
        ),
        (
            "lease",
            "deployment_id",
            "TEXT NOT NULL DEFAULT '00000000-0000-4000-8000-000000000000'",
        ),
        (
            "lease",
            "instance_id",
            "TEXT NOT NULL DEFAULT '00000000-0000-4000-8000-000000000000'",
        ),
        (
            "lease",
            "fence_token",
            "TEXT NOT NULL DEFAULT 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'",
        ),
        (
            "lease",
            "issued_at",
            "TEXT NOT NULL DEFAULT '2026-09-06T00:00:00Z'",
        ),
        (
            "lease",
            "expires_at",
            "TEXT NOT NULL DEFAULT '2026-09-06T00:00:30Z'",
        ),
        ("lease", "issued_tick", "INTEGER NOT NULL DEFAULT 0"),
        ("lease", "expires_tick", "INTEGER NOT NULL DEFAULT 30"),
        ("lease", "ttl_seconds", "INTEGER NOT NULL DEFAULT 30"),
        (
            "lease",
            "renewal_interval_seconds",
            "INTEGER NOT NULL DEFAULT 10",
        ),
        ("lease", "renew_sequence", "INTEGER NOT NULL DEFAULT 0"),
        (
            "operations",
            "deployment_id",
            "TEXT NOT NULL DEFAULT '00000000-0000-4000-8000-000000000000'",
        ),
        (
            "operations",
            "instance_id",
            "TEXT NOT NULL DEFAULT '00000000-0000-4000-8000-000000000000'",
        ),
        (
            "operations",
            "ticket_expires_tick",
            "INTEGER NOT NULL DEFAULT 0",
        ),
        ("operations", "reconcile_strategy", "TEXT"),
        ("runtime_sessions", "last_operation_id", "TEXT"),
        ("runtime_sessions", "last_action_id", "TEXT"),
    ];
    for (table, column, declaration) in migrations {
        if !table_has_column(connection, table, column)? {
            connection
                .execute(
                    &format!("ALTER TABLE {table} ADD COLUMN {column} {declaration}"),
                    [],
                )
                .map_err(FixtureError::Sql)?;
        }
    }
    Ok(())
}

fn table_has_column(
    connection: &Connection,
    table: &str,
    column: &str,
) -> Result<bool, FixtureError> {
    let mut statement = connection
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(FixtureError::Sql)?;
    let mut rows = statement.query([]).map_err(FixtureError::Sql)?;
    while let Some(row) = rows.next().map_err(FixtureError::Sql)? {
        let name: String = row.get(1).map_err(FixtureError::Sql)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_database_path(path: &Path) -> Result<PathBuf, FixtureError> {
    if path.as_os_str().is_empty() || path.to_string_lossy().contains('\0') {
        return Err(FixtureError::Invalid(
            "database path is empty or contains NUL".to_owned(),
        ));
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| FixtureError::Invalid("database filename missing".to_owned()))?;
    if file_name == "." || file_name == ".." {
        return Err(FixtureError::Invalid("database filename unsafe".to_owned()));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent_metadata = fs::symlink_metadata(parent).map_err(FixtureError::Io)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(FixtureError::Invalid(
            "database parent must be a real directory".to_owned(),
        ));
    }
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(FixtureError::Invalid(
            "database must be a regular file".to_owned(),
        ));
    }
    let canonical_parent = fs::canonicalize(parent).map_err(FixtureError::Io)?;
    Ok(canonical_parent.join(file_name))
}

fn validate_lock_path(path: &Path) -> Result<(), FixtureError> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(FixtureError::Invalid(
            "database lock must be a regular file".to_owned(),
        ));
    }
    Ok(())
}

fn is_lock_contention(error: &std::io::Error) -> bool {
    error.kind() == ErrorKind::WouldBlock
        || (error.raw_os_error().is_some()
            && error.raw_os_error() == fs2::lock_contended_error().raw_os_error())
}

fn validate_database_integrity(connection: &Connection) -> Result<(), FixtureError> {
    let result: String = connection
        .pragma_query_value(None, "integrity_check", |row| row.get(0))
        .map_err(FixtureError::Sql)?;
    if result != "ok" {
        return Err(FixtureError::Invalid(format!(
            "SQLite integrity check failed: {result}"
        )));
    }
    Ok(())
}

impl DurableHost {
    /// Open or initialize the fixture database with full synchronous writes.
    ///
    /// # Errors
    ///
    /// Returns a persistence error when `SQLite` cannot open, configure, or
    /// initialize the database.
    #[allow(clippy::too_many_lines, clippy::suspicious_open_options)]
    pub fn open(path: &Path) -> Result<Self, FixtureError> {
        let database_path = validate_database_path(path)?;
        let lock_path = database_path.with_extension("sqlite.lock");
        validate_lock_path(&lock_path)?;
        // Hold the registry guard through OS-lock acquisition so two threads
        // in this process cannot both pass the check on platforms whose file
        // locking is process-scoped (notably Windows).
        let mut registry = sidecar_lock_registry()
            .lock()
            .map_err(|_| FixtureError::Invalid("database lock registry poisoned".to_owned()))?;
        if registry.contains(&lock_path) {
            return Err(FixtureError::Busy);
        }
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(FixtureError::Io)?;
        lock.try_lock_exclusive().map_err(|error| {
            if is_lock_contention(&error) {
                FixtureError::Busy
            } else {
                FixtureError::Io(error)
            }
        })?;
        let connection = Connection::open(&database_path).map_err(FixtureError::Sql)?;
        connection
            .busy_timeout(Duration::from_secs(2))
            .map_err(FixtureError::Sql)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(FixtureError::Sql)?;
        let journal_mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(FixtureError::Sql)?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(FixtureError::Invalid(
                "SQLite WAL journal required".to_owned(),
            ));
        }
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(FixtureError::Sql)?;
        let synchronous: i64 = connection
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .map_err(FixtureError::Sql)?;
        if synchronous != 2 {
            return Err(FixtureError::Invalid(
                "SQLite synchronous FULL required".to_owned(),
            ));
        }
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(FixtureError::Sql)?;
        let foreign_keys: i64 = connection
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .map_err(FixtureError::Sql)?;
        if foreign_keys != 1 {
            return Err(FixtureError::Invalid(
                "SQLite foreign keys required".to_owned(),
            ));
        }
        validate_database_integrity(&connection)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS fence (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    deployment_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    boot_id TEXT NOT NULL,
                    instance_incarnation TEXT NOT NULL,
                    authority_generation INTEGER NOT NULL,
                    host_fence_id TEXT NOT NULL,
                    fence_generation INTEGER NOT NULL,
                    authority_state TEXT NOT NULL DEFAULT 'READY',
                    lease_epoch_counter INTEGER NOT NULL DEFAULT 0,
                    lease_ttl_seconds INTEGER NOT NULL DEFAULT 30,
                    lease_renewal_interval_seconds INTEGER NOT NULL DEFAULT 10
                );
                CREATE TABLE IF NOT EXISTS lease (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    deployment_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    lease_id TEXT NOT NULL,
                    lease_epoch INTEGER NOT NULL,
                    boot_id TEXT NOT NULL,
                    instance_incarnation TEXT NOT NULL,
                    host_fence_id TEXT NOT NULL,
                    fence_token TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    issued_tick INTEGER NOT NULL,
                    expires_tick INTEGER NOT NULL,
                    ttl_seconds INTEGER NOT NULL,
                    renewal_interval_seconds INTEGER NOT NULL,
                    renew_sequence INTEGER NOT NULL DEFAULT 0,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS operations (
                    operation_id TEXT PRIMARY KEY,
                    payload_digest TEXT NOT NULL,
                    deployment_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    boot_id TEXT NOT NULL,
                    instance_incarnation TEXT NOT NULL,
                    lease_epoch INTEGER NOT NULL,
                    host_fence_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    uncertainty_reason TEXT,
                    action_json TEXT NOT NULL,
                    expected_boundary_json TEXT NOT NULL,
                    original_context_json TEXT NOT NULL,
                    ticket_json TEXT,
                    ticket_expires_tick INTEGER NOT NULL DEFAULT 0,
                    witness_json TEXT,
                    receipt_json TEXT,
                    reconcile_strategy TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS queue (
                    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
                    ticket_json TEXT NOT NULL,
                    enqueued_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS effects (
                    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
                    payload_digest TEXT NOT NULL,
                    witness_json TEXT NOT NULL,
                    effect_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS receipts (
                    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
                    receipt_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS lease_history (
                    lease_id TEXT PRIMARY KEY,
                    lease_epoch INTEGER NOT NULL UNIQUE,
                    deployment_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    boot_id TEXT NOT NULL,
                    instance_incarnation TEXT NOT NULL,
                    host_fence_id TEXT NOT NULL,
                    fence_token_digest TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    issued_tick INTEGER NOT NULL,
                    expires_tick INTEGER NOT NULL,
                    ttl_seconds INTEGER NOT NULL,
                    renewal_interval_seconds INTEGER NOT NULL,
                    renew_sequence INTEGER NOT NULL DEFAULT 0,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS fixture_clock (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    tick INTEGER NOT NULL
                );
                INSERT OR IGNORE INTO fixture_clock(singleton, tick) VALUES(1, 0);
                CREATE TABLE IF NOT EXISTS runtime_sessions (
                    instance_id TEXT NOT NULL,
                    session_id TEXT PRIMARY KEY,
                    lease_id TEXT NOT NULL,
                    lease_epoch INTEGER NOT NULL,
                    state_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    observation_json TEXT NOT NULL,
                    legal_actions_json TEXT NOT NULL,
                    last_operation_id TEXT,
                    last_action_id TEXT,
                    stopped INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runtime_operations (
                    operation_id TEXT PRIMARY KEY,
                    instance_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    lease_id TEXT NOT NULL,
                    lease_epoch INTEGER NOT NULL,
                    action_json TEXT NOT NULL,
                    action_digest TEXT NOT NULL,
                    pre_state_id TEXT NOT NULL,
                    pre_generation INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    witness_json TEXT,
                    result_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runtime_queue (
                    operation_id TEXT PRIMARY KEY REFERENCES runtime_operations(operation_id),
                    enqueued_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS runtime_operations_active_session
                    ON runtime_operations(session_id)
                    WHERE status IN ('ADMITTED', 'EXECUTING', 'UNKNOWN');",
            )
            .map_err(FixtureError::Sql)?;
        migrate_columns(&connection)?;
        // Preserve the current singleton lease as historical evidence before
        // invalidating it. The history table is append-only; `lease` is only
        // the active projection.
        let transaction = connection
            .unchecked_transaction()
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO lease_history(lease_id,lease_epoch,deployment_id,instance_id,boot_id,instance_incarnation,host_fence_id,fence_token_digest,issued_at,expires_at,issued_tick,expires_tick,ttl_seconds,renewal_interval_seconds,renew_sequence,revoked)
                 SELECT lease_id,lease_epoch,deployment_id,instance_id,boot_id,instance_incarnation,host_fence_id,?1,issued_at,expires_at,issued_tick,expires_tick,ttl_seconds,renewal_interval_seconds,renew_sequence,revoked FROM lease WHERE singleton=1",
                params![digest(FIXTURE_TOKEN)],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE fence SET lease_epoch_counter=MAX(lease_epoch_counter,COALESCE((SELECT MAX(lease_epoch) FROM lease_history),0)) WHERE singleton=1",
                [],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE lease_history SET revoked=1 WHERE lease_id IN (SELECT lease_id FROM lease WHERE singleton=1)",
                [],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute("UPDATE lease SET revoked=1 WHERE singleton=1", [])
            .map_err(FixtureError::Sql)?;
        // An admitted or executing runtime operation crossed the prior host
        // boundary. The replacement cannot prove whether its effect happened,
        // so retain UNKNOWN and remove only the executable queue entry.
        transaction
            .execute(
                "UPDATE runtime_operations SET status='UNKNOWN',updated_at=?1 WHERE status IN ('ADMITTED','EXECUTING')",
                params![FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "DELETE FROM runtime_queue WHERE operation_id IN (SELECT operation_id FROM runtime_operations WHERE status='UNKNOWN')",
                [],
            )
            .map_err(FixtureError::Sql)?;
        // Legacy queue entries crossed the same process boundary. Preserve
        // their attempt identity as uncertainty; never leave them executable
        // for a replacement process with a different lease.
        transaction
            .execute(
                "UPDATE operations SET state='UNKNOWN',uncertainty_reason='authority_rotated',ticket_json=json_set(ticket_json,'$.state','UNKNOWN'),updated_at=?1 WHERE state='MAY_HAVE_BEEN_DISPATCHED'",
                params![FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "DELETE FROM queue WHERE operation_id IN (SELECT operation_id FROM operations WHERE state='UNKNOWN')",
                [],
            )
            .map_err(FixtureError::Sql)?;
        // Every process restart requires a fresh bootstrap/fence handshake;
        // retain the old fields for diagnostics but make them unusable as
        // current mutation authority.
        transaction
            .execute(
                "UPDATE fence SET authority_state='RESTART_REQUIRED' WHERE singleton=1",
                [],
            )
            .map_err(FixtureError::Sql)?;
        transaction.commit().map_err(FixtureError::Sql)?;
        validate_database_integrity(&connection)?;
        registry.insert(lock_path.clone());
        drop(registry);
        Ok(Self {
            connection,
            _lock: SidecarLock {
                file: lock,
                path: lock_path,
            },
        })
    }
}
