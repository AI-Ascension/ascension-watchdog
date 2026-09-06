//! Owner-local durable watchdog state.
//!
//! The store is intentionally separate from gateway and harness databases.  A
//! missing path is never opened by read-only commands, and an existing but
//! malformed path is reported as corruption instead of being recreated.

use crate::config::{DesiredMode, WatchdogConfig, hex_digest};
use crate::error::{Result, WatchdogError};
use crate::policy::ComponentState;
use crate::process::ProcessIdentity;
use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::Serialize;
use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const SCHEMA_VERSION: i64 = 1;
const MAX_AUDIT_DETAIL_BYTES: usize = 16 * 1024;
const MAX_RESULT_BYTES: usize = 64 * 1024;

/// Return wall-clock milliseconds for audit records.  Scheduling uses the
/// explicit timestamp passed to policy/runtime methods instead.
#[must_use]
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Acquire the single mutating controller lock for one owner-local store.
/// The advisory lock is held by an open file descriptor and never relies on a
/// stale PID or executable name for ownership.
#[derive(Debug)]
pub struct SingletonLock {
    path: PathBuf,
    file: File,
}

impl SingletonLock {
    /// Acquire `<database>.lock` without deleting another owner's lock file.
    #[allow(clippy::suspicious_open_options)]
    pub fn acquire(database: impl AsRef<Path>) -> Result<Self> {
        let database = database.as_ref();
        let path = lock_path(database);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)?;
        file.try_lock_exclusive().map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                WatchdogError::Busy(path.clone())
            } else {
                WatchdogError::Io(error)
            }
        })?;
        Ok(Self { path, file })
    }

    /// Path of the lock file for diagnostics.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write non-authoritative diagnostic metadata.  It is never used to
    /// decide whether a process may be terminated.
    pub fn write_owner_hint(&self, hint: &str) -> Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        if hint.len() > 512 || hint.as_bytes().contains(&0) {
            return Err(WatchdogError::InvalidInput(
                "owner hint is oversized".to_string(),
            ));
        }
        let mut file = &self.file;
        file.seek(SeekFrom::Start(0))?;
        file.set_len(0)?;
        file.write_all(hint.as_bytes())?;
        file.sync_data()?;
        Ok(())
    }
}

impl Drop for SingletonLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn lock_path(database: &Path) -> PathBuf {
    let mut value = database.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

/// Durable deployment and job store.
pub struct Store {
    conn: Connection,
    path: PathBuf,
    max_jobs: u64,
    max_payload_bytes: usize,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("path", &self.path)
            .field("max_jobs", &self.max_jobs)
            .field("max_payload_bytes", &self.max_payload_bytes)
            .finish_non_exhaustive()
    }
}

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

/// A durable job row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JobRecord {
    pub id: String,
    pub kind: String,
    pub payload: Value,
    pub payload_digest: String,
    pub status: JobStatus,
    pub created_at_ms: u64,
    pub claimed_at_ms: Option<u64>,
    pub completed_at_ms: Option<u64>,
    pub attempt_count: u32,
    pub next_retry_at_ms: Option<u64>,
    pub last_error: Option<String>,
    pub result: Option<Value>,
    pub worker_id: Option<String>,
}

/// Job status transitions are persisted transactionally.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Quarantined,
}

impl JobStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Quarantined => "quarantined",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "quarantined" => Ok(Self::Quarantined),
            other => Err(WatchdogError::Conflict(format!(
                "unknown durable job status {other}"
            ))),
        }
    }
}

/// An atomic claim includes a distinct attempt identity and lineage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JobClaim {
    pub job: JobRecord,
    pub attempt_id: String,
    pub attempt_number: u32,
    pub lineage: String,
    pub claimed_by: String,
}

/// Durable completion result, including idempotent duplicate acknowledgments.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Completion {
    pub job_id: String,
    pub attempt_id: String,
    pub result: Value,
    pub already_completed: bool,
}

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

impl Store {
    /// Initialize a new database and its schema.  Existing initialized state is
    /// never overwritten.
    pub fn initialize(path: impl AsRef<Path>, config: &WatchdogConfig) -> Result<Self> {
        config.validate()?;
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
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
        let now = now_unix_ms();
        let tx = conn.transaction()?;
        insert_metadata(&tx, "schema_version", &SCHEMA_VERSION.to_string())?;
        insert_metadata(&tx, "deployment_id", &config.deployment_id)?;
        insert_metadata(&tx, "desired_mode", mode_as_str(config.desired_mode))?;
        insert_metadata(&tx, "restart_generation", "1")?;
        insert_metadata(&tx, "config_digest", &config_digest)?;
        insert_metadata(&tx, "initialized_at_ms", &now.to_string())?;
        insert_metadata(&tx, "updated_at_ms", &now.to_string())?;
        insert_audit_tx(
            &tx,
            "store_initialized",
            &format!("schema={SCHEMA_VERSION};config_digest={config_digest}"),
            now,
        )?;
        tx.commit()?;
        Ok(Self {
            conn,
            path,
            max_jobs: config.max_jobs,
            max_payload_bytes: config.max_payload_bytes,
        })
    }

    /// Open an existing initialized store.  This call never creates a missing
    /// file or applies a migration implicitly.
    pub fn open(path: impl AsRef<Path>, config: &WatchdogConfig) -> Result<Self> {
        config.validate()?;
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(WatchdogError::MissingState(path));
        }
        let conn = open_connection(&path)?;
        let version: Option<i64> = conn
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM metadata WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match version {
            Some(SCHEMA_VERSION) => {}
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
        }
        let pragmas = connection_pragmas(&conn)?;
        if !pragmas.is_wal_full() {
            return Err(WatchdogError::Conflict(format!(
                "required SQLite durability is not active: {pragmas:?}"
            )));
        }
        let stored_config_digest: Option<String> = conn
            .query_row(
                "SELECT value FROM metadata WHERE key='config_digest'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let expected_config_digest = config.digest()?;
        if stored_config_digest.as_deref() != Some(expected_config_digest.as_str()) {
            return Err(WatchdogError::Conflict(
                "configuration digest differs from initialized owner-local state; explicit migration is required"
                    .to_string(),
            ));
        }
        Ok(Self {
            conn,
            path,
            max_jobs: config.max_jobs,
            max_payload_bytes: config.max_payload_bytes,
        })
    }

    /// Open the store's SQLite connection without changing its state.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Verify WAL/FULL/foreign-key settings on this connection.
    pub fn durability(&self) -> Result<DurabilityPragmas> {
        connection_pragmas(&self.conn)
    }

    /// Run SQLite's integrity check without attempting repair.
    pub fn integrity_check(&self) -> Result<bool> {
        let result: String = self
            .conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        Ok(result.eq_ignore_ascii_case("ok"))
    }

    /// Create a consistent SQLite backup without deleting or truncating an
    /// existing destination.
    pub fn backup_to(&self, destination: impl AsRef<Path>) -> Result<()> {
        let destination = destination.as_ref();
        validate_local_storage_path(destination, "backup")?;
        if destination.exists() {
            return Err(WatchdogError::Conflict(format!(
                "backup destination already exists: {}",
                destination.display()
            )));
        }
        if let Some(parent) = destination.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        self.conn.execute(
            "VACUUM INTO ?",
            params![destination.to_string_lossy().as_ref()],
        )?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(destination)?;
        file.sync_all()?;
        Ok(())
    }

    /// Restore an owner-local backup into a new path, then establish a fresh
    /// durable generation.  The backup itself never reissues its old
    /// authority namespace.
    pub fn restore_from(
        backup: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        config: &WatchdogConfig,
    ) -> Result<Self> {
        let backup = backup.as_ref();
        let destination = destination.as_ref();
        validate_local_storage_path(backup, "backup")?;
        validate_local_storage_path(destination, "destination")?;
        if !backup.is_file() {
            return Err(WatchdogError::NotFound(format!(
                "backup {}",
                backup.display()
            )));
        }
        if destination.exists() {
            return Err(WatchdogError::Conflict(format!(
                "restore destination already exists: {}",
                destination.display()
            )));
        }
        if config.database != destination {
            return Err(WatchdogError::InvalidInput(
                "restore config database must equal destination".to_string(),
            ));
        }
        if let Some(parent) = destination.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(backup, destination)?;
        let expected_config_digest = config.digest()?;
        let mut conn = open_connection(destination)?;
        // VACUUM INTO produces a standalone database using the source's
        // journal mode.  Re-establish the watchdog's required WAL/FULL
        // contract before any caller can reopen the restored state.
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        if !connection_pragmas(&conn)?.is_wal_full() {
            return Err(WatchdogError::Conflict(
                "required SQLite durability was not established for restored state".to_string(),
            ));
        }
        let current_generation: i64 = conn.query_row(
            "SELECT CAST(value AS INTEGER) FROM metadata WHERE key='restart_generation'",
            [],
            |row| row.get(0),
        )?;
        let next_generation = current_generation
            .checked_add(1)
            .ok_or_else(|| WatchdogError::Conflict("restored generation exhausted".to_string()))?;
        let now = now_unix_ms();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        update_metadata_tx(&tx, "config_digest", &expected_config_digest)?;
        update_metadata_tx(&tx, "restart_generation", &next_generation.to_string())?;
        update_metadata_tx(&tx, "updated_at_ms", &now.to_string())?;
        insert_audit_tx(
            &tx,
            "store_restored_and_rekeyed",
            &format!("generation={next_generation}"),
            now,
        )?;
        tx.commit()?;
        drop(conn);
        Self::open(destination, config)
    }

    /// Produce a bounded status view suitable for the CLI/API.
    pub fn status(&self) -> Result<StoreStatus> {
        let deployment_id = self.metadata("deployment_id")?.unwrap_or_default();
        let desired_mode = parse_mode(&self.metadata("desired_mode")?.ok_or_else(|| {
            WatchdogError::Conflict("desired mode metadata is missing".to_string())
        })?)?;
        let schema_version = self
            .metadata("schema_version")?
            .and_then(|value| value.parse().ok())
            .unwrap_or_default();
        let restart_generation = self
            .metadata("restart_generation")?
            .and_then(|value| value.parse().ok())
            .unwrap_or_default();
        let config_digest = self.metadata("config_digest")?.unwrap_or_default();
        let approved_release_digest = self.metadata("approved_release_digest")?;
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
        let current = self
            .metadata("restart_generation")?
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or_else(|| {
                WatchdogError::Conflict("restart generation metadata is invalid".to_string())
            })?;
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

    /// Submit a bounded JSON job.  The payload digest and row are committed in
    /// one transaction, before a worker can claim it.
    pub fn submit_job(&mut self, kind: &str, payload: &Value) -> Result<JobRecord> {
        self.submit_job_at(kind, payload, now_unix_ms())
    }

    /// Timestamp-controlled job submission.
    pub fn submit_job_at(&mut self, kind: &str, payload: &Value, now_ms: u64) -> Result<JobRecord> {
        validate_name(kind, "job kind", 128)?;
        let encoded = serde_json::to_vec(payload)?;
        if encoded.len() > self.max_payload_bytes {
            return Err(WatchdogError::InvalidInput(format!(
                "job payload exceeds {} bytes",
                self.max_payload_bytes
            )));
        }
        let id = Uuid::new_v4().to_string();
        let digest = hex_digest(&encoded);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let jobs: i64 = tx.query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get(0))?;
        if u64::try_from(jobs).unwrap_or(u64::MAX) >= self.max_jobs {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "job retention bound is full".to_string(),
            ));
        }
        tx.execute(
            "INSERT INTO jobs (id, kind, payload, payload_digest, status, created_at_ms, attempt_count, next_retry_at_ms) VALUES (?, ?, ?, ?, 'queued', ?, 0, ?)",
            params![id, kind, String::from_utf8(encoded).map_err(|error| WatchdogError::InvalidInput(error.to_string()))?, digest, sqlite_timestamp(now_ms)?, sqlite_timestamp(now_ms)?],
        )?;
        insert_audit_tx(&tx, "job_submitted", &id, now_ms)?;
        tx.commit()?;
        self.get_job(&id)?
            .ok_or_else(|| WatchdogError::Conflict("job disappeared after commit".to_string()))
    }

    /// Atomically claim the oldest ready job, creating a new attempt lineage.
    /// Running rows are never silently returned to the queue after a process
    /// crash; callers must reconcile them explicitly.
    pub fn claim_next_job(&mut self, worker_id: &str, now_ms: u64) -> Result<Option<JobClaim>> {
        validate_name(worker_id, "worker id", 128)?;
        if self.desired_mode()? != DesiredMode::Running {
            return Ok(None);
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<(String, String, String, String, i64, i64, i64)> = tx
            .query_row(
                "SELECT id, kind, payload, payload_digest, created_at_ms, attempt_count, next_retry_at_ms FROM jobs WHERE status = 'queued' AND next_retry_at_ms <= ? ORDER BY created_at_ms, id LIMIT 1",
                params![sqlite_timestamp(now_ms)?],
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
            .optional()?;
        let Some((id, kind, payload_text, payload_digest, created_at, attempt_count, _next_retry)) =
            row
        else {
            tx.commit()?;
            return Ok(None);
        };
        let next_attempt = u32::try_from(attempt_count)
            .map_err(|_| WatchdogError::Conflict("job attempt counter overflow".to_string()))?
            .checked_add(1)
            .ok_or_else(|| WatchdogError::Conflict("job attempt counter exhausted".to_string()))?;
        let changed = tx.execute(
            "UPDATE jobs SET status='running', claimed_at_ms=?, worker_id=?, attempt_count=? WHERE id=? AND status='queued'",
            params![sqlite_timestamp(now_ms)?, worker_id, i64::from(next_attempt), id],
        )?;
        if changed != 1 {
            tx.rollback()?;
            return Ok(None);
        }
        let attempt_id = Uuid::new_v4().to_string();
        let lineage = format!("{id}:{next_attempt}");
        tx.execute(
            "INSERT INTO attempts (id, job_id, sequence, lineage, status, started_at_ms, worker_id) VALUES (?, ?, ?, ?, 'running', ?, ?)",
            params![attempt_id, id, i64::from(next_attempt), lineage, sqlite_timestamp(now_ms)?, worker_id],
        )?;
        insert_audit_tx(&tx, "job_claimed", &format!("{id}:{attempt_id}"), now_ms)?;
        tx.commit()?;
        let payload: Value = serde_json::from_str(&payload_text)?;
        Ok(Some(JobClaim {
            job: JobRecord {
                id,
                kind,
                payload,
                payload_digest,
                status: JobStatus::Running,
                created_at_ms: u64::try_from(created_at).unwrap_or_default(),
                claimed_at_ms: Some(now_ms),
                completed_at_ms: None,
                attempt_count: next_attempt,
                next_retry_at_ms: None,
                last_error: None,
                result: None,
                worker_id: Some(worker_id.to_string()),
            },
            attempt_id,
            attempt_number: next_attempt,
            lineage,
            claimed_by: worker_id.to_string(),
        }))
    }

    /// Atomically persist attempt completion and job completion.  Repeating a
    /// completion after a crash is idempotent only when the existing completion
    /// has the same result digest.
    pub fn complete_job(
        &mut self,
        job_id: &str,
        attempt_id: &str,
        result: &Value,
    ) -> Result<Completion> {
        self.complete_job_at(job_id, attempt_id, result, now_unix_ms())
    }

    /// Timestamp-controlled completion transaction.
    pub fn complete_job_at(
        &mut self,
        job_id: &str,
        attempt_id: &str,
        result: &Value,
        now_ms: u64,
    ) -> Result<Completion> {
        let encoded = serde_json::to_vec(result)?;
        if encoded.len() > MAX_RESULT_BYTES {
            return Err(WatchdogError::InvalidInput(format!(
                "job result exceeds {MAX_RESULT_BYTES} bytes"
            )));
        }
        let result_text = String::from_utf8(encoded.clone())
            .map_err(|error| WatchdogError::InvalidInput(error.to_string()))?;
        let digest = hex_digest(&encoded);
        let tx = self.conn.transaction()?;
        let current: Option<(String, Option<String>, Option<String>)> = tx
            .query_row(
                "SELECT status, result, completion_digest FROM jobs WHERE id=?",
                params![job_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((status, existing_result, existing_digest)) = current else {
            tx.rollback()?;
            return Err(WatchdogError::NotFound(format!("job {job_id}")));
        };
        if status == "completed" {
            let completed_attempt: Option<String> = tx
                .query_row(
                    "SELECT id FROM attempts WHERE job_id=? AND status='completed' ORDER BY sequence DESC LIMIT 1",
                    params![job_id],
                    |row| row.get(0),
                )
                .optional()?;
            if completed_attempt.as_deref() != Some(attempt_id) {
                tx.rollback()?;
                return Err(WatchdogError::Conflict(
                    "completion attempt does not match the durable completed attempt".to_string(),
                ));
            }
            if existing_digest.as_deref() == Some(digest.as_str()) {
                let parsed = existing_result
                    .as_deref()
                    .map(serde_json::from_str)
                    .transpose()?
                    .unwrap_or(Value::Null);
                tx.commit()?;
                return Ok(Completion {
                    job_id: job_id.to_string(),
                    attempt_id: attempt_id.to_string(),
                    result: parsed,
                    already_completed: true,
                });
            }
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "job is completed with a different result".to_string(),
            ));
        }
        if status != "running" {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(format!(
                "job is {status}, not running"
            )));
        }
        let attempt_status: Option<String> = tx
            .query_row(
                "SELECT status FROM attempts WHERE id=? AND job_id=?",
                params![attempt_id, job_id],
                |row| row.get(0),
            )
            .optional()?;
        if attempt_status.as_deref() != Some("running") {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "attempt is not the active running claim".to_string(),
            ));
        }
        tx.execute(
            "UPDATE attempts SET status='completed', finished_at_ms=?, outcome=? WHERE id=? AND job_id=? AND status='running'",
            params![sqlite_timestamp(now_ms)?, result_text, attempt_id, job_id],
        )?;
        tx.execute(
            "UPDATE jobs SET status='completed', completed_at_ms=?, result=?, completion_digest=?, last_error=NULL WHERE id=? AND status='running'",
            params![sqlite_timestamp(now_ms)?, serde_json::to_string(result)?, digest, job_id],
        )?;
        insert_audit_tx(
            &tx,
            "job_completed",
            &format!("{job_id}:{attempt_id}"),
            now_ms,
        )?;
        tx.commit()?;
        Ok(Completion {
            job_id: job_id.to_string(),
            attempt_id: attempt_id.to_string(),
            result: result.clone(),
            already_completed: false,
        })
    }

    /// Mark an interrupted running claim as unknown/quarantined.  This is the
    /// conservative crash boundary: a new daemon never guesses that work did
    /// not execute and never reruns it automatically.
    pub fn quarantine_interrupted_jobs(&mut self, now_ms: u64) -> Result<u64> {
        let tx = self.conn.transaction()?;
        let mut stmt = tx.prepare("SELECT id FROM jobs WHERE status='running'")?;
        let ids: Vec<String> = stmt
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        drop(stmt);
        for job_id in &ids {
            tx.execute(
                "UPDATE attempts SET status='unknown', finished_at_ms=?, outcome='daemon_interrupted' WHERE job_id=? AND status='running'",
                params![sqlite_timestamp(now_ms)?, job_id],
            )?;
            tx.execute(
                "UPDATE jobs SET status='quarantined', last_error='daemon interrupted; outcome unknown' WHERE id=? AND status='running'",
                params![job_id],
            )?;
            insert_audit_tx(&tx, "job_quarantined_after_interruption", job_id, now_ms)?;
        }
        tx.commit()?;
        Ok(u64::try_from(ids.len()).unwrap_or(u64::MAX))
    }

    /// List a bounded number of jobs for operators.
    pub fn list_jobs(&self, limit: u64) -> Result<Vec<JobRecord>> {
        let limit = limit.min(self.max_jobs).min(1_024);
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, payload, payload_digest, status, created_at_ms, claimed_at_ms, completed_at_ms, attempt_count, next_retry_at_ms, last_error, result, worker_id FROM jobs ORDER BY created_at_ms, id LIMIT ?",
        )?;
        let rows = stmt.query_map(
            params![i64::try_from(limit).unwrap_or(i64::MAX)],
            job_from_row,
        )?;
        rows.collect::<rusqlite::Result<Vec<JobRecord>>>()
            .map_err(Into::into)
    }

    /// Fetch a job without mutating state.
    pub fn get_job(&self, id: &str) -> Result<Option<JobRecord>> {
        self.conn
            .query_row(
                "SELECT id, kind, payload, payload_digest, status, created_at_ms, claimed_at_ms, completed_at_ms, attempt_count, next_retry_at_ms, last_error, result, worker_id FROM jobs WHERE id=?",
                params![id],
                job_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Record a known failure with bounded persisted retry/backoff.  The job
    /// remains quarantined once the caller's retry budget is exhausted.
    pub fn fail_job_at(
        &mut self,
        job_id: &str,
        attempt_id: &str,
        error: &str,
        retry_at_ms: Option<u64>,
        now_ms: u64,
    ) -> Result<JobStatus> {
        validate_detail(error, "job error")?;
        let tx = self.conn.transaction()?;
        let status: Option<String> = tx
            .query_row(
                "SELECT status FROM jobs WHERE id=?",
                params![job_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(status) = status else {
            tx.rollback()?;
            return Err(WatchdogError::NotFound(format!("job {job_id}")));
        };
        if status != "running" {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(format!(
                "job is {status}, not running"
            )));
        }
        let attempt_status: Option<String> = tx
            .query_row(
                "SELECT status FROM attempts WHERE id=? AND job_id=?",
                params![attempt_id, job_id],
                |row| row.get(0),
            )
            .optional()?;
        if attempt_status.as_deref() != Some("running") {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(
                "attempt is not running".to_string(),
            ));
        }
        let target = if retry_at_ms.is_some() {
            JobStatus::Queued
        } else {
            JobStatus::Quarantined
        };
        tx.execute(
            "UPDATE attempts SET status='failed', finished_at_ms=?, outcome=? WHERE id=? AND status='running'",
            params![sqlite_timestamp(now_ms)?, error, attempt_id],
        )?;
        tx.execute(
            "UPDATE jobs SET status=?, next_retry_at_ms=?, last_error=?, worker_id=NULL WHERE id=?",
            params![
                target.as_str(),
                retry_at_ms.map(sqlite_timestamp).transpose()?,
                error,
                job_id
            ],
        )?;
        insert_audit_tx(&tx, "job_failed", &format!("{job_id}:{target:?}"), now_ms)?;
        tx.commit()?;
        Ok(target)
    }

    /// Return the restart count in a rolling window without resetting it on
    /// daemon restart.
    pub fn restart_count(&self, component_id: &str, now_ms: u64, window_ms: u64) -> Result<u32> {
        let cutoff = now_ms.saturating_sub(window_ms);
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM restart_events WHERE component_id=? AND occurred_at_ms >= ?",
            params![component_id, sqlite_timestamp(cutoff)?],
            |row| row.get(0),
        )?;
        u32::try_from(count)
            .map_err(|_| WatchdogError::Conflict("restart count overflow".to_string()))
    }

    /// Record a restart decision and prune old events only after they leave the
    /// configured window.
    pub fn record_restart(
        &mut self,
        component_id: &str,
        now_ms: u64,
        window_ms: u64,
    ) -> Result<u32> {
        validate_name(component_id, "component id", 128)?;
        let cutoff = now_ms.saturating_sub(window_ms);
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM restart_events WHERE occurred_at_ms < ?",
            params![sqlite_timestamp(cutoff)?],
        )?;
        tx.execute(
            "INSERT INTO restart_events (component_id, occurred_at_ms) VALUES (?, ?)",
            params![component_id, sqlite_timestamp(now_ms)?],
        )?;
        insert_audit_tx(&tx, "component_restart_recorded", component_id, now_ms)?;
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM restart_events WHERE component_id=? AND occurred_at_ms >= ?",
            params![component_id, sqlite_timestamp(cutoff)?],
            |row| row.get(0),
        )?;
        tx.commit()?;
        u32::try_from(count)
            .map_err(|_| WatchdogError::Conflict("restart count overflow".to_string()))
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
                |row| {
                    let state: String = row.get(1)?;
                    Ok(ComponentRecord {
                        id: row.get(0)?,
                        state: component_state_parse(&state).map_err(to_sqlite_error)?,
                        launch_nonce: row.get(2)?,
                        pid: row.get::<_, Option<i64>>(3)?.and_then(|value| u32::try_from(value).ok()),
                        executable_digest: row.get(4)?,
                        started_at_ms: row.get::<_, Option<i64>>(5)?.and_then(|value| u64::try_from(value).ok()),
                        restart_attempts: u32::try_from(row.get::<_, i64>(6)?).unwrap_or_default(),
                        last_restart_at_ms: row.get::<_, Option<i64>>(7)?.and_then(|value| u64::try_from(value).ok()),
                        last_error: row.get(8)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
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
                |row| row.get(0),
            )
            .optional()?;
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

    /// Retain an audit event with a bounded detail string.
    pub fn audit(&mut self, action: &str, detail: &str, now_ms: u64) -> Result<()> {
        validate_name(action, "audit action", 128)?;
        validate_detail(detail, "audit detail")?;
        let tx = self.conn.transaction()?;
        insert_audit_tx(&tx, action, detail, now_ms)?;
        tx.commit()?;
        Ok(())
    }

    fn metadata(&self, key: &str) -> Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT value FROM metadata WHERE key=?",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    fn job_count(&self, status: JobStatus) -> Result<u64> {
        u64::try_from(self.conn.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM jobs WHERE status=?",
            params![status.as_str()],
            |row| row.get(0),
        )?)
        .map_err(|_| WatchdogError::Conflict("job count overflow".to_string()))
    }
}

fn open_connection(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_millis(750))?;
    // Foreign-key and temp-store settings are connection-local.  Opening a
    // store for `status` does not switch journal mode or create state.
    conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY;")?;
    Ok(conn)
}

fn connection_pragmas(conn: &Connection) -> Result<DurabilityPragmas> {
    let journal_mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    let synchronous: i64 = conn.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let foreign_keys: i64 = conn.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    Ok(DurabilityPragmas {
        journal_mode,
        synchronous,
        foreign_keys,
    })
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

fn validate_local_storage_path(path: &Path, name: &str) -> Result<()> {
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
            occurred_at_ms INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS restart_events_component_idx ON restart_events(component_id, occurred_at_ms);
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
    Ok(())
}

fn insert_metadata(tx: &Transaction<'_>, key: &str, value: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata (key, value) VALUES (?, ?)",
        params![key, value],
    )?;
    Ok(())
}

fn update_metadata_tx(tx: &Transaction<'_>, key: &str, value: &str) -> Result<()> {
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

fn insert_audit_tx(tx: &Transaction<'_>, action: &str, detail: &str, now_ms: u64) -> Result<()> {
    validate_name(action, "audit action", 128)?;
    validate_detail(detail, "audit detail")?;
    tx.execute(
        "INSERT INTO audit (action, detail, occurred_at_ms) VALUES (?, ?, ?)",
        params![action, detail, sqlite_timestamp(now_ms)?],
    )?;
    Ok(())
}

fn job_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobRecord> {
    let payload_text: String = row.get(2)?;
    let result_text: Option<String> = row.get(11)?;
    let status: String = row.get(4)?;
    Ok(JobRecord {
        id: row.get(0)?,
        kind: row.get(1)?,
        payload: serde_json::from_str(&payload_text).map_err(to_sqlite_error)?,
        payload_digest: row.get(3)?,
        status: JobStatus::parse(&status).map_err(to_sqlite_error)?,
        created_at_ms: row.get::<_, i64>(5)?.try_into().unwrap_or_default(),
        claimed_at_ms: row
            .get::<_, Option<i64>>(6)?
            .and_then(|v| v.try_into().ok()),
        completed_at_ms: row
            .get::<_, Option<i64>>(7)?
            .and_then(|v| v.try_into().ok()),
        attempt_count: row.get::<_, i64>(8)?.try_into().unwrap_or_default(),
        next_retry_at_ms: row
            .get::<_, Option<i64>>(9)?
            .and_then(|v| v.try_into().ok()),
        last_error: row.get(10)?,
        result: result_text
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(to_sqlite_error)?,
        worker_id: row.get(12)?,
    })
}

fn to_sqlite_error<E: std::fmt::Display>(error: E) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error.to_string(),
        )),
    )
}

fn validate_name(value: &str, name: &str, max_bytes: usize) -> Result<()> {
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

fn sqlite_timestamp(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| {
        WatchdogError::InvalidInput("timestamp exceeds SQLite integer range".to_string())
    })
}

fn validate_detail(value: &str, name: &str) -> Result<()> {
    if value.len() > MAX_AUDIT_DETAIL_BYTES || value.as_bytes().contains(&0) {
        return Err(WatchdogError::InvalidInput(format!(
            "{name} exceeds its size bound"
        )));
    }
    Ok(())
}

fn mode_as_str(mode: DesiredMode) -> &'static str {
    match mode {
        DesiredMode::Stopped => "stopped",
        DesiredMode::Paused => "paused",
        DesiredMode::Running => "running",
        DesiredMode::Draining => "draining",
    }
}

fn parse_mode(value: &str) -> Result<DesiredMode> {
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
