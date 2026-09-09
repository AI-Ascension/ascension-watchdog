//! Owner-local durable watchdog state.
//!
//! The store is intentionally separate from gateway and harness databases.  A
//! missing path is never opened by read-only commands, and an existing but
//! malformed path is reported as corruption instead of being recreated.

use crate::config::{DesiredMode, WatchdogConfig, hex_digest, validate_digest};
use crate::error::{Result, WatchdogError};
use crate::policy::ComponentState;
use crate::process::ProcessIdentity;
use fs2::FileExt;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[path = "storage_admin.rs"]
mod storage_admin;
#[path = "storage_quarantine_admin.rs"]
mod storage_quarantine_admin;
#[path = "storage_queries.rs"]
mod storage_queries;
#[path = "storage_worker_bootstrap.rs"]
mod storage_worker_bootstrap;
#[path = "storage_worker_handoff.rs"]
mod storage_worker_handoff;
pub use storage_admin::{
    MAX_OPERATOR_COMMANDS, MAX_OPERATOR_COMMANDS_WITH_STOP_RESERVE, MAX_OPERATOR_RESPONSE_BYTES,
    OPERATOR_LEDGER_SCHEMA_VERSION, OperatorCapability, OperatorCommand, OperatorCommandContext,
    OperatorCommandOutcome, OperatorCommandReceipt, RESERVED_LIFECYCLE_COMMANDS,
    RESERVED_STOP_COMMANDS, migrate_operator_ledger_for_owner,
};
pub use storage_queries::{AttemptSummary, JobSummary, JobSummaryPage};
pub use storage_worker_bootstrap::WorkerBootstrapBinding;
pub use storage_worker_handoff::{
    MAX_WORKER_WIRE_INTEGER, WORKER_HANDOFF_CONTRACT, WORKER_HANDOFF_OPERATION,
    WORKER_HANDOFF_PAYLOAD_DIGEST, WORKER_HANDOFF_SCHEMA_DIGEST, WORKER_HANDOFF_SCHEMA_VERSION,
    WorkerAcknowledgment, WorkerBinding, WorkerClaimWitness, WorkerCompletion, WorkerControlMode,
    WorkerControlWitness, WorkerHandoff, WorkerHandoffState, WorkerHandoffTuple,
    WorkerTerminalReceipt, WorkerTerminalRecord, WorkerTerminalStatus,
};

const SCHEMA_VERSION: i64 = 2;
const PREVIOUS_SCHEMA_VERSION: i64 = 1;
const MAX_AUDIT_DETAIL_BYTES: usize = 16 * 1024;
const MAX_RESULT_BYTES: usize = 64 * 1024;
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
// Reserved for the platform launch-intent adapter. Keep the bound alongside
// the storage contract until the native adapter consumes the intent proof.
#[allow(dead_code)]
const MAX_LAUNCH_PROOF_BYTES: usize = 8 * 1024;

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
    inner: Arc<LockInner>,
}

#[derive(Debug)]
struct LockInner {
    path: PathBuf,
    file: File,
    // On Windows this handle is opened with directory backup semantics and
    // without delete sharing.  Holding it keeps the owner directory from
    // being replaced while the lock file is authoritative.  The standard
    // library does not expose a stable Windows file-id accessor on the pinned
    // toolchain, so this protected-directory/handle boundary is the identity
    // check rather than an unstable MetadataExt method.
    #[cfg(windows)]
    #[allow(dead_code)]
    protected_parent: File,
}

impl Drop for LockInner {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl SingletonLock {
    /// Acquire `<database>.lock` without deleting another owner's lock file.
    #[allow(clippy::suspicious_open_options)]
    pub fn acquire(database: impl AsRef<Path>) -> Result<Self> {
        let database = canonical_owner_path(database.as_ref(), "database")?;
        let path = lock_path(&database);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        // Parent creation is itself a filesystem boundary.  Re-resolve the
        // path after it exists and reject any link/reparse substitution before
        // opening the lock file.  The owner directory must still be protected
        // from untrusted writers; path checks alone cannot close a TOCTOU race.
        let stable_database = canonical_owner_path(&database, "database")?;
        if stable_database != database {
            return Err(WatchdogError::Conflict(
                "database path changed while preparing owner lock".to_string(),
            ));
        }
        let stable_lock = canonical_owner_path(&path, "lock")?;
        if stable_lock != path {
            return Err(WatchdogError::Conflict(
                "lock path changed while preparing owner lock".to_string(),
            ));
        }
        #[cfg(windows)]
        let protected_parent = open_protected_owner_directory(database.parent())?;
        let file = open_lock_file(&path)?;
        validate_opened_lock_handle(&path, &file)?;
        file.try_lock_exclusive().map_err(|error| {
            if is_lock_contention(&error) {
                WatchdogError::Busy(path.clone())
            } else {
                WatchdogError::Io(error)
            }
        })?;
        let inner = Arc::new(LockInner {
            path: path.clone(),
            file,
            #[cfg(windows)]
            protected_parent,
        });
        if let Ok(mut registry) = lock_registry().lock() {
            registry.retain(|_, weak| weak.strong_count() > 0);
            registry.insert(path, Arc::downgrade(&inner));
        }
        Ok(Self { inner })
    }

    /// Path of the lock file for diagnostics.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.inner.path
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
        let mut file = &self.inner.file;
        file.seek(SeekFrom::Start(0))?;
        file.set_len(0)?;
        file.write_all(hint.as_bytes())?;
        file.sync_data()?;
        Ok(())
    }

    /// Reuse an already held same-process lock for a nested store bootstrap.
    /// This is private to the storage owner path; public `acquire` remains
    /// non-reentrant so a second controller still receives `Busy`.
    fn current_for_path(database: &Path) -> Option<Self> {
        let database = canonical_owner_path(database, "database").ok()?;
        let path = lock_path(&database);
        let registry = lock_registry().lock().ok()?;
        let inner = registry.get(&path)?.upgrade()?;
        Some(Self { inner })
    }
}

fn lock_registry() -> &'static Mutex<HashMap<PathBuf, Weak<LockInner>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, Weak<LockInner>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn is_lock_contention(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::WouldBlock
        || (error.raw_os_error().is_some()
            && error.raw_os_error() == fs2::lock_contended_error().raw_os_error())
}

fn lock_path(database: &Path) -> PathBuf {
    let mut value = database.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

/// Open the lock file with no delete sharing on Windows.  This is the stable
/// standard-library equivalent of the native platform wrapper's protected
/// file boundary: another process may still open the file and receive normal
/// fs2 lock contention, but it cannot unlink, rename, or replace the file
/// underneath the authoritative handle.
#[allow(clippy::suspicious_open_options)]
fn open_lock_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    Ok(options.open(path)?)
}

#[cfg(windows)]
fn open_protected_owner_directory(path: Option<&Path>) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    let path = path.ok_or_else(|| {
        WatchdogError::InvalidInput("database path has no owner-local parent".to_string())
    })?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    Ok(options.open(path)?)
}

fn ensure_owner_lock(database: &Path, owner: &SingletonLock) -> Result<()> {
    let database = canonical_owner_path(database, "database")?;
    if owner.path() != lock_path(&database) {
        return Err(WatchdogError::Unauthorized(
            "singleton lock does not match the requested database".to_string(),
        ));
    }
    Ok(())
}

/// Resolve an owner-local database path without following a link/reparse
/// component.  The final database may be absent during initialization; all
/// existing ancestors and the existing leaf are still inspected.  A missing
/// suffix is joined to the canonical nearest existing parent so equivalent
/// relative/absolute spellings use one lock identity.
fn canonical_owner_path(path: &Path, name: &str) -> Result<PathBuf> {
    validate_local_storage_path(path, name)?;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let Some(file_name) = absolute.file_name() else {
        return Err(WatchdogError::InvalidInput(format!(
            "{name} path must name a file"
        )));
    };
    reject_existing_link_components(&absolute, name)?;

    let parent = absolute.parent().ok_or_else(|| {
        WatchdogError::InvalidInput(format!("{name} path has no owner-local parent"))
    })?;
    let mut existing = parent.to_path_buf();
    let mut missing = Vec::new();
    while !existing.exists() {
        let Some(component) = existing.file_name() else {
            return Err(WatchdogError::InvalidInput(format!(
                "{name} path has no existing owner-local ancestor"
            )));
        };
        missing.push(component.to_os_string());
        if !existing.pop() {
            return Err(WatchdogError::InvalidInput(format!(
                "{name} path has no existing owner-local ancestor"
            )));
        }
    }
    let metadata = fs::symlink_metadata(&existing)?;
    reject_link_or_reparse(&metadata, name)?;
    if !metadata.is_dir() {
        return Err(WatchdogError::InvalidInput(format!(
            "{name} owner-local parent is not a directory"
        )));
    }
    let mut canonical = fs::canonicalize(&existing)?;
    for component in missing.iter().rev() {
        canonical.push(component);
    }
    canonical.push(file_name);
    // If the leaf appeared between the first inspection and canonical path
    // construction, inspect it too.  An absent leaf remains valid for init.
    if let Ok(metadata) = fs::symlink_metadata(&canonical) {
        reject_link_or_reparse(&metadata, name)?;
    }
    Ok(canonical)
}

fn reject_existing_link_components(path: &Path, name: &str) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        // A Windows drive/verbatim prefix alone is not a rooted directory.
        // Inspect it only after RootDir has completed the volume root.
        if matches!(component, std::path::Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => reject_link_or_reparse(&metadata, name)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(WatchdogError::Io(error)),
        }
    }
    Ok(())
}

fn reject_link_or_reparse(metadata: &fs::Metadata, name: &str) -> Result<()> {
    if metadata.file_type().is_symlink() || is_reparse_point(metadata) {
        return Err(WatchdogError::InvalidInput(format!(
            "{name} path contains a symbolic link or reparse point"
        )));
    }
    Ok(())
}

/// Validate the path again after opening the lock and compare its stable file
/// identity with the opened handle where the platform exposes one.  This does
/// not replace protected owner-directory permissions, but it prevents a
/// path-swap from silently turning the descriptor into a different regular
/// file between validation and lock acquisition.
fn validate_opened_lock_handle(path: &Path, file: &File) -> Result<()> {
    let path_metadata = fs::symlink_metadata(path)?;
    reject_link_or_reparse(&path_metadata, "lock")?;
    if !path_metadata.is_file() {
        return Err(WatchdogError::InvalidInput(
            "lock path is not a regular file".to_string(),
        ));
    }
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        return Err(WatchdogError::Conflict(
            "opened lock handle is no longer a regular file".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != opened_metadata.dev()
            || path_metadata.ino() != opened_metadata.ino()
        {
            return Err(WatchdogError::Conflict(
                "lock path changed after its handle was opened".to_string(),
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // `file_index`/volume identity is still unstable in Rust 1.97.1.
        // Compare the stable metadata exposed by the pinned toolchain as a
        // post-open sanity check; the no-delete sharing on both the lock file
        // and its protected parent is the stronger anti-replacement guard.
        let path_fingerprint = (
            path_metadata.file_size(),
            path_metadata.creation_time(),
            path_metadata.last_write_time(),
            path_metadata.file_attributes(),
        );
        let opened_fingerprint = (
            opened_metadata.file_size(),
            opened_metadata.creation_time(),
            opened_metadata.last_write_time(),
            opened_metadata.file_attributes(),
        );
        if path_fingerprint != opened_fingerprint {
            return Err(WatchdogError::Conflict(
                "lock path changed after its handle was opened".to_string(),
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

/// Durable deployment and job store.
pub struct Store {
    conn: Connection,
    path: PathBuf,
    max_jobs: u64,
    max_payload_bytes: usize,
    restart_clock_epoch: String,
    restart_clock_started: Instant,
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

/// Durable pre-spawn ownership admission. The platform adapter supplies the
/// closed proof after it has created the exact process/container; runtime
/// validates that proof against the immutable binding before storage records
/// it. A missing binding marks a migrated legacy row and is never inferred.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LaunchIntent {
    pub id: String,
    pub deployment_id: String,
    pub component_id: String,
    pub launch_nonce: String,
    /// The incarnation selected before the platform launch.  This is
    /// optional only for rows migrated from schema v1; those rows are legacy
    /// and must be quarantined rather than rebinding a proof to a new value.
    pub expected_incarnation: Option<String>,
    /// Digest of the complete bounded launch specification selected before
    /// the platform launch.  Secrets are never persisted; the digest binds
    /// recovery to the original request without retaining its environment.
    pub expected_launch_spec_digest: Option<String>,
    pub planned_containment_id: Option<String>,
    pub state: LaunchIntentState,
    pub ownership_proof_json: Option<Value>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

/// State machine for a durable launch intent. Only an intent with a recorded
/// opaque ownership proof may become active.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchIntentState {
    Prepared,
    ProofRecorded,
    Active,
    Cleaned,
}

#[allow(dead_code)]
impl LaunchIntentState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::ProofRecorded => "proof_recorded",
            Self::Active => "active",
            Self::Cleaned => "cleaned",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "proof_recorded" => Ok(Self::ProofRecorded),
            "active" => Ok(Self::Active),
            "cleaned" => Ok(Self::Cleaned),
            other => Err(WatchdogError::Conflict(format!(
                "unknown launch intent state {other}"
            ))),
        }
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
        Ok(Self {
            conn,
            path,
            max_jobs: config.max_jobs,
            max_payload_bytes: config.max_payload_bytes,
            restart_clock_epoch: Uuid::new_v4().to_string(),
            restart_clock_started: Instant::now(),
        })
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

    /// Hold SQLite's writer reservation while a native worker is authorized
    /// and resumed. No rows are changed. Dropping this dedicated connection
    /// rolls back the transaction and releases the reservation, so an operator
    /// Stop either commits before admission is checked or after resumption.
    #[cfg(any(windows, test))]
    pub(crate) fn reserve_worker_admission(self) -> Result<Self> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        Ok(self)
    }

    /// Admission needs at most two rows: one exact intent, or evidence of a
    /// conflicting unsettled launch. Never collect an unbounded history here.
    #[cfg(any(windows, test))]
    pub(crate) fn worker_admission_intents(&self, component: &str) -> Result<Vec<LaunchIntent>> {
        let mut statement = self.conn.prepare(
            "SELECT id, deployment_id, component_id, launch_nonce, expected_incarnation, expected_launch_spec_digest, planned_containment_id, state, ownership_proof_json, created_at_ms, updated_at_ms FROM launch_intents WHERE component_id=? AND state <> 'cleaned' LIMIT 2",
        )?;
        let rows = statement.query_map([component], launch_intent_from_row)?;
        rows.collect::<rusqlite::Result<Vec<LaunchIntent>>>()
            .map_err(Into::into)
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
        Ok(Self {
            conn,
            path,
            max_jobs: config.max_jobs,
            max_payload_bytes: config.max_payload_bytes,
            restart_clock_epoch: Uuid::new_v4().to_string(),
            restart_clock_started: Instant::now(),
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
    /// A failure after exclusive creation can leave a partial destination;
    /// retain it for diagnosis and use a new path for a subsequent attempt.
    pub fn backup_to(&self, destination: impl AsRef<Path>) -> Result<()> {
        let destination = canonical_owner_path(destination.as_ref(), "backup")?;
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
        let stable_destination = canonical_owner_path(&destination, "backup")?;
        if stable_destination != destination {
            return Err(WatchdogError::Conflict(
                "backup destination changed while preparing copy".to_string(),
            ));
        }
        // Reserve an empty destination exclusively before SQLite writes private
        // job/provider state. VACUUM INTO accepts an existing empty file. Keep
        // the handle through flush; never truncate a competing operator file.
        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Inherit the protected destination directory ACL, but disallow
            // delete/rename while SQLite opens and writes the reserved file.
            options.share_mode(0x0000_0001 | 0x0000_0002);
        }
        let file = options.open(&destination)?;
        self.conn.execute(
            "VACUUM INTO ?",
            params![destination.to_string_lossy().as_ref()],
        )?;
        file.sync_all()?;
        #[cfg(unix)]
        if let Some(parent) = destination.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    /// Restore an owner-local backup into a new path, then establish a fresh
    /// durable generation.  The compatibility entrypoint acquires the
    /// destination singleton for the full copy/admission transition.  A
    /// controller that already owns the lock should use
    /// [`Self::restore_from_for_owner`] to avoid a second OS lock attempt.
    pub fn restore_from(
        backup: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        config: &WatchdogConfig,
    ) -> Result<Self> {
        config.validate()?;
        let destination = canonical_owner_path(destination.as_ref(), "destination")?;
        let admission = match SingletonLock::current_for_path(&destination) {
            Some(lock) => lock,
            None => SingletonLock::acquire(&destination)?,
        };
        let restored = Self::restore_impl(backup.as_ref(), &destination, config)?;
        storage_admin::migrate_operator_ledger_for_owner(restored.path(), &admission)?;
        Ok(restored)
    }

    /// Restore an owner-local backup under an already-held destination lock.
    /// The resulting watchdog namespace is fresh, stopped, and conservative;
    /// this method never rekeys gateway/game leases or claims gameplay
    /// authority.
    pub fn restore_from_for_owner(
        backup: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        config: &WatchdogConfig,
        owner: &SingletonLock,
    ) -> Result<Self> {
        config.validate()?;
        let destination = canonical_owner_path(destination.as_ref(), "destination")?;
        ensure_owner_lock(&destination, owner)?;
        let restored = Self::restore_impl(backup.as_ref(), &destination, config)?;
        storage_admin::migrate_operator_ledger_for_owner(restored.path(), owner)?;
        Ok(restored)
    }

    fn restore_impl(backup: &Path, destination: &Path, config: &WatchdogConfig) -> Result<Self> {
        let backup = canonical_owner_path(backup, "backup")?;
        let destination = canonical_owner_path(destination, "destination")?;
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
        if canonical_owner_path(&config.database, "database")? != destination {
            return Err(WatchdogError::InvalidInput(
                "restore config database must equal destination".to_string(),
            ));
        }
        let source_conn = open_connection_with_flags(&backup, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let source_schema = parse_metadata_i64(
            "schema_version",
            &metadata_from_conn(&source_conn, "schema_version")?.ok_or_else(|| {
                WatchdogError::Conflict("backup schema_version metadata is missing".to_string())
            })?,
        )?;
        if source_schema != SCHEMA_VERSION {
            return Err(WatchdogError::Unsupported(format!(
                "backup schema {source_schema} requires an explicit migration"
            )));
        }
        let source_deployment =
            metadata_from_conn(&source_conn, "deployment_id")?.ok_or_else(|| {
                WatchdogError::Conflict("backup deployment_id metadata is missing".to_string())
            })?;
        validate_metadata_identifier("deployment_id", &source_deployment)?;
        let source_mode = metadata_from_conn(&source_conn, "desired_mode")?.ok_or_else(|| {
            WatchdogError::Conflict("backup desired_mode metadata is missing".to_string())
        })?;
        parse_mode(&source_mode)?;
        let source_config_digest =
            metadata_from_conn(&source_conn, "config_digest")?.ok_or_else(|| {
                WatchdogError::Conflict("backup config_digest metadata is missing".to_string())
            })?;
        crate::config::validate_digest(&source_config_digest).map_err(|message| {
            WatchdogError::Conflict(format!(
                "backup config_digest metadata is invalid: {message}"
            ))
        })?;
        let source_compat_digest = metadata_from_conn(&source_conn, "config_compat_digest")?
            .ok_or_else(|| {
                WatchdogError::Conflict(
                    "backup config_compat_digest metadata is missing".to_string(),
                )
            })?;
        crate::config::validate_digest(&source_compat_digest).map_err(|message| {
            WatchdogError::Conflict(format!(
                "backup config_compat_digest metadata is invalid: {message}"
            ))
        })?;
        let expected_compat_digest = config_compatibility_digest(config)?;
        if source_compat_digest != expected_compat_digest {
            return Err(WatchdogError::Conflict(
                "restore configuration is incompatible with the backup owner state".to_string(),
            ));
        }
        let source_integrity: String =
            source_conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if !source_integrity.eq_ignore_ascii_case("ok") {
            return Err(WatchdogError::Conflict(
                "backup integrity check did not return ok".to_string(),
            ));
        }
        let source_generation = parse_metadata_i64(
            "restart_generation",
            &metadata_from_conn(&source_conn, "restart_generation")?.ok_or_else(|| {
                WatchdogError::Conflict("backup restart_generation metadata is missing".to_string())
            })?,
        )?;
        if source_generation <= 0 {
            return Err(WatchdogError::Conflict(
                "backup restart_generation metadata must be positive".to_string(),
            ));
        }
        if let Some(approved_digest) = metadata_from_conn(&source_conn, "approved_release_digest")?
        {
            crate::config::validate_digest(&approved_digest).map_err(|message| {
                WatchdogError::Conflict(format!(
                    "backup approved_release_digest metadata is invalid: {message}"
                ))
            })?;
        }
        drop(source_conn);
        if config.deployment_id == source_deployment {
            // Do not silently generate an identity that is absent from the
            // caller's configuration.  The caller must provide an explicit
            // fresh deployment id so a restored store can never be reopened
            // accidentally under the old authority namespace.  Returning a
            // conflict before copying also leaves the destination untouched.
            return Err(WatchdogError::Conflict(
                "restore requires an explicit fresh deployment identity".to_string(),
            ));
        }
        let mut effective_config = config.clone();
        // A restore is an admission boundary, not an implicit start command.
        // Keep the effective configuration in the same stopped state as the
        // durable metadata so a later open cannot mismatch the restore
        // contract merely because the caller's input requested Running.
        effective_config.desired_mode = DesiredMode::Stopped;
        let expected_config_digest = effective_config.digest()?;
        let expected_compat_digest = config_compatibility_digest(&effective_config)?;
        if let Some(parent) = destination.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let stable_destination = canonical_owner_path(&destination, "destination")?;
        if stable_destination != destination {
            return Err(WatchdogError::Conflict(
                "restore destination changed while preparing copy".to_string(),
            ));
        }
        std::fs::copy(&backup, &destination)?;
        let mut conn = open_connection(&destination)?;
        // VACUUM INTO produces a standalone database using the source's
        // journal mode.  Re-establish the watchdog's required WAL/FULL
        // contract before any caller can reopen the restored state.
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        if !connection_pragmas(&conn)?.is_wal_full() {
            return Err(WatchdogError::Conflict(
                "required SQLite durability was not established for restored state".to_string(),
            ));
        }
        let next_generation = source_generation
            .checked_add(1)
            .ok_or_else(|| WatchdogError::Conflict("restored generation exhausted".to_string()))?;
        let now = now_unix_ms();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        update_metadata_tx(&tx, "deployment_id", &effective_config.deployment_id)?;
        update_metadata_tx(&tx, "desired_mode", "stopped")?;
        update_metadata_tx(&tx, "config_digest", &expected_config_digest)?;
        update_metadata_tx(&tx, "config_compat_digest", &expected_compat_digest)?;
        update_metadata_tx(&tx, "restart_generation", &next_generation.to_string())?;
        update_metadata_tx(&tx, "updated_at_ms", &now.to_string())?;
        tx.execute(
            "UPDATE attempts SET status='unknown', finished_at_ms=?, outcome='restored_backup_outcome_unknown' WHERE status='running'",
            params![sqlite_timestamp(now)?],
        )?;
        tx.execute(
            "UPDATE jobs SET status='quarantined', last_error='restored backup; prior job outcome requires explicit review', worker_id=NULL WHERE status IN ('queued','running','failed')",
            [],
        )?;
        tx.execute(
            "UPDATE components SET state='quarantined', last_error='restored backup; process identity requires explicit review', updated_at_ms=?",
            params![sqlite_timestamp(now)?],
        )?;
        upsert_metadata_tx(&tx, "restore_source_deployment_id", &source_deployment)?;
        insert_audit_tx(
            &tx,
            "store_restored_new_watchdog_namespace",
            &format!(
                "source_deployment={source_deployment};new_deployment={};generation={next_generation};game_authority=unchanged",
                effective_config.deployment_id
            ),
            now,
        )?;
        tx.commit()?;
        drop(conn);
        Self::open(destination, &effective_config)
    }

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
        insert_job_tx(&tx, &id, kind, &encoded, &digest, self.max_jobs, now_ms)?;
        tx.commit()?;
        self.get_job(&id)?
            .ok_or_else(|| WatchdogError::Conflict("job disappeared after commit".to_string()))
    }

    /// Atomically claim the oldest ready job, creating a new attempt lineage.
    /// Running rows are never silently returned to the queue after a process
    /// crash; callers must reconcile them explicitly.
    pub fn claim_next_job(&mut self, worker_id: &str, now_ms: u64) -> Result<Option<JobClaim>> {
        validate_name(worker_id, "worker id", 128)?;
        let payload_read_limit = self
            .max_payload_bytes
            .checked_add(1)
            .and_then(|limit| i64::try_from(limit).ok())
            .ok_or_else(|| {
                WatchdogError::InvalidInput("job payload bound exceeds SQLite range".to_owned())
            })?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let desired = metadata_from_conn(&tx, "desired_mode")?.ok_or_else(|| {
            WatchdogError::Conflict("desired mode metadata is missing".to_owned())
        })?;
        if parse_mode(&desired)? != DesiredMode::Running {
            tx.commit()?;
            return Ok(None);
        }
        // This store owns one single-instance deployment. Any running or
        // unknown attempt reserves that deployment, regardless of worker ID.
        // A replacement worker/daemon boot cannot evade unresolved history by
        // selecting a fresh name. Only explicit reconciliation/completion can
        // release this reservation; quarantine deliberately retains it.
        let unresolved_attempt: Option<String> = tx
            .query_row(
                "SELECT id FROM attempts WHERE status IN ('running','unknown') ORDER BY started_at_ms, sequence, id LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if unresolved_attempt.is_some() {
            tx.commit()?;
            return Ok(None);
        }
        let row: Option<(String, String, String, String, i64, i64, i64)> = tx
            .query_row(
                "SELECT id, kind, substr(payload, 1, ?2), payload_digest, created_at_ms, attempt_count, next_retry_at_ms FROM jobs WHERE status = 'queued' AND next_retry_at_ms <= ?1 ORDER BY created_at_ms, id LIMIT 1",
                params![sqlite_timestamp(now_ms)?, payload_read_limit],
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
        validate_name(&id, "job id", 128)?;
        validate_name(&kind, "job kind", 128)?;
        let payload =
            validate_claim_payload(&payload_text, &payload_digest, self.max_payload_bytes)?;
        let created_at_ms = u64::try_from(created_at)
            .map_err(|_| WatchdogError::Conflict("job creation timestamp is invalid".to_owned()))?;
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
        Ok(Some(JobClaim {
            job: JobRecord {
                id,
                kind,
                payload,
                payload_digest,
                status: JobStatus::Running,
                created_at_ms,
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
                |row| {
                    let state: String = row.get(1)?;
                    Ok(ComponentRecord {
                        id: row.get(0)?,
                        state: component_state_parse(&state).map_err(to_sqlite_error)?,
                        launch_nonce: row.get(2)?,
                        pid: sqlite_optional_u32(
                            row.get::<_, Option<i64>>(3)?,
                            "component pid",
                        )?,
                        executable_digest: row.get(4)?,
                        started_at_ms: sqlite_optional_u64(
                            row.get::<_, Option<i64>>(5)?,
                            "component started_at_ms",
                        )?,
                        restart_attempts: sqlite_u32(
                            row.get::<_, i64>(6)?,
                            "component restart_attempts",
                        )?,
                        last_restart_at_ms: sqlite_optional_u64(
                            row.get::<_, Option<i64>>(7)?,
                            "component last_restart_at_ms",
                        )?,
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

    /// Record the durable pre-spawn admission for one component. The caller
    /// supplies the original incarnation and a digest of the complete launch
    /// specification before creating a process. A component may have at most
    /// one non-cleaned intent, which prevents an untracked duplicate child.
    pub fn prepare_launch_intent(
        &mut self,
        component_id: &str,
        launch_nonce: &str,
        expected_incarnation: &str,
        expected_launch_spec_digest: &str,
        planned_containment_id: Option<&str>,
        now_ms: u64,
    ) -> Result<LaunchIntent> {
        validate_name(component_id, "component id", 128)?;
        validate_name(launch_nonce, "launch nonce", 128)?;
        validate_name(expected_incarnation, "expected launch incarnation", 256)?;
        validate_digest(expected_launch_spec_digest).map_err(WatchdogError::InvalidInput)?;
        if let Some(containment_id) = planned_containment_id {
            validate_name(containment_id, "planned containment id", 256)?;
        }
        let deployment_id = self.metadata("deployment_id")?.ok_or_else(|| {
            WatchdogError::Conflict("deployment_id metadata is missing".to_string())
        })?;
        validate_metadata_identifier("deployment_id", &deployment_id)?;
        let id = Uuid::new_v4().to_string();
        let now = sqlite_timestamp(now_ms)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_running_launch_intent(&tx)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT id FROM launch_intents WHERE component_id=? AND state <> 'cleaned' LIMIT 1",
                params![component_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(format!(
                "component {component_id} already has an unsettled launch intent {existing}"
            )));
        }
        tx.execute(
            "INSERT INTO launch_intents (id, deployment_id, component_id, launch_nonce, expected_incarnation, expected_launch_spec_digest, planned_containment_id, state, ownership_proof_json, created_at_ms, updated_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, 'prepared', NULL, ?, ?)",
            params![
                id,
                deployment_id,
                component_id,
                launch_nonce,
                expected_incarnation,
                expected_launch_spec_digest,
                planned_containment_id,
                now,
                now
            ],
        )?;
        insert_audit_tx(
            &tx,
            "launch_intent_prepared",
            &format!("{component_id}:{id}"),
            now_ms,
        )?;
        tx.commit()?;
        self.launch_intent(&id)?.ok_or_else(|| {
            WatchdogError::Conflict("launch intent disappeared after commit".to_string())
        })
    }

    /// Retain the bounded platform ownership proof for a bound intent. Runtime
    /// validates its typed context before calling this storage primitive; this
    /// method still rejects migrated rows with no original binding.
    pub fn record_launch_proof(
        &mut self,
        intent_id: &str,
        ownership_proof: &Value,
        now_ms: u64,
    ) -> Result<LaunchIntent> {
        validate_name(intent_id, "launch intent id", 128)?;
        if ownership_proof.is_null() {
            return Err(WatchdogError::InvalidInput(
                "launch ownership proof must not be null".to_string(),
            ));
        }
        let encoded = serde_json::to_string(ownership_proof)?;
        if encoded.len() > MAX_LAUNCH_PROOF_BYTES {
            return Err(WatchdogError::InvalidInput(
                "launch ownership proof exceeds its bound".to_string(),
            ));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state_and_binding: Option<(String, Option<String>, Option<String>)> = tx
            .query_row(
                "SELECT state, expected_incarnation, expected_launch_spec_digest FROM launch_intents WHERE id=?",
                params![intent_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((state, expected_incarnation, expected_digest)) = state_and_binding else {
            tx.rollback()?;
            return Err(WatchdogError::NotFound(format!(
                "launch intent {intent_id}"
            )));
        };
        if expected_incarnation.is_none() || expected_digest.is_none() {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(format!(
                "launch intent {intent_id} has no persisted launch binding"
            )));
        }
        if state != "prepared" {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(format!(
                "launch intent {intent_id} is {state}, not prepared"
            )));
        }
        tx.execute(
            "UPDATE launch_intents SET state='proof_recorded', ownership_proof_json=?, updated_at_ms=? WHERE id=? AND state='prepared'",
            params![encoded, sqlite_timestamp(now_ms)?, intent_id],
        )?;
        insert_audit_tx(&tx, "launch_proof_recorded", intent_id, now_ms)?;
        tx.commit()?;
        self.launch_intent(intent_id)?.ok_or_else(|| {
            WatchdogError::Conflict("launch intent disappeared after proof commit".to_string())
        })
    }

    /// Mark an intent active after the platform has created the exact child
    /// and the complete process identity has been persisted.  A proof is
    /// mandatory; no caller may promote a bare PID or a planned path.
    pub fn activate_launch_intent(&mut self, intent_id: &str, now_ms: u64) -> Result<LaunchIntent> {
        validate_name(intent_id, "launch intent id", 128)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_running_launch_intent(&tx)?;
        let state_and_proof: Option<(
            String,
            Option<String>,
            Option<String>,
            Option<String>,
        )> = tx
            .query_row(
                "SELECT state, ownership_proof_json, expected_incarnation, expected_launch_spec_digest FROM launch_intents WHERE id=?",
                params![intent_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((state, proof, expected_incarnation, expected_digest)) = state_and_proof else {
            tx.rollback()?;
            return Err(WatchdogError::NotFound(format!(
                "launch intent {intent_id}"
            )));
        };
        if expected_incarnation.is_none() || expected_digest.is_none() {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(format!(
                "launch intent {intent_id} has no persisted launch binding"
            )));
        }
        if state != "proof_recorded" || proof.is_none() {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(format!(
                "launch intent {intent_id} lacks a recorded ownership proof"
            )));
        }
        tx.execute(
            "UPDATE launch_intents SET state='active', updated_at_ms=? WHERE id=? AND state='proof_recorded'",
            params![sqlite_timestamp(now_ms)?, intent_id],
        )?;
        insert_audit_tx(&tx, "launch_intent_activated", intent_id, now_ms)?;
        tx.commit()?;
        self.launch_intent(intent_id)?.ok_or_else(|| {
            WatchdogError::Conflict("launch intent disappeared after activation".to_string())
        })
    }

    /// Mark a prepared, proof-recorded, or active intent cleaned after the
    /// designated process authority has completed exact containment cleanup.
    /// This is a durable fact only; it does not itself terminate a process.
    pub fn clean_launch_intent(&mut self, intent_id: &str, now_ms: u64) -> Result<LaunchIntent> {
        validate_name(intent_id, "launch intent id", 128)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state: Option<String> = tx
            .query_row(
                "SELECT state FROM launch_intents WHERE id=?",
                params![intent_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(state) = state else {
            tx.rollback()?;
            return Err(WatchdogError::NotFound(format!(
                "launch intent {intent_id}"
            )));
        };
        if state == "cleaned" {
            tx.commit()?;
            return self.launch_intent(intent_id)?.ok_or_else(|| {
                WatchdogError::Conflict("launch intent disappeared after cleanup".to_string())
            });
        }
        if !matches!(state.as_str(), "prepared" | "proof_recorded" | "active") {
            tx.rollback()?;
            return Err(WatchdogError::Conflict(format!(
                "launch intent {intent_id} has unknown state {state}"
            )));
        }
        tx.execute(
            "UPDATE launch_intents SET state='cleaned', updated_at_ms=? WHERE id=? AND state=?",
            params![sqlite_timestamp(now_ms)?, intent_id, state],
        )?;
        insert_audit_tx(&tx, "launch_intent_cleaned", intent_id, now_ms)?;
        tx.commit()?;
        self.launch_intent(intent_id)?.ok_or_else(|| {
            WatchdogError::Conflict("launch intent disappeared after cleanup".to_string())
        })
    }

    /// Fetch one launch intent for platform-authority reconciliation.
    pub fn launch_intent(&self, intent_id: &str) -> Result<Option<LaunchIntent>> {
        validate_name(intent_id, "launch intent id", 128)?;
        self.conn
            .query_row(
                "SELECT id, deployment_id, component_id, launch_nonce, expected_incarnation, expected_launch_spec_digest, planned_containment_id, state, ownership_proof_json, created_at_ms, updated_at_ms FROM launch_intents WHERE id=?",
                params![intent_id],
                launch_intent_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// List unsettled intents in creation order.  A replacement controller
    /// must reconcile these through the exact platform authority before any
    /// new launch is admitted.
    pub fn unsettled_launch_intents(&self) -> Result<Vec<LaunchIntent>> {
        let mut statement = self.conn.prepare(
            "SELECT id, deployment_id, component_id, launch_nonce, expected_incarnation, expected_launch_spec_digest, planned_containment_id, state, ownership_proof_json, created_at_ms, updated_at_ms FROM launch_intents WHERE state <> 'cleaned' ORDER BY created_at_ms, id",
        )?;
        let rows = statement.query_map([], launch_intent_from_row)?;
        rows.collect::<rusqlite::Result<Vec<LaunchIntent>>>()
            .map_err(Into::into)
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

    fn job_count(&self, status: JobStatus) -> Result<u64> {
        u64::try_from(self.conn.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM jobs WHERE status=?",
            params![status.as_str()],
            |row| row.get(0),
        )?)
        .map_err(|_| WatchdogError::Conflict("job count overflow".to_string()))
    }
}

/// Shared transaction primitive for worker-local and authenticated operator
/// admission. The caller owns commit so a job and its replay receipt can be
/// published atomically; neither insert is acknowledged independently.
fn insert_job_tx(
    tx: &Transaction<'_>,
    id: &str,
    kind: &str,
    encoded: &[u8],
    digest: &str,
    max_jobs: u64,
    now_ms: u64,
) -> Result<()> {
    let jobs: i64 = tx.query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get(0))?;
    if u64::try_from(jobs).unwrap_or(u64::MAX) >= max_jobs {
        return Err(WatchdogError::Conflict(
            "job retention bound is full".to_owned(),
        ));
    }
    let payload = std::str::from_utf8(encoded)
        .map_err(|error| WatchdogError::InvalidInput(error.to_string()))?;
    tx.execute(
        "INSERT INTO jobs (id, kind, payload, payload_digest, status, created_at_ms, attempt_count, next_retry_at_ms) VALUES (?, ?, ?, ?, 'queued', ?, 0, ?)",
        params![id, kind, payload, digest, sqlite_timestamp(now_ms)?, sqlite_timestamp(now_ms)?],
    )?;
    insert_audit_tx(tx, "job_submitted", id, now_ms)
}

fn open_connection(path: &Path) -> Result<Connection> {
    open_connection_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )
}

fn open_connection_with_flags(path: &Path, flags: OpenFlags) -> Result<Connection> {
    let conn = Connection::open_with_flags(path, flags)?;
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

pub(crate) fn validate_claim_payload(
    text: &str,
    expected_digest: &str,
    bound: usize,
) -> Result<Value> {
    if text.len() > bound || hex_digest(text.as_bytes()) != expected_digest {
        return Err(WatchdogError::Conflict(
            "stored job payload exceeds its bound or differs from its admission digest".to_owned(),
        ));
    }
    serde_json::from_str(text)
        .map_err(|_| WatchdogError::Conflict("stored job payload is not valid JSON".to_owned()))
}

fn require_running_launch_intent(tx: &Transaction<'_>) -> Result<()> {
    let desired = metadata_from_conn(tx, "desired_mode")?
        .ok_or_else(|| WatchdogError::Conflict("desired mode metadata is missing".to_owned()))?;
    if parse_mode(&desired)? != DesiredMode::Running {
        return Err(WatchdogError::Conflict(
            "durable desired mode does not authorize launch admission or activation".to_owned(),
        ));
    }
    Ok(())
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

pub(crate) fn metadata_from_conn(conn: &Connection, key: &str) -> Result<Option<String>> {
    conn.query_row(
        "SELECT value FROM metadata WHERE key=?",
        params![key],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

fn config_compatibility_digest(config: &WatchdogConfig) -> Result<String> {
    let mut normalized = config.clone();
    normalized.deployment_id = "watchdog-compatibility-identity".to_string();
    normalized.database = PathBuf::from("/owner-local/watchdog.sqlite3");
    normalized.desired_mode = DesiredMode::Stopped;
    normalized.digest()
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

fn upsert_metadata_tx(tx: &Transaction<'_>, key: &str, value: &str) -> Result<()> {
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

pub(crate) fn job_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobRecord> {
    let payload_text: String = row.get(2)?;
    let result_text: Option<String> = row.get(11)?;
    let status: String = row.get(4)?;
    Ok(JobRecord {
        id: row.get(0)?,
        kind: row.get(1)?,
        payload: serde_json::from_str(&payload_text).map_err(to_sqlite_error)?,
        payload_digest: row.get(3)?,
        status: JobStatus::parse(&status).map_err(to_sqlite_error)?,
        created_at_ms: sqlite_u64(row.get::<_, i64>(5)?, "job created_at_ms")?,
        claimed_at_ms: sqlite_optional_u64(row.get::<_, Option<i64>>(6)?, "job claimed_at_ms")?,
        completed_at_ms: sqlite_optional_u64(row.get::<_, Option<i64>>(7)?, "job completed_at_ms")?,
        attempt_count: sqlite_u32(row.get::<_, i64>(8)?, "job attempt_count")?,
        next_retry_at_ms: sqlite_optional_u64(
            row.get::<_, Option<i64>>(9)?,
            "job next_retry_at_ms",
        )?,
        last_error: row.get(10)?,
        result: result_text
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(to_sqlite_error)?,
        worker_id: row.get(12)?,
    })
}

fn launch_intent_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LaunchIntent> {
    let state: String = row.get(7)?;
    let expected_incarnation: Option<String> = row.get(4)?;
    let expected_launch_spec_digest: Option<String> = row.get(5)?;
    if expected_incarnation.is_some() != expected_launch_spec_digest.is_some() {
        return Err(to_sqlite_error(
            "launch intent has a partially persisted launch binding",
        ));
    }
    if let Some(incarnation) = &expected_incarnation {
        validate_name_sqlite(incarnation, "expected launch incarnation", 256)?;
    }
    if let Some(digest) = &expected_launch_spec_digest {
        validate_digest(digest).map_err(to_sqlite_error)?;
    }
    let proof_text: Option<String> = row.get(8)?;
    if proof_text
        .as_ref()
        .is_some_and(|value| value.len() > MAX_LAUNCH_PROOF_BYTES)
    {
        return Err(to_sqlite_error(
            "launch ownership proof exceeds its persisted bound",
        ));
    }
    let parsed_proof = proof_text
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(to_sqlite_error)?;
    let parsed_state = LaunchIntentState::parse(&state).map_err(to_sqlite_error)?;
    if matches!(
        parsed_state,
        LaunchIntentState::ProofRecorded | LaunchIntentState::Active
    ) && parsed_proof.is_none()
    {
        return Err(to_sqlite_error(
            "launch intent state requires a recorded ownership proof",
        ));
    }
    if matches!(parsed_state, LaunchIntentState::Prepared) && parsed_proof.is_some() {
        return Err(to_sqlite_error(
            "prepared launch intent unexpectedly contains an ownership proof",
        ));
    }
    Ok(LaunchIntent {
        id: row.get(0)?,
        deployment_id: row.get(1)?,
        component_id: row.get(2)?,
        launch_nonce: row.get(3)?,
        expected_incarnation,
        expected_launch_spec_digest,
        planned_containment_id: row.get(6)?,
        state: parsed_state,
        ownership_proof_json: parsed_proof,
        created_at_ms: sqlite_u64(row.get::<_, i64>(9)?, "launch intent created_at_ms")?,
        updated_at_ms: sqlite_u64(row.get::<_, i64>(10)?, "launch intent updated_at_ms")?,
    })
}

fn validate_name_sqlite(value: &str, field: &str, bound: usize) -> rusqlite::Result<()> {
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

fn sqlite_optional_u64(value: Option<i64>, field: &str) -> rusqlite::Result<Option<u64>> {
    value.map(|value| sqlite_u64(value, field)).transpose()
}

fn sqlite_optional_u32(value: Option<i64>, field: &str) -> rusqlite::Result<Option<u32>> {
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

fn parse_metadata_i64(key: &str, value: &str) -> Result<i64> {
    value.parse::<i64>().map_err(|_| {
        WatchdogError::Conflict(format!("{key} metadata is not a valid SQLite integer"))
    })
}

fn validate_metadata_identifier(key: &str, value: &str) -> Result<()> {
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
