//! Owner-local backup and atomic restore publication.
//!
//! Extracted from `storage.rs` (issue #97) without behavior change: the
//! staged restore target that is published only after compatibility,
//! integrity, rekey and quarantine updates commit, the platform-specific
//! no-replace publication/retry helpers, and the `Store` backup/restore
//! entrypoints.  Publication stays fail-closed with no streaming-copy
//! fallback: the destination is never created before the complete file is
//! durable.

use super::{
    SCHEMA_VERSION, SingletonLock, Store, canonical_owner_path, config_compatibility_digest,
    connection_pragmas, ensure_owner_lock, insert_audit_tx, metadata_from_conn, now_unix_ms,
    open_connection, open_connection_with_flags, parse_metadata_i64, parse_mode, sqlite_timestamp,
    storage_admin, storage_release, update_metadata_tx, upsert_metadata_tx,
    validate_metadata_identifier,
};
use crate::config::{DesiredMode, WatchdogConfig};
use crate::error::{Result, WatchdogError};
use rusqlite::{OpenFlags, TransactionBehavior, params};
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// A newly-created restore target that is published only after all
/// compatibility, integrity, rekey, and quarantine updates have committed.
/// Dropping an uncommitted staging file removes only that fresh temporary
/// object; an existing owner-local database is never replaced or truncated.
struct RestoreStagingFile {
    path: PathBuf,
    committed: bool,
}

impl RestoreStagingFile {
    fn create(destination: &Path) -> Result<Self> {
        let parent = destination.parent().ok_or_else(|| {
            WatchdogError::InvalidInput("restore destination has no parent".to_owned())
        })?;
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
        let name = destination.file_name().ok_or_else(|| {
            WatchdogError::InvalidInput("restore destination must name a file".to_owned())
        })?;
        // A random suffix makes an attacker-selected pre-existing staging name
        // impractical while create_new preserves the no-overwrite boundary.
        for _ in 0..8 {
            let path = parent.join(format!(
                ".{}.restore-{}.tmp",
                name.to_string_lossy(),
                Uuid::new_v4()
            ));
            let mut options = OpenOptions::new();
            options.create_new(true).read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => {
                    file.sync_all()?;
                    return Ok(Self {
                        path,
                        committed: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(WatchdogError::Conflict(
            "could not reserve a unique restore staging path".to_owned(),
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn commit(mut self, destination: &Path) -> Result<()> {
        let stable = canonical_owner_path(&self.path, "restore staging")?;
        if stable != self.path {
            return Err(WatchdogError::Conflict(
                "restore staging path changed before publication".to_owned(),
            ));
        }
        #[cfg(not(windows))]
        {
            let file = OpenOptions::new().read(true).open(&self.path)?;
            file.sync_all()?;
        }
        // On Windows the SQLite connection was closed with synchronous=FULL
        // immediately before this method.  Re-opening the staging file just
        // to call `FlushFileBuffers` can itself return ERROR_ACCESS_DENIED
        // when a host scanner has a restrictive sharing handle; skipping that
        // redundant open lets the bounded publication handoff below perform
        // its no-replace link/copy fallback instead of failing before it.
        // Close the staging handle before publishing.  Windows can reject a
        // rename while any handle to the source lacks delete sharing, even
        // though the database connection itself has already been dropped.
        publish_restore_staging(&self.path, destination)?;
        self.committed = true;
        #[cfg(unix)]
        if let Some(parent) = destination.parent()
            && !parent.as_os_str().is_empty()
        {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
}

/// Publish a fully-validated restore database without widening the operation
/// into an overwrite.  Windows security software and SQLite's last shared
/// mapping can briefly retain a handle after the explicit close above.  A
/// short, bounded retry handles that local handoff race while revalidating the
/// exact staging path on every attempt; all other errors remain fail-closed.
fn publish_restore_staging(staging: &Path, destination: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        publish_restore_staging_windows(staging, destination, 200)
    }
    #[cfg(not(windows))]
    {
        fs::rename(staging, destination)?;
        Ok(())
    }
}

#[cfg(windows)]
fn publish_restore_staging_windows(
    staging: &Path,
    destination: &Path,
    attempts: usize,
) -> Result<()> {
    if attempts == 0 {
        return Err(WatchdogError::InvalidInput(
            "restore publication requires at least one attempt".to_owned(),
        ));
    }
    // Antivirus/indexer handles on hosted Windows runners can outlive the
    // SQLite close by more than a few scheduler ticks. Keep the handoff
    // bounded while allowing the ordinary local publication race to settle.
    for attempt in 0..attempts {
        match fs::rename(staging, destination) {
            Ok(()) => return Ok(()),
            Err(error) if attempt + 1 < attempts && restore_publish_retryable(&error) => {
                let stable = canonical_owner_path(staging, "restore staging")?;
                if stable != staging {
                    return Err(WatchdogError::Conflict(
                        "restore staging path changed during publication".to_owned(),
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(error) => {
                // Some Windows hosts keep the parent directory open
                // without FILE_SHARE_DELETE (for example a test
                // harness' temporary-directory guard).  In that case a
                // rename can remain denied even after every SQLite
                // handle has closed.  Try an atomic no-replace hard link,
                // which needs directory create permission but not delete
                // sharing.  There is deliberately no streaming-copy
                // fallback: creating the destination before copying
                // bytes would expose a partial database after a crash or
                // I/O failure and would violate the publication contract.
                if restore_publish_retryable(&error) {
                    let rename_error = format!(
                        "restore staging publication {} -> {}: {error}",
                        staging.display(),
                        destination.display()
                    );
                    return match fs::hard_link(staging, destination) {
                        Ok(()) => {
                            let _ = fs::remove_file(staging);
                            Ok(())
                        }
                        Err(link_error) => Err(WatchdogError::Io(std::io::Error::new(
                            link_error.kind(),
                            format!(
                                "{rename_error}; atomic no-replace hard-link publication: {link_error}"
                            ),
                        ))),
                    };
                }
                return Err(WatchdogError::Io(std::io::Error::new(
                    error.kind(),
                    format!(
                        "restore staging publication {} -> {}: {error}",
                        staging.display(),
                        destination.display()
                    ),
                )));
            }
        }
    }
    Err(WatchdogError::Conflict(
        "restore staging publication remained unavailable after 5 seconds of bounded retries"
            .to_owned(),
    ))
}

#[cfg(windows)]
fn restore_publish_retryable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::WouldBlock
    ) || matches!(error.raw_os_error(), Some(5 | 32 | 33 | 1224))
}

impl Drop for RestoreStagingFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl Store {
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
        // Materialize and validate the transformed copy away from the final
        // destination.  A failed pragma, migration, or metadata update must
        // not leave a newly-created destination that looks usable to a later
        // operator.  The final rename is the only point at which the new
        // namespace becomes addressable.
        let staging = RestoreStagingFile::create(&destination)?;
        fs::copy(&backup, staging.path()).map_err(|error| {
            WatchdogError::Io(std::io::Error::new(
                error.kind(),
                format!(
                    "restore backup copy {} -> {}: {error}",
                    backup.display(),
                    staging.path().display()
                ),
            ))
        })?;
        let stable_staging = canonical_owner_path(staging.path(), "restore staging")?;
        if stable_staging != staging.path() {
            return Err(WatchdogError::Conflict(
                "restore staging path changed while preparing copy".to_string(),
            ));
        }
        let mut conn = open_connection(staging.path()).map_err(|error| match error {
            WatchdogError::Io(error) => WatchdogError::Io(std::io::Error::new(
                error.kind(),
                format!("open restore staging {}: {error}", staging.path().display()),
            )),
            other => other,
        })?;
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
        // A rekeyed restore never carries forward release selection or a
        // prepared activation marker. The new namespace must explicitly
        // inspect and activate a release after fresh authority fencing.
        storage_release::clear_release_selection_tx(&tx)?;
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
        // Explicitly close the SQLite connection before publishing the staged
        // file.  `Drop` normally closes the connection, but on Windows the
        // SQLite WAL/shared-memory handles can outlive that destructor boundary
        // long enough for MoveFile/rename to report `ERROR_ACCESS_DENIED`.
        // `Connection::close` finalizes every statement and surfaces a busy
        // close as an error while the staging guard still removes only the
        // newly-created temporary object.
        conn.close()
            .map_err(|(_, error)| WatchdogError::Sqlite(error))?;
        let staging_path = staging.path().to_owned();
        staging.commit(&destination).map_err(|error| match error {
            WatchdogError::Io(error) => WatchdogError::Io(std::io::Error::new(
                error.kind(),
                format!(
                    "publish restore staging {}: {error}",
                    staging_path.display()
                ),
            )),
            other => other,
        })?;
        Self::open(destination, &effective_config)
    }
}

#[cfg(all(test, windows))]
mod restore_publication_tests {
    use super::publish_restore_staging_windows;
    use std::fs::{self, OpenOptions};
    use std::os::windows::fs::OpenOptionsExt;

    #[test]
    fn sharing_error_fails_closed_without_streaming_copy() {
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;

        let directory = tempfile::tempdir().expect("temporary restore directory");
        let staging = directory.path().join("restore-staging.sqlite3");
        let destination = directory.path().join("watchdog.sqlite3");
        let staging_bytes = b"fully transformed restore bytes";
        let destination_bytes = b"existing destination bytes";
        fs::write(&staging, staging_bytes).expect("staging bytes");
        fs::write(&destination, destination_bytes).expect("destination bytes");
        let destination_guard = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&destination)
            .expect("hold destination without delete sharing");

        let error = publish_restore_staging_windows(&staging, &destination, 1)
            .expect_err("sharing failure must fail closed");
        let message = error.to_string();
        assert!(
            message.contains("atomic no-replace hard-link publication")
                || message.contains("restore staging publication"),
            "unexpected publication error: {message}"
        );
        assert_eq!(
            fs::read(&destination).expect("destination remains readable"),
            destination_bytes
        );
        assert_eq!(
            fs::read(&staging).expect("staging remains available"),
            staging_bytes
        );
        drop(destination_guard);
    }
}
