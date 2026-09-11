# Owner-local watchdog backups

The authenticated `backup` admin command creates a SQLite snapshot of the
watchdog owner store. It does not stop or pause supervised work, restore state,
rekey authority, activate a release, or contact the game, gateway, harness, or
provider.

## Invocation

Configure the local admin endpoint and admin token, then use a stable
idempotency key and a logical backup identifier:

```text
watchdog backup --config /absolute/path/watchdog.json \
  --idempotency-key backup-2026-09-07-a \
  --backup-id release-a
```

`--backup-id` is not a filesystem path. The owner loop resolves it to the
protected, fixed namespace:

```text
<database-parent>/backups/<backup-id>.sqlite3
```

Only one path component containing ASCII letters, digits, `_`, `-`, or `.` is
accepted. Traversal, separators, symlinks/reparse points, non-owner
permissions, non-regular files, and an existing destination are rejected. The
backup directory is created with owner-only permissions; the snapshot is
created with mode `0600` on Unix.

## Ordering and replay

The owner loop first commits a pending `backup` command receipt to the existing
operator ledger (`durable=false`). Only after that transaction commits does it
create the namespace and call `Store::backup_to`. The resulting file is checked
for SQLite integrity and exact `schema_version`, deployment identity,
configuration digest, compatibility digest, and approved release digest before
the ledger receipt is completed (`durable=true`). It must also contain the exact
admitted command receipt (sequence, request ID, idempotency key, principal,
capability, command, fingerprint, and backup ID). These metadata and ledger
values are inside the snapshot and bind it to the exact owner
deployment/configuration and command state that was read before the copy.

The destination is never truncated or replaced. Reusing the same idempotency
key after a timeout, owner restart, completion-write failure, or other
uncertain result verifies the existing destination and completes the original
receipt when it is an exact valid snapshot. A partial, corrupt, mismatched, or
permission-weakened destination remains in place for diagnosis and keeps the
receipt unresolved; the command does not silently retry into another file.
Reusing a backup identifier under a new command also fails rather than
overwriting the retained snapshot.

Backup admission is bounded to a 512 MiB SQLite logical database and requires
at least twice its checked `page_count * page_size` size plus 64 MiB of free
space on the owner-local volume. The logical size includes committed WAL state;
the check does not rely on the main database file's metadata length. These are
point-in-time headroom checks, not a reservation; a later disk or filesystem
failure remains an uncertain command and must be replayed with the same key
after the condition is corrected.

## Restore boundary

Restore is an offline, owner-local operation; do not run it while a daemon owns
the destination store. Supply a configuration containing a fresh deployment
identity and the destination database, then require the explicit rekey flag:

```text
watchdog restore --config /absolute/path/restored-watchdog.json \
  --backup /absolute/path/backups/release-a.sqlite3 \
  --database /absolute/path/restored/watchdog.sqlite3 --rekey
```

The command verifies the backup schema, integrity, compatibility digest and
owner-local paths before copying. It refuses an existing destination or a
configuration that reuses the backup deployment identity. The restored store
is written stopped, increments the durable generation, marks running attempts
unknown, quarantines queued/running/failed jobs and components, and reports
`blocked_until_fenced=true`. It does not restore gateway/game leases, launch a
process, activate a release, or infer that any old mutation did not execute.
After independent review, establish fresh authority and explicitly change the
desired mode through the normal authenticated admin path.
