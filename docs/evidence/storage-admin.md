# Watchdog storage admission review

This note records the storage boundary delivered by the W5 operator-ledger
slice. It is source and synthetic-test evidence only; it is not proof of a
running OS service, native Windows transport, live host, gateway, or game
authority.

## Owner and path admission

`SingletonLock::acquire` resolves an absolute owner-local path, rejects a
symbolic-link or Windows reparse-point database, lock file, or existing
ancestor, and uses the canonical parent plus filename as the lock identity.
`Store::open_for_owner` and `migrate_operator_ledger_for_owner` require that
same lock. Parent directories are rechecked after creation. This is a
defense-in-depth path boundary, not a claim that path checks alone solve a
TOCTOU attack: the owner state directory and its ancestors must be protected
from untrusted writers, and callers must retain the stable owner lock for the
whole mutation admission.

Read-only SQLite opens use `SQLITE_OPEN_READ_ONLY` and never run the additive
operator migration. WAL/SHM side effects therefore remain an owner-local
filesystem concern; status and doctor must use the read-only API and supported
local storage, not a shared or untrusted mount.

## Durable operator command admission

`Store::admit_operator_command` accepts only a token-free
`OperatorCommandContext`: UUIDv4 request ID, bounded idempotency key, bounded
principal, `read`/`admin` capability class, and a lowercase SHA-256 command
fingerprint. Credentials, deadlines, and command arguments are not stored.
Read-only command kinds return `ReadOnly` without a SQL write.

For a mutating command, one owner SQLite `IMMEDIATE` transaction performs all
of the following before the API returns an accepted receipt:

1. updates desired mode when the command is a lifecycle transition;
2. inserts a sequence-ordered command receipt with request/key/principal/
   capability/fingerprint and a bounded caller-supplied redacted response;
3. inserts the corresponding audit event.

The unique request and idempotency keys reject identity reuse. A matching key
and fingerprint returns the retained receipt as `Replayed`; it does not apply
the stored desired mode again. Consequently a replayed `start` or `resume`
cannot revive `running` after a later distinct `stop` admission. A key reused
with a different fingerprint, command, principal, or capability is rejected.

The storage API intentionally does not execute the command or own transport
authentication. The root admin dispatcher must validate the credential and
command first, prepare a response that contains no credential, call this API,
then perform the external effect only for `Accepted`. `Replayed` returns the
retained response and must skip the effect. The watchdog-local retry admission
is narrower than generic command admission: it requeues only a latest known
failure with no terminal result or worker-handoff row, preserves `last_error`,
and retains the original attempt lineage.

## Bounded retention and availability tradeoff

The command ledger retains 256 normal rows and one explicit emergency-stop row;
it never evicts a key. Ordinary mutations are admitted only below 248 rows,
reserving eight rows for lifecycle commands (`start`, `resume`, `pause`, and
`drain`). A fresh `stop` may consume the single row 257 slot when the normal
bound is full, so durable stop remains available; once that slot is consumed,
all new admissions return bounded `Busy` until explicit archival/migration.
There is no fake unbounded cache and no silent replay-authority loss. This
preserves replay safety at the cost of availability after the bounded stop
reserve is also consumed.

The audit table is likewise bounded at 4096 rows plus one explicit stop-audit
slot. Ordinary audit events stop at 4088, reserving eight rows for critical
lifecycle/operator/restore events; a fresh stop can consume the one emergency
audit row at 4097. Events then stop at the hard bound rather than evicting
history. Job rows remain bounded by `WatchdogConfig::max_jobs`. A future
archival design should use an explicit sequence/tombstone protocol and retain
non-replayable terminal records before reclaiming bytes; it must not delete a
start/resume key and then accept that key as new authority.

## Verification

`crates/watchdog/tests/storage_admin.rs` covers ordered lifecycle admission,
restart and replay persistence, key/request/fingerprint/capability conflicts,
read-only zero-write behavior, bounded response rejection, lifecycle reserve
backpressure, known-failure retry and idempotent oversized-response replay,
worker-handoff exclusion, owner-only additive migration, an injected SQLite
insert fault with transaction rollback, and symlink database/lock aliases. The
focused locked test command is:

```text
cargo +1.97.1 test --locked --offline -p ascension-watchdog --test storage_admin
```
