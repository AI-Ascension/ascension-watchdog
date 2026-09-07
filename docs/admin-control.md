# Watchdog admin control (`watchdog-admin-v1`)

## Integrated lifecycle commands

Configure `admin.endpoint`, `admin.read_token_path`, and `admin.admin_token_path`
with protected local references before starting `watchdog daemon --config PATH`.
The configured daemon remains available while desired mode is stopped. Config
validation does not open credentials; the server validates and loads them at startup.

`watchdog start|pause|resume|drain|stop --config PATH --idempotency-key KEY` uses
authenticated IPC and persists intent, response, and audit before acknowledgment.
Reuse the exact key and command after an uncertain response. `status` uses the
read credential. Acknowledgment means intent accepted, not completed cleanup.

`watchdog job submit --config PATH --idempotency-key KEY --kind KIND
--payload JSON` submits a bounded watchdog-owned job through the same
authenticated queue. `--payload-file PATH` is also accepted for an absolute,
regular, owner-only file; the file is read once and its JSON is validated before
transport. The successful result contains only the durable `job_id`. The job
row, `job_submitted` audit event, operator receipt, and operator audit event are
one SQLite transaction. Reusing the exact key and payload returns the original
job ID even after completion or while stopped; changing the kind or payload is
a conflict. Submission never changes desired mode, and a stopped deployment
cannot claim the queued job until an operator separately admits running mode.
On Linux, payload files are opened through owner-anchored directory handles and
read only from the validated regular-file handle; ancestor and leaf symlinks are
rejected. Windows accepts only local absolute drive paths, rejects reparse-point
ancestors and leaves, holds the checked handles through the bounded read, and
requires the current user as owner with a protected owner-only DACL. Other Unix
targets fail closed for `--payload-file`; use inline `--payload` there instead.
Without admin configuration, direct mode writes are restricted to the explicit
synthetic-child configuration; production lifecycle commands fail closed.

Status, lifecycle, job submission/inspection, and quarantine are wired into the
real service loop.
Retry, reconciliation, restore, and release-activation dispatcher operations
remain unsupported pending integration; their transport types alone are not
operational evidence. Windows native service execution and uninstall recovery
remain unverified.

This sideband is a local operator control plane. It is an authenticated,
bounded request queue into the watchdog reconciliation loop; it is not a game
or gateway protocol. The package does not contain a gameplay dispatch,
settlement, save mutation, lease, host-fence, or arbitrary process proxy
command.

## Transport and protection

On Unix the endpoint is a Unix-domain stream socket with a four-byte
big-endian body-length prefix. The implementation accepts no TCP or wildcard
listener. The socket's direct parent must already exist, be owned by the
watchdog user, and have mode `0700`; unsafe symlink ancestors and non-sticky
world-writable ancestors are rejected. The socket is set to mode `0600` after
bind. Existing paths are never unlinked to make a bind succeed: an incumbent
returns `BUSY`.

An `EndpointGuard` captures the bound socket's `(device,inode)` identity. Drop
or explicit cleanup removes the path only when it is still that exact socket;
replacement or incumbent paths are left untouched. This prevents an old
server's cleanup from deleting a new server's endpoint.

On Windows the same contract is backed by a real local named pipe in the fixed
`\\.\pipe\ascension-watchdog-*` namespace. Each fixed worker owns one
`PIPE_TYPE_MESSAGE` instance with a bounded length-prefixed frame, protected
by a non-inheritable, protected DACL containing only the configured operator
SID and `PIPE_REJECT_REMOTE_CLIENTS`. The server captures the peer PID, session,
user SID, and executable path while the process handle is held. The client
holds the server process handle and verifies PID plus process-creation time on
each exchange; callers may additionally require an exact canonical executable
path. Partial reads/writes, cancellation, disconnect, and deadlines stay
inside the native boundary. A named-pipe namespace entry is removed by closing
the exact kernel handle; no filesystem cleanup or stale-name deletion is used.

The server receives explicit references to two owner-only token files through
`AuthReferences`: one read token and one admin token. Raw token bytes are held
only by the transport owner and are never present in status/result types,
audit details, `Debug`, or error response text. A read credential may inspect
status, jobs, attempts, and release metadata. Desired-state, quarantine,
retry, reconciliation, backup/restore, and release activation require the
admin credential. Supplying a read token with an admin claim produces
`FORBIDDEN`; an unknown or incorrect token produces `UNAUTHORIZED`.

The Windows adapter still performs token authentication in the watchdog layer:
the protected peer SID authenticates the local operator identity, while the
explicit read/admin token determines command capability. After authentication
the queue receives only a token-free `DispatchContext` containing the UUID,
idempotency key, capability, coarse principal class, and SHA-256 command
fingerprint.

## Closed command contract

Every request contains:

```json
{
  "contract": "watchdog-admin-v1",
  "request_id": "uuidv4",
  "idempotency_key": "bounded-operator-key",
  "capability": "read|admin",
  "token": "transport credential",
  "deadline_ms": 1,
  "command": { "kind": "status", "params": {} }
}
```

The command kind is one of `status`, `start`, `pause`, `resume`, `drain`,
`stop`, `jobs`, `job_submit`, `attempt`, `quarantine`, `retry`, `reconcile`,
`backup`, `restore`, `release_inspect`, or `release_activate`. Each `params` object is a
closed typed structure. Jobs and attempts return bounded summaries without
private payload/result text. Backup and restore take approved logical IDs,
not arbitrary paths; restore requires explicit `rekey: true`. Release
activation requires the exact expected SHA-256 digest.

`job_submit` has exactly `{ "kind": "...", "payload": <JSON value> }` in its
`params`; it is not a generic command proxy. Its payload is bounded by the
transport and the configured owner-local store limit, and request `Debug`
output redacts the payload. Only the admin credential may submit; the read
credential is rejected before queue admission.

`quarantine` takes `{ "attempt_id": "...", "reason": "..." }`. The owner
thread refuses a completed attempt or completed job, records a running
attempt's outcome as unknown, moves its job to the durable quarantined state,
and commits that transition with the operator receipt and audit rows. A
replayed idempotency key returns the retained response without reapplying the
transition. This is a watchdog disposition only; it does not cancel, settle,
or retry a gateway, host, provider, or gameplay operation.

Duplicate JSON member names are rejected recursively before typed decoding.
Unknown fields, unknown command kinds, invalid UUIDs, unsafe identifiers,
invalid digest values, and restore without rekey fail closed. Request and
response bodies are capped at `256 KiB`, command payloads at `64 KiB`,
deadlines at 30 seconds, clients at 16, workers at 8, queue entries at 64,
and idempotency entries at 256. Response error statuses carry no arbitrary
detail, so local paths and credentials cannot leak through the wire.

## Main-loop handoff

The integration owner creates an `AdminQueue` and `MainLoopHealth`, then starts
the server:

```text
let queue = AdminQueue::new(configured_capacity)?;
let health = MainLoopHealth::new();
let server = AdminServer::start(server_config, queue.clone(), health.clone())?;
```

The server's fixed accept/client threads only authenticate, validate, and
enqueue. They never open SQLite and never call `AdminDispatcher`. The actual
watchdog reconciliation thread must call the queue drain on every bounded
iteration:

```text
health.publish(snapshot_from_this_reconciliation_iteration)?;
let drained = queue.drain(&mut dispatcher, &health, now_ms, MAX_DRAIN_BATCH);
```

`AdminDispatcher` is implemented by the watchdog service. It is the sole
SQLite writer and must persist desired-state intent/audit before child effects.
It may map the typed admin commands to watchdog-owned store transitions, but
must reject or leave unsupported any attempt to schedule gateway-owned game
lifecycle work. It must not dispatch a gameplay action or manufacture a
settlement/effect witness. Dispatch errors are sanitized into a fixed status
enum. The queue itself preserves the idempotency record even if the client
disconnects or the response write fails.

`MainLoopHealth` is published only by the actual reconciliation loop. The I/O
thread cannot increment `heartbeat_seq`, set `ready`, or turn a responsive
socket into readiness. Heartbeat regressions are rejected, and a same-sequence
phase update cannot reset the monotonic progress age. If the health state is
poisoned, reads fail closed to `BLOCKED`/not-ready. Status responses therefore
expose the last genuine loop progress snapshot, including phase, progress age,
deadline, queue age, pending operation count, incarnation, and lease remaining
time.

## Idempotency and deadlines

`idempotency_key` identifies one logical command. The cache fingerprint covers
the contract, claimed capability, and typed command (including a job's kind and
payload) but deliberately excludes credentials, request UUID, and transport
deadline. A same-key/same-command retry returns the retained response without a
second dispatch; a same-key different-command or job-payload retry returns
`CONFLICT`. A request already queued returns
`IN_PROGRESS`. Queue-full returns `BUSY` and releases the pending cache slot.

The operator ledger is at schema v2. Opening an owner-held v1 store performs a
transactional constrained-table migration that preserves every receipt,
idempotency key, sequence, and stop record before `job_submit` is enabled. A
marker/table mismatch or a missing ledger with an existing marker fails closed;
read-only status and doctor paths never run this migration.

If the caller's deadline expires while queued, the main loop records a
`TIMEOUT` response without invoking the dispatcher. If the transport caller
times out first, the queued item is not silently cancelled: the main loop
still decides it once and caches the resulting response. This is necessary to
avoid a client reconnect causing a second durable stop/pause/recovery action.

## Root integration requirements

The root service owns the following integration points:

1. Add `pub mod admin;` and include the package's source files. On Unix, add
   the direct `rustix = { version = "1.1.4", features = ["fs", "process"] }`
   dependency for process-effective-UID checks; do not infer the current UID
   from the service's current working directory. Windows uses the isolated
   `ascension-platform-windows` dependency for named pipes and ACL checks.
2. Construct the queue/server only while the service owns the existing
   singleton reconciliation lock. `Supervisor` (or its service loop) is the
   `AdminDispatcher`; the IPC thread must never open or write the Store.
3. Publish `MainLoopHealth` from real reconciliation progress and drain the
   queue from that same loop. Mark `ready` only after store validation and
   ordinary startup invariants are complete.
4. Route `start`, `pause`, `resume`, `drain`, and `stop` through the queue so
   durable desired intent is acknowledged before child termination/launch.
   A failed response write does not roll back the committed intent.
5. Route jobs/attempt/reconcile/backup/restore/release operations through
   owner-approved store/release APIs. Do not expose job payload/result text or
   local paths in `StatusView`, audits, or errors. Historical/release reads
   remain read-only and cannot rekey or activate authority.
6. Keep existing read-only CLI status side-effect free. Offline init/migrate
   commands must take the existing singleton lock before changing state and
   must not delete an incumbent socket or database.
7. Add native Unix subprocess/socket tests for capability misuse,
   unauthorized credentials, duplicate/unknown fields, oversized frames,
   queue full, exact cleanup/incumbent preservation, main-loop-only reply,
   idempotent duplicate, and stop/pause durable acknowledgement. Add a
   separate P2 Windows named-pipe acceptance lane; do not label Unix evidence
   as Windows or live-host evidence.
