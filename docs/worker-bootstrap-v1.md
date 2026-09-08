# Worker bootstrap v1

Status: approved implementation contract; transport wiring and native validation
remain unverified. Owner: watchdog. This is not a gameplay authority contract.

The harness worker reserves standard input exclusively for one startup frame.
Ordinary harness invocations retain their existing stdin behavior. The native
launcher supplies a dedicated anonymous pipe to worker stdin, never an environment
variable, command-line payload, reusable file, or the launch helper control pipe.
Linux must install the dedicated descriptor as stdin only after its existing
ready/GO handshake. Windows must explicitly inherit only approved handles and
install the pipe as stdin using its process startup handle list. Close unused
ends on every success/failure path. Never wait for EOF: read exactly one frame,
close the reader, and reject startup on a bounded deadline or any truncated frame.

Wire framing: eight ASCII bytes `ASC-WB01`, four-byte big-endian unsigned JSON
payload length, then that many UTF-8 bytes; payload length is 1..16384. JSON objects
are closed and reject duplicate fields. No credentials or provider configuration
are present. The top-level fields are exactly:

- `version`: integer 1.
- `launch_nonce`: canonical lowercase UUIDv4 of this worker launch.
- `watchdog_boot_id`: canonical lowercase UUIDv4 generated once per Supervisor.
- `component_id`: approved component identifier, 1..128 ASCII letters, digits,
  underscore, hyphen, or period; neither `.` nor `..`.
- `expected_peer`: one of the closed platform objects below.

Linux peer fields: `platform` = `linux`, `pid` (positive u32), `creation_token`
(canonical decimal string of positive /proc start ticks, at most 20 digits and
within u64), `executable` (absolute Linux path, at most 4096 UTF-8 bytes, no NUL),
`executable_sha256` (64 lowercase hexadecimal characters), `uid` and `gid` (u32).
The creation token deliberately is not the native adapter's boot-id-prefixed
fingerprint; the producer must obtain and validate the actual start ticks.

Windows peer fields: `platform` = `windows`, `pid` (positive u32),
`creation_token` (canonical positive u64 decimal Windows process creation time),
`executable` (absolute drive-rooted Windows path, at most 4096 UTF-8 bytes, no NUL),
`executable_sha256` (64 lowercase hexadecimal characters), `session_id` (u32),
and `sid` (canonical numeric SID string, at most 184 ASCII bytes).

Parsing establishes only expected policy, never an authenticated peer witness.
Before decoding any worker command, the listener verifies actual OS process
identity, held process lifetime/image identity, configured credential, and all
platform peer fields. Linux also verifies per-frame credentials. Boot IDs supplied
by a command cannot replace the bootstrap boot. The harness creates its own fresh
worker boot and persists it before opening admission. Static endpoint and secret
references remain harness-owned approved settings.

Keep this dynamic frame separate from the immutable release/config LaunchSpec
digest. Persist its SHA-256 and watchdog boot beside the launch intent before
process creation, bound to the exact component and launch nonce. Storage and
launch plumbing must preserve that binding rather than silently adding dynamic
environment entries. A new Supervisor cannot adopt a worker bound to a different
watchdog boot: retain exact cleanup ownership, stop/quarantine, and only relaunch
after confirmed cleanup and current durable desired-state authorization.

## Owner-local launch binding storage

The additive `worker_bootstrap_bindings` table stores only launch-intent identity,
extension version 1, watchdog boot UUID, and encoded-frame SHA-256. It retains no
frame bytes, credential, or executable path. `Store::bind_worker_bootstrap` validates
and encodes the frame, then atomically binds it and writes its audit entry while
durable desired mode is running and the exact component/nonce intent is prepared.
Repeating the same binding in that phase is idempotent; changing it or binding
after ownership proof has been recorded fails. Historical lookup remains read-only
after stop.

Fresh initialization creates the extension. For an older store,
`Store::migrate_worker_bootstrap` is an explicit library operation requiring its
matching singleton lock and durable stopped mode. Installation and audit commit
together, only if both table and version marker are absent. It never backfills
historical launch identities. Missing or altered installed DDL/marker fails closed;
ordinary startup and reads do not repair it. A backed-up database retains this
table with the rest of owner state; restoring it does not authorize an old boot.

This storage API is not yet wired into the launch path or an authenticated
operator migration command. Its tests therefore establish storage behavior only,
not successful worker bootstrap delivery or restart admission.

Acceptance requires bounded codec malformed/duplicate/unknown-field tests,
cross-consumer fixtures, distinct boots across Supervisor restart, binding checks,
partial-launch and unused-pipe cleanup tests, bootstrap timeout, credential and
OS-peer mismatch tests, and actual native producer-to-worker startup tests on
each claimed platform. Codec/unit success alone does not satisfy those gates.
