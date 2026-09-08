# Watchdog worker client

This repository now contains the watchdog-side consumer for the frozen
`ascension-watchdog-worker-handoff-v1` protocol.  The client is deliberately
separate from `Supervisor`: the later runtime integration supplies a verified
current worker boot and calls the client only after the normal component probe
has established the configured process identity.

## Transport authentication proposal

The frozen JSON schema has no credential member, and adding one would change
the schema digest.  The client therefore proposes a transport-only
authentication envelope on every fresh local IPC connection:

1. On Linux it connects to the protected Unix socket, verifies the endpoint
   owner and mode, obtains `SO_PEERCRED`, pins the peer with `pidfd_open`, and
   checks the configured PID, process start token, executable path, and
   executable SHA-256.  Windows uses the existing owner/SID ACL and held
   server-process identity in `AdminPipeClient`, followed by the configured
   PID/creation timestamp, image path, and image digest checks.
2. Only after the exact peer process has passed those checks does the client
   open the credential.  Linux walks held, non-following directory descriptors
   and opens the final descriptor with `O_NONBLOCK` before validating its
   regular-file type, owner, mode, and approved local filesystem.  This closes
   ancestor and regular-file-to-FIFO replacement races; unsupported remote or
   pseudo filesystems fail closed because a synchronous regular-file read cannot
   be cancelled safely.  Windows walks and holds protected ancestors before
   reading the final owner-only handle.  Both paths reject symlinks,
   non-regular files, non-owner files, group/world permissions, whitespace,
   NUL bytes, and credentials over 4 KiB.
3. It writes one ordinary four-byte-length-prefixed transport body whose
   bytes are `ascension-worker-auth-v1\\0` followed by the credential bytes.
   The worker endpoint consumes and authenticates this body before decoding
   the next four-byte-length-prefixed JSON protocol frame.  The auth body is
   never echoed, logged, persisted, or included in a protocol digest.
4. It writes exactly one request frame and reads exactly one response frame.
   A single absolute monotonic deadline (at most 5 seconds) covers connect,
   peer authentication, credential open/validation, write, and read.  On
   Linux, credential opening and reading are also deadline-bounded and fail
   closed on unsupported filesystems.  The Windows protected-file adapter
   receives the size bound and performs the held-handle read; this portable
   client checks the deadline before and after that adapter call, while the
   adapter's synchronous file read cannot be cancelled by this layer.  The
   client opens a fresh connection for every exchange.

This envelope is intentionally a cross-consumer decision point.  A harness
endpoint must implement the same prelude, or the owner may approve an
equivalent OS-protected credential channel before wiring the runtime.  No
worker server is claimed by this repository, and no end-to-end harness
evidence is implied.

## Public client surface

`WorkerPeerIdentity::new(executable, executable_sha256, pid, creation_token)`
requires the exact supervised process PID and platform creation token in
addition to the executable identity.  `from_process_identity` accepts the
supervisor's live `ProcessIdentity` and rejects a missing creation fingerprint.
On Linux construction verifies the configured executable digest once and
retains that proof only for the exact PID/start-token/path tuple; every
exchange still rechecks the live peer credentials, PID, start token, and
path before opening the credential.
`WorkerClientConfig::new(endpoint, credential_path, binding, peer_identity)`
then binds the endpoint, dedicated credential reference, immutable
profile/release/config/schema digests, and exact process identity.
`WorkerClient::new(config, watchdog_boot_id)` creates one watchdog boot session;
`with_new_boot` allocates a canonical UUIDv4.

The public operations are `probe`, `set_control_mode`, and `lookup`.  The raw
dispatch and acknowledgment exchanges are private implementation details of
the store-backed orchestration; callers cannot send a `prepared`, terminal, or
already-marked handoff directly.  Every response validates its command,
contract/schema digest, request correlation, watchdog/worker boots, scope, and
complete tuple before returning.

`set_control_mode_and_persist` commits the matching control witness only after
the worker has acknowledged the authenticated control frame.
`claim_and_dispatch` first checks the exact configured claim witness and a
ready, non-admitting probe for that worker boot, then uses the owner-local store
in this order: claim and persist the full tuple, commit
`may_have_been_dispatched`, send exactly once, then either mark worker
admission or commit a matching terminal receipt and send/commit acknowledgment.
Transport failure leaves the durable reservation held.
`reconcile_handoff` accepts the current authenticated control witness and
performs lookup only; it never dispatches a replacement episode.  Terminal
completion and acknowledgment use the current-witness recovery storage APIs,
so a fresh worker boot can settle an older tuple without rewriting its identity
or resuming it.
