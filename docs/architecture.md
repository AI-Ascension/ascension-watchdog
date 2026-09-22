# Ownership and implementation contract

Classification: implemented watchdog architecture; cross-repository release
admission and native/live evidence remain pending.

The watchdog owns desired deployment mode, component supervision, job scheduling
records, operational audit, retry windows and approved release identity. Gateway
owns durable mutation authority, operation journals and game lifecycle. Harness
owns episodes, pending decisions, provider accounting and execution checkpoints.
MCP remains a thin harness-owned transport. The authoritative host fences queued
execution and supplies operation-specific effect witnesses.

Use a single Rust package with cohesive policy, storage, runtime, broker and CLI
modules initially. Pure policy consumes explicit time and observations. SQLite
WAL with synchronous FULL stores watchdog state on a local filesystem. A separate
singleton lock owns reconciliation; administrative commands transact desired mode
before process effects. Read-only status must never initialize missing state.

Owner-local storage lives in `storage.rs` and its flat sibling modules. Durable
release selection is coordinated by `storage_release.rs`, which re-exports the
selector values and delegates to three cohesive children:
`storage_release/identity.rs` owns the selector metadata key namespace, the
selector value types and the strict parsing of durable release identities;
`storage_release/transactions.rs` owns activation and rollback preparation and
completion, including the retained `prepared` recovery marker, the validated
activation receipt and the restore/rekey clearing transaction;
`storage_release/queries.rs` owns the read-only projection that status,
recovery and owner opens consume. The coordinator keeps the existing entrypoint
(`ReleaseSelection`, `ReleaseIdentity`, `PendingReleaseActivation`,
`ReleaseSelectionState`, `Store::release_selection`,
`Store::prepare_release_activation`, `Store::complete_release_activation`) so
callers, tests and the `storage.rs` re-exports are unchanged, and it names the
child files with explicit `#[path]` attributes because `storage` is itself a
`#[path]` module. Selector metadata keys and their parse rules exist only in
`identity`; no child re-implements them.

The reviewed Windows boundary in `crates/platform-windows/src/native.rs` is
being split along the same seams. Win32 resource ownership and identity
primitives are coordinated by `native.rs`, which re-exports them from the
cohesive child `native_resource_ownership.rs`: the RAII wrappers
(`OwnedHandle`, `ProtectedDirectoryHandle`, `SecurityDescriptor`) that close
kernel objects exactly once, the process creation-time and image-path identity
reads, and the UTF-16/Win32 error helpers. The public entrypoints
(`open_protected_directory`, `ProtectedDirectoryHandle`) and the shared
`pub(crate)` helpers keep their existing names, so callers in `native.rs`,
`native_current_process.rs` and `admin_pipe.rs` are unchanged. Child files use
explicit `#[path]` attributes to remain flat siblings of `native.rs`.

The owner-local worker handoff transport keeps its authentication helpers in
`worker_client_auth.rs`. That coordinator re-exports `WorkerPeerIdentity`,
`LinuxPeerSession`, `authenticate_linux_peer`, `capture_linux_controller`,
`read_credential` and `validate_credential_reference`, and delegates to three
cohesive children named with explicit `#[path]` attributes because
`worker_client.rs` declares the coordinator with `#[path]`:
`worker_client_auth/identity.rs` owns the immutable `WorkerPeerIdentity` model,
its trusted constructors and validation, and the Linux file/seal identity proof
(`LinuxFileIdentity`, `LinuxSealedImage`, `require_full_image_seals`, digest
priming); `worker_client_auth/credential.rs` owns the credential reference
check, the held-descriptor owner-only directory walk and read, the protected
filesystem allowlist and the bounded zeroizing payload;
`worker_client_auth/peer.rs` owns live Linux peer validation: controller image
capture, `pidfd`/`/proc/<pid>/exe` inspection, process birth-token probing and
bounded image hashing. Credential exposure and authority boundaries are
unchanged: the credential stays out of protocol frames and durable records and
is presented only after the peer process has been checked by the operating
system.

Incompatible recovery interfaces must have explicit versions and digests and be
integrated with their real consumers. Frozen runtime-v3 artifacts stay frozen.
No watchdog database is shared with gateway or harness. No watchdog action
directly mutates the game or treats changed observations as settlement evidence.

All production mutations require admission validation and bounded resources.
Persistence uncertainty blocks new work; unavailable telemetry does not grant
authority or cause whole-stack restarts. Stop, pause, quarantine and completed-job
records survive every recovery path. A process identity includes creation context
and launch identity; PID or executable name alone never authorizes termination.
