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

The root-owned Linux broker stays coordinated by `platform/linux_broker.rs`.
Launch admission, exact-nonce idempotence, receipts and the versioned
inspect/stop lifecycle now live in `platform/linux_broker/broker.rs`, together
with the `UnitObservation`, `LaunchReceipt` and `BrokerLifecycleReceipt`
contracts the backend shares. The coordinator re-exports
`LinuxSystemdBroker`, `UnitObservation`, `LaunchReceipt` and
`BrokerLifecycleReceipt` (and keeps `pub(crate)` re-exports of `unit_name`,
`receipt_from` and `verify_receipt_identity`) so the socket server, native
backend, ledger and the broker tests keep their existing import paths. The
`SystemdBackend` trait stays with the coordinator because the socket server,
the bounded client and the native backend all consume it; the shared error
vocabulary, protocol bounds and the `ledger`/`descriptor_store` module
declarations also stay there. Durable admission, nonce replay, retained
containment and uncertainty are enforced only in `broker`; no child
re-implements them.

Incompatible recovery interfaces must have explicit versions and digests and be
integrated with their real consumers. Frozen runtime-v3 artifacts stay frozen.
No watchdog database is shared with gateway or harness. No watchdog action
directly mutates the game or treats changed observations as settlement evidence.

All production mutations require admission validation and bounded resources.
Persistence uncertainty blocks new work; unavailable telemetry does not grant
authority or cause whole-stack restarts. Stop, pause, quarantine and completed-job
records survive every recovery path. A process identity includes creation context
and launch identity; PID or executable name alone never authorizes termination.
