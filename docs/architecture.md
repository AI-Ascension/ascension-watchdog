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

The synthetic recovery fixture's runtime-v3 integration target keeps the same
shape. `crates/fault-fixture/tests/runtime.rs` stays the crate root so every
`#[test]` keeps its discovered name, and it delegates its scaffolding to child
modules under `crates/fault-fixture/tests/runtime/` (named with `#[path]`
attributes because an integration-test file is its own crate root):
`runtime/running_server.rs` owns the `RunningServer` child-process owner with
its `Drop` reaping, database cleanup and the connection/health assertions, and
`runtime/http_support.rs` owns the newline and HTTP request helpers, the
bootstrap/envelope builders and the schema assertion. The crate root
re-exports those items, so the runtime-v3 conformance assertions stay in the
test functions and no child re-implements them.

Incompatible recovery interfaces must have explicit versions and digests and be
integrated with their real consumers. Frozen runtime-v3 artifacts stay frozen.
No watchdog database is shared with gateway or harness. No watchdog action
directly mutates the game or treats changed observations as settlement evidence.

All production mutations require admission validation and bounded resources.
Persistence uncertainty blocks new work; unavailable telemetry does not grant
authority or cause whole-stack restarts. Stop, pause, quarantine and completed-job
records survive every recovery path. A process identity includes creation context
and launch identity; PID or executable name alone never authorizes termination.
