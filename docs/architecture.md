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

Linux launch authority is coordinated by `platform/linux_launcher.rs`, a facade
that keeps the module-level framing constants and re-exports the existing
launcher API while delegating to six cohesive children:
`linux_launcher/protected_bootstrap.rs` owns `LinuxHelperBootstrap`,
`ProtectedFileIdentity`, protected path opening, parent-descriptor validation
and strict helper argument parsing;
`linux_launcher/parent_launcher.rs` owns `TrustedLinuxLauncher`,
`ParentBootstrap`, `PendingLaunch`, `LauncherStreams` and readiness/release
handling; `linux_launcher/helper_authorization.rs` owns the
`run_hidden_helper*` entry points, `authorize_after_release`,
`authorize_request` and `spawn_authorized_target`;
`linux_launcher/framed_protocol.rs` owns frame encoding/decoding and bounded
bootstrap I/O; `linux_launcher/cgroup.rs` owns cgroup v2 discovery and
membership verification; `linux_launcher/executable_snapshot.rs` owns verified
executable opening, sealed snapshot creation and bounded hashing. The facade
keeps the existing import path (`LinuxHelperBootstrap`,
`LinuxHelperAuthorization`, `LinuxHelperRequest`, `TrustedLinuxLauncher`,
`LauncherStreams`, `OutputMode`, `helper_argument`,
`helper_invocation_requested`, `protected_config_argument` and the
`run_hidden_helper*` functions), and the inline launcher tests move to
`linux_launcher/tests.rs` with unchanged names, so callers are unaffected.

Incompatible recovery interfaces must have explicit versions and digests and be
integrated with their real consumers. Frozen runtime-v3 artifacts stay frozen.
No watchdog database is shared with gateway or harness. No watchdog action
directly mutates the game or treats changed observations as settlement evidence.

All production mutations require admission validation and bounded resources.
Persistence uncertainty blocks new work; unavailable telemetry does not grant
authority or cause whole-stack restarts. Stop, pause, quarantine and completed-job
records survive every recovery path. A process identity includes creation context
and launch identity; PID or executable name alone never authorizes termination.
