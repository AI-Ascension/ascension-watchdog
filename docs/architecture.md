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

The authenticated worker client is coordinated by `worker_client.rs`, which keeps
the existing entrypoint (`WorkerClient`, `WorkerClientConfig`,
`WorkerDispatchResult`, `WorkerReconcileResult`, `WorkerPhaseError`,
`WorkerPeerIdentity`) and declares cohesive `#[path]` children:
`worker_client_config.rs` owns the immutable binding, credential references and
protected-endpoint validation; `worker_client_session.rs` owns the session
lifecycle, the phase deadline and request header construction;
`worker_client_exchange.rs` owns the bounded authenticated probe, control,
dispatch, lookup and acknowledge exchanges; `worker_client_orchestration.rs`
owns the store-backed claim/dispatch and handoff reconciliation paths and their
result types; `worker_client_validation.rs` owns response, handoff and witness
validation plus the protocol/storage tuple conversions. The existing
`worker_client_auth.rs`, `worker_client_transport.rs` and
`worker_client_sealed_tests.rs` children are unchanged. Bounded transport,
worker identity binding and the persist-before-send / persist-after-terminal
`Store` updates stay in their owning module; no child re-implements a validator
or reorders persistence relative to an exchange.

Incompatible recovery interfaces must have explicit versions and digests and be
integrated with their real consumers. Frozen runtime-v3 artifacts stay frozen.
No watchdog database is shared with gateway or harness. No watchdog action
directly mutates the game or treats changed observations as settlement evidence.

All production mutations require admission validation and bounded resources.
Persistence uncertainty blocks new work; unavailable telemetry does not grant
authority or cause whole-stack restarts. Stop, pause, quarantine and completed-job
records survive every recovery path. A process identity includes creation context
and launch identity; PID or executable name alone never authorizes termination.
