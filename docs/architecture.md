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

Operator command admission lives in `storage.rs::storage_admin.rs`, a sibling
module that re-exports the ledger values and delegates to four cohesive
children. `storage_admin/types.rs` owns the closed capability/command
vocabulary, the token-free authenticated command context, the retained
receipt/outcome types, the retention-bound constants and the bounded field
validators. `storage_admin/admission.rs` owns read-only, mutation and
job-submission admission plus the bounded read projections.
`storage_admin/receipt.rs` owns idempotency-key/request-id lookup, ledger
capacity enforcement, response validation and strict receipt-row decoding.
`storage_admin/migrations.rs` owns the owner-locked additive ledger upgrade,
the v1-to-v2 command-constraint rebuild and the strict table-shape validation.
The coordinator keeps the existing entrypoints (`OperatorCapability`,
`OperatorCommand`, `OperatorCommandContext`, `OperatorCommandReceipt`,
`OperatorCommandOutcome`, `Store::admit_operator_read`,
`Store::admit_operator_command`, `Store::admit_operator_job_submission`,
`Store::admit_operator_job_submit`, `Store::operator_command`,
`Store::list_operator_commands`, `Store::operator_command_count`,
`migrate_operator_ledger_for_owner` and the `MAX_*`/`RESERVED_*` retention
bounds) so callers, tests and the `storage.rs` re-exports are unchanged, and it
names the child files with explicit `#[path]` attributes because `storage` is
itself a `#[path]` module. Durable stop reserve, lifecycle reserve and the
replayable-receipt capacity rule live only in the type constants and the
receipt capacity check; no child re-implements them.
Cross-repository release admission lives in `source_set.rs`. The read-only
verifier is coordinated by `source_set.rs`, which keeps the existing entrypoint
(`verify_document`, `SourceSetReport`, `RepositoryReport`, `ArtifactReport`,
`ContractComparisonReport`, `digest_hex`) and delegates to five cohesive
children: `source_set/validation.rs` owns manifest schema admission plus the
shared revision, remote and digest primitives; `source_set/io.rs` owns the
bounded file reads and the Git process probe; `source_set/repository.rs` owns
repository pin and clean-worktree identity verification, including the
source-revision/artifact-only ancestry check; `source_set/artifact.rs` owns the
artifact checksum, required-file and golden-contract verification; and
`source_set/conformance.rs` owns consumer-conformance parsing and the
cross-artifact contract comparison. The coordinator keeps `verify_document` and
the shared manifest/report vocabulary, and the unit tests stay a direct
`tests` child of it so discovery names are unchanged. Fail-closed admission,
byte bounds, ancestry and remote checks exist only in these children; the
coordinator never re-implements them.
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

The Linux native broker backend in
`crates/watchdog/src/platform/linux_broker/native.rs` follows the same pattern.
`native.rs` keeps the `NativeSystemdBackend` state, inherited-containment
recovery and the public `run_native_broker` entrypoint, and delegates to flat
`#[path]` children: `native_transport.rs` (system-bus connection, manager and
property proxies, unit inspection and observation policy),
`native_queued_job.rs` (the bounded, identity-checked queued-job protocol and
`JobRemoved` decoding), `native_process_identity.rs` (boot-scoped start tokens
and exact executable/status proofs) and `native_systemd_backend.rs` (the
effectful `SystemdBackend` lifecycle, including retained-containment capture,
retirement and stop). Re-exports keep the `native::` names
(`process_start_token`, `verify_process_executable`,
`require_no_supplementary_groups`, `run_native_broker` and the queued-job types)
unchanged for `linux_broker.rs`, and the queued-job tests stay declared as
`mod queued_job_tests` so their discovery names are unchanged.

Worker handoff authentication is coordinated by `worker_client_auth.rs`, kept
as the `worker_client::auth` coordinator so the existing entrypoint
(`WorkerPeerIdentity`, `capture_linux_controller`,
`validate_credential_reference`, `read_credential`, `authenticate_linux_peer`
and `LinuxPeerSession`) is unchanged. It delegates to cohesive children, named
with explicit `#[path]` attributes because the parent `worker_client` declares
the module with `#[path]`: `worker_client_auth/models.rs` owns
`WorkerPeerIdentity` and the Linux file and sealed-image identity records it
retains; `worker_client_auth/credential.rs` owns credential-reference
validation and protected credential loading, including the held-descriptor
Linux open/validate walk and the bounded read;
`worker_client_auth/bootstrap.rs` owns capture of the controller's own
immutable image identity; `worker_client_auth/peer.rs` owns Linux peer identity
validation, the retained peer session, image hashing and process-start tokens.
Credential bytes still leave only through `ProtectedCredential::bytes`, and no
child adds a new path that exposes them.

The Windows administration transport is split across `admin_pipe.rs` and four
child modules, and the coordinator keeps every existing entrance so
`crate::admin_pipe::...` callers and tests are unchanged. `admin_pipe/win32.rs`
owns the shared Win32 pipe primitives: the unique-ownership handle and
security-descriptor wrappers, the bounded-frame, timeout and endpoint-name
validators, the polling read/write helpers with their pending-I/O
classification, the pipe-local-information query, and the SID, token,
process-image and creation-time identity queries. `admin_pipe/server.rs` owns
the fixed admin pipe instance: creation with the local-only owner/SID ACL mode,
accept and peer authentication, bounded frame reads and writes, the
outbound-drain proof, and cancel and disconnect of the exact server handle.
`admin_pipe/client.rs` owns the admin `connect` and worker `connect_worker`
entry points, the mandatory expected-server-executable binding, server
account, session and image verification against launch policy, the immutable
worker image digest guard, and the bounded request read/write and cancel paths.
`admin_pipe/protected.rs` owns the protected credential, payload and
service-config readers, the local-path and no-reparse ancestor traversal with
its retained handles, and the `ProtectedFileAcl` policy enforcement.
`MAX_ADMIN_PIPE_FRAME`, `process_user_sid`, `AdminPipeServer`, `AdminPipePeer`,
`AdminPipeClient` and the protected-file entrypoints keep their existing
visibility through coordinator re-exports, so peer identity checks, the
single-instance local-only endpoint restriction, bounded frames, cancellation
semantics, the owner/DACL requirements, bounded reads and the no-reparse
traversal are all preserved for every caller.

Runtime construction and reconciliation coordination is extracted into
`runtime/coordinator.rs`: runtime construction and `from_store`, the
owner-local singleton `acquire_lock`, the ordered `reconcile_once` pass
(persisted launch intents and identities before any new effect, the worker
binding before scheduling, durable stop/pause admission before cleanup), the
`run_until_stopped` loop and the read-only status/job facade. `runtime.rs`
keeps the `Supervisor` type and re-exports the same public entry points, so
callers, tests and the `lib.rs` re-exports are unchanged.

Persisted launch and identity recovery is extracted into
`runtime/recovery.rs`: `reconcile_persisted_launch_intents` reconstructs an
owned handle only from a proof-recorded native intent whose persisted binding
still validates, and `reconcile_persisted_identities` fences orphans left by an
earlier controller generation. Both keep the unknown-outcome handling: a legacy
or unbound intent, an uncertain containment cleanup, a failed proof binding or
an ambiguous platform authority quarantines instead of guessing, and no live
orphan is adopted into a new `Child` handle.

Component health, policy and quarantine bookkeeping is extracted into
`runtime/health.rs`: `reconcile_component`, the authenticated
`worker_heartbeat_age_ms` witness that feeds it, and the `quarantine_component`
/ `retain_quarantined_child` bookkeeping. Health and retry decisions, retained
child ownership and quarantine semantics are unchanged; missing or
unauthenticated telemetry still quarantines rather than granting restart
authority.

Start, abort and stop lifecycle is extracted into `runtime/lifecycle.rs`:
`release_start_gate`, `start_component`, `abort_launched_child` and
`stop_component`. The persisted intent and its binding still commit before any
process effect, activation is verified before a spawn is admitted, an
unverifiable launch is aborted instead of adopted, and an unconfirmed stop
leaves cleanup uncertain rather than reporting success.

Launch binding and adapter validation is extracted into
`runtime/launch_binding.rs`: `launch_spec_for`, `launch_spec_binding_digest`,
the persisted-proof decoder and validator, and the `RuntimeAdapter` boundary.
Backend, session, component and configuration binding stay checked against
trusted runtime configuration rather than a persisted proof, synthetic launches
still require an explicit opt-in, and `runtime.rs` re-exports the same public
adapter values so `lib.rs` and every `super::launch_spec_*` caller are
unchanged.

Incompatible recovery interfaces must have explicit versions and digests and be
integrated with their real consumers. Frozen runtime-v3 artifacts stay frozen.
No watchdog database is shared with gateway or harness. No watchdog action
directly mutates the game or treats changed observations as settlement evidence.

All production mutations require admission validation and bounded resources.
Persistence uncertainty blocks new work; unavailable telemetry does not grant
authority or cause whole-stack restarts. Stop, pause, quarantine and completed-job
records survive every recovery path. A process identity includes creation context
and launch identity; PID or executable name alone never authorizes termination.
