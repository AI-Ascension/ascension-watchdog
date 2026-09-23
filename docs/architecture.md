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

Runtime process ownership is coordinated by `runtime_process.rs`. The Linux
broker protocol seam is delegated to one cohesive child,
`runtime_process/broker.rs`, which owns broker request identity validation and
construction, the versioned planned-containment encoding and its two decoders,
unit-name derivation, the broker error mapping and the receipt correlation and
binding verification (`verify_broker_receipt`, `verify_broker_receipt_request`,
`verify_broker_receipt_against_proof`, `verify_broker_receipt_binding`). The
coordinator re-exports every helper its dispatch, recovery and regression tests
still call so callers, tests and the `runtime.rs` imports are unchanged, and it
names the child file with an explicit `#[path]` attribute because `runtime` is
itself a `#[path]` module. There is exactly one request encoder/decoder pair and
one receipt verifier; the coordinator never re-implements either.


Runtime process ownership is coordinated by `runtime_process.rs`. The
supervision facade is delegated to one cohesive child,
`runtime_process/facade.rs`, which owns the `RuntimeProcessManager` entrypoint,
the `RuntimeChild` handle and its synthetic/native variants, the
`RuntimeObservation`, `RuntimeStopOutcome` and `RuntimeLaunchError` vocabulary
and the cleanup-uncertain classification applied when a native launch cannot
prove its identity. The coordinator re-exports `RuntimeChild`,
`RuntimeLaunchError`, `RuntimeObservation`, `RuntimeProcessManager` and
`RuntimeStopOutcome` so `runtime.rs`, the sibling runtime modules and the
existing regression tests are unchanged, and it names the child file with an
explicit `#[path]` attribute because `runtime` is itself a `#[path]` module.
The facade owns no platform authority: every native effect goes through the
coordinator's `NativeBackend` dispatch, which stays in the entry file together
with the shared proof-size bound and native timeouts.


Runtime process ownership is coordinated by `runtime_process.rs`. Native
backend dispatch and its platform conversions are delegated to one cohesive
child, `runtime_process/native_backend.rs`, which owns the `NativeBackend` enum
and its create/launch/reopen/inspect/stop/force-cleanup implementation over the
Linux adapter, the Linux broker client and the Windows job backend, the
`NativeChild` handle and its retained broker receipt, and the platform
observation/stop/error conversions (`map_platform_observation`,
`map_stop_outcome`, `map_adapter_error`, `map_windows_error`,
`windows_component_kind`, `windows_launch_spec`, `windows_process_identity`).
The coordinator imports `NativeBackend`, `NativeChild` and `map_adapter_error`
back so its facade, recovery path and regression tests are unchanged, and it
names the child file with an explicit `#[path]` attribute because `runtime` is
itself a `#[path]` module. Broker request/receipt binding and the shared
containment policy stay in the coordinator; the child only dispatches behind
the existing platform adapters and never widens containment.

The reviewed Windows boundary in `crates/platform-windows/src/native.rs` is
being split along the same seams. Executable integrity and bounded hashing are
coordinated by `native.rs`, which re-exports them from the cohesive child
`native_integrity.rs`: the retained immutable-image guard (`IntegrityGuards`),
the kernel file identity captured from the hashed handle (`FileIdentity`), the
no-write/no-delete reopen path used by the launch barrier, the bounded
immutable-file SHA-256 (`hash_immutable_file`, `Sha256`, `MAX_HASH_BYTES`,
`HASH_READ_BYTES`) and `check_image_deadline`. The public `executable_sha256`
entrypoint and the shared `pub(crate)` helpers keep their existing names, so
callers in `native.rs`, `native_current_process.rs` and `admin_pipe.rs` are
unchanged. Child files use explicit `#[path]` attributes to remain flat
siblings of `native.rs`.

The reviewed Windows boundary in `crates/platform-windows/src/native.rs` is
being split along the same seams. Job containment and process lifecycle are
coordinated by `native.rs`, which re-exports them from the cohesive child
`native_job.rs`: the `JobOwnedProcess` owner, `create_job` with an owner-only
security descriptor, the exact process/job limit queries and verification,
prepared-job recovery (`open_planned_job`), the bounded
`terminate_job_and_wait` stop path and its `StopOutcome`, and the nonce-bound
`job_name`/`planned_job_nonce` helpers with their `JOB_NAME_PREFIX`/
`PLANNED_JOB_PREFIX` constants. The public `JobOwnedProcess`/`StopOutcome`
entrypoints and the shared `pub(crate)` helpers keep their existing names, so
callers in `native.rs` and the `watchdog` runtime are unchanged. Child files
use explicit `#[path]` attributes to remain flat siblings of `native.rs`.

The reviewed Windows boundary in `crates/platform-windows/src/native.rs` is
being split along the same seams. The lifecycle named-pipe transport is
coordinated by `native.rs`, which re-exports it from the cohesive child
`native_named_pipe.rs`: the peer identity captured from the local pipe
(`NamedPipePeer`), the owner-only one-instance server (`NamedPipeServer`), the
configured executable/session authentication and durable epoch/nonce replay
window (`create_for_config`, `configure_replay_policy`,
`authenticate_configured_peer`), the bounded length-prefixed message poll
reader/writer (`read_frame`/`read_request`, `write_frame`/`write_request`) and
the cancel/disconnect reset path. The public transport entrypoints keep their
existing names, and the owner-only ACL, fixed local pipe namespace,
remote-client rejection and replay-window monotonicity are unchanged. Child
files use explicit `#[path]` attributes to remain flat siblings of
`native.rs`.

The reviewed Windows boundary in `crates/platform-windows/src/native.rs` is
being split along the same seams. Service installation, binding and runtime are
coordinated by `native.rs`, which re-exports them from the cohesive child
`native_service.rs`: the idempotent least-privilege `ServiceInstallPlan`
(`install_as`, `install_as_with_config`, `uninstall`), the opaque
`ServiceBinding` and `StoppedServiceWitness` used by the uninstall path, the
bounded `ScmHealthChecker`, and the readiness-gated `ServiceRuntime`
(`run`, `run_with_readiness`) with `bind_installed_service`,
`stop_bound_service` and `delete_bound_stopped_service`. The public service
entrypoints keep their existing names, and the fixed service name, the refusal
of the legacy `LocalSystem` installer and the canonical command-line/config
revalidation before stop and delete are unchanged. Child files use explicit
`#[path]` attributes to remain flat siblings of `native.rs`.

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

The restricted process adapter is coordinated by `process.rs`, which keeps the
existing entrypoints (`ProcessIdentity`, `OwnedChild`, `OutputSnapshot`,
`ProcessSpawnError`, `ensure_identity`) and delegates to cohesive children:
`process/validation.rs` owns the fail-closed pre-spawn validation of one
approved component specification; `process/spawn_error.rs` owns the
spawn-failure classification, including the retained `CleanupUncertain`
outcome; `process/identity.rs` owns the launch identity, its validation and the
executable-digest and creation-fingerprint helpers; `process/observation.rs`
owns non-reaping child observation, the exact group signal and the bounded
process-group membership proof; `process/output.rs` owns bounded diagnostic
output capture; and `process/child.rs` owns `OwnedChild`, its process-group
authority, the spawn path and the stop/reap/`Drop` cleanup paths. Every module
is below the 1,000-line target, so no exception has to be documented. The
functional acceptance tests remain at `process::tests` so test discovery and
test names are unchanged.
The host lease-control conformance target is coordinated the same way.
`crates/fault-fixture/tests/host_lease_schema/main.rs` keeps the eight
root-level `#[test]` functions so discovery is unchanged, and delegates to
`support.rs` (bounded artifact loading, closed-object accessors, canonical
encoding), `time.rs` (strict UTC parsing and wall/monotonic deadline
arithmetic), `validators.rs` (grant and acknowledgment shape/semantic rules),
`frame.rs` (frame validation and the canonical grant-digest rule),
`reference_host.rs` (the stateful lifecycle reference host) and `strict.rs`
(duplicate-member rejection). `support` is the only owner of the artifact root,
digest, UUID and canonical-JSON helpers; no child re-implements them.

The authenticated admin wire contract lives in `admin/protocol.rs` and its
cohesive children. The coordinator keeps the `MAX_*` bounds and re-exports every
public item so `admin::protocol` remains the single entrypoint:
`admin/protocol/identity.rs` owns the capability, principal-class and
command-name identity; `admin/protocol/commands.rs` owns the closed command
payloads (`AdminCommand`, the retry/backup/quarantine/reconcile/release/restore
requests, `JobFilter`, `JobsRequest`, `JobSubmitRequest` and `EmptyParams`);
`admin/protocol/request.rs` owns the authenticated request envelope and
`DispatchContext`; `admin/protocol/views.rs` owns the bounded wire views;
`admin/protocol/response.rs` owns the response envelope and the dispatcher
contract; `admin/protocol/duplicate.rs` owns strict duplicate-member rejection
applied before typed deserialization; and `admin/protocol/validation.rs` owns the
bounded validation helpers. No wire contract, error semantic, input bound or
caller changes.
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
The opt-in real-harness scope ownership test support lives in
`tests/support/real_harness_worker_scope.rs` and its cohesive children. The
coordinator keeps the shared bound constants and re-exports every value the test
crate consumes, so the entrypoint and its `real_harness_worker_scope_tests.rs`
child are unchanged: `real_harness_worker_scope/properties.rs` owns the pure
systemd property parsing and proof validation; `.../paths.rs` owns canonical
file identity and digests; `.../commands.rs` owns bounded helper execution and
the retained launcher child handles; `.../cgroup.rs` owns the retained
cgroup-v2 directory/events handles and device/inode identity checks;
`.../evidence.rs` owns the durable proof writer; and `.../owner.rs` owns scope
admission, live-property verification and durable stop ownership. Because this
file is itself included through a `#[path]` module declaration, the children are
named with explicit `#[path]` attributes so nested-module lookup stays relative
to this file's directory. No proof semantic, identity/authorization check,
bound or caller changes.
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

The linux broker unit tests in
`crates/watchdog/src/platform/linux_broker/tests.rs` keep the same shape. The
coordinator retains every `#[test]` so discovery names stay
`platform::linux_broker::tests::*`, and it delegates the fixture scaffolding to
two cohesive children: `linux_broker/fake_backend.rs` owns the in-memory
`FakeBackend` and its `SystemdBackend`/`QueuedJobBackend` implementations, and
`linux_broker/fixtures.rs` owns the policy, request, credential, observation and
protected-temporary-directory builders. The coordinator re-exports those
fixtures (and the `retirement`, `failed_launch_cleanup` and `orphan_cleanup`
test modules) so the sibling test modules and
`bootstrap_transport_tests.rs` keep their existing imports; the extracted items
carry the same effective linux-broker visibility as before. Lifecycle,
refusal/uncertainty and conformance assertions exist only in the test modules;
no child re-implements them.
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
The reviewed Windows boundary in `crates/platform-windows/src/native.rs` is
being split along the same seams. Suspended launch and bootstrap handoff are
coordinated by `native.rs`, which re-exports them from the cohesive child
`native_launch.rs`: the `WindowsProcessLauncher` facade, the suspended
`CreateProcess` path (`spawn_suspended_with_job`) that assigns the exact named
Job Object through `PROC_THREAD_ATTRIBUTE_JOB_LIST` before `ResumeThread`, the
inheritable-handle list and bootstrap pipe handoff (`LaunchBootstrap`,
`BootstrapPipe`, `write_bootstrap`), the post-creation cleanup classification
(`WindowsLaunchError`, `SpawnFailure`, `classify_spawn_cleanup`) that keeps a
possibly-owned Job authoritative, the session/token selection
(`select_active_session`, `ActiveSession`, `query_user_token`,
`current_process_session`) and the process-creation material (`command_line`,
`environment_block`) plus the shared Win32 wait-bound helpers
(`duration_to_millis`, `validate_stop_timeouts`). The public
`WindowsProcessLauncher`/`WindowsLaunchError`/`ActiveSession` entrypoints and
the shared `pub(crate)` helpers keep their existing names, so callers in
`native.rs` and the `watchdog` runtime are unchanged. Child files use explicit
`#[path]` attributes to remain flat siblings of `native.rs`.

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
Runtime process ownership is coordinated by `runtime_process.rs`. The launch
ownership proof is delegated to one cohesive child,
`runtime_process/ownership.rs`, which owns the closed `OwnershipProof` shape,
its bounded serialized size, construction from native, broker and synthetic
identities, the stable runtime incarnation and the strict recovery validation
applied before a persisted proof is adopted. The coordinator keeps
`MAX_NATIVE_PROOF_BYTES` because it also enforces that bound when it
re-serializes a live child proof, and re-exports `OwnershipProof`,
`validate_proof`, `preflight_synthetic_proof_budget` and `runtime_incarnation`
so callers, tests and the `runtime.rs` imports are unchanged. There is exactly
one construction and one validation path for a proof; the coordinator never
re-implements either.
Runtime process ownership is coordinated by `runtime_process.rs`. The Linux
privileged helper path is delegated to one cohesive child,
`runtime_process/linux_helper.rs`, which owns protected-bootstrap config
reading and validation, worker/gateway-health bootstrap binding checks, the
durable prepared-intent correlation and the exact delegated-cgroup-leaf proof
(`validate_planned_cgroup_leaf`, `verify_current_cgroup_full_path`,
`validate_exact_cgroup_child`, `cgroup_v2_mountpoint`). The coordinator
re-exports `run_linux_helper_if_requested` so `runtime.rs` is unchanged and
keeps the two cgroup predicates the existing regression tests call. The child
delegates all process authority to `linux_launcher`/`linux_process`; it never
widens containment and never re-implements the protected config or membership
rules.
The root-owned Linux broker stays coordinated by `platform/linux_broker.rs`.
Its closed request and lifecycle envelopes, the fixed launch-policy model, the
strict JSON policy documents and the policy validators now live in
`platform/linux_broker/protocol.rs`. The coordinator re-exports the protocol
surface (`BrokerComponent`, `BrokerRequest`, `BrokerLifecycleOperation`,
`BrokerLifecycleState`, `BrokerLifecycleRequest`, `BrokerPolicy`, `LaunchPolicy`,
`PeerPolicy`, `CapabilityPolicy`, `CgroupPolicy`) so callers, sibling modules,
tests and the `platform` re-exports keep their existing import paths, and it
keeps the shared protocol bounds and broker error vocabulary. Unknown-member
rejection, duplicate-member rejection and every identity, capability, argument,
environment, timeout and cgroup bound are enforced only in `protocol`; no child
re-implements them.

The root-owned Linux broker stays coordinated by `platform/linux_broker.rs`.
Peer authentication and the protected-filesystem helpers now live in
`platform/linux_broker/peer.rs`: the kernel-derived `PeerCredentials` captured
with `SO_PEERCRED`, the executable-identity check that pins the peer with a
`pidfd` and compares the resolved `/proc/<pid>/exe` digest against the
root-owned allowlist, and the protected path, bounded-read and
executable-hashing helpers. The coordinator re-exports `PeerCredentials` and
`peer_credentials` and keeps `pub(crate)` re-exports of the helpers that
sibling modules (`native`, `ledger`, `descriptor_store`, `bootstrap_transport`)
and the broker tests already import, so their existing import paths are
unchanged. The generic `hex_digest`/`io_error` utilities and every identity,
deadline and ownership bound stay with the coordinator; no child re-implements
them.

The root-owned Linux broker stays coordinated by `platform/linux_broker.rs`.
Launch admission, exact-nonce idempotence, receipts and the versioned
inspect/stop lifecycle now live in `platform/linux_broker/broker.rs`, together
with the `UnitObservation`, `LaunchReceipt` and `BrokerLifecycleReceipt`
contracts the backend shares. The coordinator re-exports
`LinuxSystemdBroker`, `UnitObservation`, `LaunchReceipt` and
`BrokerLifecycleReceipt` (and keeps `pub(crate)` re-exports of `unit_name`,
`receipt_from` and `verify_receipt_identity`) so the socket server, native
backend, ledger and the broker tests keep their existing import paths. The
`SystemdBackend` trait now lives with the bounded client in
`platform/linux_broker/client.rs` because the socket server, the bounded client
and the native backend all consume it; the shared error
vocabulary, protocol bounds and the `ledger`/`descriptor_store` module
declarations also stay there. Durable admission, nonce replay, retained
containment and uncertainty are enforced only in `broker`; no child
re-implements them.

The root-owned Linux broker stays coordinated by `platform/linux_broker.rs`.
The Unix socket server and framed transport now live in
`platform/linux_broker/transport.rs`: the one-request-per-connection `serve`
loop, `handle_connection`, the typed launch and lifecycle wire responses, the
bounded `read_frame` and deadline-driven `write_deadline` helpers, and
`bind_root_owned_socket` (root-owned directory, `0o660`, peer group ownership).
The coordinator re-exports `serve` and `bind_root_owned_socket` and keeps
`pub(crate)` re-exports of `read_frame`, `write_deadline` and (test-only)
`handle_connection` so the native backend, the bootstrap transport and the
broker tests keep their existing import paths. Endpoint permissions, frame
bounds, timeout budgets and typed failure responses are enforced only in
`transport`; no child re-implements them.

The root-owned Linux broker stays coordinated by `platform/linux_broker.rs`.
The bounded launch client and the backend contract now live in
`platform/linux_broker/client.rs`: the `BrokerClient` launch and
inspect/lifecycle calls, the deadline-driven `connect_with_deadline` helper, the
owned wire-response DTOs decoded from the transport responses, and the
`SystemdBackend` contract implemented by the native and fake backends. The
coordinator re-exports `BrokerClient` and `SystemdBackend` and keeps a
`pub(crate)` re-export of `connect_with_deadline` so the bootstrap transport
keeps its existing import path. The client only frames bounded requests and
never reconstructs a unit or widens authority; request identity, receipt
correlation and containment capability checks stay enforced in `broker` and
`native`.

Incompatible recovery interfaces must have explicit versions and digests and be
integrated with their real consumers. Frozen runtime-v3 artifacts stay frozen.
No watchdog database is shared with gateway or harness. No watchdog action
directly mutates the game or treats changed observations as settlement evidence.

All production mutations require admission validation and bounded resources.
Persistence uncertainty blocks new work; unavailable telemetry does not grant
authority or cause whole-stack restarts. Stop, pause, quarantine and completed-job
records survive every recovery path. A process identity includes creation context
and launch identity; PID or executable name alone never authorizes termination.
