# Ascension Watchdog — Complete Implementation Orchestration Prompt

## 1. Mission and required outcome

You are the root implementation orchestrator for AI-Ascension. Create the
repository AI-Ascension/ascension-watchdog and deliver the complete, integrated
crash-resilient autonomous runtime described below. Use real Luna Max subagents
through three descendant levels. This is an implementation assignment, not a
request for another proposal, research report, scaffolding exercise, or collection
of disconnected pull requests.

Deliver working source, companion changes in the existing repositories,
migrations, service packaging, operational commands, automated tests, security
controls, documentation, and traceable validation evidence. The watchdog must
keep authorized experiments operating through recoverable failures without
repeating uncertain game actions, reviving stale authority, losing attempt
history, resetting budgets, or overriding an intentional stop.

The product is a deterministic Rust service. LLM subagents build it; LLMs must
not be required for its ordinary supervision, health checks, scheduling, restart
decisions, or reconciliation policy. Gameplay providers remain separate,
explicitly configured dependencies.

The primary supported deployment is the existing Windows game-host topology,
including WSL-hosted components where actually used. Also implement and validate
the Linux service adapter against synthetic processes. Do not claim Linux game
compatibility without separate host evidence. Begin with one game instance;
design identifiers and storage for more, but never weaken current isolation
guards to advertise concurrency.

The required new repository name is exactly ascension-watchdog, not
ai-runtime-supervisor.


## 2. Scope, authorization, and operating discipline

Treat this prompt as authorization to create the new repository, inspect the
named organization repositories, create isolated implementation branches/worktrees,
edit source and tests, run builds and synthetic tests, and prepare narrowly scoped
commits, pushes, issues, and pull requests using available authorized credentials.
Follow organization repository-creation policy; when visibility is unspecified
and no policy resolves it, create the new repository privately. Do not change an
existing repository's visibility.

Read applicable AGENTS.md, architecture decisions, coding standards, licensing
rules, and workflow requirements before editing each repository. Preserve unrelated
dirty work. Do not reset, clean, force-push, broadly stage, rewrite history, or
copy private/proprietary material into repositories. Assign implementation issues
and pull requests to the authenticated implementing account when permitted.
Merge only when authorized and all applicable checks and review requirements
are satisfied; never bypass branch protection. Track merge status separately
from local integration status.

Do not provision paid infrastructure, buy credits, modify account security,
rotate unrelated credentials, disable sandboxing, alter system approval policy,
or access unapproved hosts. Install services and run host-level crash, reboot,
or gameplay tests only in an explicitly authorized disposable environment.
A development workstation is not automatically an approved destructive-test
target. Never enable unattended desktop login or silently accept mod consent.

Use existing approved disposable-host configuration when available. Otherwise
finish every unblocked implementation and synthetic-validation task, provide
executable gated host-validation tooling, and mark missing live evidence
accurately. Missing host access must not become an excuse to stop building
unrelated components. Conversely, compilation or a fake host must never be
represented as a successful live deployment.

Do not stop after producing a plan. Execute the dependency graph, integrate
results, repair defects, and rerun checks. Ask only for genuinely non-resolvable
authorization or external inputs required for an action; do not ask for
confirmation of ordinary implementation choices already covered here.


## 3. Mandatory Luna Max orchestration

### Model selection

Keep the root's current orchestration model unless the operator explicitly
changes it. Every spawned descendant—including leads, coordinators,
implementers, researchers, and reviewers—must use:

    model: gpt-5.6-luna
    reasoning effort: max

This is a model/effort pair, not a model named luna-max. Do not silently substitute
another model or xhigh, lower effort to save tokens, or claim that a prompt
instruction proves the effective runtime setting.

Before substantial delegation, inspect the installed client version, effective
configuration, custom-agent overrides, model catalog/access, and actual
spawn-tool schema. Verify the supported way to select both values. Inspect native
thread/session metadata or trustworthy execution records where available.
Distinguish requested, accepted, and observed settings; a child saying
“I am Luna” is not verification.

Use project-local configuration and explicit custom-agent settings where
supported. Current candidate settings to validate against the installed schema
are:

    [agents]
    enabled = true
    max_concurrent_threads_per_session = 12
    default_subagent_model = "gpt-5.6-luna"
    default_subagent_reasoning_effort = "max"

Set model and model_reasoning_effort explicitly in each supported custom-agent
configuration as well. Do not assume editing configuration changes an
already-running session. Do not invent CLI switches or tool arguments.
Do not add an obsolete or unsupported max_depth key merely because an older
example used it.

If the installed client cannot provide Luna Max or genuine nested agents,
record the exact capability failure. Continue independent authorized work, but
do not label the requested orchestration verified or the entire assignment
complete. Do not bypass account restrictions, agent limits, or permission
boundaries with hidden subprocesses or alternate providers.

### Depth semantics

Use this exact hierarchy:

    Depth 0: Root orchestrator and integration authority
      Depth 1: Workstream leads — Luna / max
        Depth 2: Bounded work-package coordinators — Luna / max
          Depth 3: Implementation, testing, or review specialists — Luna / max

Three levels deep means three descendant layers below the root. Depth-3 agents
are leaves and may not spawn children. Use genuine three-level delegation for
suitable implementation and independent-review work, not ceremonial empty agents.
Simpler tasks may use shallower delegation.

Use native depth restrictions when supported and verify them. Also enforce
depth through a root-owned spawn registry and supported tool/role restrictions;
remove delegation tools from leaf roles where possible. Record actual
parent/child metadata. Never reset ancestry by launching another client or
calling a child a new root. A native restriction that is stricter than this
requested tree must not be circumvented.

### Concurrency and ownership

Use a default global ceiling of 12 open descendant threads across the entire
tree, reduced to the actual account/runtime/resource allowance. This is a
project budget, not a claim about the product's maximum. Count waiting leads
and coordinators, not only active leaf workers. Do not assume a per-session
setting enforces an aggregate multi-session limit.

The root allocates and releases thread reservations. Keep enough capacity for
actual leaf work; run leads in waves instead of filling all slots with managers
waiting for children. No independent recursive fan-out, duplicate active tasks,
busy polling, or respawning timed-out tasks before their earlier process/thread
is confirmed inactive.

Use these depth-1 workstreams:

- Architecture and contracts: ownership, recovery protocol, threat model,
  compatibility, requirement traceability.

- Watchdog implementation: deterministic reconciliation, durable scheduling/state,
  CLI, health and shutdown.

- Gateway and host recovery: durable authority, execution fencing, journals,
  process-port/broker integration.

- Harness and MCP recovery: checkpoints, resume, provider lifecycle/accounting,
  replay and completion semantics.

- Platform and operations: Windows/WSL, Linux, installation, release sets,
  telemetry, backups and diagnostics.

- Independent verification: adversarial review, fault injection, integration,
  security, evidence and documentation audit.

Depth-1 leads split work into explicit depth-2 packages. Depth-2 coordinators
assign narrow depth-3 source, test, or review tasks. For example, the gateway
lead delegates an authority-store package, whose leaf specialists implement
migrations, test restart fencing, and independently review the resulting
transition rules.

Implementation and final review of a critical subsystem must not be assigned
to the same leaf. Independent verification must inspect the resulting code and
execute relevant tests; approval cannot rely solely on an implementer's narrative.

### Delegation packet and result contract

Every task packet must identify task ID, actual depth and ancestry, model/effort,
repository and base commit, worktree/branch, allowed paths, forbidden paths/actions,
prerequisites, accepted contract versions, invariants, precise acceptance tests,
resource/deadline budget, and expected output.

Give each writer an isolated worktree and a non-overlapping file assignment.
Serialize changes to shared manifests, lockfiles, migrations, and normative
schemas. Root or an explicitly assigned integrator owns cross-workstream
integration. Do not have children independently merge each other's branches.

Every result must return changed files and commit/diff identity, implemented
requirements, exact commands with exit results, evidence paths/digests,
outstanding defects, external blockers, and a concise decision summary.
Do not request private chains of thought. Run critical tests again after
integration; a child reporting success is not sufficient.

Maintain resumable development orchestration records separately from production
watchdog state. Persist the task DAG, file ownership, agent registry, contract
decisions, validated commit set, next actions, and blockers. Keep sensitive logs
and local paths outside committed artifacts. On resumption, reconcile actual
worktrees/threads/commits before rescheduling work.

Share concise milestone updates. Prefer targeted reads and artifact references
over sending the full repository or repeating the entire prompt to every agent.
Keep stable instructions reusable; do not issue model calls for build-log polling
or deterministic bookkeeping.


## 4. Discover the actual baseline before modifying it

Inspect current default branches, relevant issues/PRs, repository policies,
executables, tests, deployment scripts, and release artifacts for:

    AI-Ascension/ascension-watchdog
    AI-Ascension/sts2-gateway
    AI-Ascension/sts2-harness
    AI-Ascension/sts2-mcp-server
    AI-Ascension/sts2-game-mod
    AI-Ascension/sts2-protocol
    AI-Ascension/sts2-game-core
    AI-Ascension/ai-agent-observability
    AI-Ascension/.github
    AI-Ascension/AI-Ascension.github.io

First determine whether the exact target repository already exists. Reuse it
safely when it does; do not recreate it or overwrite existing work. If remote
creation is denied, retain the correctly named local implementation, record
the genuine remote blocker, and continue permitted work.

Pin source revisions in a machine-readable workspace/release-set manifest.
Treat earlier review findings as investigation leads, not immutable descriptions
of current code. Resolve stale README/source contradictions through exact
revisions and recorded runtime evidence.

Inspect these starting points and follow their current equivalents if refactored:

    sts2-gateway/crates/gateway/src/process_supervisor.rs
    sts2-gateway/crates/gateway/src/ports.rs
    sts2-gateway/crates/gateway/src/bin/runtime_support/service.rs
    sts2-gateway/crates/gateway/src/bin/runtime_support/service_lease.rs
    sts2-gateway/crates/gateway/src/bin/runtime_support/service_v3.rs
    sts2-gateway/crates/gateway/src/bin/runtime_support/journal.rs
    sts2-gateway/docs/COMPATIBILITY.md

    sts2-harness/crates/harness/src/bin/runtime_support/runtime_v3.rs
    sts2-harness/crates/harness/src/bin/runtime_support/runtime_v3_ledger.rs
    sts2-harness/crates/harness/src/bin/runtime_support/runtime_v3_recovery.rs
    sts2-harness/crates/harness/src/bin/runtime_support/runtime_v3_recording.rs
    sts2-harness/crates/harness/src/exo_process.rs
    sts2-harness/README.md

    sts2-game-mod/experiments/managed-rust-interop/game-loader/RuntimeV3GameplayHost.cs
    sts2-game-mod/experiments/managed-rust-interop/live-combat-session.sh
    sts2-game-mod/experiments/managed-rust-interop/live-combat-demo.ps1
    sts2-game-mod/docs/LIVE_COMBAT_DEMO.md

    ai-agent-observability/deploy/compose.yaml
    ai-agent-observability/deploy/otel-collector.yaml
    ai-agent-observability/systemd/ai-agent-observability.service

Verify executable wiring, not just whether a type or method exists. Determine
which profiles actually persist operations, which process owners are concrete,
where authority is enforced, how completed work is recorded, and which recovery
behaviors have real evidence.

Create an evidence-backed baseline map and numbered requirements-to-code/test
matrix before broad parallel editing. Preserve useful existing implementations
and tests. Do not reimplement an existing recovery capability under a different
name.


## 5. Repository and ownership architecture

The new repository owns deployment desired-state reconciliation, supervision of
gateway/harness executables, durable deployment/job scheduling records, platform
adapters/broker implementation, operational CLI, release manifests, and
cross-repository integration tests.

Maintain these authority boundaries:

    OS service manager -> watchdog process
    watchdog -> gateway executable and harness worker supervision
    harness -> MCP subprocess and provider execution/session
    harness -> MCP -> gateway -> mod -> authoritative game host
    gateway -> exclusive game lifecycle decisions -> restricted host broker
    container runtime -> observability container restart mechanics

The host broker executes gateway-authorized lifecycle requests. It must not
become an independent lease issuer, gameplay client, or second scheduler.
The watchdog must not bypass MCP/gateway to play the game, mutate saves,
or infer authoritative game effects.

Keep experiment semantics, episodes, trajectories, provider accounting, and
execution checkpoints in the harness. Keep game leases, game-process authority,
and operation forwarding/reconciliation in the gateway and host boundary.
Keep MCP thin. Keep sts2-game-core free of process, network, clock, and
persistence concerns. Put only accepted, genuinely shared neutral artifacts
in sts2-protocol.

Use owner-local storage and versioned interfaces. Do not make several
repositories write directly to one shared database, import sibling implementation
crates through path dependencies, or vendor their source into the watchdog.
Consume released artifacts/binaries and explicitly versioned contracts.

Implement a cohesive Rust workspace with non-empty packages/modules for pure
supervision policy, durable storage, runtime adapters, restricted host broker,
CLI, and test tooling. Prefer the fewest packages that preserve meaningful
boundaries. Use thin PowerShell/shell installation wrappers only where necessary;
do not hide production supervision logic in scripts.

Deliver at least:

    Cargo.toml / Cargo.lock / pinned toolchain
    AGENTS.md / README.md / SECURITY.md / licensing and provenance
    crates/ or equivalent cohesive Rust source layout
    schemas/ and valid/invalid conformance fixtures
    config/ with safe examples and schema validation
    deploy/windows/ and deploy/linux/
    tests/unit/, tests/integration/, tests/faults/ or equivalent suites
    docs/architecture, recovery, threat model, operations, compatibility
    docs/evidence and requirements-to-tests matrix
    docs/orchestration plus validated project-local agent configuration
    prompts/ containing this implementation prompt
    machine-readable workspace and release-set manifests

Do not pad the repository with empty crates, placeholder adapters, fake-green
health endpoints, or production todo!/unimplemented! paths. Follow each
repository's restrictions on panics and unsafe code. Prefer safe platform
wrappers; isolate any permitted native FFI boundary with explicit invariants and
focused review instead of weakening workspace-wide policy.


## 6. Non-negotiable runtime invariants

Assign stable requirement IDs and executable tests to all of these:

1. At most one authorized mutating controller exists per game-instance incarnation.

2. A restart never restores revoked or expired mutation authority by reusing
   configuration.

3. Every potentially dispatched mutation has a durable identity and uncertainty
   record first.

4. A timeout, connection loss, missing receipt, or changed observation is not
   proof of non-execution or settlement.

5. An unresolved operation is reconciled, never blindly resent or assigned a
   new identity to evade deduplication.

6. Historical receipt access cannot grant new mutation authority.

7. Game mutation and final execution-time fencing remain at the authoritative
   host boundary.

8. One subsystem owns each process's restart decisions; other layers use its
   bounded control interface.

9. Successful job completion, budgets, stop/pause intent, cooldowns, and attempt
   lineage survive crashes.

10. Restart/replay/reconstruction never masquerades as uninterrupted continuation.

11. Persistence failure prevents new mutation admission; telemetry failure alone
    does not.

12. Recovery never changes protected saves, consent, model policy, credentials,
    permissions, or release selection implicitly.

13. Queues, payloads, retries, logs, receipt retention, subprocess counts, and
    recovery time are bounded.

14. The operator can durably pause, stop, inspect, and uninstall the service.

15. Build, synthetic-process, live-host, reboot, and soak evidence remain distinct.


## 7. Durable stores, jobs, and identity

Implement owner-local transactional persistence, with SQLite WAL and
synchronous=FULL as the initial single-host choice unless a documented, tested
alternative better fits the existing policies. Verify pragmas and transaction
behavior in tests. Keep databases on supported local filesystems, with one
owning process/service and appropriate locking. Do not share a database across
Windows and WSL writers or assume network/shared mounts have the required
semantics.

Provide bounded busy handling, schema migrations, transaction constraints,
integrity checks, backups, restoration, archival, and explicit corrupt/missing-state
behavior. Never “repair” corruption by silently deleting state, recreating epoch 1,
clearing unresolved operations, or resetting budgets. Separate mutable state
directories from replaceable release directories.

The watchdog store must persist deployment identity and desired mode, approved
release/config digests, supervised component identity, job admission/claim/completion,
attempt relationships, recovery state, retry budgets, cooldowns, resource
reservations, and auditable operator commands.

The harness store must persist episode/trajectory identity, last verified
boundary, pending operations, decision/result references, provider usage
reservations, completion records, and replay provenance. The gateway store must
persist authoritative boot/lease history, revocation, instance incarnation,
canonical operation identity/digest, dispatch uncertainty, receipts, and
reconciliation status.

Keep distinct namespaces for deployment, boot, instance, instance incarnation,
gateway/MCP sessions, lease/epoch, job, run, episode, attempt, trajectory, request,
operation, action, trace, model execution, and artifact identifiers. Define
exactly which remain stable during transport reconnect, worker restart,
authority replacement, host replacement, and replay.

Use uniqueness constraints and atomic transitions for job claims. Make
completion durable before an acknowledgment or worker exit can cause the
scheduler to treat a completed job as incomplete. Reconcile crashes between
worker completion and scheduler acknowledgment without rerunning the job.

Persist only policy-approved runtime data outside the repository. Sensitive
provider results or observations needed for recovery require protected storage
and retention controls. Hash/reference them in committed evidence; do not commit
credentials, private prompts, raw private outputs, or proprietary game bytes.


## 8. Durable boot authority, leases, and historical recovery

Before opening mutation admission, the gateway must acquire exclusive
authority-store ownership, validate state and release compatibility, establish
a fresh durable boot context, invalidate prior active leases, and complete the
host-fence handshake.

Use both a checked monotonic authority generation and a fresh unpredictable
boot/incarnation namespace where the contract requires it. Handle wire integer
bounds and exhaustion explicitly. Expired, released, old-boot, or
wrong-incarnation requests must be rejected before forwarding and again before
queued host execution.

Implement renewable leases with an initial configurable TTL of 30 seconds and
renewal interval of 10 seconds. Renewal must not depend on model inference
completing. Use monotonic time for in-process deadlines and audit timestamps
separately. Invalidate authority after reboot and suspend/resume ambiguity;
do not restore a prior process's monotonic timestamp as a valid deadline.

Define the linearization point at which new host authority replaces old
authority. Prevent overlapping controllers and old queued work from executing
after that point. An operation already executing remains an uncertainty to
reconcile; lease rotation is not cancellation of an effect that already happened.

Implement an authenticated bootstrap/control channel that can establish new
authority when no gameplay lease exists. Do not create a circular dependency
requiring the old lease to obtain the new lease. Broker/gateway/host identities
and permitted endpoints must be explicitly configured and authenticated.

Separate historical read-only operation lookup from current mutation permission.
Recovery uses current authorized recovery credentials to address an operation's
original identity, payload digest, and epoch. It does not require reactivating
old mutation credentials, rewrite old receipts into the new epoch, or bypass
identity checks.

Handle backup restoration and disk rollback explicitly. Restoring old state
must not reissue an old authority namespace. Provide a tested rekey/new-incarnation
recovery path, revoke or terminate prior controllers/hosts, and block admission
until authority is established. Do not claim disk rollback protection from a
counter stored only inside the restored backup.

Version incompatible contract changes. Preserve frozen profile artifacts,
publish additive/new recovery artifacts through their owner, update real
consumers together, and reject mixed digests. A shared profile name is not a
compatibility check.


## 9. Mutation journal and gateway/mod integration

Wire persistence into the actual runtime gameplay path, not only fake tests or
a different runtime profile. Build on existing operation-ledger and journal
semantics where suitable.

Before transmitting a mutation, commit an operation record containing its
stable identity, original authority context, canonical payload digest, expected
state/catalog identity, and dispatch uncertainty. Use explicit transitions such as:

    INTENT_RECORDED -> MAY_HAVE_BEEN_DISPATCHED
      -> ACCEPTED | SETTLED | REJECTED | UNKNOWN
      -> RECONCILED

The names may follow existing contracts, but the semantics must not collapse
admission, effect, uncertainty, and terminal rejection. Commit
MAY_HAVE_BEEN_DISPATCHED before handing work to the transport. A crash in the
commit-to-send interval is conservatively uncertain until the destination
provides sufficient authoritative evidence.

Stable-operation duplicate handling must return a compatible retained result
without a second mutation. Conflicting payload reuse must be rejected.
HTTP success, HTTP conflict, generation movement, or a missing receipt alone
must not determine whether an effect occurred.

At the mod boundary, require a valid durable admission ticket and current fence
before execution on the game thread. Keep disk/network blocking work off the
game thread where possible without weakening the persist-before-effect ordering.
Record authoritative effect witnesses tied to the exact operation, not merely
the latest observation.

Do not promise exactly-once effects across a host-mutation/receipt-persistence
crash window unless a tested atomic host mechanism actually provides it.
Where certainty is impossible, retain UNKNOWN, prevent conflicting mutation,
and use the authorized interruption/reconstruction policy.

Implement bounded active-operation retention, archival and deduplication
tombstones with documented retention horizons. Never evict unresolved operations.
Test well beyond all existing small capacity bounds, including more than
64 gateway operations and any host receipt limit discovered during inspection.
Backpressure must not silently lose deduplication protection.

Implement concrete gateway process-port integration and restricted broker
requests. Enforce configured executable, argument, working-directory,
environment, profile, port, and release-hash allowlists. No arbitrary command
execution or generic proxy endpoint.


## 10. Harness, MCP, provider, and replay recovery

Add an explicit harness resume entry point that loads durable execution state
rather than invoking the ordinary new-episode flow against a surviving game.
Restore pending identities, reconcile authority and operations, obtain a fresh
legal observation, and only then permit new model decisions or game mutations.

Preserve bounded MCP recovery-only reconnection. The harness remains the sole
owner of its stdio transport. Do not let the watchdog attach another reader/writer
or restart an MCP child concurrently with the harness. Preserve separate MCP
and gateway session namespaces and correlation validation.

Implement three distinct recovery outcomes:

- In-place continuation: the original host incarnation survives, pending work
  is resolved, fresh authority is valid, and the harness resumes at a verified
  boundary.

- Reconstruction: a new isolated host attempt is built from an approved
  checkpoint or verified settled replay prefix, with new attempt/incarnation
  lineage.

- Interrupted-unknown: the old attempt cannot be proven safe to continue;
  preserve its evidence and either quarantine it or schedule a new independent
  attempt according to explicit policy.

A watchdog must not imply that the same seed recreates exact lost state.
Reuse the existing replay machinery, verify its input requirements, and
implement a real checkpoint-to-continued-execution handoff where required.
Match approved build, seed policy, relevant configuration, action payloads,
and fair-play observation semantics. Do not compare process-local generation
numbers as though they were globally stable. Stop reconstruction on divergence;
never guess past it or skip an unresolved mutation.

Preserve seed-blind experiments and provider policy. Do not change gameplay
providers to Luna merely because the development team uses Luna. Protect
original saves and do not invent full-campaign support absent in the host
adapter. The service may supervise supported full-episode workflows, but generic
gameplay expansion is not a substitute for crash recovery.

Persist provider execution identities, approved result references, usage
reservations, and actual/unknown consumption. Reuse a completed decision only
when its complete input/model/configuration fingerprint and current state remain
valid. Do not duplicate inference during transport polling or replay.

Bound provider deadlines, cancellation, pipe I/O, output size, and descendant
cleanup. Classify invalid credentials, quota exhaustion, incompatible output,
provider outage, and timeout separately. Do not reset budgets on restart,
automatically renew credentials, change billing routes, or select an unapproved
fallback. Ambiguous billed calls must retain conservative accounting until
resolved.


## 11. Watchdog reconciliation, health, and operator interface

Implement a persisted desired-state reconciler with explicit states such as:

    STOPPED / STARTING / RUNNING / SUSPECT / DRAINING
    RECOVERING / BACKOFF / PAUSED / BLOCKED / QUARANTINED
    WAITING_FOR_SESSION

Define component, attempt, and deployment states separately. A completed episode
is a scheduler event, not a crashed daemon. One failed attempt or telemetry
exporter must not automatically restart the entire stack.

Reconcile from durable desired state after every watchdog restart. Obtain
singleton ownership, inventory exact process identities, resolve orphan
ownership through the designated process authority, assess dependencies,
and perform the smallest authorized recovery step. Default to verified cleanup
over ambiguous orphan adoption. No name-based killing, wildcard process
matching, or PID-only ownership assumptions.

Health must distinguish liveness, readiness, and phase-specific progress.
Publish authenticated bounded status including current phase, heartbeat sequence,
meaningful-progress age, phase deadline, queue age, pending-operation count,
current incarnation, and lease remaining time. No secrets or unrestricted payloads.

A responsive socket is not proof of game-thread progress. An unchanged game
generation during valid inference is not a hang. Track startup, inference,
dispatch, settlement, replay, idle, and shutdown deadlines independently.
A heartbeat unrelated to the supervised control loop cannot prove that loop
is healthy.

Initial tunable defaults:

    game instances: 1
    probe interval: 2 seconds
    suspect threshold: 3 consecutive misses
    game startup grace: 90 seconds
    lease TTL / renewal: 30 / 10 seconds
    restart backoff: exponential with jitter, capped at 60 seconds
    restart budget: 5 in 10 minutes per affected component/attempt
    unresolved mutations: at most 1 per instance
    provider timeout: explicit provider-specific configuration

Validate timer relationships. Use injected clocks in policy tests. Persist
cooldown/retry information across restarts and define when sustained health
legitimately resets a budget. When budgets are exhausted, quarantine the affected
work and permit bounded non-mutating diagnostic probes, not endless expensive
relaunches.

Implement a documented CLI/API for config validation, doctor/preflight,
installation planning, service installation/removal, start, status, pause,
resume, drain, stop, job submission/listing, attempt inspection, authorized
reconciliation, retry/reconstruction, quarantine, diagnostics, backup/restore,
and release activation/rollback.

Keep read-only commands side-effect free. Make mutating administrative commands
authenticated, idempotent where possible, and audited. Persist stop/pause intent
before terminating work so recovery cannot override it. A pause stops new
decisions/dispatch and accounts for in-flight uncertainty; a force stop does
not claim to undo a mutation.


## 12. Windows, WSL, Linux, and process containment

Implement a native Windows watchdog service with automatic start and bounded
Service Control Manager failure recovery. Add a minimal trusted health checker
for watchdog hangs that requests recovery through SCM; it must not become a
competing process launcher or restart healthy paused/blocked deployments.

Implement a restricted user-session broker for graphical host launch. Detect
session availability; report WAITING_FOR_SESSION rather than repeatedly launching
in the wrong session. Support explicit approved session startup, not automatic
login or credential capture. Authenticate named-pipe/local IPC peers and protect
endpoints with ACLs.

Use Windows Job Objects or an equivalently justified mechanism for owned
descendants, with tested containment, assignment timing, cleanup, breakaway
policy, and handle ownership. Broker failure, gateway disconnection, and owner
lease expiry must leave controlled, fenced outcomes. Verify executable identity,
creation/incarnation identity, and launch nonce rather than relying on reused PIDs.

For WSL components, identify the exact distro and execution context, use bounded
direct process invocation, validate interop paths and endpoints, and test WSL
termination/restart independently of Windows process failure. Do not assume
Linux systemd keeps the distro alive or that Windows/WSL localhost behaves
identically in every networking mode. Do not broaden loopback listeners to
wildcard/remote binds to hide configuration failures.

Implement Linux systemd packaging with real readiness notification and watchdog
integration, bounded start/stop timeouts, least privilege, protected writable
state directories, and cgroup/process-tree cleanup. Notifications must reflect
actual reconciliation-loop progress. Test native synthetic processes and service
restart behavior; separately label unsupported game-host environments.

Across platforms, launch executables directly with validated arguments and
minimal environment. Keep secrets out of command lines and logs. Drain bounded
stdout/stderr asynchronously. Enforce memory/process/file/queue limits where
supported. Use graceful shutdown followed by a deadline-bound force stop of
owned descendants only.

Test partial launches, pipe inheritance, children outliving parents, PID reuse,
port conflicts, hung termination, owner death, reboot, suspend/resume, unavailable
desktop sessions, and configured stop surviving every restart path.


## 13. Observability, release sets, installation, and storage operations

Integrate the existing observability repository without making it a gameplay
prerequisite. Implement local authoritative journals plus bounded export
buffering. Add and validate persistent Collector queues and their writable
volume, capacity limits, recovery, and drop accounting. Verify all stateful
services' volume and backup behavior instead of assuming Compose restart
policies provide durability.

Decouple Collector ingestion readiness from dashboard availability where
compatible with the deployment. Handle exporter outage and queue exhaustion
explicitly. Never recreate databases, regenerate existing secrets, or rerun
destructive bootstrap during ordinary restart. Respect intentional container
stops and keep one restart-policy owner per container.

Expose bounded-cardinality metrics for component availability, recovery
reason/duration, restarts, unresolved operations, oldest pending age,
lease-fence rejections, stalled host work, provider budget/usage, disk headroom,
queue depth, and telemetry drops. Put high-cardinality operation identifiers
in protected logs/traces, not unbounded metric labels. Redact and size-limit
diagnostic bundles.

Create immutable release-set manifests containing repository revisions,
executable hashes, schema/profile digests, host/mod compatibility, provider
adapter identity, configuration digest, and migration compatibility. Verify
bytes before activation. Prevent time-of-check/time-of-use replacement of
approved binaries through protected immutable release directories and
platform-appropriate checks.

Separate installation/initialization, normal startup, migration, upgrade,
and rollback. Recovery must not run git pull, compile changing branches,
download latest binaries, modify source, or select a different model/release.
Stage and validate an approved release, drain safely, activate atomically,
and recover an interrupted activation. Binary rollback must never roll back
authority generations or silently open an incompatible database.

Provide idempotent installers and uninstallers, dedicated service accounts where
appropriate, OS-native secret references, log rotation, disk quotas/headroom
checks, backups, restore/rekey procedures, and verified release inspection.
Uninstallation must durably disable restarting and preserve or remove data only
according to an explicit option. Do not remove unrelated containers, files,
profiles, saves, or user services.


## 14. Security and failure containment

Threat-model stale controllers, duplicate supervisors, malicious/untrusted game
text and model output, compromised child processes, forged health messages,
replayed IPC, unauthorized local clients, path traversal, symlinks/reparse points,
malformed journals, excessive payloads, and dependency/release tampering.

Keep listeners local by default and authenticate even on loopback. Separate read,
mutation, lifecycle, recovery, and administrative capabilities. A read credential
cannot dispatch, rekey, launch, or stop another user's process. Recovery commands
need current authorization plus narrowly scoped historical access.

Validate configuration and contract messages as closed bounded types. Reject
duplicate/unknown fields where required by the boundary, unsafe paths, unapproved
environment injection, digest mismatch, and incompatible schema revisions.
Keep credentials outside serialized task packets and committed artifacts.
Preserve sandbox and repository permissions during agent work.

Document the safety/availability tradeoff: when persistence or authority is
uncertain, block new mutation while keeping diagnostics and read-only health
available. A controlled blocked state is not a reason to restart indefinitely.
The operator's stop and revocation always take precedence over autonomous
continuation.


## 15. Required validation and fault-injection matrix

Every numbered requirement needs a source implementation, a failure-path test,
and an evidence classification. Build an automated synthetic host with
controllable admission, queue execution, effect counters, receipts, crashes,
malformed responses, and restarts. Keep test-only fault injection out of ordinary
production exposure.

Use deterministic unit/property/state-machine tests for invariants, then real
subprocess/transport integration tests. Killing a process is not a power-loss
simulation; distinguish graceful exit, forced process death, VM/OS restart,
and verified storage-durability tests.

At minimum automate these scenarios and assert durable postconditions:

1. Root agent routing/depth smoke: real descendants use accepted Luna Max
   settings, reach depth 3, and cannot create depth 4 through the configured policy.

2. Two watchdogs or gateways compete for the same deployment/store; only one
   obtains authority.

3. Crash before/after each job claim, intent commit, uncertainty commit,
   network send, host admission, host mutation, receipt commit, harness
   checkpoint, and job completion acknowledgment.

4. Mutation succeeds but its response is lost; reconciliation never invokes
   the mutation again.

5. Duplicate operation with the same payload returns its retained outcome;
   conflicting reuse fails.

6. Old boot/lease/session/incarnation proofs arrive after replacement,
   including queued pre-crash requests.

7. Historical receipts remain readable through authorized recovery without
   reactivating old authority.

8. MCP dies during dispatch, inference stalls, or provider quota/authentication
   fails; recovery remains correctly scoped.

9. Harness crashes after a completed provider result or completed episode;
   no needless inference or completed-job rerun occurs.

10. Gateway dies while game/broker survive; the replacement cannot mutate
    until fresh fencing and reconciliation succeed.

11. Game, broker, watchdog, service manager context, or WSL distro fails;
    owned descendants and uncertainty remain accounted for.

12. Disk-full, read-only filesystem, torn/corrupt record, busy lock, missing
    store, migration interruption, and incompatible backup/release are handled
    without silent reset.

13. Boot, suspend/resume, clock adjustment, PID reuse, port reuse/conflict,
    partial launch, and hung cleanup do not revive stale authority.

14. Stop/pause/uninstall during every recovery stage survives daemon and
    machine restart.

15. Telemetry and all relevant backends fail independently; gameplay continues
    only while authoritative persistence remains healthy.

16. Queues, logs, telemetry buffers, subprocess output, and operation retention
    hit limits; memory remains bounded and unresolved operations are retained.

17. Execute beyond discovered receipt-capacity limits and verify
    tombstone/archival semantics.

18. Valid seeded prefix reconstruction resumes at a verified checkpoint;
    changed seed/build/catalog or divergence rejects before unsafe dispatch.

19. Unknown host-effect outcomes remain unknown; generation changes and
    not_found responses do not manufacture settlement/non-execution.

20. Local unauthorized requests, malformed identities, excessive payloads,
    credential misuse, path escape, reparse points, and launch-policy bypass
    fail closed.

21. Partial cross-repository upgrades and identical profile names with
    different digests never become mutation-ready.

22. Watchdog-loop deadlock stops legitimate watchdog progress reporting and
    triggers bounded OS recovery, while a healthy blocked/paused loop is not
    restarted.

23. A real disposable-host crash campaign, cold reboot with session
    availability checks, and supported replay/recovery retain exact
    versioned evidence.

24. A long-running soak crosses restart, archival, budget, and telemetry-outage
    boundaries without unbounded growth or duplicated effects.

Run repository policy checks and applicable format, lint, test, schema,
security/dependency, and build gates in every changed repository. For Rust,
use the pinned toolchain and locked dependency resolution; run the existing
strict policy checker where provided, cargo fmt --all --check, Clippy with
warnings denied, and workspace/all-target/all-feature tests where valid for
that platform. Add the corresponding managed-code and deployment validation gates.

Build and execute appropriate Windows and Linux CI lanes. Never represent
cross-compilation as native process/service execution. Use only approved runners;
do not send proprietary host files or credentials to public CI. Make live-host
tests explicit gated workflows. Provide a configurable 24-hour soak runner and
run the authorized available campaign; record the actual elapsed duration.
Do not label a shorter run as a 24-hour pass or a synthetic soak as live-game
evidence.

Independent reviewers must inspect fencing linearization, journal ordering,
unknown-operation handling, restore/rekey, terminal job deduplication,
process-tree ownership, and operator stop persistence. Resolve every discovered
correctness/security blocker, add regressions, and rerun the integrated release set.


## 16. Dependency-ordered execution and integration

Use this delivery order, parallelizing only independent work:

Gate A — Capability and baseline:
Verify repository access, tools, Luna Max routing, nested delegation, source
revisions, policies, and the actual deployment topology.

Gate B — Contracts and failing tests:
Establish ownership, threat model, requirement matrix, identity lifetimes,
state transitions, recovery contracts, and failing regression/fault tests.

Gate C — Minimal executable vertical slice:
Real watchdog, durable store, CLI, supervised synthetic gateway/harness/host,
persisted stop, and one verified restart. This must be executable rather than
documentation-only scaffolding.

Gate D — Authority and operation safety:
Durable gateway boot/lease lifecycle, host fencing, historical recovery,
Runtime-v3 journals, migrations, and cross-consumer conformance.

Gate E — Experiment recovery:
Harness resume/checkpoints, MCP/provider handling, durable job
completion/budgets, reconstruction/interruption policies, and
small-capacity/long-run tests.

Gate F — Platform and operations:
Windows service/broker/WSL, Linux adapter, install/uninstall, immutable
activation/rollback, backups, diagnostics, and telemetry persistence.

Gate G — Integrated verification:
Rebuild the exact companion commit set, execute fault suites, independently
review, fix defects, and run authorized native/live/reboot/soak validation.

Gate H — Delivery:
Finish documentation and traceability, push approved branches, create/update
linked PRs, resolve CI/merge conflicts, record actual merge/deployment status,
and deliver verified commands and artifacts.

Do not ship a watchdog-only wrapper while leaving required gateway/harness/mod
changes as suggestions. Do not make a new wire contract a hidden dependency of
an old consumer. Track companion dependencies and exact commits in the release
manifest. Validate the integrated binaries from a clean build using that
manifest, not accidentally cached binaries from mixed worktrees.

When a new defect appears, return it to the owning workstream with a reproducible
test and keep unrelated work moving. Root is accountable for consistency,
integration, and final evidence—not just delegating tasks.


## 17. Definition of done and final report

The implementation is complete only when the required code paths are concrete,
companion changes are integrated into a reproducible release set, required
executable tests pass, security/correctness blockers are resolved, and the
claimed platform/runtime validations have actually run.

Use separate statuses:

    IMPLEMENTATION_COMPLETE
    SYNTHETIC_INTEGRATION_VERIFIED
    WINDOWS_SERVICE_VERIFIED
    LINUX_SERVICE_ADAPTER_VERIFIED
    LIVE_HOST_RECOVERY_VERIFIED
    COLD_BOOT_RECOVERY_VERIFIED
    SOAK_VERIFIED
    REMOTE_DELIVERY_STATUS
    BLOCKED_EXTERNAL

These are separate axes, not interchangeable badges. For each evidence item
use the organization's vocabulary: confirmed, source-derived, inferred,
proposed, unverified, or unsupported. A skipped or unavailable test is not a
pass. Open PRs are not merged commits. A packaged service is not an installed
service. An installed service is not proof of crash recovery.

The final handoff must include the actual repository location; exact
revisions/branches/PRs for every changed repository; architecture and contract
changes; verified agent ancestry/model/effort and concurrency evidence;
completed requirement IDs; exact test commands/results and artifact digests;
install/start/status/stop/uninstall and recovery commands;
migration/backup/rollback procedures; measured recovery and soak results;
known limits; and precise external blockers with the smallest executable
next action.

State explicitly whether repositories were created, changes
committed/pushed/merged, services installed, games/providers launched,
hosts rebooted, or releases activated. Never claim actions that were only
scripted or proposed.

If authorization, tools, quotas, game files, desktop sessions, or host access
prevent a required gate, complete all other reachable work and report the
specific incomplete axis. Preserve resumable task and execution state.
Do not manufacture evidence, silently lower model/depth requirements, or replace
the requested result with a general future-work plan.

Begin now: verify the runtime and repository baseline, create or safely adopt
AI-Ascension/ascension-watchdog, establish the bounded three-level Luna Max team,
write the task DAG and acceptance matrix, and implement the first executable
vertical slice while the independent contract and fault-test workstreams proceed.
