# Ascension Watchdog — complete cross-machine resumption prompt

Prepared 2026-09-11. Give this entire file to the coding agent on the destination
machine. It contains a checkpoint followed by the full original implementation
assignment. No previous chat, old local checkout, or old agent handle is required.

## 1. Your assignment and precedence

Resume the entire AI-Ascension crash-resilient autonomous runtime assignment.
This is an implementation continuation, not a new proposal and not merely a PR
maintenance task. Finish remaining source, integration, packaging, security,
recovery, test, documentation, and operational acceptance work from the full
original assignment included below. Preserve completed work and verify uncertain
claims before repeating or replacing implementations.

Apply this checkpoint as the factual update to the original assignment.
The original specification remains the requirements baseline. Fresh verified
remote/source/host observations supersede historical state in this checkpoint.
A merged PR is a completed delivery step; it does not close requirements whose
acceptance evidence is still missing.

Use the destination machine's actual paths and capabilities. Do not assume the
prior WSL filesystem, caches, credential files, VM staging paths, or agent
sessions are available locally.

## 2. Verified delivery checkpoint

The following watchdog facts were checked live while preparing this handoff:

- Repository: https://github.com/AI-Ascension/ascension-watchdog
- Default branch: bootstrap (NOT main). Repository is public.
- PR #9: https://github.com/AI-Ascension/ascension-watchdog/pull/9
- State: MERGED, at 2026-09-11T04:53:01Z.
- Merged feature head: f0e592dc796278b9dc56a292297ba299f81c8b37.
- Merge commit and observed remote bootstrap head:
  1b7582a941437c1a460659ea9a1bf14eb97d2c67.
- Former feature branch: codex/watchdog-integrated-20260910.
- Final implementation/test update: cfd06860a77e8be11267eaeb668452ac810a8a22.
- Final evidence update: f0e592dc796278b9dc56a292297ba299f81c8b37.
- All eight PR check records passed: duplicated Ubuntu, Windows,
  dependency/security, and standards checks.
- Post-merge workflow runs at 1b7582a BOTH completed successfully:
  https://github.com/AI-Ascension/ascension-watchdog/actions/runs/34563862328
  https://github.com/AI-Ascension/ascension-watchdog/actions/runs/34563862311

Do not reopen or recreate PR #9. Start follow-up work from the current fetched
bootstrap branch in a fresh isolated branch/worktree. Preserve the merged
implementation and its history. Do not rename the default branch as incidental
cleanup.

The user explicitly authorized the PR #9 merge after green CI. That action is
complete. Historical text saying "no merge authorized for PR #9" or "PR #9 is a
draft" is obsolete. That specific approval does not automatically authorize
unrelated future PR merges or production activation.

## 3. Companion repository checkpoint

These are the last recorded companion pins from the integrated candidate.
Unlike the watchdog merge above, they were not all re-queried while preparing
this file. Discover each current default branch, fetch it, compare ancestry,
and record any drift before selecting a new release set.

| Repository under AI-Ascension | Last selected revision |
| --- | --- |
| sts2-gateway | 8ba5521c2ec8f158d437a7104567592703e53259 |
| sts2-harness | ce86ced41d8b9e93d19f2c440f28b3223397f3ca |
| sts2-mcp-server | 037d10def1cbcb1c807e136d31b294355a92c010 |
| sts2-game-mod | 888b06702021cd2bbd22773b0267733766c3b04a |
| sts2-protocol | f22dd7216f65de91a0ffa27f50bc2036be6c8b24 |
| sts2-game-core | f9db577530a4d159b066d3facbd780d61c044eb0 |
| ai-agent-observability | 89539a6e7754b389f8eac148ba8a49c3892cddd8 |

Also inspect AI-Ascension/.github and AI-Ascension/AI-Ascension.github.io as
required by the original assignment.

Previously delivered companion work:

- Gateway PR #34 restart fencing feature:
  87792cf3f6e2c3b6627d3a34bf380bb337c01373, merged into the selected gateway head.
  Its author reported local 270-test validation plus hosted quality/policy pass.
- Harness PR #66 authenticated native Linux worker endpoint and hardening:
  feature 58dede2eb661133d8910a1f785e8a90346efe8dd,
  merge a0ace6712686cb30d6f0b556cb6814ad4c0721d1.
  Hardening includes true bootstrap EOF, bounded authentication slots/deadlines,
  sealed executable snapshots, and durable admission/unknown handling.
- Harness PR #54 recovery/catalog/provider work subsequently merged into ce86ced.
  Native endpoint evidence used the earlier endpoint artifact, not a complete
  rebuild and acceptance run of the later ce86ced release set.
- Other companion PRs and artifact conformance results are recorded in the
  candidate manifest and dated evidence files. Inspect their actual source.

## 4. Authorization and working discipline

The original assignment authorizes repository inspection, isolated worktrees,
implementation, builds, synthetic tests, narrowly scoped commits/pushes/issues/PRs
with approved credentials. Keep making progress within that authority.

The user supplied Train as the Windows/Linux VM environment. Previous work used
fresh staged binaries and bounded native synthetic/process tests there. Continue
that scope after verifying guest identity and existing state. Service installation,
host reboot, destructive crash tests, game/provider execution, paid resources,
and release activation require the applicable existing explicit authorization.
Do not infer all such actions are approved merely because Train VMs exist.
Prepare concrete tooling and finish independent implementation while resolving
only the genuinely missing authorization or external inputs.

Preserve dirty worktrees, saves, game installs, Steam sessions, and retained
failure evidence. Never broadly reset, clean, stash, stage, force-push, or delete
unrelated work. Keep secrets and private environment details outside Git.
Use new worktrees and stage only your assigned files.

The architecture is deterministic Rust supervision. Gameplay providers remain
independently configured. Keep database ownership separate: watchdog, gateway,
harness. Do not add sibling implementation crates via local path dependencies.
Never turn uncertainty into success, reset durable budgets, revive stale
authority, or restart against durable Stopped intent.

## 5. Bootstrap the destination machine

1. Inspect the actual OS, shell, disk space, Git, GitHub authentication, Rust
   toolchains, native Windows and Linux build capabilities, and available agent
   orchestration tools. Never print credentials. Do not copy old private keys.
2. Pick a workspace with adequate free space. The old host ran out of space in
   /home and /dev/shm; use dedicated target/temp directories on a suitable disk.
   Do not delete existing data to make room without classifying it first.
3. Clone or safely adopt ascension-watchdog. A possible fresh-clone sequence is:

   gh repo clone AI-Ascension/ascension-watchdog
   cd ascension-watchdog
   git fetch origin
   git switch -c codex/watchdog-resume-<unique-suffix> origin/bootstrap

   Substitute a unique real suffix. If the checkout already exists or is dirty,
   use git worktree add with a new branch instead of switching shared work.
4. Discover/fetch all companion repositories into sibling isolated checkouts.
   The old aggregate directory was not itself a Git repository; do not assume
   an aggregate root is a single repository on the new machine either.
5. Read all applicable AGENTS.md, organization policy, docs/architecture.md,
   ownership/contracts, toolchain files, and the original prompt below before
   changing boundaries.
6. Verify the merged watchdog source is in the fetched default branch.
   Query PRs and CI using GitHub APIs/gh, and compare exact SHA values.
7. Record destination-local checkout paths privately. Publish a portable
   source manifest of repository names, revisions, and artifact hashes.
8. Create a current requirement ledger and bounded task DAG from the entire
   specification, retaining historical evidence with its original scope.

## 6. Read these repository records

Start with:

- prompts/IMPLEMENTATION.md — full original assignment, also included below.
- AGENTS.md and docs/architecture.md.
- workspace-manifest.candidate.json.
- docs/evidence/requirements.md and requirement-evidence.json.
- docs/evidence/real-harness-worker.md.
- docs/evidence/release-set-verification-20260910.json.
- docs/evidence/current-source-conformance-20260910.md.
- docs/evidence/candidate-source-set-20260910.md.
- docs/evidence/postmerge-harness-hardening-20260910.md.
- docs/evidence/open-review-findings.md and review-repair-wave.md.
- docs/evidence/windows-integration-20260910.md.
- docs/worker-endpoint-v1.md and docs/evidence/release-activation.md.
- docs/orchestration/task-dag.json, agent-registry.json,
  consolidated-integration-checkpoint.json, and integration-wave-20260910.json.

Important drift: several requirements/agent/source records still call PR #9
open/draft at older f5eaf5e/62bf0fc revisions and state that all Windows native
evidence is missing. Those claims predate the merge and Train guest tests.
Update current-state summaries without rewriting historical run results.
The old requirements matrix counted 49 partial and 7 unverified rows; re-audit
the rows rather than copying those counts as a new verdict.

The candidate manifest contains source pins and evidence, not an activated
release. Native service, live gameplay/provider recovery, cold boot, and soak
remain separate acceptance requirements.

## 7. What the watchdog already implements

The merged repository includes deterministic SQLite/WAL supervision; durable
deployment/job/attempt state; restart and recovery policy; operator controls;
authenticated worker and gateway health interfaces; restricted process adapters;
Linux containment/broker support; Windows process/service adapters; migrations;
release inspection, staging, activation/rollback owner-state logic; bounded
telemetry; packaging; recovery schemas; and synthetic/integration tests.

Do not rebuild these from scratch. Read and exercise actual implementations,
audit contract seams and full requirements, then fix demonstrated gaps.

The last fixture changes were confined to:

- crates/platform-windows/tests/windows_safety_regressions.rs:
  locate adjacent platform_synthetic.exe when a cross-built test is copied
  into a Windows guest, with Cargo's embedded path as native-run fallback.
- crates/watchdog/tests/support/real_harness_worker_fixture.rs:
  honor ASCENSION_WATCHDOG_EXECUTABLE for guest staging, and pass immutable
  STS2_WORKER_RUNTIME_BINARY plus STS2_WORKER_RUNTIME_SHA256 to the endpoint.
- crates/watchdog/tests/support/real_harness_worker_gateway.rs:
  opt-in ASCENSION_WATCHDOG_REAL_HARNESS_HOLD_GATEWAY=1 holds each response
  for a bounded two seconds to exercise explicit stop during admission.
- crates/watchdog/tests/support/real_harness_worker_scope.rs:
  handle removed cgroups and retained-descriptor ENODEV while checking original
  cgroup identity and rejecting path replacement.

A temporary production launcher stdout/stderr diagnostic was reverted before
commit. Do not reintroduce global inherited child streams just to debug tests.

## 8. Validation already obtained

Local watchdog gates passed before publication: pinned fmt; workspace Clippy
with warnings denied; locked all-target/all-feature workspace tests; standards;
dependency/license checks; focused fault and integration suites. The library
result at the later checkpoint was 206 passed with 4 ignored. Test counts vary
across earlier snapshots; associate every count with its source/run.

Portable package tests on Linux do not execute cfg(windows) native tests.
Native Windows results below came from actual Windows guest execution.

### Train Linux

Guest: <approved-linux-guest>.
Operator context: the approved unprivileged Linux guest user, systemd user manager and cgroup v2.
The ignored test real_watchdog_native_launch_reaches_built_harness_worker passed
1/1, 0 failed, 0 ignored, in 9.44 seconds on the supplied VM.

Artifact SHA-256 values:

- watchdog: 96d0eca7d22f585fbacb9c6162e09f4bb698c458170501e23308a65f1cb2a4f6
- harness endpoint: 5286706d03c27c00e32493c1adf8864e972f7a53d1f863c046aed32d56a1644f
- test executable: 2220833acae0c7d3f88ec9d7dd2dff1637fb0070646274b94b9c5f67d575009d

The run used ASCENSION_WATCHDOG_REAL_HARNESS_SMOKE=1,
ASCENSION_WATCHDOG_REAL_HARNESS_HOLD_GATEWAY=1,
ASCENSION_WATCHDOG_EXECUTABLE, STS2_HARNESS_RUNTIME_BINARY, and the pinned
STS2_HARNESS_RUNTIME_SHA256. DBUS_SESSION_BUS_ADDRESS pointed at the guest user's bus; discover its
XDG_RUNTIME_DIR and UID rather than assuming those values on a different guest.

Assertions crossed authenticated startup/control and dispatch admission,
persisted stop, daemon and worker termination, endpoint removal, and original
cgroup cleanup. HTTP 503 gateway and /usr/bin/true MCP were intentional faults.
The endpoint emitted "runtime-v3 execution store is busy" during the stop race,
but assertions passed. This was not a successful game episode.

The successful binary preceded a final behavior-preserving environment-helper
refactor and reversal of diagnostic streams. Treat the hashes as the actual
historical artifact identities; do not claim a new build is byte-identical.
Rebuild final source and rerun when establishing the destination release set.

An independent gated Linux descendant-boundary attempt failed due to a stale
protected bootstrap ("process 6308 executable is gone"). That native boundary
case remains without a successful run in this checkpoint. Default tests that
ignore it are not substitutes.

### Train Windows

Guest: <approved-windows-guest>.
Release tests were cross-built for x86_64-pc-windows-gnu and run in the guest.

- native_synthetic: 7/7 pass.
- native_worker_bootstrap: 4/4 pass.
- native_gateway_health_bootstrap: 4/4 pass.
- native_current_process: 2/2 pass.
- windows_safety_regressions: 5 passed, 2 expected ignored by default.
- Explicit native_owner_death::windows_owner_death_terminates_owned_child:
  1/1 pass (0.15 seconds).
- platform_synthetic.exe SHA-256:
  958438bc1f9303ce006a640876cf8d1b3505adf8d97c8305e6794ac9bd777e10.
- Cross-target locked Clippy passed.

These prove the tested Windows process/bootstrap/identity/cleanup behaviors.
They do not prove a Windows harness endpoint implementation, installed SCM
service behavior, session-0 operation, reboot recovery, or gameplay.

## 9. Train access and evidence recovery

Use the operator's existing approved Train host, account, and destination-machine
SSH identity. Obtain those values from the private environment inventory;
credentials, usernames, key paths, and guest staging paths are not distributed
in this public handoff.

ssh -i <approved-key-path> -o IdentitiesOnly=yes -o BatchMode=yes <approved-account>@<approved-train-host>

Discover domains with virsh -c qemu:///system list --all, inspect XML, and verify
the supplied Linux and Windows guests before actions. Both were previously
accessed through QEMU Guest Agent. A QGA timeout does not prove a launched guest
process stopped; query execution status and reconcile its exact owned identity.

Recover prior native test images, result files, hashes, and failed fixture
directories from the operator's private guest inventory. Preserve failed
fixtures because they may contain uncertainty and cleanup proofs. If evidence
is unavailable, retain the historical claim with its limits and rebuild/rerun
the relevant gate rather than inventing a result.

Guest paths are not Train host paths or destination-local paths. Use fresh
staging directories, verify transferred hashes, and preserve game/save state.
Do not copy credentials or proprietary material into repositories.

## 10. Remaining work: audit, implement, and verify

These are investigation priorities, not permission to assume old source
findings still exist. Verify against fetched revisions and the full assignment.

A. Freeze and build one complete consumer source set.
Build the selected watchdog, gateway, harness, MCP, game-mod, protocol, core,
and observability components with their own locked toolchains. Record artifacts,
digests, contract versions, and producer/consumer compatibility. There is no
single established cross-repository Cargo workspace. Existing matching fixture
bytes and independent component passes do not establish a combined runtime.

B. Verify real recovery and host-authority paths across boundaries.
Exercise gateway install/renew/revoke/host-fence operations, managed-host
consumption, lease epochs/incarnations, catalog digests, operation witnesses,
pending-rejoin responses, restart fencing, and unknown outcomes. Inspect merged
repairs before writing replacements. Acknowledged/queued is not settled;
require authoritative host completion plus the specified fresh effect witness.

C. Integrate harness recovery/provider semantics.
Verify canonical payload and context persistence, current-authority
reconciliation, explicit continuation/reconstruction/interrupted-unknown,
checkpoint/resume, replay divergence, cancellation, provider identity/accounting,
and billing ambiguity. Native endpoint smoke covered only the admission/stop
boundary, and the later PR #54 source needs verification in the complete set.

D. Close platform implementation and execution gates.
Re-provision the scoped protected Linux bootstrap and rerun the failed boundary
case. Audit Linux broker identity, delegation, cleanup uncertainty, and installer
release checks. Verify whether the runtime actually selects the intended broker.
Inspect Windows harness/pipe endpoint support: it was last reported unsupported
even though the watchdog Windows native bootstrap consumer tests pass.
Complete missing implementation before interpreting those tests as end-to-end
Windows runtime support. Prepare and execute installed systemd/SCM, session-0,
WSL termination, and durable-stop tests where authorized.

Historical review leads to verify include Linux broker release-path defaults,
manifest/hash validation before copying binaries, and Windows provisioning
path/ACL and TOCTOU guarantees. These are not new confirmed bugs without source
inspection.

E. Complete release, storage, telemetry, and campaigns.
Verify sealed immutable executable authority across release consumers,
activation/rollback through crash boundaries, archival/tombstone behavior beyond
fixture backpressure, backup/restore ownership, bounded durable telemetry,
collector behavior, and long-running scheduling. Owner-store activation tests
alone do not prove cross-consumer release switching.

F. Execute the required fault and operational acceptance matrix.
Use every named fault case in the full original prompt. Preserve stop intent,
budget accounting, attempt history, stale-authority rejection, and conservative
unknown outcomes through crashes. Keep synthetic, native-process, installed
service, live-host, reboot/suspend, and soak results separately inspectable.
Do not shorten the required soak and call it complete. Resolve only necessary
host/provider inputs and authorization when ready to execute those gates.

G. Reconcile documentation and delivery state.
Update the requirements ledger, source manifest, evidence references, task DAG,
and operational documentation to the actual merged/runtime state. Review
critical repairs independently. Commit/push follow-ups and open focused PRs.
Apply actual review/protection rules; never bypass them. Do not treat PR #9's
specific merge permission as a blanket for unrelated PRs.

## 11. Orchestration and continuation

The original user explicitly required gpt-5.6-luna with reasoning effort max
for descendants, up to twelve open descendants, and three descendant layers
below root. Keep the root's actual current model.

Inspect the destination's real spawn schema/model access. Use native explicit
model/effort parameters where supported. Record requested, accepted, and observed
settings separately. Historical records observed depth 1 only; depth 2/3 was
unavailable in that runtime. Test whether the destination supports the original
requirement. Do not invent options or emulate ancestry through another client.
If unavailable, report the exact limitation and continue independent authorized
work without declaring the orchestration requirement satisfied.

Use substantive workstreams with bounded file ownership and independent review.
Old handles gateway_lane, harness_lane, integration_audit, platform_watchdog_lane
belong to the earlier session and are not available on the destination.
Reconcile source results before assigning new work; do not restart finished
tasks just because their agents are gone.

Maintain concise resumable task/evidence records on the destination and in
appropriate repository documents. Do not rely on the previous assistant's
private state.

## 12. Practical validation commands

Read rust-toolchain.toml and CI first. The previous pinned toolchain was 1.97.1.
Examples from the successful watchdog validation:

cargo +1.97.1 fmt --all -- --check
cargo +1.97.1 build --workspace --all-targets --all-features --locked -j1
cargo +1.97.1 test --workspace --all-targets --all-features --locked -j1
cargo +1.97.1 clippy --workspace --all-targets --all-features --locked -j1 -- -D warnings
cargo +1.97.1 run --locked --manifest-path standards/tools/standards-sync/Cargo.toml -- validate --root .
cargo +1.97.1 test --locked -p ascension-watchdog --test real_harness_worker --test linux_boundary
cargo +1.97.1 test --locked -p ascension-platform-windows --all-targets

Use --offline only after provisioning dependencies. Choose task-specific
CARGO_TARGET_DIR and TMPDIR values on a disk with adequate capacity; never
repurpose HOME or CODEX_HOME. Cross-target compilation requires its actual
target/toolchain/linker and remains distinct from running on Windows.

For native Linux smoke, build the harness runtime from the chosen isolated
harness source first, obtain its SHA-256, and read the current fixture gates.
An explicit example, with locally resolved absolute paths, is:

ASCENSION_WATCHDOG_REAL_HARNESS_SMOKE=1 \
ASCENSION_WATCHDOG_REAL_HARNESS_HOLD_GATEWAY=1 \
ASCENSION_WATCHDOG_EXECUTABLE=<absolute-watchdog-image> \
STS2_HARNESS_RUNTIME_BINARY=<absolute-harness-image> \
STS2_HARNESS_RUNTIME_SHA256=<verified-image-sha256> \
<absolute-real_harness_worker-test-image> --ignored --exact \
real_watchdog_native_launch_reaches_built_harness_worker --nocapture

The angle-bracket values are placeholders, not executable shell arguments.
Run only in the verified scoped guest environment with its proper user bus,
immutable staged images, and cgroup authority. Compilation/default skipping
does not count as this test passing.

## 13. Required working outcome

Begin with a short reconciled status of the merged baseline and the next
executable task, then implement and verify. Do not stop at writing another
plan. Keep progressing across all unblocked requirements.

For each completed requirement, attach source revision, actual command/run,
exit/result, artifact identity, evidence location, and limitations. For every
remaining requirement, record the smallest concrete next action and its real
dependency. Do not call the entire assignment complete until the full
specification and its mandatory acceptance gates are satisfied, or explicitly
report the exact remaining externally blocked axes.

The full original assignment follows verbatim. Its initial instruction to
create/adopt the repository is already fulfilled; resume the merged baseline.
Historical machine/client assumptions must be checked on the destination.

---

# Original implementation assignment (full text)

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
