# Worker handoff v1: integration contract

Status: accepted identity and lifecycle design after W26 review; transport, scheduler, and harness
consumer implementation are **not yet verified**. This replaces the unintegrated
W23 proposal. No automatic scheduler is enabled by this document.

## Ownership and configuration

The watchdog schedules jobs and supervises the configured harness component.
The harness exclusively owns episodes, provider calls, MCP, and its execution
database. Neither owner opens the other's database. A worker request cannot
select an executable, argument, environment, credential, endpoint, seed, model,
save, or arbitrary path. The first operation is `runtime_v3_episode`; its job
parameters are exactly an empty object. Experiment settings come exclusively
from an explicitly approved, digest-bound harness worker profile. Reconstruction
requires a separate explicit operation; dispatch cannot imply reconstruction.

Enabling scheduling requires a configured worker component with a mandatory
executable hash, immutable release/config/profile binding, dedicated protected
local endpoint and credential references, and this contract's exact schema
digest. Missing configuration leaves jobs queued, not claimed and failed.
Only a verified live worker from the configured component may receive dispatch.
The single-instance deployment has one durable worker reservation, including
unknown attempts. A new worker boot does not free that reservation.

## Durable identity

The logical identity is the complete tuple:

`(deployment_id, job_id, attempt_id, attempt_number, worker_owner_id,
worker_profile_digest, run_id, episode_id, trajectory_id, payload_digest)`.

`job_id` and `attempt_id` are exactly the watchdog's existing durable IDs.
`attempt_number` is its checked positive attempt sequence. `worker_owner_id` is
the stable configured component identity, not a caller-selected worker string.
The watchdog allocates distinct random UUIDv4 run/episode/trajectory identities
and persists the entire tuple with the claim before any worker IPC. Each tuple
has a separately allocated random UUIDv4 `handoff_id`; it is **not** a concatenated
path, hash-derived UUID, or transport request ID. Uniqueness constraints cover
handoff ID, attempt ID, and episode ID. A known existing job/attempt with a
different tuple is a conflict even if a new handoff ID is supplied.

`payload_digest` is SHA-256 of the canonical UTF-8 bytes `{}` for this operation.
All digests are 64 lowercase hexadecimal characters. Durable IDs obey existing
owner bounds; new run/episode/trajectory/handoff IDs use lowercase canonical
UUIDv4 syntax. The harness persists the exact tuple, maps attempt ID to its
execution lineage and claim token, and never generates replacement lineage
on receipt of an existing handoff. The worker profile digest binds the complete
approved execution configuration, not replaceable transport credentials.

Worker **boot** identity is separate: a fresh UUIDv4 generated on worker startup
and bound to the supervised OS process creation identity and launch nonce.
Dispatch specifies the current worker boot. Lookup and acknowledgment carry the
original tuple but target an independently authenticated current worker boot;
a terminal record from an earlier boot is historical evidence, not permission
to resume its mutations. Watchdog restart follows the same distinction.

## Framing and authorization

Contract name: `ascension-watchdog-worker-handoff-v1`. An additive frozen JSON
schema and conformance fixtures must be committed before transport consumers
are enabled. No existing runtime-v3 or recovery artifact is modified.

Frames use a four-byte unsigned big-endian body length and at most 65,536 UTF-8
JSON bytes, with maximum JSON nesting 16. All objects are closed and duplicate
members are rejected recursively before typed decoding. A frame carries exact
contract/schema digest, a new UUIDv4 request ID, caller boot, target worker boot,
and a command with its closed scope described below. Job-command responses echo
the request ID, current worker boot, and complete tuple; mismatches retain
uncertainty.

The transport is a protected Unix socket or Windows named pipe. Authenticate
both peer OS/process identity and a dedicated control credential; operator
read/admin tokens and gameplay leases are not worker credentials. Never log or
persist credentials in handoff records. Historical lookup is read-only and
cannot dispatch. Authentication must precede queue or database admission.

Each connection has one absolute monotonic deadline of at most five seconds,
starting before connect. Partial successful I/O does not reset it. No absolute
wall-clock deadline or monotonic value crosses process boundaries. A bounded
relative `timeout_ms` (1..5000) may reduce the server's local deadline but cannot
extend the connection bound. Limit clients and queued calls independently;
worker control cannot block behind model inference or wait for an episode.

Bootstrap uses a read-only `probe` command. It has no job tuple, handoff ID, or
target worker boot: the client verifies the server's held process creation
identity against its configured live component before accepting the reply.
The reply supplies fresh worker boot, stable owner, deployment, exact
profile/release/config/schema bindings, and non-admitting readiness. Probe
cannot initialize a store, establish control, claim a job, or start an episode.

`set-control-mode` also has no handoff ID or job tuple. Its control scope is
exactly deployment, stable worker owner, profile digest, current watchdog boot,
target worker boot, mode, and positive sequence. Its response echoes that scope
after durable commit. Thus Running control can be acknowledged before the first
claim. Dispatch, lookup, and acknowledgment carry the complete handoff tuple.

## State transitions and completion

1. The reconciliation owner verifies Running mode, acknowledged current Running
   worker control, a ready configured worker,
   an eligible queued job (including its actual `next_retry_at_ms`), no reserved
   attempt, and exact release/profile compatibility. In one transaction it
   claims the job and persists the tuple and `prepared` handoff.
2. Before IPC, it rechecks durable mode and reservation, then commits
   `may_have_been_dispatched`. Only this commit authorizes the single dispatch
   send. Failure or crash at any later point permits lookup, **not redispatch**.
3. The worker validates current dispatch authority and tuple, persists admission
   and claim before starting execution, and responds promptly. Duplicates return
   retained state without a second execution. Conflicting tuples are rejected.
4. The worker commits its episode completion and matching compact terminal
   receipt before reporting terminal. A crash between episode completion and
   receipt projection is repaired from the matching durable completion, never
   by starting the episode again. A terminal receipt contains the complete
   tuple, completion status, checkpoint sequence, terminal reference, and result
   digest; it contains no provider output or arbitrary observations.
5. The watchdog validates and commits its matching completion plus acknowledgment
   intent atomically, then sends acknowledgment. Repeated matching acknowledgments
   are harmless. Lost acknowledgment never returns the job to the queue.
   Acknowledgment is delivery state, not a successful execution outcome. The
   retained terminal receipt determines whether job/attempt projections must
   remain completed or failed, including after owner-store reopen.

The only commands are probe, dispatch, lookup, acknowledge, and set-control-mode.
Lookup never starts/resumes an episode; missing, running, rejected, transport
failure, process exit, and incompatible records are not terminal completion.
An explicit terminal failure remains failure; it does not authorize automatic
new execution. Initial v1 conservatively quarantines any uncertain handoff.
Prepared rows after restart also remain held for explicit recovery; absence
of a send marker must not silently free an unrelated unknown reservation.

Terminal lookup may finish accounting while paused/stopped/quarantined, but it
cannot restore Running or resume work. Completed and acknowledged deduplication
records have a bounded documented retention horizon; unresolved rows are never
evicted. Capacity is backpressure, not evidence of completion.

## Pause, stop, and control ordering

The worker's control-mode ledger is separate from its completion ledger.
It starts non-admitting after every process boot. The watchdog persists desired
mode first. Authenticated set-control-mode messages bind the current watchdog
and worker boot and carry a checked monotonically increasing mode sequence.
Older sequences cannot restore Running after a newer pause/stop. Dispatch is
bound to the currently acknowledged Running sequence. Replacement of a watchdog
boot requires explicit current-owner authentication and invalidates the old
control session, never a greater caller-provided integer alone.

The worker observes pause before each new provider decision and mutation
dispatch. In-flight provider usage and host uncertainty remain accounted for.
Stop/pause is not retroactive cancellation of a dispatched host effect. If a
control update cannot be acknowledged, keep the job unknown and use the existing
exact-process containment owner for bounded cleanup; do not report quiescence.
Control connectivity loss closes new admission within a configured monotonic
deadline independently of model inference. Only current authenticated Running
control can reopen it; stale dispatch frames cannot do so.

## Required executable acceptance

Use eligible injected timestamps and an explicitly approved worker in the
scheduler regression. Test no configuration, incompatible profile, future job,
stopped/paused mode, and occupied reservation all produce zero claims/sends.
Then exercise actual daemon-to-worker IPC, owner-local stores and harness runtime,
not a manual Store completion or mock-only adapter. Crash tests cover every
claim/send/admit/episode-complete/receipt/ack boundary, fresh worker/watchdog
boots, response loss, completion lookup, stale mode messages, and uncertainty
without redispatch. The same terminal episode must produce one provider/execution
count before and after restart. Native process/service and live-host evidence
remain separate from this synthetic protocol suite.
