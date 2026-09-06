# Recovery sideband threat model

Status: proposed design input for `watchdog-recovery-v1`. This is a contract
threat model, not a claim that the current product repositories enforce these
controls.

## Assets and safety properties

- The current deployment authority, lease epoch, host fence, and instance
  incarnation must not be forged, replayed, or revived after replacement.
- Operation identity, canonical payload digest, expected boundary, admission
  ticket, receipt, and effect witness must remain linked and auditable.
- An unresolved operation must remain conservative `UNKNOWN`; a retry must not
  create a second mutation or erase evidence.
- Approved release/config/profile/schema digests, protected saves, consent,
  provider policy, credentials, and operator stop/pause intent must not change
  implicitly during recovery.
- Bounded storage, queues, subprocesses, payloads, and credentials must not be
  exhausted or exposed by an untrusted local client.

## Trust boundaries

1. The watchdog process and its owner-local store supervise deployment desired
   state but do not own gameplay authority.
2. The gateway authority store and process own boot/lease/operation state. A
   watchdog restart or harness reconnect cannot grant a lease.
3. The host broker/game boundary owns the current execution fence and validates
   admission tickets immediately before game-thread mutation.
4. The harness owns MCP stdio and provider lifecycle. The sideband cannot attach
   a second reader/writer or infer provider results.
5. Operators and bootstrap credentials are separate capabilities from gameplay
   leases and historical read access.
6. Telemetry/exporters are observers. Their outage cannot grant mutation or
   cause an intentional pause/stop to be ignored.

## Adversaries and failure sources

| Source | Attack or failure | Required containment |
| --- | --- | --- |
| Stale gateway/harness/controller | Replays an old boot, lease, queued request, or ticket after replacement | Fresh boot/incarnation namespaces, durable revocation, current-fence checks before forwarding and at execution |
| Duplicate supervisor | Opens the same deployment store or launches a second controller | Owner-local singleton lock and one restart-decision owner; return `BUSY` |
| Malicious local client | Uses read, historical, or telemetry credentials to dispatch, stop, rekey, or launch | Capability-separated authenticated channels; current authorization on every mutating endpoint |
| Untrusted game text/model output | Injects JSON, paths, commands, credentials, or policy changes | Closed bounded schemas, no arbitrary proxy/command fields, digest allowlists, credentials outside frames |
| Compromised child/broker | Survives a parent, spoofs health, or mutates after lease expiry | Concrete process identity/launch nonce, OS containment, broker authentication, execution-time fence |
| Transport attacker/replay | Modifies or replays a frame or proof | Authenticated local IPC, correlation/message identity, canonical digest, capability and digest checks |
| Storage attacker/corruption | Replaces, truncates, rolls back, or symlinks a journal | Protected owner-local directory, integrity/migration checks, backup/rekey workflow, block on uncertainty; never silently reset |
| Resource exhaustion | Sends oversized frames, many operations, long logs, or unresolved receipts | 256 KiB frame and 64 KiB action limits, bounded queues/retention, backpressure, unresolved records never evicted |
| Clock/suspend ambiguity | Makes an expired lease appear live | Monotonic in-process deadlines, separate audit timestamps, invalidate on suspend/resume ambiguity |
| Partial upgrade | Presents an identical profile name with incompatible bytes | Release/config/profile/runtime-v3 digests and all-consumer compatibility checks |
| Crash at an effect boundary | Effect happens but receipt/persistence is lost | Persist intent and uncertainty first; retain `UNKNOWN`; reconcile original operation only; do not promise exactly once |

## Control requirements

### Authentication and authorization

All endpoints are local by default and still authenticated. `bootstrap`,
`host_fence`, lease, operation-submit, historical-read, and reconcile
capabilities are distinct. A proof is transport-bound and never written to a
journal, log, fixture, or diagnostic bundle. A historical read response is
explicitly `mutation_authorized:false`.

### Replay and identity

Every current authority check compares deployment, logical instance, process
incarnation, boot id, authority generation, lease id/epoch, host fence, and
expiry. Message retries may change `message_id`, but operation retries retain
the operation id and payload digest. An old authority can be retained for audit
but cannot satisfy a current mutation check.

### Input and path safety

The sideband has no executable path, argument, environment, shell, save path, or
credential field. Those are owner-specific configuration inputs and must be
validated against approved allowlists at their own boundary. Implementations
must reject duplicate JSON keys, unknown fields, invalid UTF-8, non-canonical
action bytes, invalid UUIDs, integer overflow, unsafe paths/reparse points, and
unbounded output. Do not expose a generic forwarding endpoint.

### Persistence and rollback

Authority and operation owners must use a local transactional store with an
exclusive owner. They must fail closed on missing/corrupt/incompatible state,
disk-full, read-only filesystems, migration interruption, or uncertain commit.
Backup restoration is a rekey operation: revoke/terminate old controllers and
hosts, create a new deployment/boot/authority namespace, and remain blocked until
the new host fence is established. A counter restored from the same backup is not
anti-rollback protection.

### Effect uncertainty

`MAY_HAVE_BEEN_DISPATCHED` is committed before transport handoff. Timeout,
connection loss, receipt loss, changed observation, generation movement, or
`not_found` cannot prove non-execution. Only an operation-specific authoritative
receipt/effect witness can support settlement. Otherwise preserve `UNKNOWN` and
quarantine or reconstruct under explicit policy. Exactly-once host effects are
not claimed across the host-mutation/receipt-persistence crash window.

### Availability and resource limits

The safe response to uncertain authority is a bounded blocked state with
read-only diagnostics. Renewal is independent of model inference and defaults to
30-second TTL/10-second renewal. Active operation retention is bounded only after
resolution; unresolved records remain. Payloads, queues, response text, logs,
receipt archives, child output, and recovery attempts require explicit limits.

## Residual risks and evidence gates

- A compromised host process can still perform an effect during a narrow
  execution race unless the host's fence and mutation are implemented at one
  authoritative boundary. The contract therefore requires execution-time checks
  and does not claim perfect exactly-once behavior.
- A restored or malicious storage layer may defeat a monotonic counter; only an
  external anti-rollback mechanism or mandatory rekey closes that risk.
- A valid witness can be semantically wrong if the host implementation does not
  bind it to the exact operation. Witness source and identity must be tested at
  the host boundary.
- Local authentication, Windows ACLs/named pipes, Linux permissions/cgroups,
  process identity, and secure secret storage remain platform-specific and need
  separate implementation and native tests.

The required evidence is source plus executable tests for every trust boundary:
competing owners; stale proofs; duplicate/conflicting operations; crash windows;
disk rollback/corruption; resource bounds; suspend/resume; host fence races; and
independent telemetry/provider failure. Schema conformance alone cannot prove
these properties.
