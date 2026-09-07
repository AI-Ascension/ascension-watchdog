# Watchdog recovery contract v1

Status: proposed companion contract. This document is normative for the
`schemas/recovery-v1/frame.schema.json` artifact, but it does not claim that any
gateway, host, mod, harness, or watchdog implementation already implements it.

## 1. Boundary and compatibility

`watchdog-recovery-v1` is an additive, authenticated sideband used for authority
bootstrap, host fencing, lease lifecycle, operation journaling, and recovery. It
does not replace or alter the frozen `runtime-v3-gameplay` envelope. A v3 action
is carried in `payload.action.canonical_json_b64`; the receiver must decode it,
validate it against the exact approved runtime-v3 schema, and compare its digest
with `payload_digest` before admission.

The sideband frame has exactly these top-level fields:

```text
contract, schema_digest, message_id, correlation_id, sent_at, actor, auth,
kind, payload
```

Every object is closed. Unknown fields, duplicate JSON member names, invalid
UTF-8, non-canonical action bytes, an unexpected `schema_digest`, or a frame
over `262144` bytes are rejected before state mutation. A decoded action and its
canonical JSON representation are each limited to `65536` bytes. Queues,
responses, and diagnostic strings must be bounded by the owning implementation.

The contract artifact is neutral and is not silently copied into an existing
protocol release. If the protocol repository accepts publication, it must publish
this exact artifact (or a reviewed, digest-changing version), update all real
consumers together, and reject mixed release/profile/schema digests. A shared
profile name is not compatibility evidence.

## 2. Canonicalization and digests

This v1 contract deliberately uses a bounded canonical subset rather than
calling an arbitrary language serializer "JCS". `RCJ-1` (Recovery Canonical
JSON profile 1) is the only canonicalization accepted for an operation action:

1. Decode `canonical_json_b64` as UTF-8 and reject a byte-order mark, duplicate
   member names, control characters, non-ASCII characters, escapes, floating
   point values, negative numbers, and numbers with leading zeroes.
2. Permit only the frozen runtime-v3 `legal_action` shape: an object with
   `action_id` and `action`; the nested action has one of the existing ASCII
   `kind` values and only its schema-approved ASCII identity fields or `null`.
   The frozen schema limits identities to `[A-Za-z0-9_.:/-]` and all action
   values are strings, enum values, or `null`; no Unicode or numeric action
   value is needed by this profile.
3. Emit UTF-8 bytes with no whitespace. Sort each object's ASCII member names by
   unsigned UTF-8 byte order and emit strings without escapes. Emit `null` and
   the permitted literal enum values exactly as written. Arrays are not part of
   the action grammar and are rejected.
4. Compute SHA-256 over those exact emitted bytes. The digest is lowercase
   hexadecimal with exactly 64 characters and no `sha256:` prefix.

This restriction is intentional: ASCII keys/values and integer-free action
variants have identical ordering and scalar representations in Rust and C#.
Future action inputs requiring Unicode, arrays, or numbers must define a new
contract version and ship cross-language golden vectors before admission. A
consumer must not substitute `serde_json::to_string`, a default C# serializer,
or a JSON pretty-printer for RCJ-1.

Release artifact digests (`schema_digest`, release/config/profile/runtime-v3 schema) are
SHA-256 of the exact approved immutable artifact bytes named by the
release manifest, not a reserialized object. This makes release inspection
reproducible across languages. Producers still reject duplicate JSON member
names, invalid UTF-8, and values outside the closed schema. The resulting
digest is lowercase hexadecimal with exactly 64 characters and no `sha256:`
prefix.

Digest meanings are distinct:

| Field | Bytes covered | Stable across |
| --- | --- | --- |
| `schema_digest` | Exact approved bytes of `frame.schema.json` | retries and all authorities using the same contract artifact |
| `release_digest` | Exact approved release-set manifest bytes | process restarts only when the release is unchanged |
| `config_digest` | Exact approved non-secret configuration bytes | process restarts only when configuration is unchanged |
| `profile_digest` | Exact approved runtime/profile declaration bytes | process restarts only when profile is unchanged |
| `runtime_v3_schema_digest` | Exact frozen runtime-v3 schema bytes | all v3 participants in that release |
| `payload_digest` | RCJ-1 bytes obtained by decoding `canonical_json_b64` | operation retries, reconciliation, and archival |
| `catalog_digest` | Exact UTF-8 bytes of the `legal_actions` JSON value emitted by the authoritative host under the approved profile | the verified state boundary |
| `effect_digest` | Exact approved witness bytes | only the exact witness, never an observation merely adjacent in time |

The catalog is a state-scoped artifact, not the release's profile declaration.
Its byte range starts at the array's opening bracket and ends at its matching
closing bracket in a validated successful host response; outer whitespace and
envelope fields are excluded. Inner whitespace, ordering and escapes remain
part of the bytes. Consumers must retain/hash that raw value, not deserialize
and reserialize it. Bind the catalog to instance incarnation, session/lease,
state ID and gameplay generation. Retention is bounded; a missing current
artifact requires a fresh observation, not a substitute digest. An existing
operation retains its original binding across lookup, retries and archival.
The approved release pins the producer/profile and byte rule, while each
operation records its dynamic catalog digest. Frozen runtime-v3 wire fields
are unchanged. Consumer conformance requires exact-byte cross-language tests;
this clarification alone is not proof that existing consumers conform.

`schema_digest` is listed in `manifest.json` and must match every frame. The
sideband action's `schema_digest` is separately checked against the approved
`runtime_v3_schema_digest`; these two fields must not be conflated.

## 3. Wire endpoints and capabilities

Endpoints are local/authenticated control endpoints. The transport may be HTTP
over a protected local channel or an equivalent authenticated IPC adapter, but
the request and response bodies are always the closed frames in this artifact.
No endpoint accepts arbitrary command text, executable paths, or an unbounded
proxy request.

| Endpoint | Request/response kinds | Caller capability | Linearization or safety rule |
| --- | --- | --- | --- |
| `POST /v1/recovery/bootstrap` | `bootstrap_request` / `bootstrap_response` | `bootstrap` | exclusive store ownership, integrity/release checks, fresh boot record and prior-lease revocation commit |
| `POST /v1/recovery/host-fence` | `host_fence_request` / `host_fence_response` | `host_fence` | host atomically replaces its accepted boot fence; no gameplay admission until success is durably recorded |
| `POST /v1/recovery/lease/acquire` | `lease_acquire_request` / `lease_acquire_response` | `lease_acquire` | fresh lease id/token and current boot/incarnation only |
| `POST /v1/recovery/lease/renew` | `lease_renew_request` / `lease_renew_response` | `lease_renew` | monotonic renewal sequence; inference is not on the renewal path |
| `POST /v1/recovery/lease/revoke` | `lease_revoke_request` / `lease_revoke_response` | `lease_revoke` | durable revocation precedes cleanup; revocation cannot claim an already-running effect was undone |
| `POST /v1/recovery/operation/intent` | `operation_intent_request` / `operation_intent_response` | `operation_submit` | durable `INTENT_RECORDED` before dispatch is possible |
| `POST /v1/recovery/operation/dispatch` | `operation_dispatch_request` / `operation_dispatch_response` | `operation_submit` | durable `MAY_HAVE_BEEN_DISPATCHED` before handing work to host transport |
| `POST /v1/recovery/operation/lookup` | `operation_lookup_request` / `operation_lookup_response` | `recovery_read` | historical read only; response is always `mutation_authorized:false` |
| `POST /v1/recovery/operation/reconcile` | `operation_reconcile_request` / `operation_reconcile_response` | `recovery_reconcile` | addresses the original operation identity and digest; never sends the mutation again |

HTTP/IPC adapters map the closed `result.status` values to bounded transport
responses. `AUTH_REQUIRED` is 401; `FORBIDDEN` is 403; `NOT_FOUND` is 404;
`CONFLICT`, `STALE_BOOT`, `STALE_INCARNATION`, `STALE_LEASE`, and `CONTRACT_MISMATCH`
are 409; `LEASE_EXPIRED` is 410; `BUSY` is 423; `BOUNDS_EXCEEDED` is 413;
`PERSISTENCE_UNAVAILABLE` and `HOST_NOT_READY` are 503; and `INVALID` is 400.
Successful operation results use 200 or 202 according to whether the requested
transition is durably complete. The status value, not HTTP success alone, is
authoritative.

## 4. Identity lifetimes

Every identity is a separate namespace. Implementations must persist the
identity and its relation before using it as an authorization or deduplication
key.

| Identity | Lifetime and replacement rule |
| --- | --- |
| `deployment_id` | Stable for one installed deployment. Uninstall/re-initialize creates a new deployment namespace; backup restore never reissues the old authority. |
| `instance_id` | Stable logical slot inside a deployment. It does not identify a process. |
| `instance_incarnation` | Fresh unpredictable UUIDv4 for every game-host process attempt, including a replacement after crash. Never reused after stop, rollback, or restore. |
| `boot_id` | Fresh unpredictable UUIDv4 for every gateway authority boot. Never restored or reused. |
| `authority_generation` | Persisted positive wire-safe counter, strictly increasing at each authority replacement. Exhaustion blocks admission. Backup rollback requires operator-approved rekey and a new namespace; a restored counter alone is not rollback protection. |
| `lease_id` and `lease_epoch` | Fresh lease id and strictly checked epoch for each gameplay authority grant. Expiry/revocation is terminal for that grant. |
| `fence_token` | Unpredictable transport-bound token for one active lease; never logged or journaled in plaintext. |
| `host_fence_id`/`fence_generation` | Host-side current fence for a boot context. Replaced atomically when a new boot is accepted; old fences reject queued work. |
| `message_id` | Fresh per frame. A transport retry may use a new message id but must retain the same correlation and operation identity. |
| `correlation_id` | Stable for one request/response exchange and reconnect-safe; it is not an authority or operation identity. |
| `operation_id` | Fresh at intent and stable through every retry, receipt, reconciliation, archive, and tombstone. Never assign a new id to evade deduplication. |
| `ticket_id` | Fresh admission ticket for one operation/host fence. It is not valid after expiry, incarnation replacement, or fence replacement. |
| `witness_id` | Fresh identity for one authoritative operation-specific effect witness. A changed generation or latest observation alone cannot manufacture a witness. |

The `original_context` stored with an operation is immutable and contains
deployment, instance, incarnation, boot, authority generation, lease id, and
lease epoch. The current recovery authority is supplied separately by the
authenticated request; it must never overwrite the original context.

## 5. Boot, fence, and lease protocol

The gateway owner performs this sequence while mutation admission is closed:

1. Acquire the exclusive owner-local authority-store lock. A second gateway
   receives `BUSY` and cannot become a controller.
2. Validate integrity, migrations, release/config/profile digests, and rollback
   markers. Missing, corrupt, incompatible, or persistence-failing state blocks
   admission; it is not recreated as epoch 1.
3. Generate a fresh `boot_id`, verify a non-exhausted
   `authority_generation + 1`, and transactionally write the new boot context
   while revoking every previous active lease. The successful commit is the
   authority replacement linearization point.
4. Complete `POST /v1/recovery/host-fence`. The host atomically records the new
   fence and rejects old boot, lease, instance-incarnation, and fence proofs.
5. Persist the successful handshake and mark the boot `READY`. Only then may a
   lease be acquired or operation intent admitted.

If the process dies between steps 3 and 5, a subsequent boot creates another
fresh context and repeats the handshake. It does not resume the old context.
If a host effect was already executing, its operation remains `UNKNOWN` until
reconciled; lease rotation is not cancellation evidence. Queued work is checked
again at host execution time, not only when it enters the gateway queue.

The default policy is TTL 30 seconds and renewal every 10 seconds. Configuration
may choose another bounded TTL/interval only when `1 <= renewal < ttl <= 300`
and the approved config digest changes. In-process expiry uses a monotonic clock;
wall-clock timestamps in frames are audit data only. Renewal runs independently
of model inference. Suspend/resume or monotonic-clock ambiguity revokes the
lease and requires a new boot/fence handshake.

## 6. Operation and ticket semantics

An operation intent contains the stable operation id, immutable original
authority context, expected state/catalog boundary, exact frozen v3 schema
digest, canonical action bytes, and payload digest. The gateway transactionally
records `INTENT_RECORDED` before any host handoff.

The dispatch operation accepts only an existing matching intent and current
lease/fence. In one owner-controlled transition it records
`MAY_HAVE_BEEN_DISPATCHED` and only then gives the operation to the host broker.
The host persists an `admission_ticket` bound to operation id, payload digest,
boot id, instance incarnation, lease epoch, host fence id, and ticket expiry
before queueing game-thread work. The game-thread boundary checks all of those
claims again immediately before mutation. A ticket state progresses only as:

```text
ISSUED -> ADMITTED -> EXECUTING -> EFFECT_WITNESS_RECORDED -> SETTLED
                                  \-> UNKNOWN
             \-> REJECTED
```

The operation state machine is:

```text
INTENT_RECORDED -> MAY_HAVE_BEEN_DISPATCHED
                 -> ACCEPTED | SETTLED | REJECTED | UNKNOWN
                 -> RECONCILED
```

The `UNKNOWN` state is mandatory after a timeout, connection loss, gateway or
host crash, missing receipt, or persistence failure after a possible send. A
generation change, `not_found`, changed observation, HTTP conflict, or missing
receipt is not proof of non-execution. Reconciliation may use only the original
operation id/digest and an authoritative receipt or operation-specific witness.
It must not invoke the mutation or create a replacement operation id. If safety
cannot be proven, leave `UNKNOWN` and quarantine/reconstruct according to the
approved policy.

Submitting the same operation id and identical payload digest returns the
retained record with response status `DUPLICATE`; it never sends a second
mutation. Reusing the id with a different payload digest returns `CONFLICT`.
Unresolved records are never evicted. Resolved records may be archived only
after the documented retention horizon and with a deduplication tombstone.

## 7. Historical recovery and authorization

`operation_lookup` is a read-only historical query. The caller presents current
authenticated `recovery_read` authorization and the immutable original context,
operation id, and payload digest. The response may return the record, receipt,
ticket, witness, or `NOT_FOUND`, but always sets `mutation_authorized:false`.
An old gameplay lease, old boot proof, or historical receipt cannot activate a
new mutation path.

`operation_reconcile` additionally requires current `recovery_reconcile`
authorization and the current host fence. Its strategy is one of `reobserve`,
`receipt_lookup`, or `quarantine`; none permits dispatch. A witness must identify
the exact operation and authoritative host source. A new authority may then
record `RECONCILED` only after the evidence is sufficient under the owner policy.

## 8. Required rejection rules

The implementation must fail closed with the corresponding bounded status for:

- missing/invalid auth, capability mismatch, replayed proof, or old authority;
- old `boot_id`, wrong `authority_generation`, expired/revoked lease, wrong
  `instance_incarnation`, wrong host fence, or stale queued ticket;
- missing, corrupt, rolled-back, incompatible, or unavailable persistence;
- runtime-v3 or recovery schema digest mismatch, release/config/profile mismatch,
  non-canonical action bytes, digest mismatch, or unknown fields;
- operation-id payload conflict, operation not found, invalid transition, or
  attempt to reconcile by dispatching;
- duplicate JSON members, invalid UUID/UUIDv4 identity, wire integer overflow,
  unsafe payload size, unsupported strategy, or exceeded queue/retention limits.

Telemetry and status readers may remain available during a persistence or
telemetry failure, but they cannot turn a blocked authority into a mutation
authority. `STOPPED`, `PAUSED`, `QUARANTINED`, and operator revocation always
take precedence over autonomous recovery.

## 9. Conformance fixtures and implementation gates

The `fixtures/valid` directory contains representative bootstrap, intent,
historical lookup, and reconcile frames. The `fixtures/invalid` directory must
be rejected by the schema validator for unknown fields, stale contract version,
and over-bounded action bytes. Companion implementation tests must additionally
exercise semantic rules that JSON Schema cannot express (digest equality,
identity cross-field equality, monotonic transitions, capability authorization,
durable ordering, and crash windows).

Before integration is accepted, owners must provide executable tests for:

1. competing gateways and boot linearization;
2. crash before/after boot commit, host fencing, intent, uncertainty, send,
   ticket admission, host mutation, receipt, and result persistence;
3. duplicate identical operation and conflicting payload reuse;
4. stale boot/lease/incarnation/fence proofs, including queued work;
5. historical lookup without mutation authority;
6. lease TTL/renewal with injected monotonic time and suspend ambiguity;
7. unresolved-operation retention beyond current small capacity bounds;
8. digest, canonicalization, frame-size, and closed-field rejection.

These artifacts establish the contract only. A passing schema check is not
evidence of a durable gateway, host, live game, reboot, or soak implementation.
