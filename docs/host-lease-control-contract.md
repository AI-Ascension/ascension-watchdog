# Host lease-control contract v1

Status: additive contract artifact. This document defines the wire and semantic
rules for `schemas/host-lease-control-v1/frame.schema.json`; it does not claim
that a gateway, managed host, or live game consumer has implemented it.

## Boundary and compatibility

`watchdog-host-lease-control-v1` is a separate authenticated sideband for
installing a gateway-issued lease at the managed host and synchronizing that
lease's renewal and revocation. The frozen `watchdog-recovery-v1` artifact is
unchanged. A recovery-v1 `lease_acquire_request` must not be forwarded to this
sideband: doing so would let the host mint a second authority instead of
installing the gateway's exact grant.

The frame has exactly these top-level fields:

```text
contract, schema_digest, message_id, correlation_id, sent_at, actor, auth,
kind, payload
```

The six closed kinds are:

```text
lease_install_request / lease_install_response
lease_renew_request   / lease_renew_response
lease_revoke_request  / lease_revoke_response
```

The request actor is the authenticated gateway and the response actor is the
authenticated host. `actor.principal_id` must equal `auth.principal_id`.
Requests use the matching `lease_install`, `lease_renew`, or `lease_revoke`
capability. Response proofs authenticate the host acknowledgment on the
protected gateway-to-host channel; a HTTP 2xx or a syntactically valid frame is
not itself an acknowledgment of a durable state transition.

Unknown fields, duplicate JSON member names, invalid UTF-8, wrong contract or
schema digest, invalid identities, unsupported kinds, and frames over 262144
bytes are rejected before a state mutation. The payload and authentication
proof are bounded as recorded in `manifest.json`.

## Grant and digest binding

Each request contains:

```text
installation_id, grant, grant_digest
```

Renewal adds `renew_sequence`; revocation adds `reason`. `grant` is closed and
contains the complete gateway-issued authority:

```text
boot, fence, lease, release, gateway
```

The `boot` object is the current READY gateway boot. `fence` is the current host
fence. `lease` contains the gateway lease, including host-fence ID and
generation, lease ID and epoch, token, issue/expiry timestamps, and bounded TTL
policy. `release` repeats the protected four-digest release identity. `gateway`
contains the authenticated gateway principal, instance, and session identity.

Consumers require all of these equalities before accepting a grant:

1. Boot, fence, lease, and gateway instance fields agree on deployment,
   instance, incarnation, boot, and authority generation.
2. The lease host-fence ID/generation equals the fence ID/generation.
3. `grant.release` equals `grant.boot.release` and the host's approved release
   and configuration identity, including all four digests.
4. `grant.gateway.principal_id` equals both top-level actor and auth principal;
   its instance and session are the authenticated gateway session.
5. `grant_digest` equals SHA-256 of the exact HCJ-1 canonical bytes of
   `payload.grant`.

HCJ-1 is a bounded canonical JSON profile for this grant. Object member names
are sorted by unsigned UTF-8 byte order; arrays preserve order; no whitespace
is emitted; wire-safe integers are emitted in decimal; strings use JSON
escaping; and no floating-point values are permitted. The proof is
domain-separated from the canonical frame/payload bytes:

```text
host-lease-control/v1/lease-install-request
host-lease-control/v1/lease-renew-request
host-lease-control/v1/lease-revoke-request
host-lease-control/v1/lease-install-ack
host-lease-control/v1/lease-renew-ack
host-lease-control/v1/lease-revoke-ack
```

The exact HMAC or equivalent authenticated proof mechanism is owned by the
transport/security implementation. It must cover the domain, contract and
schema digest, correlation, operation kind, installation ID, grant digest, and
all request or acknowledgment fields. Secrets and plaintext fence tokens are
never written to logs or durable journals.

## Install, acknowledgment, and retry

The gateway is the sole lease issuer. It transactionally persists the exact
grant, installation ID, digest, current boot/fence, and state
`PENDING_HOST_INSTALL` before sending the request. The host validates the
current boot/fence/release and then durably journals the exact grant and active
installation before returning `INSTALLED`. The host must fsync or use its
equivalent durable commit boundary before emitting that acknowledgment.

The response payload contains one closed `ack` object. It echoes the
installation ID, grant digest, boot/incarnation, host-fence identity, lease
identity, a host installation generation, and the host's durable timestamp.
Successful install acknowledgments use `INSTALLED`; a repeated request with the
same installation ID and byte-identical grant uses `DUPLICATE` and replays the
original durable acknowledgment identity. Reusing an installation ID with a
different grant, or presenting the same lease under a different installation
identity, is `CONFLICT`.

If the gateway times out, disconnects, or loses the acknowledgment after the
request may have been written, it retains `PENDING_HOST_INSTALL`/unknown state.
It retries or reconciles the same installation ID, grant, digest, and current
correlation lineage. It must not mint a replacement lease merely to escape the
uncertainty. Mutation readiness and operation admission remain blocked until a
matching `INSTALLED` or `DUPLICATE` acknowledgment is durably recorded by the
gateway.

`PERSISTENCE_UNAVAILABLE` and transport uncertainty are retryable. Context,
authorization, release, lease, and expiry errors are not silently retried with
different authority. `retryable` and `retry_after_seconds` are advisory only;
the status and identity match are authoritative.

## Renewal and revocation

Renewal carries the same installation ID and complete grant, with the gateway's
new exact expiry and a strictly increasing `renew_sequence`. The host checks
that the installed grant is the same lease/boot/fence/release authority, that
the grant is not already expired, and that the sequence advances. It durably
records the renewal before acknowledging `RENEWED`. A repeated identical
sequence and grant replays the original acknowledgment as
`RENEW_DUPLICATE`; a sequence conflict is rejected. Renewal never installs a
missing lease and never creates a new lease ID.

Revocation carries the same installation ID and exact grant plus one bounded
reason. The host durably records revocation before acknowledging `REVOKED`.
Repeating the same revocation is `REVOKE_DUPLICATE`; a lost response leaves the
gateway blocked and retrying the same revocation identity until it receives a
matching acknowledgment or a current-authority reconciliation result.

`host_install_generation` identifies the durable host installation record and
does not replace the lease epoch. It is echoed on every acknowledgment. A
renewal does not create a new installation generation; a fresh install after a
new authority context does.

## Time, fences, and restart

The lease policy is bounded by `1 <= renewal_interval < ttl <= 300`, with the
usual default of 10 seconds and 30 seconds. Timestamps are audit data. Each
implementation uses a monotonic deadline for in-process expiry and rejects an
expired grant at install, renewal, admission, and execution time. Clock
suspend/resume ambiguity blocks mutation and requires revocation/rekey.

Every queued ticket and host execution rechecks the installed grant against the
current deployment, instance, incarnation, boot, authority generation,
host-fence ID/generation, lease ID/epoch, and unexpired deadline. A changed
observation or a current HTTP success cannot replace those checks.

A gateway restart creates a fresh boot/incarnation/authority generation and
does not expose a persisted lease as active. A host restart may replay its
journal for history, but a replayed grant is not active until a fresh matching
install is durably committed. Old boot, incarnation, fence, release, or gateway
session values are rejected. During one unchanged authority context, lost-ACK
retries use the same grant. After authority rotation, the old grant is first
retained as stale/unknown history; only then may a new grant be issued under
the new boot and fence.

## Semantic test boundary

JSON Schema cannot prove equality between nested fields, cryptographic proof
validity, monotonic renewal, timestamp ordering, durable-before-ack behavior,
or crash/reconnect outcomes. The executable contract tests therefore assert:

- all valid lifecycle fixtures have closed shape and coherent cross-field
  identity;
- unknown fields are rejected;
- grant digests are exact HCJ-1 bytes;
- mismatched boot/fence/release/gateway identities are rejected;
- expired or non-advancing renewals are rejected; and
- duplicate install/renew/revoke identities preserve the same grant lineage.

These artifacts establish the wire contract only. They do not prove consumer
integration, a durable gateway, a managed host, a live game, reboot recovery,
or release readiness.
