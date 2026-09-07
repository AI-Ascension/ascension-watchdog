# Recovery integration seams

Status: source-derived defects; proposed contract resolution, not implemented
or integration-verified. Frozen runtime-v3 artifacts must remain unchanged.

## Gateway-issued lease installation

The recovery-v1 `lease_acquire_request` contains only `boot` and `fence`.
Its response contains the newly issued lease. Gateway currently acquires that
lease in its own store, while the managed host has a separate lease store.
Forwarding the existing acquire request would create another issuer, not
install the gateway's exact authority. Renewal must not implicitly create a
missing lease, and operation admission must not implicitly install authority.

Implement an explicitly versioned gateway-to-host lease installation contract
through the contract owner. It must bind the complete gateway-issued lease,
current boot and host fence, protected release/config identity, and authenticated
gateway identity. Bound all fields and reject unknown/duplicate fields. Publish
its digest and update both consumers and the release-set manifest together.
Do not add fields silently to recovery-v1 or reinterpret a renewal as install.

Gateway persists issuance before sending installation. The host durably installs
the exact grant before acknowledging. Gateway must not expose mutation readiness
until an authenticated, identity-matching acknowledgment is recorded. Lost
installation acknowledgment requires idempotent installation/reconciliation of
the same grant; it must not mint a replacement grant to evade uncertainty.
Revocation and renewal require corresponding host synchronization and
execution-time expiry checks. Partial failure blocks admission and retains
durable history. Tests must cover each commit/send/ack boundary and restart.

## Exact catalog artifact

Gateway `service_recovery_v3.rs` currently substitutes `profile_digest` for
`catalog_digest`. Managed `RuntimeV3GameplaySupport.cs` hashes a pipe-delimited
string assembled from actions, while its actual responses use
`FairPlayProjection` and `SerializeEnvelope`. Neither establishes agreement on
the exact action-catalog artifact required by the recovery contract.

Proposed resolution: define the boundary artifact as the exact UTF-8 JSON value
bytes of `legal_actions` in a validated authoritative host response. The host
must produce and retain those bytes through one serialization path, and use
that same artifact for admission checks. The gateway must extract raw bytes,
not deserialize and reserialize them. Bind retained bytes/digest to state ID,
gameplay generation, instance incarnation, and active authority. Retention is
bounded; missing or invalidated catalog requires a fresh read, never a fallback
profile digest. A duplicate operation uses its original durable catalog binding,
not whichever catalog is newest. Reject mismatched boundaries before dispatch.

Before adoption, reconcile the recovery contract's immutable release-artifact
wording with the state-scoped catalog lifetime, publish the precise byte rule,
and execute shared vectors with escaping, delimiter characters, nulls, action
ordering, changed generations and conflicting operation reuse. This document
does not itself authorize claiming consumer conformance.
