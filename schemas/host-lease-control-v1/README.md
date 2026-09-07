# `watchdog-host-lease-control-v1`

This directory contains the additive gateway-to-host lease-control artifact.
It installs the exact gateway-issued authority grant and synchronizes its
renewal and revocation. It is deliberately separate from the frozen
`watchdog-recovery-v1` sideband: no recovery-v1 kind, field, issuer, or digest
is changed by this artifact.

`manifest.json` identifies the exact closed `frame.schema.json` bytes. Consumers
must verify that digest before decoding a frame and must reject mixed contract
or schema digests. The frame is bounded to 262144 bytes and its authentication
proof is bounded to 512 bytes.

JSON Schema validates the closed wire shape and scalar bounds. Consumers must
additionally enforce the semantic rules in `docs/host-lease-control-contract.md`:
grant field equality, digest and proof domains, gateway/host identity binding,
strict renewal sequencing, the received-at wall check plus clamped monotonic
deadline, durable-before-ack ordering, idempotent same-grant retries, duplicate
member rejection, protected persistence without a plaintext fence token, and
current boot/fence checks.

The valid fixtures exercise install, duplicate install, renewal, duplicate
renewal, revocation, and duplicate revocation. Schema-invalid fixtures
demonstrate unknown-field rejection. Semantic-negative fixtures demonstrate
grant-context mismatch, digest mismatch, and an expired renewal; those cases
have valid closed shape because their cross-field or received-at invariants are
enforced by the reference semantic tests and real consumers.
Fixture values are deterministic and contain no credentials.
