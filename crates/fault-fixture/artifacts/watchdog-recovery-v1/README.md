# `watchdog-recovery-v1` release-like neutral artifact

This is the protocol repository's exact release-like copy of the approved
sideband contract from `ascension-watchdog` commit `fd32e9d`. It is inert data:
it owns no transport, authentication, lease authority, persistence, host
objects, process control, MCP framing, provider behavior, or mutation.

The normative file is [`schemas/watchdog-recovery-v1.schema.json`](../../schemas/watchdog-recovery-v1.schema.json);
`schema.json` is byte-identical. Consumers must verify the schema digest in
`manifest.json` before parsing and must reject mixed artifact/profile digests.

The existing `runtime-v3-gameplay` schema and bytes remain frozen. Recovery is an
additive sideband wrapper; publication here does not claim that gateway, mod,
harness, MCP, or watchdog consumers have implemented it. Those owners must add
their own boundary-specific mappings and executable integration/fault evidence.

The 18 valid fixtures cover all nine request and nine response kinds. Invalid
shape fixtures cover unknown fields, stale contract version, and action bounds.
RCJ-1 malformed and action-vector cases are in `rcj-vectors.json` and are exercised by the neutral
conformance test. It requires exact canonical action bytes, recomputes each action's SHA-256 digest,
and rejects duplicate members, unsorted keys, Unicode, numbers, escapes, and malformed Base64.
