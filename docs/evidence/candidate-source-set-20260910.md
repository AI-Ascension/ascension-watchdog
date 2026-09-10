# Candidate source set — 2026-09-10

This record pins the remote pull-request heads used for the next integration
review. It is deliberately a candidate source set, not an activated release:
the JSON manifest records each exact revision, ref, PR, and current state in
`workspace-manifest.candidate.json`.

The pins were refreshed from authoritative remote PR and branch metadata on
2026-09-10T23:40Z. The watchdog integration branch is draft PR #9 at
`f5eaf5e35be025015a28da931aa973a0ade8f0ef`; its durable exact-digest release
selector, strict selector/receipt binding, request-collision rejection,
authenticated activation/rollback boundary, and collision-safe Windows fixture
allocation are source-tested. Hosted validation runs `34525217061` and
`34525218190` passed on Ubuntu and Windows; standards runs `34525217025` and
`34525218179` passed. Native service-session remains explicitly `UNVERIFIED`
and is not native service proof.

The selected revisions are gateway `c8be3a72ba9e304392575a1b2bdbc262e392be21`,
MCP `037d10def1cbcb1c807e136d31b294355a92c010`, game-mod
`888b06702021cd2bbd22773b0267733766c3b04a`, protocol
`f22dd7216f65de91a0ffa27f50bc2036be6c8b24`, game-core
`f9db577530a4d159b066d3facbd780d61c044eb0`, and observability
`89539a6e7754b389f8eac148ba8a49c3892cddd8`. The harness entry is merged PR
#66: feature head `58dede2eb661133d8910a1f785e8a90346efe8dd`, now on main at
`a0ace6712686cb30d6f0b556cb6814ad4c0721d1`; it is the exact hardening source
used by the native worker smoke. Locked component gates and
runtime-v2/v3/v4/seeded-run artifact bytes are recorded in
[`release-set-verification-20260910.json`](release-set-verification-20260910.json).
The current protocol artifact records serialized component conformance for the
gateway/MCP/harness heads, while the worker endpoint is a separate Linux
process-boundary contract. The exact watchdog-to-harness smoke passed with
image SHA-256 `5286706d03c27c00e32493c1adf8864e972f7a53d1f863c046aed32d56a1644f`,
but the downstream gateway/MCP inputs were synthetic faults. No claim is made
that the full set composes, installs, activates, or runs a live game host.

Required next gate: rebuild and test this exact set together, verify immutable
artifact digests, then run the separately authorized native Windows/Linux/WSL,
activation/rollback, cold-boot, and soak lanes. Until those gates pass, do not
change the manifest classification to an activated release.
