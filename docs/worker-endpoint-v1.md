# Worker endpoint namespace v1

Owner: watchdog launch boundary. The Linux producer is implemented in harness PR
#66 (`ef8c45e853d5f86c2653159a449826ffc20b5950`) and is consumed by the
watchdog's configured worker client. The source/component gates and one native
Linux process-boundary smoke pass; Windows producer implementation, service
installation, live gameplay, and native producer-to-consumer release acceptance
remain unverified.

Approved configuration contains a static `endpoint_namespace`, not a fixed worker
endpoint. The legacy `worker.endpoint` field is rejected by the closed config
decoder. This requires explicit approved configuration replacement, with the new
configuration digest; startup does not reinterpret or migrate old configuration.

Both consumers independently derive the endpoint using the same fresh launch nonce
already carried in worker bootstrap v1. The watchdog uses its currently owned child
identity, never a remote request or a historical process row. The harness uses the
validated bootstrap nonce and static `STS2_WORKER_ENDPOINT_NAMESPACE` policy. The
ordinary launch arguments/environment and their binding digest do not change per
launch. No runtime selects a different release or credential to resolve a failure.
Watchdog configuration requires the harness launch environment's exact
`STS2_WORKER_ENDPOINT_NAMESPACE` value to equal `endpoint_namespace`. Missing or
different values, legacy endpoint keys, and case-variant reserved keys are rejected;
validation does not inject or rewrite environment values.

The nonce must be a canonical lowercase RFC4122 UUIDv4. Linux namespace is an
absolute UTF-8 directory path without empty, dot, dot-dot, backslash, or control
components. It has no trailing slash. Append exactly
`/ascension-worker-{nonce}.sock`; the resulting UTF-8 endpoint is at most 100 bytes.
Windows namespace is exactly `\\.\pipe\ascension-worker-`; append the nonce without
a suffix. Static endpoints are not accepted as namespace aliases.

Configuration validation and derivation perform no filesystem or IPC operations.
The native transport still authenticates peers and validates protected directories.
A fresh nonce selects a distinct endpoint. An occupied current endpoint fails closed;
no blind unlink, path scan, name-based cleanup, or adoption is authorized. A stale
prior socket is not an active authority and cannot prevent a different nonce's
endpoint from binding. Its eventual removal requires separately owned exact-identity
cleanup; this derivation alone is not a retention or garbage-collection mechanism.

Conformance example for nonce `12345678-1234-4234-8234-123456789abc`:

| Platform | Namespace | Endpoint |
| --- | --- | --- |
| Linux | `/run/worker` | `/run/worker/ascension-worker-12345678-1234-4234-8234-123456789abc.sock` |
| Windows | `\\.\pipe\ascension-worker-` | `\\.\pipe\ascension-worker-12345678-1234-4234-8234-123456789abc` |

Acceptance requires matching independent consumer vectors, wrong-nonce rejection,
unchanged approved launch bytes, current/prior socket fault tests, and actual native
bootstrap-to-authenticated-exchange tests. Pure derivation tests are not that final
integration evidence. The current native Linux evidence is recorded in
[`docs/evidence/real-harness-worker.md`](evidence/real-harness-worker.md): the
watchdog launched the exact PR #66 harness image, authenticated the bootstrap and
control exchange, admitted one dispatch, and persisted stop/cleanup. The downstream
gateway and MCP processes were intentionally bounded synthetic fault fixtures, so
the run does not establish a settled game action or provider result.

## Current component gate

Harness PR #66 was rebased onto current harness `main` (`63dc563690c93c575e75228f54672c1689d8a879`).
Its locked format, check, Clippy, policy, and all-target/all-feature tests pass. The
release image used by the native smoke is retained outside the repository with
SHA-256 `4b71eeb3c9ff410707ff2272e730889b1378cf4cae1a6b08c7531233f3bb48f2`.
The image and endpoint namespace are immutable, owner-local test inputs; no
credential or local path is part of the committed contract.
