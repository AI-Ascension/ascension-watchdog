# Worker endpoint namespace v1

Owner: watchdog launch boundary. Implementation in progress; companion integration
and native producer-to-consumer acceptance remain unverified.

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
integration evidence.
