# Linux broker typed bootstrap v2

Classification: implemented broker-side source and synthetic transport/descriptor
validation. This is not runtime backend selection or native systemd validation.

The authenticated Unix listener accepts an additive binary launch envelope for
Gateway health and Harness worker stdin. The existing four-field JSON launch
request and version-1 Inspect/Stop messages remain separate. There is no fallback
from a failed typed launch to a legacy launch.

## Transport

The existing protected socket and kernel peer/executable authentication apply
before request bytes are accepted and again before broker admission. One
connection carries one request followed by write-side EOF.

| Bytes | Meaning |
| --- | --- |
| 0–7 | ASCII `ASC-BB02` |
| 8–11 | Big-endian u32 header byte length |
| 12–15 | Big-endian u32 raw bootstrap frame length |
| Next header length bytes | Closed UTF-8 JSON header |
| Remaining frame length bytes | Exact raw stdin frame, not JSON encoding |

The header is at most 4,096 bytes. The frame is at most the worker codec's
16,396-byte complete-frame bound; the complete request is at most 20,508 bytes.
The parser requires exact lengths and EOF, rejects trailing bytes, and uses an
absolute connection deadline. Legacy requests retain their 16,384-byte bound.
Request accumulation and encoded binary buffers use zeroizing storage.

The header contains exactly `version`, `request` and `binding`. Version is 2.
`request` is the unchanged component/instance/incarnation/nonce object. `binding`
contains exactly version 2, kind (`gateway_health` or `worker`), canonical UUIDv4
watchdog boot ID, and lowercase frame SHA-256. No caller-supplied command,
argument, path, environment, descriptor number, or secret field is accepted.

Gateway health requires the Gateway role and an exact fixed `STS2GH01` frame
whose UUID matches the request nonce. Worker bootstrap requires the Harness
role and an exact `ASC-WB01` frame whose nonce, watchdog boot ID and component ID
match the request/binding, with a Linux expected controller. The broker checks
that expected controller against the authenticated PID, UID, GID, executable
path/digest and decimal process start ticks. Broker receipt births include the
kernel boot prefix; worker frame births remain their existing decimal contract.

Decoding a frame is not durable launch authorization. The watchdog owner must
still bind it to its prepared launch intent and enforce deployment Stop/Running
ordering before selecting this backend.

## Native stdin and fixed policy

The broker creates its own bounded anonymous memfd, writes the validated raw
frame, removes executable/write mode bits, seals write/shrink/grow/further-seal
changes, and rewinds it. A D-Bus owned `h` value duplicates that descriptor for
`StandardInputFileDescriptor` in `StartTransientUnit`. Bootstrap bytes are not
placed in `StandardInputData`, unit property data, the environment or ledgers.
There is no incoming descriptor or caller-selected file path to validate.

This API is present in the inspected [systemd v257 service implementation](https://github.com/systemd/systemd/blob/v257/src/core/dbus-service.c#L630-L636).
Its [descriptor setter](https://github.com/systemd/systemd/blob/v257/src/core/dbus-service.c#L446-L474)
duplicates the received descriptor rather than writing its content into unit
configuration. This source inspection is not proof that an installed manager
accepted the property; native manager/child execution remains gated. Unsupported
manager behavior never triggers a metadata-based or legacy fallback.

For Gateway health only, the broker derives the non-secret
`STS2_GATEWAY_WATCHDOG_LAUNCH_NONCE` value from the validated UUID. Fixed policy
may not supply that variable for a typed launch, and adding it cannot exceed
the existing environment count limit. Other environment entries and all
executable/argument/UID/GID/capability/cgroup decisions remain fixed policy.

The memfd is anonymous kernel storage, not a durable secret file. Userspace
buffers are zeroized; this does not claim cryptographic erasure of kernel pages.

## Durable identity and uncertain outcomes

Before a native start, the broker's Pending record includes the non-secret
bootstrap binding. It remains identical through Committed, StopPending and
Stopped. Reopen rejects changed/removed bindings between transitions. Reusing
an identity with a changed frame or watchdog boot ID, upgrading a legacy
reservation to typed stdin, or downgrading a typed reservation to legacy launch
is rejected. Legacy records omit the optional binding field and keep their
existing encoding. Older readers reject records containing the new field;
do not roll back a broker binary over a ledger containing typed launches.

The typed response contains exactly version, accepted, duplicate, binding and
receipt. Accepted responses must correlate to the request and exact binding;
receipts are closed objects. Errors do not reflect bootstrap bytes or parser
input. A negative reply is not a non-execution witness: failure can happen
after Pending, PID 1 acceptance or receipt persistence.

`BrokerBootstrapLaunchError::NotDispatched` means only that this invocation did
not attempt to write request bytes. It does not clear earlier uncertainty for
the same identity. Any error after a write attempt is `Unknown`, including a
negative reply, partial write, timeout, EOF or malformed response. Retain the
nonce and prepared intent; use exact Inspect/Stop reconciliation, never a new
nonce or a blind launch retry. A committed launch whose response was lost is
inspectable and stoppable without delivering its frame again.

## Runtime selection and remaining lifecycle boundary

`RuntimeProcessManager` now has an explicit `linux_broker` configuration
selector. Omitting it keeps the direct Linux adapter; selecting it routes
launch, inspect, recovery and stop through `BrokerClient` and the exact receipt
identity. This source wiring and its synthetic tests do not prove an installed
root-owned broker, a systemd/D-Bus effect, or a native service run.

The broker retains the exact `StartTransientUnit` job object identity in the
pending journal, resolves it by its immutable job ID/object path, and exposes a
bounded `CancelJob` path. A Stop request for a still-pending launch invokes that
exact cancellation when the job is queued, but keeps the reservation pending:
neither a `CancelJob` reply nor a raced `JobRemoved` event proves whether the
unit executed. Matching `JobRemoved` decoding is available only with the
durable binding; unrelated or malformed signals fail closed.

The one-way cancellation intent is now durable in the pending journal and is
replayed after a broker-ledger reopen. Asynchronous `JobRemoved`
subscription/replay across broker death and the final watchdog Stop/exec
admission barrier remain open. Pending records without retained original containment still cannot
authorize pathname adoption or termination. These cases remain uncertain, not
successful cleanup. Add parent/broker death, late job execution, lost response,
concurrent Stop, missing original capability and same-name replacement
regressions before claiming the asynchronous lifecycle complete. Then validate
the real systemd stdin/bootstrap/containment path on an authorized disposable
host.
