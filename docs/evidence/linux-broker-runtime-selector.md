# Linux broker runtime selector

Status: explicit source selection, broker job-binding, and synthetic unit
evidence only. The broker service, its protected policy, and a native host have
not been installed or validated by this change.

## Selection contract

`WatchdogConfig.linux_broker` is an explicit opt-in. Its canonical shape is:

```json
{
  "linux_broker": {
    "socket": "/run/ascension-watchdog/broker.sock",
    "timeout_ms": 30000
  }
}
```

Omitting the field keeps the existing delegated-cgroup
`LinuxProcessAdapter`. The selector accepts only the protected socket
reference and a 1..120000 millisecond deadline. Validation is lexical and
has no filesystem, socket, process, or store side effects. Absolute paths,
control characters, dot components, pseudo-filesystem roots, and overlong
Unix socket names are rejected. Non-Linux builds reject the selector as
unsupported.

When the field is present, runtime backend construction performs the separate
protected-parent/socket checks required by `BrokerClient`; it does not create
or repair the socket. The broker remains the authority for executable,
arguments, environment, target identity, capabilities, cgroup and unit
policy. Those values are not request-controlled IPC fields.

## Runtime and recovery binding

The runtime maps each launch specification to the broker's closed
`component/instance/incarnation/nonce` request and persists a versioned
`linux-broker-v1` planned identity. Legacy launches use `BrokerClient::launch`;
worker and Gateway-health launches use the typed binary bootstrap transport.
The resulting receipt must match the complete request, deterministic unit,
nonzero PID and creation token, executable digest, non-root UID/GID, zero
capability sets, and the exact unit cgroup path.

Inspect, stop, and reopen use the same request identity. Reopen requires an
active broker lifecycle receipt whose process binding still matches the
persisted proof. Stop verifies the returned receipt before accepting the
terminal state; no PID, executable name, or reconstructed unit path is used
as authority. A pending Stop is forwarded to the broker's exact queued-job
resolution/cancellation seam when a durable job binding exists, then remains
uncertain until the unit effect is reconciled.

An unknown legacy launch result is retained as cleanup uncertainty because
the legacy client cannot distinguish a pre-dispatch error from a response
lost after dispatch. Typed bootstrap errors preserve the distinction between
`NotDispatched` and `Unknown`. In either case the runtime keeps the exact
durable identity and does not generate a replacement nonce or blindly retry.

## Verification and remaining boundaries

The focused source checks are:

```text
cargo fmt --all -- --check
cargo test --locked --offline -p ascension-watchdog --lib config::config_linux_broker::tests
cargo test --locked --offline -p ascension-watchdog --lib runtime_process::tests::broker_
cargo clippy --locked --offline -p ascension-watchdog --lib --all-targets -- -D warnings
```

The final local focused gate passed 116 tests with one explicitly gated native
systemd test ignored. The final locked all-target/all-feature workspace gate
passed 255 library tests with four explicit ignores and all workspace
integration/example tests. Strict workspace Clippy, production lint, formatting,
standards validation, and schema/conformance fixtures also passed. The
Windows-target cross-Clippy lane was not runnable on this Linux host because
`x86_64-w64-mingw32-gcc` is unavailable; hosted Windows validation remains the
authoritative native lane.

These checks prove selector bounds, direct-backend defaulting, request
round-tripping, receipt correlation, exact job identity, and pending
cancellation uncertainty. They do not prove a root-owned socket, systemd/D-Bus
effects, cross-UID execution, reboot recovery, or live service behavior.

The broker API remains synchronous at the wire boundary. A pending Stop now
persists a one-way cancellation intent before touching the manager job, and
that intent is replayed after a broker-ledger reopen. Bounded job identity
resolution/cancellation is still separate from `JobRemoved` subscription and
replay across broker restarts. Callers must retain the operation in their own
durable journal and use an operation-specific effect witness; this selector
does not claim terminal success from a cancellation reply.
