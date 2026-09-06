# Platform operations contract

Status: implementation in progress. Linux notification and packaging sources
are present; native Windows and live service evidence remain separate gates.

## Ownership boundary

The watchdog owns desired deployment mode and component supervision. An OS
adapter may launch only an approved direct executable and must return ownership
only after it has established containment and captured the full process identity.
The identity includes deployment, instance, component, incarnation, launch
nonce, OS creation token, canonical executable/hash, containment identifier and
session. PID is an observation field and never a termination authority.

The adapter contract is in `crates/watchdog/src/platform/contract.rs`.
`launch` errors must leave no child behind. `inventory` must query the designated
containment authority, not enumerate by process name. Identity mismatch or
ambiguous orphan ownership is quarantined; force stop applies only to the
verified containment owner and descendants.

## Linux service

`deploy/linux/ascension-watchdog.service` uses `Type=notify`, finite startup and
stop deadlines, `WatchdogSec`, `KillMode=control-group`, a dedicated account,
and protected state. The watchdog must call `SystemdNotifier::progress` from the
actual reconciliation loop. The first increasing progress sequence emits
`READY=1`; later increasing sequences emit `WATCHDOG=1` only when systemd has
provided `WATCHDOG_USEC`. Repeated or stalled sequences emit no heartbeat.
`STOPPING=1` is idempotent. Missing `NOTIFY_SOCKET` is reported as an explicit
disabled result and never as readiness.

The notifier currently accepts filesystem Unix sockets. Abstract Linux notify
socket support is intentionally rejected until a reviewed sockaddr boundary is
added. No background thread fabricates liveness.

## Windows and WSL requirements

The Windows service must be registered with SCM automatic start and bounded
failure actions. The graphical host broker must select an explicitly approved
active user session, authenticate a local named pipe with an owner-only ACL,
and launch with `CreateProcessAsUser`. Job Object assignment must occur before
the child can execute, descendants must not be allowed to break away, and the
owner must retain the Job handle or a durable named-owner authority for
reconciliation.

The standalone `crates/platform-windows` package includes a direct-process
synthetic fixture and a Windows-only integration test. The test creates a
descendant without a shell, reopens the named Job Object, verifies membership,
force-stops the complete job, and then exercises a crash followed by a fresh
nonce launch. It is only evidence when executed on Windows; Linux builds run
the portable contract tests and do not claim native containment.

WSL invocation uses an exact configured distribution and direct `--exec`
arguments. `WslInvocation` rejects shell-like ambiguity, unbounded arguments,
and non-loopback expected endpoints. It never performs login or credential
capture.

## Release installation

The Linux install wrapper only prepares an already validated release under
`/opt/ascension-watchdog/releases`, refuses links, installs the fixed unit, and
does not start the service. It preserves state and releases on uninstall. The
watchdog's release activation path must still perform byte/hash verification,
durable activation intent, atomic publication, interruption recovery and
compatibility checks before this wrapper is called.
