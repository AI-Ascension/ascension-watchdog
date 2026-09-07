# Platform operations contract

Status: implementation in progress. Linux notification, bounded launch
containment, and packaging sources are present; native Windows and live service
evidence remain separate gates.

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

On Linux, `LinuxProcessAdapter` creates the durable cgroup before starting the
trusted watchdog helper. `TrustedLinuxLauncher` sends one bounded launch frame,
the adapter assigns and verifies the helper PID in that cgroup, and only then
sends the nonce-bound release marker. The helper rechecks root-owned durable
authorization, cgroup membership, the role allowlist, and the executable hash
before replacing itself with the approved target via `exec`. A helper EOF,
nonce mismatch, timeout, or failed target launch is a hard failure and cleans
the cgroup; there is no direct-spawn fallback. Persist the result of
`LinuxProcessAdapter::planned_containment_for` before effects and pass it to
`launch_with_planned_containment` so a retry cannot silently choose a new
containment authority. When a protected config path is available, bind it with
`LinuxHelperBootstrap`/`TrustedLinuxLauncher::with_bootstrap` and use
`run_hidden_helper_with_bootstrap_authorizer` from the executable entrypoint.

## Linux service

`deploy/linux/ascension-watchdog.service` uses `Type=notify`, finite startup and
stop deadlines, `WatchdogSec`, `KillMode=control-group`, `Delegate=yes`, a
dedicated account, and protected state. It intentionally has no reload action:
the daemon has no unreviewed signal-based reconfiguration path. The watchdog
must call `SystemdNotifier::progress` from the actual reconciliation loop. The
first increasing progress sequence emits
`READY=1`; later increasing sequences emit `WATCHDOG=1` only when systemd has
provided `WATCHDOG_USEC`. Repeated or stalled sequences emit no heartbeat.
`STOPPING=1` is idempotent. Missing `NOTIFY_SOCKET` is reported as an explicit
disabled result and never as readiness.

The notifier currently accepts filesystem Unix sockets. Abstract Linux notify
socket support is intentionally rejected until a reviewed sockaddr boundary is
added. No background thread fabricates liveness.

## Windows and WSL requirements

The Windows service is entered by `watchdog.exe daemon --service` through the
existing `ServiceRuntime` SCM dispatcher. Its readiness witness opens the
owner-local store and completes one real `ServiceLoop::reconcile` before SCM
receives `Running`. SCM stop is first converted to durable `Stopped` intent on
the reconciliation thread; only subsequent iterations perform child cleanup.
The service command line is closed and bounded to the fixed marker plus one
absolute `--config` path. Credentials are never command-line arguments.

`watchdog service install` calls the native `ServiceInstallPlan` API, registers
automatic start and bounded failure actions, and does not start or initialize
the service. `deploy/windows/uninstall.ps1` removes only the SCM definition by
default; state and releases remain unless an operator supplies the explicit
data-removal switch and exact path.

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
