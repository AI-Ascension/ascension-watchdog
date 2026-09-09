# Windows supervisor worker producer integration

The supervisor retains the native current-controller image guard for its own
lifetime. It constructs the owner-validated Windows bootstrap with a fresh launch
nonce and supervisor boot identity, persists its exact frame digest with the
prepared launch intent, and supplies those immutable bytes to the Windows pipe
component. Ordinary non-worker launches remain on the existing launch path.

The native worker overload requires a callback immediately before ResumeThread.
The watchdog callback reloads protected source configuration, requires its digest
to match the in-memory approved configuration, and opens existing owner-local state
without migration. It acquires a SQLite `BEGIN IMMEDIATE` writer reservation but
changes no rows. The reservation is retained across the native `ResumeThread`
call and released by dropping the dedicated connection. Thus an operator Stop
commits before the checked admission snapshot or after resumption, not between
the final check and resumption.
It checks Running mode, current restart generation, complete launch specification,
planned Job identity, Windows frame/component/nonce, the sole unsettled component
intent (at most two rows are read to detect conflict), its Prepared state with
the exact specification digest, and the exact stored boot/frame binding. A final
mode/generation read and deadline check precede authorization. Failure uses the
native exact-Job cleanup path; uncertainty cannot become a clean launch failure.

The source path is mandatory for this native worker path. A stale in-memory
configuration or serialized frame does not independently grant resume authority.
The platform crate deliberately owns only the immutable envelope and native
handles; the watchdog owns schema, digest, configuration, and durable admission.

The five-second checks are cooperative. SQLite lock waiting is bounded, but
filesystem and SQLite kernel I/O cannot be preempted by these checks. No hard
five-second wall-clock guarantee is claimed; strict stalled-I/O validation remains
an open requirement. A completed over-deadline check rejects before resumption.

## Validation status

Windows-target all-target/all-feature strict Clippy passed for the current wiring.
Linux-target strict all-target/all-feature Clippy and four durable admission tests
also passed (4.13 seconds). Those tests exercise changed/missing source configuration, changed specification,
wrong planned identity, changed bootstrap boot, expired deadline, durable Stop,
and a cleaned intent, plus Stop serialization while the reservation is held and
conflicting component intents after removal of the unique index. They test
admission logic, not Windows Supervisor service-session resumption.

Native Windows component regression: five tests passed in 3.22 seconds, exit 0.
This includes complete frame delivery, a guard whose destructor witnesses a
resumed child's marker, callback rejection, bounded undersized-pipe failure,
and exact cleanup. Test executable SHA-256:
`059120006f694d47fd2e7a36bd34b0594f096c91cfc52c2c7646bc3747fcf272`.
Synthetic fixture SHA-256:
`456c7ef73949821b90454657fb0c9698c34e4e075662c3ba6c0b1670069297ce`.

Native Windows Supervisor desktop-session rejection: one test passed in
15.06 seconds, exit 0, on confirmed session 1. It asserts no resumed child,
unsettled intent, identity, or fixture marker. Test executable SHA-256:
`c2f8457b1818d3504d6170baef9cdcafb9d6e86a27fd9b1d17c71e77ace5a852`.

The native pipe and current-controller components have separate native evidence in
[windows-worker-pipe.md](windows-worker-pipe.md). The real Supervisor launch fixture
initially failed on the workstation: `IdentityMismatch("launch ownership proof
differs from the original launch intent")`. Investigation found that the native
adapter treated `Explicit(0)` as the caller's current session. The service-only
runtime requested session 0 but received a nonzero desktop-session child. The
adapter now rejects that mismatch before Job/process creation; `CurrentService`
remains an explicit caller-session selector for portable component fixtures.

The positive Supervisor worker fixture requires an explicitly authorized session-0
controller. It must not be counted as a pass in a desktop session or enabled by
silently installing a service. Independent review confirmed the explicit-session
guard, duplicate-intent rejection, and database reservation lifetime. The durable
Stop commit is the linearization point; an SCM notification not yet persisted
does not constitute that commit. No Windows
service installation, real harness exchange, game/provider run, reboot, release
activation, or soak is established by these checks.
