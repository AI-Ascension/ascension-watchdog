# Real-harness daemon scope ownership

The opt-in real harness smoke launches the watchdog daemon in a unique,
transient per-run systemd user scope. The scope unit name and description are
fresh UUID-derived values; no existing unit is enumerated, reused, or stopped.

Before the daemon is admitted, the test records a durable JSON proof beside the
protected configuration and then verifies the live systemd properties and
cgroup-v2 membership:

- `Delegate=yes` and `KillMode=control-group` contain descendants;
- `SendSIGKILL=yes`, `RuntimeMaxSec=120s`, and `TimeoutStopSec=5s` provide
  bounded failure and stop behavior;
- `CollectMode=inactive-or-failed` permits post-stop observation;
- the scope `Id`, description, control-group path, daemon executable, and
  daemon SHA-256 and stable configuration digest all match the proof;
- the daemon and the authenticated worker PID are in the scope or a child
  cgroup.

The systemd-run launcher is placed under a retained `Child` handle and pidfd
before any post-spawn admission check can fail. The command helper drains both
nonblocking output pipes with a fixed byte cap and uses bounded kill/reap
cleanup; it does not call an unbounded `wait_with_output`. The daemon child
handle and pidfd remain owned by the test process. On normal durable stop, the
daemon observes persisted Stop and the test waits for both an inactive/not-found
unit and an empty retained original cgroup before writing `stopped`.
The directory and `cgroup.events` handles are retained at admission; the events
file is opened relative to that directory descriptor. Device/inode checks reject
replacement paths. Missing admission handles cannot establish cleanup. A removed
cgroup's `ENODEV` is accepted only with a positive original-path unlink check. It does not send a systemd
stop by unit name: checking a name and then stopping it could target a recreated
unit. Direct emergency cleanup uses the retained daemon pidfd; the manager's
already configured lifetime remains responsible for descendant cleanup when
that direct cleanup cannot settle. Failed Stop persistence retains uncertainty
rather than authorizing a new name-based or numeric-PID effect.
On a test-process crash, systemd's runtime bound remains the independent
containment authority. If identity or liveness observation is lost, the proof
is written as `uncertain`; no terminal worker or job state is fabricated.

The target daemon receives a cleared environment (`/usr/bin/env -i`) so test
tokens cannot leak through the scope. Only the systemd client retains the
protected user-bus variables required to contact the already-running user
manager. Systemd properties and `/proc`/cgroup observations, rather than those
variables, are the ownership evidence.

`real_harness_worker_scope.rs` contains pure parser/proof negative tests that
run by default. The native process smoke remains ignored and requires the
explicit gate and separately built harness image documented in
`real-harness-worker.md`.

After the author reached the account usage limit, root removed name-based scope
stopping, completed the pidfd cleanup correction, and added synthetic helper
tests. Nine focused tests passed after integration, covering parser/proof rejection,
recreated or missing cgroup identity, descriptor-relative original events,
bounded helper termination, pipe output beyond buffer capacity, and UTF-8-safe
truncation. Full-workspace strict Clippy also passed without lint allowances.
Independent review subsequently passed, and root ran the opt-in native smoke:
one test passed in 114.50 seconds with successful original-cgroup cleanup.
Exact image identities and the narrow evidence classification are recorded in
`real-harness-worker.md`. No persistent service was installed.
