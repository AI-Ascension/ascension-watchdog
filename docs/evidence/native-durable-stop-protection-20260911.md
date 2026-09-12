# Native durable-stop protection under the service manager — 2026-09-11

Classification: `native user-scope systemd evidence`. A service-manager
`Restart=on-failure` restart must not revive work that was durably stopped. This
is user-scope, synthetic-child evidence; it is not the installed root service,
live host, cold boot, activation/rollback, or soak.

## Purpose

Item 4 of the assignment requires native evidence for service-manager recovery,
containment, and durable stop protection. The earlier user-scope run proved
readiness, keepalive, and restart recovery; this run proves that a restart
cannot resurrect a durably stopped component.

## Setup

- Binary: release `watchdog` SHA-256
  `ff34fca397628fca5aa4e8b0bb5066c96fc249ed7a99063378a067da6ff87ced` (includes
  the orphaned-socket recovery fix in
  [`admin-socket-recovery-fix-20260911.md`](admin-socket-recovery-fix-20260911.md)).
- Config: `desired_mode=running`, an authenticated admin endpoint, and one
  synthetic component `id=synthetic-sleeper`, `executable=/bin/sleep`,
  `args=["987654"]`, `restart=true` under `allow_synthetic_children=true`.
- Unit: `systemd-run --user --property=Type=notify --property=WatchdogSec=20
  --property=Restart=on-failure --property=RestartSec=2
  --property=StartLimitBurst=4 --property=KillMode=control-group
  --property=NotifyAccess=main --collect`.

The marker duration `987654` is unique on the host, so `pgrep -fc "sleep 987654"`
counts only this component.

## Observed sequence

| Step | Result |
| --- | --- |
| after start | `active/running`; `sleep 987654` count = 1 |
| `watchdog stop` (authenticated, idempotency key) | accepted; `sleep 987654` count = 0 (child terminated) |
| `SIGKILL` of the daemon | journal: `Main process exited, code=killed, status=9/KILL`, `Failed with result 'signal'`, `Scheduled restart job, restart counter is at 1`, `Started ...` |
| after service-manager restart | `NRestarts=1`, `Result=success`, `active/running`; `sleep 987654` count = **0** |
| cleanup | unit stopped; final `inactive`; child count stays 0 |

The restarted daemon read the durable stop intent and did not relaunch the
component, while still recovering into a healthy running supervisor.

## Boundary

Verified at user scope: durable stop terminates the supervised child, and
`Restart=on-failure` recovers the daemon into stopped mode without reviving the
component. Not verified: the installed root system service, install/uninstall
idempotence, Windows SCM, live host, cold boot, activation/rollback, or soak.
