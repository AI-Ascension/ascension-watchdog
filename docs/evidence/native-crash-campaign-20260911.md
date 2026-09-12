# Native crash/restart campaign under the service manager — 2026-09-11

Classification: `native user-scope systemd evidence`. A repeated
`SIGKILL`/service-manager-restart campaign over a supervised synthetic child.
This is user-scope, synthetic-child evidence; it is not the installed root
service, live host, cold boot, cross-repository soak, or gameplay.

## Purpose

Item 4/5 require native evidence for service-manager recovery, containment, and
`INV-08`/`INV-10` (no repeated uncertain action, reconcile before relaunch).
This campaign exercises repeated unclean daemon deaths and measures whether the
supervisor duplicates an uncertain child or conservatively withholds relaunch.

## Setup

- Binary: release `watchdog` SHA-256
  `ff34fca397628fca5aa4e8b0bb5066c96fc249ed7a99063378a067da6ff87ced`.
- Fresh owner-local store, `desired_mode=running`, one synthetic component
  (`/bin/sleep 987655`) under `allow_synthetic_children=true`, authenticated
  admin endpoint.
- Unit: `Type=notify`, `WatchdogSec=20`, `Restart=on-failure`, `RestartSec=1`,
  `StartLimitBurst=20`, `KillMode=control-group`, `NotifyAccess=main`.

## Observed sequence

| Step | Result |
| --- | --- |
| after start | `active`, child count = 1 |
| 5 × (`SIGKILL` main, wait 5 s) | each cycle: `ActiveState=active`, `NRestarts` 1→5, new `MainPID`; child count = 0 every cycle |
| authenticated `watchdog stop` | accepted; child count = 0 |
| `SIGKILL` after durable stop | `NRestarts=6`, `active/running`, `Result=success`; child count = 0 |
| cleanup | unit stopped, `inactive`; no matching process remained |

After the first unclean death the supervisor recovered into `active` but
reported the component health `phase=blocked` and did not relaunch it. This is
the documented conservative policy: a bare launch intent cannot be rebound, so
`policy.rs` returns `"component is blocked or quarantined; autonomous relaunch is
disabled"` and the operator must reconcile/retry rather than the supervisor
repeating an uncertain launch. `watchdog reconcile --target component`
accepted the request for the configured component (queued), which is the audited
operator path; the campaign did not observe an autonomous relaunch.

`KillMode=control-group` removed the orphaned child on each unit restart, so the
`child count = 0` results reflect the supervisor's own decision, not a surviving
duplicate.

## Boundary

Verified at user scope: repeated service-manager restart recovery, cgroup
containment of the supervised child, no duplicate/uncertain relaunch after an
unclean crash, conservative blocked state, and durable stop that a later restart
does not override. Not verified: the installed root service, install/uninstall
idempotence, Windows SCM, live host, cold boot, multi-repository soak, or
gameplay.
