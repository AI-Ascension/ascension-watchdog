# Admin-endpoint crash-recovery defect and fix — 2026-09-11

Classification: `implementation defect found by a native run, fixed, unit-tested,
and re-verified on the host`. This concerns the local authenticated admin
Unix-socket endpoint and service-manager restart recovery. It is not
activation, live-host, reboot, or soak evidence.

## Defect

A native systemd **user-scope** run (documented in
[`native-user-systemd-lifecycle-20260911.md`](native-user-systemd-lifecycle-20260911.md))
exposed a crash-recovery defect. With an authenticated admin endpoint
configured, `SIGKILL` of the watchdog daemon left the Unix socket file behind
(`SIGKILL` cannot run cleanup). On the next `Restart=on-failure` attempt the
daemon exited immediately:

```text
watchdog[4065829]: watchdog: watchdog store is already owned: <state>/admin.sock
```

`bind_endpoint` treated every `EADDRINUSE` as `BUSY` and deliberately never
unlinked the path, so a live incumbent could not be displaced. That safety
property is correct, but an **orphaned** socket (no listener) then blocked every
restart, so systemd exhausted its restart burst and the service could not
recover from an unclean crash without manual socket removal. For a
crash-resilient supervisor this is an availability defect.

## Fix

`crates/watchdog/src/admin/endpoint.rs` now reclaims a socket only when it can
prove no process is listening:

- on `EADDRINUSE`, connect to the existing path;
- if the connection succeeds, or fails with anything other than
  `ConnectionRefused`, keep the existing `BUSY` behavior — a live or
  unverifiable incumbent is never displaced;
- only when the probe is refused, and the path is still a Unix socket owned by
  the current user with the same device/inode before and after the probe, unlink
  it and retry the bind exactly once.

A unit test asserts both halves: a live incumbent stays `BUSY`, and an orphaned
socket (guard forgotten, listener dropped) is reclaimed and then cleaned up.

## Native re-verification

- Binary: release `watchdog` SHA-256
  `ff34fca397628fca5aa4e8b0bb5066c96fc249ed7a99063378a067da6ff87ced`.
- `systemd-run --user` unit with `Type=notify`, `WatchdogSec=15`,
  `Restart=on-failure`, `RestartSec=2`, `StartLimitBurst=4`, and an authenticated
  admin endpoint.
- `SIGKILL` of `MainPID=4142138` produced
  `Main process exited, code=killed, status=9/KILL`, `Failed with result
  'signal'`, `Scheduled restart job, restart counter is at 1`, `Started ...`.
- The restarted daemon reached `ActiveState=active`, `SubState=running`,
  `Result=success`, `NRestarts=1`, new `MainPID=4143362` — it reclaimed the
  orphaned socket instead of failing `BUSY`.
- A second unit confirmed the admin path still works: `status` returned
  `status":"OK"` and `stop` returned `Accepted`.
- Cleanup: the units were transient and `--collect`; the unit ended `inactive`.

## Boundary

This is a user-scope endpoint-recovery fix and verification. It does not cover
the installed root system service, uninstall idempotence, Windows SCM, live-host
recovery, cold boot, activation/rollback, or soak.
