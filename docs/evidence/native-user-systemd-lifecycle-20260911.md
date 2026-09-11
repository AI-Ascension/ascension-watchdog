# Native Linux user-scope systemd lifecycle evidence — 2026-09-11

Classification: `native user-scope systemd service-manager evidence
(transient unit)`. This is real systemd/cgroup-v2 behavior against the pinned
watched binary. It is **not** the installed root system service, WSL, live-host
recovery, cold boot, activation/rollback, or soak evidence, and it does not
claim `install.sh`/`uninstall.sh` idempotence.

## Why this run exists

The supported Linux service path (`deploy/linux/install.sh`) requires root and
installs a persistent system unit; that remains unauthorized and is prepared in
[`host-execution-authorization-request.md`](host-execution-authorization-request.md).
The systemd **user manager** is available on the supplied Train host with linger
enabled, so a transient, auto-collected user unit was used to obtain bounded
native service-manager evidence without root, a reboot, or a persistent service.

## Environment

- Host `completetrain-B550-GAMING-X-V2` (`train.home.complete.tech`), kernel
  `7.0.0-31-generic`, cgroup v2.
- systemd `255.4-1ubuntu8.17`; user manager `degraded` (pre-existing, unrelated
  to this run); user linger enabled.
- Watched binary: staged
  `/home/completetrain/watchdog-native-smoke-20260911-current-main/watchdog`,
  SHA-256 `105ca9fba97ec8024689b31a017ba9edcd978a77f46c5e1a9eb323158744d204`
  (admitted product revision `28e20fa8cfb9a43635a5c167e03ade6219d87a5a`).
- Configuration: `deployment_id=user-smoke`, `desired_mode=running`,
  `components=[]`, owner-local SQLite under
  `/home/completetrain/wd-usersmoke-20260911b/`.

## Procedure and observed results

A transient user unit was started with an explicit notify contract:

```text
systemd-run --user --unit=<unit> \
  --property=Type=notify --property=WatchdogSec=30 --property=Restart=on-failure \
  --property=RestartSec=2 --property=KillMode=control-group \
  --property=NotifyAccess=main --collect \
  <watchdog> daemon --config <config>
```

### Readiness notification (`Type=notify`)

After 4 seconds: `ActiveState=active`, `SubState=running`,
`NotifyAccess=main`, `WatchdogUSec=30s`. Under `Type=notify` systemd holds the
unit in `activating`/`start` until `READY=1`, so reaching `running` proves the
daemon emitted `READY=1` well inside the start timeout.

### Watchdog keepalive (`WATCHDOG=1`)

A second unit ran with `WatchdogSec=10`. It was `active/running` at 3 seconds and
still `active/running` at 25 seconds with `Result=success`. Because systemd
kills a unit that misses its watchdog interval, surviving more than twice the
interval proves the daemon sent `WATCHDOG=1` keepalives.

### Service-manager recovery (`Restart=on-failure`)

`kill -KILL` of the main process (`MainPID=2995399`) produced:

```text
ascension-wd-usersmoke-2995396.service: Main process exited, code=killed, status=9/KILL
ascension-wd-usersmoke-2995396.service: Failed with result 'signal'.
ascension-wd-usersmoke-2995396.service: Scheduled restart job, restart counter is at 1.
ascension-wd-usersmoke-2995396.service: Started ...
```

The unit returned to `active/running` with a new `MainPID=2998478`.

### Retained state

After the crashed and restarted runs, `watchdog status --config` reported
`restart_generation=3`, `desired_mode=running`, and WAL durability, showing the
owner-local store was retained across process replacement.

### Stop and cleanup

`systemctl --user stop` produced `Stopping`/`Stopped`; afterwards
`unit_active=inactive`, `unit_loaded=0`, no matching user scope, and no
`watchdog` process remained. The units were transient and `--collect` unloaded
them; no persistent unit file was created.

## Boundary

Verified: transient native systemd readiness notification, `WATCHDOG=1`
keepalive, `Restart=on-failure` service-manager recovery, `KillMode=control-group`
containment, clean stop, and retained owner-local state, all under cgroup v2.

Not verified: root system-service install/start/status/stop/uninstall and
idempotence, the fixed `ascension-watchdog` service account and protected paths,
uninstall's durable no-restart intent, live-host recovery, cold boot,
activation/rollback, and the 24-hour soak. Those require the authorization in
[`host-execution-authorization-request.md`](host-execution-authorization-request.md).
