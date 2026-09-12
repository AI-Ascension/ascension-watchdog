# Native Linux system-service lifecycle evidence — 2026-09-11

Classification: `native installed system-service lifecycle evidence on the
supplied Train host`. This exercises the supported root `systemd` deployment:
install, start/readiness, status, service-manager recovery, durable stop, and
uninstall. It is not live-host gameplay, cold boot, Windows SCM, activation on a
host, or the measured soak, and the host was **not** rebooted.

## Setup

- Host `completetrain-B550-GAMING-X-V2`, systemd `255.4-1ubuntu8.17`, cgroup v2.
- Release binary: release `watchdog` SHA-256
  `ff34fca397628fca5aa4e8b0bb5066c96fc249ed7a99063378a067da6ff87ced` (includes
  the orphaned-socket recovery fix).
- Release staged under `/opt/ascension-watchdog/releases/native-lifecycle-20260911210715`
  with a packaging `release-manifest.json`; installed read-only (`555 root:root`).
- Config `/etc/ascension-watchdog/watchdog.json`: desired mode running, no
  components, authenticated admin endpoint owned by the service account.

## Observed lifecycle

| Step | Command | Result |
| --- | --- | --- |
| install | `deploy/linux/install.sh <release>` | rc 0; created the `ascension-watchdog` user/group, `/etc`, `/opt`, `/var/lib` trees, installed and enabled the unit, linked `current`, made the release read-only |
| start/readiness | `systemctl start ascension-watchdog.service` | `Type=notify`, `NotifyAccess=main`, `User=Group=ascension-watchdog`, `KillMode=control-group`, `Restart=on-failure`, `WatchdogSec=30s`; reached `ActiveState=active`, `SubState=running` (READY received) |
| status | admin `status` as the service user | authenticated reply; local read-only `diagnostics` reports `desired_mode` |
| service-manager recovery | `SIGKILL` the main process | journal `Main process exited, code=killed, status=9/KILL`, `Failed with result 'signal'`, `Scheduled restart job, restart counter is at 9`, `Started ...`; unit returned `active/running`, `Result=success` |
| durable stop | authenticated `stop --idempotency-key` as the service user | `ACCEPTED`; `diagnostics` then reports `desired_mode=stopped` |
| uninstall | `deploy/linux/uninstall.sh --config ... --watchdog ...` | rc 0; unit stopped, disabled, unit file removed (`FragmentPath` empty, `is-enabled=not-found`); state and releases preserved |

The restart counter is not 1 because earlier configuration attempts failed
validation before the successful run; the counter reflects those unit restarts.

## Defect found and fixed

The first uninstall attempt failed:

```text
watchdog: unauthorized: admin socket parent is not owned by the current user
watchdog status could not prove the owner-local store is readable
```

`uninstall.sh` runs as root and used `watchdog status` to prove durable stopped
intent. When a deployment configures the authenticated admin endpoint, `status`
uses that channel, and the admin client's endpoint trust check requires the
socket parent to be owned by the invoking user — the endpoint is owned by the
service account, so the root uninstaller could never read it.

Fix: `deploy/linux/uninstall.sh` now uses `watchdog diagnostics`, the bounded
local read-only owner-store snapshot that needs no admin transport. The
namespace-isolated installer harness
(`deploy/linux/test-install-uninstall.sh`) was tightened so its fake watchdog
fails `status` and serves only `diagnostics`, locking the fix in; the harness
passes (`linux install/uninstall namespace test passed`).

## Boundary

Verified: supported Linux root system-service install, notify readiness,
service-account identity, control-group containment, `Restart=on-failure`
recovery, authenticated durable stop, and uninstall with state/release
preservation. Not verified: uninstall data-removal option, WSL termination,
Windows SCM, live-host gameplay recovery, cold boot, on-host release
activation/rollback, or the 24-hour soak.
