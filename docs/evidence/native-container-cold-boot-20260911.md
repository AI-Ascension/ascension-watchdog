# Container-scope cold boot evidence — 2026-09-11

Classification: `container-scope cold boot` using a disposable privileged
Podman container with systemd as PID 1. The shared Train host was **not**
rebooted (explicit constraint). This is not a VM-level or host-level reboot, and
it is not Windows, WSL, gameplay, or soak evidence.

## Environment

- Host `completetrain-B550-GAMING-X-V2` (unchanged; no host restart).
- Disposable container image `docker.io/jrei/systemd-ubuntu:24.04`, run as
  `podman run -d --name ascension-boot-test --privileged --systemd=always`.
  Privileged was required because the shipped unit uses `Delegate=yes`, which
  otherwise fails with `Failed to keep CAP_SYS_ADMIN` inside a container.
- Inside the container: the shipped unit and `install.sh`, a read-only
  `/opt/ascension-watchdog/releases/boot-test` release carrying the fixed
  watchdog binary
  (`ff34fca397628fca5aa4e8b0bb5066c96fc249ed7a99063378a067da6ff87ced`),
  `/etc/ascension-watchdog/watchdog.json`, an authenticated admin endpoint, and
  a synthetic component (`/bin/sleep <marker>`, `restart=true`).

Process accounting used `ps -eo pid,user,args | grep <marker> | grep -v grep`
so a shell never counted itself.

## Observed sequence

| Phase | Action | Result |
| --- | --- | --- |
| readiness | `systemctl start` in-container | `active`; `Type=notify`, `NotifyAccess=main`, `User=ascension-watchdog`, `KillMode=control-group`; supervised child count 1 |
| boot with running intent | `podman stop` / `podman start` | `systemctl is-system-running=running`; the enabled unit auto-started to `active/running` (READY); the synthetic child was quarantined rather than relaunched (see below) |
| durable stop | authenticated `stop` as the service account | `ACCEPTED`; supervised child count 1 → 0 |
| boot with durable stop | graceful `podman stop -t 90` / `podman start` | `systemctl is-system-running=running`; the enabled unit auto-started (`active (running)`); `Status: watchdog_loop=Stopped`; `desired_mode=stopped`; supervised child count 0 |

So a cold boot restarts the enabled service into a ready supervisor, and a
durable stopped intent survives the boot: the loop stays `Stopped` and no
component is revived.

## Conservative quarantine across boot

With `desired_mode=running`, a boot still did **not** relaunch the synthetic
component: its health was `Blocked`. The persisted launch intent for a synthetic
child cannot be reconstructed into an owned process handle, so
`reconcile_persisted_launch_intents` retains the intent and quarantines the
component instead of launching a replacement (`runtime.rs`: "unreconstructable
launch intent retained for operator quarantine"). That is the intended
no-repeat-uncertain-action behavior; it means a *real* component only resumes
autonomously across a boot when its adapter proof is reconstructable, which this
synthetic fixture cannot exercise.

## Cleanup

The container and the pulled image were removed; no container, unit, or process
remains, and the host was not rebooted.

## Boundary

Verified: container-scope cold boot restarts the enabled systemd service into
`READY`; durable stopped intent survives the boot; unreconstructable synthetic
intents are quarantined rather than relaunched. Not verified: host-level or
VM-level cold boot, autonomous resumption of a real supervised component across
a boot, Windows SCM, WSL, live-host gameplay, or the 24-hour soak.
