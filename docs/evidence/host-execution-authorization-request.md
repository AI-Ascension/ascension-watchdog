# Host-execution authorization request — native service, recovery, reboot, rollback, soak

Classification: `prepared, not executed`. This record prepares the remaining
native/live evidence work with a concrete target, commands, impact, recovery,
and acceptance so that only the genuinely required authorization is requested.
No service was installed, no host was rebooted, and no live campaign was run.

## Target and observed state

Read-only inspection of `completetrain@train.home.complete.tech`
(`BatchMode=yes`) on 2026-09-11 found:

- hostname `completetrain-B550-GAMING-X-V2`, kernel `7.0.0-31-generic`, cgroup v2
  (`cpuset cpu io memory hugetlb pids rdma misc dmem`).
- systemd `255.4-1ubuntu8.17`; user manager `degraded` (pre-existing), user
  linger enabled.
- 91 GB free on `/`.
- `deploy/linux/install.sh` requires `id -u` = 0 and installs to
  `/etc`/`/opt`/`/var`; non-interactive general sudo is unavailable and the
  narrow unrelated `NOPASSWD` helpers must not be used to bypass that.

This host is a busy shared workstation with unrelated workloads (Docker,
Podman, many active services). It is not a blanket destructive-test target.

## Already-authorized evidence (no new permission needed)

Synthetic child-process tests are authorized. The native Linux watchdog-to-harness
process-boundary smoke already passed on this host and remains process-boundary
evidence only. The unified cross-repository locked build now passes locally.

## Requested authorizations

Each item lists the objective, the exact commands that would run, the impact,
the recovery plan, and the acceptance checks. Approval for one item does not
imply approval for another; the reboot item is separate.

### 1. Native Linux systemd service lifecycle (install/start/status/stop/uninstall)

- Objective: prove the supported Linux service adapter end to end against a real
  systemd system manager: `Type=notify` readiness, `WATCHDOG=1` heartbeat,
  `Restart=on-failure` service-manager recovery, cgroup containment, durable stop
  protection, and retained state.
- Requires: root (or an approved disposable Linux VM/host).
- Commands (on an approved target, using a validated release under
  `/opt/ascension-watchdog/releases/`):
  ```text
  sudo deploy/linux/install.sh /opt/ascension-watchdog/releases/<release>
  sudo systemctl start ascension-watchdog.service
  systemctl status ascension-watchdog.service
  systemctl show ascension-watchdog.service -p Type,NotifyAccess,SubState,ActiveState
  sudo systemctl kill -s KILL ascension-watchdog.service   # Restart=on-failure recovery
  sudo systemctl stop ascension-watchdog.service
  sudo deploy/linux/uninstall.sh                            # verify durable no-restart intent
  ```
- Impact: installs a system service, a system user/group, and state under
  `/var/lib/ascension-watchdog`; may briefly occupy the watchdog unit only. It
  does not touch the game or unrelated units.
- Recovery: `sudo deploy/linux/uninstall.sh`; confirm the unit is gone and the
  state directory is removed or retained per the requested data option.
- Acceptance: `READY=1` only after reconciliation; heartbeat after the first
  completed loop; a killed main process is restarted by systemd; a durable stop
  is not revived by restart; no orphaned cgroup; state retained across restart.

### 2. Live-host recovery campaign

- Objective: kill and restart the real watchdog daemon while the supervised
  child/host survives, and prove fresh-authority reconciliation with retained
  `UNKNOWN` outcomes and no repeated game action.
- Commands: start the installed service (item 1), then `systemctl kill -s KILL`,
  `systemctl restart`, and `systemctl stop` at each recovery stage while logging
  the daemon store.
- Impact: bounded to the watchdog unit and its own supervised child; no reboot.
- Recovery: stop and uninstall the unit; restore the previous state file.
- Acceptance: unknown admission after a crash between durable boundaries is
  quarantined, not repeated; historical reads never authorize mutation; a
  durable stop survives restart.

### 3. Cold-boot recovery

- Objective: prove durable boot/fence/lease invalidation after a real reboot.
- Requires: explicit authorization to reboot the target; a busy shared host must
  not be rebooted. An approved disposable host is required.
- Commands: `sudo systemctl reboot`, then after boot re-inspect the watchdog
  store and service state.
- Impact: full host reboot; all unrelated workloads restart. This is the item
  that most needs a disposable target.
- Recovery: host returns to multi-user; unrelated services are expected to
  self-recover; a snapshot/rollback should be taken first.
- Acceptance: stale boot/lease cannot authorize mutation after reboot; durable
  intent is preserved; the service reaches `READY=1` only after reconciliation.

### 4. Activation and rollback on a host

- Objective: exercise `watchdog release activate`/`release rollback` against a
  validated on-host release set with a sealed cross-repository handoff.
- Commands: build the admitted set, stage a validated release under
  `/opt/ascension-watchdog/releases/`, then `release activate` and
  `release rollback` with exact digests and idempotency keys, observing the
  selector and audit rows.
- Impact: switches the managed `current` symlink and the durable selector; no
  reboot.
- Recovery: `release rollback` to the recorded previous release; re-run the
  activation with the same idempotency key after an uncertain response.
- Acceptance: a partial/unknown release is rejected before mutation readiness;
  rollback is restricted to the exact previous identity; replay is idempotent.

### 5. Measured 24-hour soak

- Objective: run the configurable 24-hour cross-repository soak across restart,
  archive, budget, and telemetry outage, recording elapsed duration, bounds, and
  duplicate-effect evidence.
- Commands: start the installed service with soak configuration and a
  restart/outage schedule, then collect the watchdog/companion stores for 24
  wall-clock hours.
- Impact: 24 hours of a dedicated target; not appropriate for the shared
  workstation without a dedicated slot.
- Recovery: stop and uninstall the unit; archive the collected stores.
- Acceptance: elapsed wall-clock duration is at least 24 hours; no duplicate
  effects; bounded memory/queue growth; unresolved operations retained.

## Lower-impact partial option (if full authorization is not granted)

A systemd **user-scope transient unit** (`systemd-run --user`) can exercise
readiness notification and cgroup containment of the Linux adapter against a
synthetic child without root and without a persistent system service. It does
not prove the installed system-service path, live host, reboot, activation,
rollback, or soak, and it would be labeled as synthetic/user-scope evidence
only. This is offered only if the higher-impact host work remains unauthorized.

## Status

No item above has been executed. Native service, live-host, cold-boot, rollback,
and soak axes remain unverified.
