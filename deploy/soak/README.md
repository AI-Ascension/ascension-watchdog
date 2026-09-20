# Supervisor soak campaign

`supervisor-soak.sh` runs the shipped systemd unit inside a disposable,
privileged Podman container (systemd as PID 1), supervises synthetic components,
and records one JSONL sample per minute to a host directory.

Scope: this is **supervisor-scope** evidence (restart recovery, restart-budget
backoff, bounded memory, no duplicate launches). It is not the cross-repository
gameplay soak, which needs the companion gateway/MCP/harness topology with a
synthetic game downstream.

The container is booted before it is used. `podman run -d --systemd=always`
returns when the container exists, not when the systemd manager inside it can
answer, so bring-up waits for `systemctl is-system-running` to report `running`
or `degraded` — `STS2_SUPERVISOR_SOAK_SYSTEMD_READY_TRIES` polls of 100 ms,
default 300 — instead of for a fixed sleep: the setup exec is the first thing
that calls `systemctl`, and it fails with "Failed to connect to bus" while PID 1
is still coming up. A container that never answers, or that exits during the
wait, ends bring-up with exit 69 naming the container and printing its own log
tail. Bring-up also owns what it created: a failure before the window is open
removes the privileged container and the staging copy it was fed, while the
container whose window did open is left running for `finalize`.
`deploy/soak/supervisor-soak-lifecycle.test.sh` runs the fail-closed regression
matrix for both against a stub runtime and is a Linux step in CI.

## Usage

```text
# on a host with podman and root
deploy/soak/supervisor-soak.sh start \
  --release-dir DIR --duration-seconds 86400 \
  [--container NAME] [--image IMAGE] [--out-dir DIR]

deploy/soak/supervisor-soak.sh finalize \
  --out-dir DIR --duration-seconds 86400
```

`--release-dir` must contain `watchdog` (executable) and
`release-manifest.json`; the script reuses `deploy/linux/install.sh` and the
unit file from `deploy/linux/`.

Each sample includes the daemon RSS, restart counter, supervised child counts, and
(when the release binary supports `watchdog components`) the durable component
records for restart attempts and backoff state.

`crossrepo-campaign.sh --bin-dir DIR --results PATH --duration-seconds N
[--single-deployment] [--fault-kinds LIST] [--env-file FILE]
[--fault-interval-seconds N] [--max-failure-diagnostics N] [--mod-addr ADDR]
[--gateway-port-base N] [--max-execution-stores N] [--exo-revision SHA]` runs
the cross-repo campaign: it keeps one synthetic downstream
(`synthetic_mod_server` from `sts2-harness` test support) running for the whole
window while each iteration runs one harness episode (which launches MCP) and
injects a fault every fault interval. It records `{"ts","iteration","result"}`
and `{"ts","fault":KIND,"result"}` lines. Without `--single-deployment` each
iteration starts a fresh gateway (the legacy single-episode topology; validated
end-to-end with a 70-second run: 13/13 iterations pass, 2 downstream faults
recovered, `campaign_complete=true`, and re-validated 2/2 at the 2026-09-17
pins).

`--single-deployment` starts **one** gateway for the whole window and runs
every episode against it with the gateway's negotiated repeated-episode lease
profile (`STS2_EPISODE_PROFILE=true`, sts2-gateway ADR 0033 / harness #262), a
fresh `STS2_LEASE_ID` and a strictly increasing `STS2_LEASE_EPOCH`; iteration
records carry `"lease_epoch"`, the first record is
`{"ts","mode":"single-deployment",...}`, and a gateway that exits ends the
campaign as a failed iteration. The profile negotiates only on the gateway's
durable recovery path, whose environment is supplied with `--env-file`
(STS2_* `KEY=VALUE` lines). That same file also supplies the synthetic
downstream's host sideband: with `STS2_SYNTHETIC_HOST_LEASE_KEY` (and
optionally `STS2_SYNTHETIC_HOST_PRINCIPAL_ID`) set, `synthetic_mod_server`
answers signed `host-lease-control-v1` frames and reports `host_lease=enabled`
on its readiness line, and without the key it reports `host_lease=closed`.
`crossrepo-campaign.sh` forwards both names to the downstream launch and refuses
to start when the reported state disagrees with the configuration, so a
durable-recovery campaign cannot begin against a downstream that would refuse
every frame. Supply the key as 64 hex characters: the pinned host terminal
decodes hex only, and the gateway accepts either hex or base64, so hex is the
one encoding that satisfies both sides of the connection. Pins, topology, the
fault matrix, and the revision that supplied
the host-lease-capable downstream are in
[`docs/evidence/single-deployment-soak-prerequisite-20260917.md`](../../docs/evidence/single-deployment-soak-prerequisite-20260917.md).

Every gateway launch is followed by a bounded wait for the runtime's own
`listening on <addr>` report — `STS2_CAMPAIGN_GATEWAY_READY_TRIES` polls of
100 ms, default 300 — rather than a fixed sleep: a launched process is not a
listening one, and a campaign that posts its durable bring-up or opens its
window first can only fail. A gateway that never reports, or that exits during
the wait, ends the campaign with exit 69 naming the address and the gateway log
tail. The campaign also kills the downstream and the gateway it launched on
every exit path, not only the normal one: a fail-closed exit used to leave the
downstream holding the address the next run needs, which turned a restart into a
campaign that could only report that readiness never arrived.
`deploy/soak/crossrepo-campaign-lifecycle.test.sh` runs the fail-closed
regression matrix for both — readiness ordering and component reaping — against
stub binaries and is a Linux step in CI.

The failure this sideband prevents is not hypothetical. A served gateway and a
served downstream were run against each other over loopback, with the
downstream's sideband configured, mismatched, and absent; only the configured
run completed the fence and the lease install. The operator-only probe is
`deploy/soak/host-sideband-gateway-probe.sh` (it needs both pinned binaries, so
it cannot run in CI), and the results are recorded in
[`docs/evidence/host-sideband-cross-process-20260920.md`](../../docs/evidence/host-sideband-cross-process-20260920.md).

Fault kinds (`--fault-kinds`, round-robin; default `downstream_restart` in
legacy mode and `restart,archive,budget,telemetry_outage` in single-deployment
mode; any other kind is a usage error): `restart` (alias `downstream_restart`)
kills and restarts the downstream; `archive` copy-truncates the long-lived logs
and moves completed execution stores into `archive/<seq>/` while the gateway
keeps running; `budget` is a burst of three consecutive downstream restarts;
`telemetry_outage` requires the next episode to pass while its own export
reports `status=partial` against the harness's fixed loopback OTLP endpoint.
Every injection records `recovered` or `failed`, and in single-deployment mode
a fault whose recovery finds the gateway dead is `failed`.

Successful iteration logs are discarded. A failed iteration retains its runtime
and gateway logs under `failure-diagnostics/` and records both relative paths
plus its runtime exit status in JSONL. Retention defaults to 16 failure pairs
and is bounded with `--max-failure-diagnostics`; this prevents a long campaign
from overwriting the only diagnostics needed to investigate a failure.
The long-lived synthetic downstream log is retained as `synthetic-mod.log` in
the supplied results directory, rather than in `/tmp`, so startup and restart
diagnostics survive host temporary-file cleanup.

Successful per-episode execution stores are bounded as well: the runner retains
at most 64 `execution-*.sqlite3` files by default, configurable with
`--max-execution-stores`. Failed iterations move their execution store into the
same bounded failure-diagnostic group as their logs. This keeps a fixed-duration
campaign from accumulating an unbounded per-episode database history.

`crossrepo-campaign-finalize.sh --results PATH --duration-seconds N
[--single-deployment]` summarizes a cross-repo campaign results file
(iterations, pass/fail, faults and recoveries per kind, elapsed seconds) and
prints `campaign_complete=true` only when the elapsed wall-clock reaches the
duration, there are no failed iterations, every injected fault of every kind
recovered and no unknown fault kind was recorded, and the final non-empty line
is a complete terminal
`{"ts":"<iso8601>","done":true,"iterations":N}` record whose count reconciles with
the recorded iteration and pass/fail records. A truncated or interrupted results
file — lost iteration records, a torn or non-terminal `done` record, or a missing
marker — is reported `campaign_complete=false` with `records_reconciled=false`, so
an incomplete campaign cannot be presented as a completed soak.
With `--single-deployment` (or whenever the file carries the runner's mode
record) it additionally requires exactly one mode record, a `lease_epoch` on
every iteration record with strictly increasing values, and at least one
recovered `restart`, `archive`, `budget` and `telemetry_outage` fault, so a
fresh-gateway run or a partial fault matrix cannot be finalized as
single-deployment evidence.
`deploy/soak/crossrepo-campaign-finalize.test.sh` runs the fail-closed regression
matrix, including torn and non-terminal `done` records.

`finalize` prints the sample count, first/last timestamp, elapsed seconds,
`active_samples`, and `soak_complete=true` only when the elapsed wall-clock
reaches the requested duration *and* at least one sample saw the supervisor
active. Each gate that refuses is printed with the value that refused it, so an
accelerated observation cannot be presented as a 24-hour soak, and a window
whose service never came up cannot be presented as a supervised one.
