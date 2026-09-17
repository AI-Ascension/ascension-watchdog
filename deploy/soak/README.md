# Supervisor soak campaign

`supervisor-soak.sh` runs the shipped systemd unit inside a disposable,
privileged Podman container (systemd as PID 1), supervises synthetic components,
and records one JSONL sample per minute to a host directory.

Scope: this is **supervisor-scope** evidence (restart recovery, restart-budget
backoff, bounded memory, no duplicate launches). It is not the cross-repository
gameplay soak, which needs the companion gateway/MCP/harness topology with a
synthetic game downstream.

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
(STS2_* `KEY=VALUE` lines). Pins, topology, the fault matrix, and the current
blocker (a host-lease-capable synthetic downstream does not exist yet) are in
[`docs/evidence/single-deployment-soak-prerequisite-20260917.md`](../../docs/evidence/single-deployment-soak-prerequisite-20260917.md).

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

`finalize` prints the sample count, first/last timestamp, elapsed seconds, and
`soak_complete=true` only when elapsed wall-clock is at least the requested
duration. A shorter run is reported `soak_complete=false`, so an accelerated
observation cannot be presented as a 24-hour soak.
