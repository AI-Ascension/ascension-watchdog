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
[--fault-interval-seconds N] [--max-failure-diagnostics N] [--mod-addr ADDR]
[--gateway-port-base N]` runs the
cross-repo campaign: it keeps one synthetic downstream (`synthetic_mod_server`
from `sts2-harness` test support) running for the whole window while each
iteration starts a fresh gateway and runs one harness episode (which launches
MCP), restarting the downstream every fault interval. It records
`{"ts","iteration","result"}` and `{"ts","fault","result"}` lines. Validated
end-to-end with a 70-second run: 13/13 iterations pass, 2 downstream faults
recovered, `campaign_complete=true`.

Successful iteration logs are discarded. A failed iteration retains its runtime
and gateway logs under `failure-diagnostics/` and records both relative paths
plus its runtime exit status in JSONL. Retention defaults to 16 failure pairs
and is bounded with `--max-failure-diagnostics`; this prevents a long campaign
from overwriting the only diagnostics needed to investigate a failure.
The long-lived synthetic downstream log is retained as `synthetic-mod.log` in
the supplied results directory, rather than in `/tmp`, so startup and restart
diagnostics survive host temporary-file cleanup.

`crossrepo-campaign-finalize.sh --results PATH --duration-seconds N` summarizes a
cross-repo campaign results file (iterations, pass/fail, downstream faults and
recoveries, elapsed seconds) and prints `campaign_complete=true` only when the
elapsed wall-clock reaches the duration, there are no failed iterations, and
every downstream fault recovered.

`finalize` prints the sample count, first/last timestamp, elapsed seconds, and
`soak_complete=true` only when elapsed wall-clock is at least the requested
duration. A shorter run is reported `soak_complete=false`, so an accelerated
observation cannot be presented as a 24-hour soak.
