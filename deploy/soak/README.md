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

`crossrepo-campaign-finalize.sh --results PATH --duration-seconds N` summarizes a
cross-repo campaign results file (iterations, pass/fail, downstream faults and
recoveries, elapsed seconds) and prints `campaign_complete=true` only when the
elapsed wall-clock reaches the duration, there are no failed iterations, and
every downstream fault recovered.

`finalize` prints the sample count, first/last timestamp, elapsed seconds, and
`soak_complete=true` only when elapsed wall-clock is at least the requested
duration. A shorter run is reported `soak_complete=false`, so an accelerated
observation cannot be presented as a 24-hour soak.
