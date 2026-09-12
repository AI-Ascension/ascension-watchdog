# Supervisor soak campaign and cross-repo soak boundary — 2026-09-12

Classification: `running measured supervisor soak; cross-repo soak blocked by
missing companion game topology`. This records the long-running soak that is
accumulating wall-clock evidence and the exact reason the specified cross-repo
soak cannot be assembled from this workspace.

## Running supervisor soak

A disposable privileged Podman container (`ascension-soak`,
`jrei/systemd-ubuntu:24.04`, systemd PID 1) runs the shipped unit with a
two-component synthetic configuration:

- `stable`: `/bin/sleep 100000`, `restart=true`;
- `cycler`: `/bin/sh -c 'sleep 90'`, `restart=true` (exits every 90 s and is
  restarted subject to the restart budget of 5 per 600 s window).

A `soak-collect.timer` (60 s) appends one JSON line per sample to a host volume:

```json
{"ts":"...","active":"active","restarts":0,"rss_kb":7064,"stable":1,"cycler":0}
```

Observed so far (start `2026-09-12T02:26:51Z`):

- 31 samples, all `active`;
- daemon RSS bounded between 7064 KB and 7640 KB (steady, no growth);
- `stable` child count never above 1 (no duplicate supervisor launches);
- `cycler` is frequently 0 because it exits every 90 s and the restart budget
  puts it into backoff — the intended restart/budget behavior.

Component-level snapshot (read-only `watchdog components`, added this wave;
`/usr/local/bin/watchdog-components` in the soak container):

```json
[{"id":"cycler","state":"quarantined","restart_attempts":5,"last_error":"component is blocked or quarantined; autonomous relaunch is disabled"},
 {"id":"stable","state":"suspect","restart_attempts":1,"pid":187}]
```

So the `cycler` reached the restart budget (5 attempts in the 600 s window) and
was quarantined rather than relaunched forever, while `stable` remained the only
supervised child. This is the durable restart/budget behavior the soak is meant
to exercise.

Completion criterion: elapsed wall-clock >= 24 h (target
`2026-09-13T02:26:54Z`). Any shorter observation must not be reported as a
24-hour soak.

This is **supervisor-level** evidence: restart recovery, restart-budget backoff,
bounded memory, and no duplicate child launches. It is **not** the specified
cross-repo soak across restart, archive, budget, and telemetry outage.

## Why the cross-repo soak is not assemblable here

The companion artifacts from the admitted release set were exercised in a
disposable container:

- `gateway` starts and listens (`sts2-gateway runtime listening on
  127.0.0.1:15525 for instance instance-1`) with `STS2_GATEWAY_TOKEN` and
  `STS2_MOD_TOKEN` set.
- `mcp` starts with the same token environment.
- `harness` requires `STS2_MCP_BINARY` to launch MCP; with it set, harness
  reached MCP but then failed:

```text
sts2-harness runtime failed: MCP tool get_state content was not JSON; gateway returned HTTP 409
```

So harness needs a live MCP that can answer `get_state` with JSON and a gateway
allocation that is not in conflict — i.e. the companion game/MCP topology and its
provider configuration, which the watchdog repository does not own and this
workspace cannot assemble. A cross-repo gameplay soak therefore requires an
environment provisioned by the companion stack (or its own integration harness).

## Boundary

Verified: a real 24-hour-scale supervisor soak can run and is running with
bounded memory and no duplicate launches; the companion binaries' startup
requirements are characterized. Not verified: the cross-repo 24-hour soak,
telemetry outage, and archive/budget matrix across gateway/harness/MCP.
