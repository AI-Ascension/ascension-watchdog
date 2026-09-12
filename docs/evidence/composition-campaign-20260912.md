# 24-hour cross-repo composition campaign — 2026-09-12

Classification: `running 24-hour repeated cross-repo executable composition
campaign`. This is genuine long-running cross-repo evidence (real gateway, MCP,
and harness processes), but it is **not** the continuous-deployment gameplay
soak: each iteration composes the stack from a clean start with a synthetic
provider and the harness test-support fake mod server, rather than keeping one
deployment running across restart/archive/budget/telemetry-outage injection.

## Setup

- Runs as the dedicated `completetech` account (uid 1003) on the supplied Train
  host inside **rootless Podman**, using the environment created for this work
  (network `ascension-watchdog`, volume `ascension-watchdog-state`).
- Container `ascension-composition-soak` (`ubuntu:24.04`) mounts the built
  gateway/MCP/harness and composition-test binaries read-only and a campaign
  directory read-write.
- Loop: every 30 seconds, run the harness operator test
  `executable_runtime_v4_composes_unknown_reconcile_and_foreign_state_fence`
  and append `{"ts","iteration","result"}` to
  `results/iterations.jsonl`; at the end append a `{"done",...}` summary line.
- Duration: 24 hours from `2026-09-12T05:36:55Z` (target
  `2026-09-13T05:36:55Z`).

## Observed so far

- Iteration 1 at `2026-09-12T05:36:55Z`: `pass`.

Completion evidence will report the iteration count and pass/fail totals, so a
run shorter than 24 hours cannot be presented as the campaign.

## Boundary

No first effect is produced against a real game, and no continuous deployment
state is carried across iterations. Windows SCM, WSL, host-level reboot, and the
continuous cross-repository soak remain open.
