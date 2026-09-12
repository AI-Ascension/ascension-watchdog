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

## Why a single continuous deployment is not yet possible

To see whether one running deployment could be soaked continuously, the topology
was exercised outside the test: a long-lived synthetic downstream
(`sts2-harness` PR [#89](https://github.com/AI-Ascension/sts2-harness/pull/89),
merged as `9e85c29049e942140b97d8fbab2e52ba95475964`) plus a persistent gateway,
with the harness runtime launched repeatedly against the same gateway instance.
The first episode succeeded (`rc=0`); the second failed:

```text
sts2-harness runtime failed: Runtime-v3 episode failed: episode launch failed
```

A follow-up experiment varied `STS2_SESSION_ID`, `STS2_LEASE_ID`, and
`STS2_LEASE_EPOCH` per episode against one gateway; every attempt still failed
with `episode launch failed` (the gateway pins its configured session, and a
second episode on the same instance is rejected). So the current companion
contract admits one episode per gateway instance; a continuous
single-deployment soak needs companion support for repeated episodes (or one
fresh gateway per episode), which is why the running campaign restarts the
gateway/harness stack each iteration while keeping the synthetic downstream
persistent. The campaign here
therefore restarts the whole stack each iteration, which still exercises
cross-repo coordination, restart, and telemetry-outage behavior: each harness run
reports `telemetry export status=partial sent=0 failed=3` with no collector.

## Boundary

No first effect is produced against a real game, and no continuous deployment
state is carried across iterations. Windows SCM, WSL, host-level reboot, and the
continuous cross-repository soak remain open.
