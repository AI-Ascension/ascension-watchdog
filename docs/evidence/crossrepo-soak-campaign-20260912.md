# Persistent-downstream cross-repo soak campaign — 2026-09-12

Classification: `running 24-hour cross-repo campaign with a persistent synthetic
downstream`. This supersedes the earlier repeated-composition campaign: the
deterministic synthetic downstream (the fake mod server from `sts2-harness` test
support, merged as PR #89) now stays up for the whole campaign, while the
gateway + MCP + harness stack cycles once per iteration. It is still not the
continuous single-deployment soak (one gateway instance admits one episode per
lease), but it exercises cross-repo coordination, restart, and telemetry-outage
behavior against a long-lived downstream.

## Setup

- Runs as `completetech` (uid 1003) on the supplied Train host inside a rootless
  Podman container (`ascension-crossrepo-soak`, `ubuntu:24.04`), with the built
  binaries mounted.
- One long-lived synthetic downstream on `127.0.0.1:20001`
  (`STS2_SYNTHETIC_MOD_ADDR`), started once and kept running for the campaign.
- Each iteration: start the real gateway on an ephemeral fixed port with
  `STS2_MOD_ADDR` pointing at the persistent downstream, run the real harness
  runtime one episode (which launches MCP via `STS2_MCP_BINARY`) with
  `STS2_PROVIDER_KIND=synthetic` and the bounded exo bridge, then stop the
  gateway and record `{"ts","iteration","result"}`.
- Fault injection: every 15 minutes the persistent downstream is killed and
  restarted on the same address, and the outcome is recorded as a
  `downstream_restart` event, so the campaign also covers a downstream outage
  and recovery.
- Duration: 24 hours from `2026-09-12T07:01:36Z` (target
  `2026-09-13T07:01:36Z`).

## Observed so far

- First iterations at `2026-09-12T07:01:36Z` onward: `pass` (6/6 at capture).

Each harness run reports `telemetry export status=partial sent=0 failed=3`
because no collector is configured, so the campaign also exercises telemetry
outage with authoritative persistence healthy.

## Boundary

The downstream is deterministic test support (no real game behavior) and each
iteration uses a fresh gateway/harness process, so this is not a continuous
single-deployment soak; a gateway that supports repeated episodes per lease
would be required for that.
