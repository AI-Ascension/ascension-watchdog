# Persistent-downstream cross-repo soak campaign — 2026-09-12

Classification: `complete 24-hour cross-repo campaign with a persistent synthetic
downstream` (repeated composition; see Final result). This supersedes the earlier
repeated-composition campaign: the
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

## Initial capture (historical)

- First iterations at `2026-09-12T07:01:36Z` onward: `pass` (6/6 at capture).

Each harness run reports `telemetry export status=partial sent=0 failed=3`
because no collector is configured, so the campaign also exercises telemetry
outage with authoritative persistence healthy.

## Boundary

The downstream is deterministic test support (no real game behavior) and each
iteration uses a fresh gateway/harness process, so this is not a continuous
single-deployment soak; a gateway that supports repeated episodes per lease
would be required for that.

## Final result (recorded 2026-09-14)

The campaign completed. The final appended line is
`{"ts":"2026-09-13T07:01:28Z","done":true,"iterations":15640,"pass":15629,"fail":11}`,
which is 24 h 0 m after the first record (`2026-09-12T07:01:25Z`). The raw
appended log (`results/iterations.jsonl`, 15,731 lines) was read back on the
Train host. Its contents:

| record kind | count |
|---|---|
| iteration `pass` | 15,628 |
| iteration `fail` | 6 |
| `downstream_restart` fault events | 95 (95 `recovered`, 0 `failed`) |
| truncated / unparseable line | 1 |
| final `done` summary | 1 |

The per-iteration records do not reconcile with the summary counters:
`iterations=15640` implies six more iteration records than are present (15,634),
with five `fail` and one `pass` increment unaccounted for, and one appended line
truncated. The campaign script appends `downstream_restart` records outside the
iteration counter and does not fsync, but the retained artifacts do not establish
the exact cause. Treat the per-iteration records as authoritative and the summary
counters as advisory.

The six recorded iteration failures are transient and clustered:

- `2026-09-12T10:22:14Z`, iteration 2094 — `fail`
- `2026-09-12T10:22:21Z`, iteration 2095 — `fail`
- `2026-09-12T10:33:07Z` … `2026-09-12T10:33:22Z`, iterations 2207–2210 (four
  records) — `fail`

None coincides with a `downstream_restart` event (all 95 recovered). The loop
reuses `127.0.0.1:21000+(i % 400)` for the gateway listener with a 1 s settle
before each harness run, so listener/port reuse or unrelated host load is a
plausible campaign-harness cause, but the per-iteration harness/gateway logs were
written under `/tmp` and overwritten each iteration and were not retained, so the
cause is not confirmed.

Machine-readable counts are in
[`crossrepo-soak-campaign-20260912-result.json`](crossrepo-soak-campaign-20260912-result.json).
The boundary is unchanged and `SOAK_VERIFIED` remains unverified: 24 h of
repeated cross-repo composition is not the continuous single-deployment soak.
