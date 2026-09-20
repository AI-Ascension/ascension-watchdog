# Single-deployment soak prerequisite and runbook — 2026-09-17

Classification: `source-derived` prerequisite record plus a `confirmed` local
smoke that **did not** reach two consecutive episodes on one deployment. This
document pins what the continuous single-deployment soak
([ascension-watchdog#58](https://github.com/AI-Ascension/ascension-watchdog/issues/58))
must run against, and records the exact reason the campaign cannot start yet.
It is not soak evidence; `SOAK_VERIFIED` stays `unverified`.

Revision 2 (2026-09-17): the gateway pin moved to `2f7490d7` and the
two-episode claim was corrected after [sts2-gateway#81](https://github.com/AI-Ascension/sts2-gateway/pull/81)
proved that sequence at the gateway component level. The campaign blocker is
narrower than first recorded, not lifted; see "Correction" below.

Revision 3 (2026-09-20): the narrower blocker is delivered in
[sts2-harness#362](https://github.com/AI-Ascension/sts2-harness/pull/362).
`synthetic_mod_server` — the same operator target the campaign already launches
from `--bin-dir` — now serves signed `host-lease-control-v1` frames when
`STS2_SYNTHETIC_HOST_LEASE_KEY` is set, and reports `host_lease=enabled` (or
`host_lease=closed`) on its readiness line.
`deploy/soak/crossrepo-campaign.sh` forwards that sideband to the downstream
launch and refuses to start when the reported state disagrees with the
configuration. The campaign therefore moves from "cannot start" to "can start
once the window is authorized"; AC3–AC5 and `SOAK_VERIFIED` are unaffected.

## Accepted companion prerequisite (issue AC1)

| item | value | label |
|---|---|---|
| Ownership-backed prerequisite | [sts2-gateway#67](https://github.com/AI-Ascension/sts2-gateway/issues/67), reopened 2026-09-17 pending review of the real-process evidence in [sts2-gateway#81](https://github.com/AI-Ascension/sts2-gateway/pull/81) | confirmed (API read: `state=OPEN`, `stateReason=REOPENED`) |
| Gateway delivery | [sts2-gateway#78](https://github.com/AI-Ascension/sts2-gateway/pull/78) `173a7ed7`, [sts2-gateway#79](https://github.com/AI-Ascension/sts2-gateway/pull/79) `c9ccbea9` (stop-precedence correction), [sts2-gateway#81](https://github.com/AI-Ascension/sts2-gateway/pull/81) `2f7490d7` (spawned-process episode evidence) | confirmed |
| Decision record | gateway `docs/decisions/0033-repeated-episode-lease-profile.md` | source-derived |
| Profile / capability / header | `repeated-episode-lease-v1` / `sts2-gateway/repeated-episode-lease-v1` / `x-sts2-episode-profile` | source-derived |
| Descriptor schema digest | `f3a04bab61ce4898eda0fa88cb546441493e49eef19b1e5e0841a3b4ef7c4331` | source-derived (harness `episode_profile.rs` carries the same constant) |
| Harness consumer | [sts2-harness#262](https://github.com/AI-Ascension/sts2-harness/pull/262); opt-in `STS2_EPISODE_PROFILE=true`; the profile is armed only for a completed episode | source-derived |
| MCP | no change required: sts2-mcp-server is not on the gateway allocate/release path | source-derived |

Owner boundaries are preserved: the profile is gateway-owned, its consumer is
harness-owned, and this repository changes only its own soak tooling and
evidence.

## Pins (issue AC2)

| component | revision | notes |
|---|---|---|
| sts2-gateway `main` | `2f7490d72e262378d5a55c920b6ca6355e21ef68` | includes #78, #79, #80 and #81. The local smoke recorded below was run against `804691c5`, which does not contain #81; the smoke's findings are unchanged by #81 (see the component-evidence note) |
| sts2-harness pinned revision | `f673658065d3f7ec5087afa221536799fe30aa13` | merge of #262, the campaign's harness pin; it is an ancestor of live `main` (`67de2007`, which adds #263/#264/#265/#266). Moving the pin is an owner decision, not a prerequisite for the correction above |
| sts2-mcp-server `main` | `65cb405616ecddfb7bf7b76edf341be30a442ca2` | unchanged for this prerequisite |
| ascension-watchdog | base `a50474dd5dbd63b9093af223bfe0348fddc27f05` plus the merge commit of the pull request that adds this document | the campaign scripts live at `deploy/soak/` |
| Reviewed Exo source revision | `b06869ab789dee3f80ca474b5fa89dbe47ccb859` (harness `EXO_SOURCE_REVISION`, ADR 0017) | the campaign's previous pin `7801005e…` is the retired base revision and is refused by the pinned harness |
| Synthetic provider bridge | `bounded-exo-bridge.sh` from harness `tests/support/runtime_v4_executable_composition_process.rs`, run with `STS2_EXO_ADMISSION=legacy` | raw-wire test probe, not a provider |

Binaries built on this machine from the pinned revisions with
`cargo build --release --locked` (gateway `sts2-gateway-runtime`, MCP
`sts2-mcp-server`, harness `sts2-harness-runtime`) and
`cargo test --release --locked -p sts2-harness --test synthetic_mod_server --no-run`:

```text
0f97b0f737ab83a85b327589658165b4169d0bdfd712b0fa83d842b81ff2f340  sts2-gateway-runtime
533353748ffc2d2e6f41221dda96da358c612c7984c1417ae827a64f369cc642  sts2-mcp-server
96f27fd85ad337ef1691af1b5f27a4d1d86de9e87f473677b03dd93175e5e800  sts2-harness-runtime
d578943b06b8b75292d0e6e48ad407d0cecd49c91dd55399b707691b564051e3  synthetic_mod_server
d1ba6f6dddf27cbd1fd53a34f377a7256edf740435686bb88bddb9202abb9063  bridge.sh
```

These digests are `confirmed` for the local build only (Rust 1.97.1, Linux
x86_64) and are **pinned to gateway `804691c5`**; they are not
reproducible-build claims. A campaign run at the corrected gateway pin
`2f7490d7` must rebuild and re-hash `sts2-gateway-runtime`. The soak host must
rebuild from the same revisions, record its own `SHA256SUMS` for the campaign `--bin-dir`,
and, for the supervisor-scope lane, the `release-manifest.json` of the watchdog
release directory (`deploy/soak/supervisor-soak.sh --release-dir`), in the
campaign evidence before the clock starts.

## Topology

- One synthetic downstream (`synthetic_mod_server`, harness test support) for
  the whole window.
- **One** `sts2-gateway-runtime` process for the whole window. The gateway is
  never restarted inside the window; a gateway that exits ends the campaign as
  a failed iteration (`"gateway_exited":true`).
- One harness episode per iteration (`sts2-harness-runtime`, profile
  `runtime-v4-expert`, which launches `sts2-mcp-server`), each with
  `STS2_EPISODE_PROFILE=true`, `STS2_LEASE_ID=lease-<n>` and
  `STS2_LEASE_EPOCH=<n>` where `n` is the iteration; the iteration record
  carries `"lease_epoch":n` and the finalizer requires the sequence to be
  strictly increasing.
- Duration: `--duration-seconds 86400`; the finalizer refuses
  `campaign_complete=true` below it.
- Runner: `deploy/soak/crossrepo-campaign.sh --single-deployment`; finalizer:
  `deploy/soak/crossrepo-campaign-finalize.sh --single-deployment`.

Lease rule, as pinned by the runner (label `inferred` for the soak topology: the
two-episode sequence itself is now proven at the gateway component level, but
never end to end through this runner, see below): each episode is launched
with a fresh lease id and an epoch strictly above the previous completed one.
On the gateway's durable recovery path the allocation response carries the
gateway-issued `lease_id`/`lease_epoch` (`MAX(lease_epoch)+1`) and the harness
adopts them (`runtime_allocation_context.rs::ValidatedAllocation::apply_current_lease`),
so the harness-side pins are the campaign's record of intent and the
finalizer's monotonicity witness; on the attached adapter the pins must match
exactly and the profile is unsupported (below).

The profile is gateway-process-local state bound to boot id, incarnation and
authority generation (ADR 0033); a gateway restart discards it, which is why the
gateway is never restarted inside the window.

### Recovery environment the profile requires (source-derived)

`negotiate_episode_profile` answers `503 episode_profile_boot_required` unless
the gateway holds a boot authority, and the attached adapter "issues no durable
lease, so it cannot hand out a distinct lease/epoch" (`service_lease.rs`). The
single-deployment gateway therefore needs the durable recovery path:
`STS2_RECOVERY_STORE`, `STS2_DEPLOYMENT_ID`, `STS2_RUNTIME_HOST_PRINCIPAL_ID`,
`STS2_RUNTIME_HOST_LEASE_KEY` (32 bytes, hex or base64), and lowercase UUID
`STS2_INSTANCE_ID` / `STS2_CALLER_ID` / UUIDv4 `STS2_SESSION_ID` shared by the
gateway and every harness launch. The runner accepts these through
`--env-file` (STS2_* `KEY=VALUE` lines). With a store the served gateway starts
its own boot (`service_runtime.rs`, `store.start_boot`), then requires a host
fence (`POST /v1/recovery/host-fence`, control scope, forwarded to the
downstream which must answer a signed `FENCE_ACCEPTED`) and, on allocate,
a signed host-lease install acknowledgement from the downstream
(`host-lease-control-v1`; install/renew/revoke frames).

## Fault matrix (issue AC2/AC3)

All four kinds are injected round-robin every `--fault-interval-seconds` by
`crossrepo-campaign.sh --single-deployment` (default matrix
`restart,archive,budget,telemetry_outage`); every injection writes
`{"ts","fault":<kind>,"result":"recovered"|"failed"[,"detail"]}`, the finalizer
requires each kind at least once with every record `recovered`, and any other
kind fails the campaign closed.

| kind | injection | recovery evidence required for `recovered` |
|---|---|---|
| `restart` | the supervised synthetic downstream is killed and restarted on the same address | the restarted downstream logs `synthetic_mod_listening` within 10 s; the gateway process is still alive; the next iteration passes on a higher epoch |
| `archive` | copy-truncate rotation of the long-lived `gateway.log` and `synthetic-mod.log` into `archive/<seq>/`, and completed `execution-*.sqlite3` stores moved there, while the gateway keeps running | both logs archived (`detail` names the directory); the gateway process is still alive; subsequent iterations pass and keep logging |
| `budget` | a burst of three consecutive downstream restarts inside one interval, exceeding a one-restart-per-interval budget | every restart in the burst comes back (`detail` = `restarts=3`); the gateway process is still alive; the next iteration passes |
| `telemetry_outage` | no collector listens on the harness's fixed loopback OTLP endpoint `127.0.0.1:14318` during the next episode | that episode passes and its runtime log carries `telemetry export status=partial` (the outage was observed, not masked); the gateway process is still alive; recorded after the episode with `detail` = `iteration=<n>` |

Tooling validation (`confirmed`, this machine, legacy fresh-gateway topology so
that episodes pass): a 45 s run with `--fault-kinds
restart,archive,budget,telemetry_outage --fault-interval-seconds 2` recorded
9/9 iterations `pass` and `restart=2/2 archive=2/2 budget=2/2
telemetry_outage=2/2` recovered, `records_reconciled=true`. This validates the
injection and finalizer code paths only; it is not soak evidence and not the
single-deployment topology.

Supervisor-scope restart-budget and backoff evidence (watchdog daemon restarting
a crashed component under its own budget) is a separate lane:
`deploy/soak/supervisor-soak.sh`.

## Local two-episode smoke (pre-soak proof, this machine, 2026-09-17)

Status: **`unverified: local two-episode smoke could not complete`**. This is a
smoke, not a soak; nothing here counts toward the 24-hour window.

Baseline (fresh gateway per iteration, `crossrepo-campaign.sh` without
`--single-deployment`, 8 s): `2/2` iterations `pass`, `done` record
reconciled — the pinned gateway/harness/MCP/downstream stack composes on this
machine once `STS2_EXO_REVISION` is the reviewed `b06869ab…` and
`STS2_EXO_ADMISSION=legacy` is set (with the retired `7801005e…` pin every
iteration failed with `STS2_EXO_REVISION is not the reviewed Exo revision`).

`--single-deployment` against the attached adapter (no recovery store; the only
downstream available is the harness synthetic mod server), 12 s:

```text
{"mode":"single-deployment","gateway_addr":"127.0.0.1:23100","episode_profile":"repeated-episode-lease-v1"}
{"iteration":1,"result":"fail","runtime_exit":2,...,"lease_epoch":1}   runtime: Runtime-v3 episode failed: episode cleanup failed
{"iteration":2,"result":"fail","runtime_exit":2,...,"lease_epoch":2}   runtime: Runtime-v3 episode failed: episode launch failed
{"iteration":3,"result":"fail","runtime_exit":2,...,"lease_epoch":3}   runtime: Runtime-v3 episode failed: episode launch failed
```

Episode 1 ran to its terminal state (nine telemetry spans exported as
`partial`) and failed only on the profiled release; episodes 2 and 3 were not
admitted. Direct route probes of the same pinned gateway binary (identity
headers only, `curl` defaults suppressed) give the exact reasons:

| deployment | request | response |
|---|---|---|
| attached adapter | `POST /v1/sessions/allocate` | `200 {"status":"allocated","lease_id":"lease-1","lease_epoch":1,...}` |
| attached adapter | release with `x-sts2-episode-profile: repeated-episode-lease-v1` | `503 {"error_code":"episode_profile_boot_required"}` |
| attached adapter | release without the header | `200 {"status":"released",...}` |
| attached adapter | second `POST /v1/sessions/allocate` | `409 {"error_code":"lease_context_revoked"}` |
| durable store (`STS2_RECOVERY_STORE`, host principal, host lease key, UUID identities) | `POST /v1/sessions/allocate` | `503 {"error_code":"recovery_host_fence_required"}` |
| durable store | profiled release | `409 {"error_code":"lease_not_active"}` |

A harness episode against the durable gateway fails the same way
(`episode launch failed`, exit 2), because no host fence can be accepted.

Finding (label `source-derived`, confirmed by the probes above): at these pins
the repeated-episode profile is reachable only through the durable recovery
path, and that path needs a downstream that implements
`host-lease-control-v1` (signed host fence, install, renew and revoke
acknowledgements) plus a control-scoped host-fence driver. The gateway proves
it with its in-crate signed host fake
(`service_allocation_negative_test_support.rs::spawn_signed_ack_server`, test
code, not a runnable target); the harness `synthetic_mod_server` — the only
long-lived synthetic downstream any repository ships — implements the
runtime-v3/v4 downstream API only and hard-codes `lease-1`/epoch `1`.

Correction (2026-09-17, after this document's first merge): the earlier text
here claimed that no repository contains a process-level test that boots
`sts2-gateway-runtime` with a recovery store, and that the two-episode proof
"cannot be produced". That absolute claim is now false. [sts2-gateway#81](https://github.com/AI-Ascension/sts2-gateway/pull/81)
(merge `2f7490d72e262378d5a55c920b6ca6355e21ef68`) adds
`crates/gateway/tests/gateway_real_process_episode.rs`, a cargo integration
test that spawns the real `sts2-gateway-runtime` binary against a temporary
recovery store over loopback TCP, drives a signed host fake that answers
`host-lease-control-v1` frames, and asserts that consecutive episodes land on
one boot authority with distinct lease ids and a strictly higher epoch, that a
later episode cannot dispatch or resolve an earlier episode's receipt, and that
a released lease's fence headers are refused. The two-episode sequence is
therefore proven, on `main`, at the gateway component level.

What #81 does **not** supply is a shippable runnable downstream: the signed
host fake is test code compiled into that integration test, not an operator
target, and it is not on any campaign `--bin-dir`. The narrower blocker
therefore stands unchanged — until a host-lease-capable synthetic downstream
(or an owner-approved equivalent) exists as a runnable artifact, the campaign
below cannot start, and the soak topology rule above stays `inferred`. A
passing cargo test is component evidence, not a substitute for the 24-hour
window; `SOAK_VERIFIED` is unaffected.

Handoff (proposed, owner decision required; this repository does not implement
companion-owned protocol fakes): a gateway/harness-owned operator target that
answers `host-lease-control-v1` frames for a synthetic deployment, or a
gateway-owned decision that the attached adapter may negotiate the profile.
(Delivered as the first of those two in sts2-harness#362, 2026-09-20; see
Revision 3.)

## What remains external (issue AC3–AC5)

- AC3: a dedicated soak host and 24 h of wall clock
  (`host-execution-authorization-request.md` §5); blocked additionally by the
  handoff above.
- AC4: evidence arrives only with AC3; the tooling half is in place
  (`crossrepo-campaign-finalize.sh --single-deployment`, regression suite
  `crossrepo-campaign-finalize.test.sh`).
- AC5: independent receipt review after the run; `SOAK_VERIFIED` stays
  `unverified` until then.
