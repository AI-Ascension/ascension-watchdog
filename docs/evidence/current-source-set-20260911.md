# Current source set and verification boundary — 2026-09-11

Captured at `2026-09-11T10:41:43Z`; root verification and gateway main were
refreshed at this source-set wave. The prior delivery update was recorded at
`2026-09-11T10:15:56Z`, and the current PR-head correction is recorded below.
This is a resumable integration record, not an activated release. Every
revision below is an exact local source revision; a component
passing its own gates does not establish cross-consumer, service, live-host,
reboot, or soak evidence.

## Exact source set

| Repository | Ref / delivery | Revision | State |
| --- | --- | --- | --- |
| `ascension-watchdog` | `codex/watchdog-resume-20260911` / PR [#11](https://github.com/AI-Ascension/ascension-watchdog/pull/11) | `538346e8909a2f4fc23e5b3ea9ec2960b8b34530` | selected implementation pin; current PR head `f5b81f4` contains the systemd readiness/heartbeat correction; local and exact-head hosted gates pass |
| `sts2-gateway` | `main` | `f4d14091ce1f3b5327925a7a536e2c7bf7b0c56b` | current remote main after PR #42 merge; merged host-lease safety changes included |
| `sts2-harness` | `main` | `00bd9e123a86fca39bbffb65b370aac7ed2c8218` | current remote main; component gates pass |
| `sts2-mcp-server` | `main` | `98ab84b3fad371b45b141e6d81dd9124769a4c59` | current remote main; component gates pass |
| `sts2-game-mod` | `main` | `bd8e90542dfc89366f820150c5c755e32716b1b0` | current remote main; component gates pass |
| `sts2-protocol` | `main` | `0bc689eabc5542ede2b09b030d9ea32daa8a73e7` | current remote main; artifact/conformance tests pass |
| `sts2-game-core` | `main` | `f5daf69f4f2c43fddbb04e7799d32503f7066110` | current remote main; component gates pass |
| `ai-agent-observability` | `main` / merged PR [#20](https://github.com/AI-Ascension/ai-agent-observability/pull/20), [#22](https://github.com/AI-Ascension/ai-agent-observability/pull/22) | `630431716ebfbf86280f9fd56f19d6016ad7aeb2` | current remote main; persistent Collector queue/WAL, materialization repairs, and static-probe portability merged |

A gateway safety follow-up was merged as PR
[#42](https://github.com/AI-Ascension/sts2-gateway/pull/42). The selected gateway
main commit is the merge commit `f4d1409`; its branch tip was
`9575b8b7eed684df00135ec0f2f02c9fc8ab6a3f`. It checks that durable host install
and renewal transitions change exactly one row before exposing a host-effect
candidate, and invalidates restored host bindings during rekey before a fresh
fence. The branch's exact-head hosted Rust quality and repository-policy checks
passed (workflow runs `34580441918` and `34580442118`); the merged main source
also receives a local gate below.

A harness safety/platform follow-up is also open: PR
[#84](https://github.com/AI-Ascension/sts2-harness/pull/84), current commit
`40a41285ac44964c712eabfde37e3527ce6a1939`, rejects `--resume` when the
durable episode is missing instead of creating a fresh episode and adds the
source-derived Windows named-pipe worker boundary. Its local format, strict
Clippy, and serial locked workspace gates pass. Hosted Rust-quality run
`34588219783` and policy run `34588219842` also pass for this head, but the
branch remains unmerged and is excluded from the exact source set.

The source set was fetched into isolated worktrees. The root source pin was
verified from a clean detached worktree at `538346e`; the candidate manifest
itself is committed in the newer documentation head. No changes were made to
the companion `main` worktrees. The earlier observability review branch PR #21
was closed as superseded by merged PR #20; its persistence work is represented
by current observability main. The static-probe fallback is now merged in PR
#22, but neither observability change is silently treated as an activated
release artifact.

The organization-wide public policy and site inspection is recorded in
[`organization-policy-inspection-20260911.md`](organization-policy-inspection-20260911.md).
It confirms the shared evidence labels, pull-request-only delivery boundary,
no-proprietary-file/no-copied-source rules, and the site's static proof limits;
it does not authorize metadata mutation or promote runtime claims.

## Gates executed

The watchdog passed pinned-toolchain format, standards validation, workspace
check, strict Clippy, and the full serial all-target/all-feature test command
at `538346e`:

```text
cargo +1.97.1 fmt --all -- --check
cargo +1.97.1 run --locked --manifest-path standards/tools/standards-sync/Cargo.toml -- validate --root .
cargo +1.97.1 check --locked --workspace --all-targets --all-features
cargo +1.97.1 clippy --workspace --all-targets --all-features --locked -- -D warnings
TMPDIR=/home/agent/wd-tmp-0911 cargo +1.97.1 test --locked --workspace --all-targets --all-features --no-fail-fast -- --test-threads=1
```

The final test command exited zero; it included 210 watchdog library tests,
all watchdog integration suites, fault-fixture suites, and the platform
packages, with only the repository's four expected ignored watchdog tests and
the separately labeled platform-boundary ignores. The new executable CLI
quarantine path and read-only diagnostics test are included. The storage query
suite now also covers rollback when either durable update is suppressed for
completion, known failure, or interruption quarantine. The dedicated short
temporary directory keeps test endpoint names within the product's 100-byte
Unix socket contract while avoiding the nearly-full system `/tmp` tmpfs.

The current PR head `f5b81f42dbb525fa3fdbb32a29c202822e01aaa7` was then rerun
with the same serial locked workspace command and exited zero. Its focused
Linux notifier tests passed 5/5, and the service-loop integration tests passed
6/6. Hosted validation run `34589427447` passed Ubuntu, Windows, and dependency
lanes; standards run `34589427371` also passed. These current-head results do
not change the selected source-set implementation pin above.

Gateway, harness, MCP, game-mod, protocol, and game-core each passed their
locked workspace format, strict Clippy, and all-target/all-feature test gates
in their isolated source worktrees; gateway was rerun on merged main commit
`f4d1409` for this refresh. The observability main worktree passed its shell
syntax, validation-regression, bootstrap, installer-guard, materialization-
guard, query-provision, and Collector persistence fixture suites on merged
main. Its health-probe fixture passed on current main after the portable
`readelf` fallback was merged. The official
`otel/opentelemetry-collector-contrib:0.160.0` binary validated the updated
Collector configuration with
`--feature-gates=+extension.healthcheck.useComponentStatus`.

Docker and Podman are not installed here. Therefore Compose rendering, image
build, live named-volume permissions, queue restart recovery, and service
health are not claimed. `tests/compose-invariants.sh` failed only at its
required `docker` invocation (`command not found`); this is an environment
blocker, not a passing Compose result.

## Artifact and consumer boundary

The inspected `coop-native-v1` copies agree on the schema and conformance
bytes:

```text
schema.json       2f3bc99e53080fa11b39592b64fb0ab964a16f568719a2622d0b2caf766ab629
conformance.json  8da68488ca75de12a73521eee30d3464d8c8c9f3a623a6233f2cf97fb68f43b3
```

The consumer binding is not one byte-identical current set: the protocol
artifact has manifest `ae6b0df...` and consumer-conformance
`ca8a60ba...`; current gateway/MCP copies have manifest `50a7a2b...` and
consumer-conformance `377be44...`; current harness has the same manifest and
consumer-conformance `10f71cbc...`. This is preserved as an admission
failure, not normalized by editing consumer bytes. A unified clean
cross-repository build and current consumer-conformance run were not available
in the repository layout.

## Completion axes

| Axis | Current classification |
| --- | --- |
| `IMPLEMENTATION_COMPLETE` | watchdog implementation patch complete and tested; full cross-repository assignment not complete |
| `SYNTHETIC_INTEGRATION_VERIFIED` | partial; watchdog and component synthetic suites pass, exact current consumer set is not unified |
| `WINDOWS_SERVICE_VERIFIED` | unverified; no installed SCM session |
| `LINUX_SERVICE_ADAPTER_VERIFIED` | source/unit and synthetic adapter tests pass; installed systemd adapter unverified |
| `LIVE_HOST_RECOVERY_VERIFIED` | unverified |
| `COLD_BOOT_RECOVERY_VERIFIED` | unverified |
| `SOAK_VERIFIED` | unverified |
| `REMOTE_DELIVERY_STATUS` | watchdog PR #11 open at f5b81f4 with current local and exact-head hosted gates green; gateway PR #42 merged into main at f4d1409 after green branch gates; harness PR #84 open at 40a4128 with local and hosted Rust-quality/policy gates green; observability PRs #20 and #22 merged; no activation |
| `BLOCKED_EXTERNAL` | yes: native authorized hosts, Docker/Podman, unified consumer build, and nested spawn surface are unavailable |

The historical native Linux process-boundary smoke remains linked from the
README and is not promoted here: it used a synthetic gateway/MCP downstream
and did not verify a service, gameplay, provider, reboot, release, or soak.
Only depth-1 delegation was observed in the available orchestration records;
no depth-2 or depth-3 child was created, and no depth-4 bypass was attempted.

## Delivery update — 2026-09-11 10:15 UTC

Harness PR #84 now points to `40a41285ac44964c712eabfde37e3527ce6a1939`.
The local gates at that exact head are confirmed: pinned format, strict
repository policy (`879 sized files, 0 warning(s), 0 error(s)`), Linux
warnings-denied Clippy, Windows-target boundary and harness Clippy/check, the
focused `phase3_cli` rerun, and the full serial locked workspace test command.
The first serial attempt had one transient `phase3_cli` BrokenPipe; the
focused rerun and clean serial rerun passed. Hosted Rust-quality run
`34588219783` and policy run `34588219842` also pass. The branch is still an
open PR, so the exact source set remains on harness main `00bd9e1`.

The Windows implementation is source-derived and cross-compiled here; this
machine has no native Windows linker/runtime, so Windows service installation,
named-pipe execution, SCM/Job Object behavior, live host, cold boot, and soak
remain unverified. The separate [Windows boundary ADR in the pending harness
PR](https://github.com/AI-Ascension/sts2-harness/blob/40a41285ac44964c712eabfde37e3527ce6a1939/docs/decisions/0015-windows-worker-endpoint-boundary.md)
is not part of the root source set.

## Delivery update — 2026-09-11 10:41 UTC

Root PR #11 is now at `f5b81f42dbb525fa3fdbb32a29c202822e01aaa7`. The Linux
systemd notifier now sends `READY=1` on the first completed reconciliation and
defers `WATCHDOG=1` until a later strictly increasing completed sequence when
systemd supplies a watchdog interval. Focused notifier tests, the service-loop
integration test, and the full serial workspace all-target/all-feature run
passed at this head. Hosted Ubuntu, Windows, dependency, and standards checks
are green in runs `34589427447` and `34589427371`.

The read-only source-set verifier was rerun against the unchanged selected
implementation worktree and refreshed manifest. It returned exit 1 with
`admitted=false` and manifest digest
`0902e33c084b97efc5ee0afd4af120c4b61fe527bbbc5bf13a580d2a8ccbae0d`; the
report is `/home/agent/wd-tmp-0911/source-set-report-1041.json`. All eight
repositories remain clean and exactly pinned. Admission is still rejected only
at the consumer boundary: gateway/MCP retain pending markers and the current
consumer bindings are not one identical current set. No artifact bytes were
edited to force admission.

## Delivery update — 2026-09-11 11:17 UTC

The consumer contract refresh is now delivered as four focused open PRs:
protocol [#41](https://github.com/AI-Ascension/sts2-protocol/pull/41), gateway
[#43](https://github.com/AI-Ascension/sts2-gateway/pull/43), MCP [#44](https://github.com/AI-Ascension/sts2-mcp-server/pull/44),
and harness [#85](https://github.com/AI-Ascension/sts2-harness/pull/85). Their
branches carry aligned `coop-native-v1` contract files and passing checksum
inventories, with serialized consumer bindings for the current main source
heads. The protocol, gateway, MCP, and harness locked package gates pass at
those refreshed copies; hosted policy/quality checks are green except that
harness quality was still running at capture. These branches are not part of
the approved source set until reviewed and merged.

The current source-set manifest and the read-only report above intentionally
remain unchanged: the exact main worktrees still contain the pre-refresh
copies and admission remains closed. A post-merge refresh must account for
the merge revisions themselves, rerun the source-set verifier, and preserve
the separate native service/live-host/reboot/soak classifications.

## Delivery update — 2026-09-11 11:42 UTC

The source-set verifier now distinguishes an exact artifact delivery revision
from the source revision/tree represented by its consumer-conformance record.
This is constrained to an ancestral source commit, an exact source tree, and
file changes inside the declared artifact directory.

The new
workspace-manifest.coop-refresh.candidate.json pins the four open artifact
refresh PR heads and their underlying current-main source revisions. The
eight-worktree gate passed with admitted=true, no issues, four identical
contract files, and complete checksum inventories (34 protocol rows and 25
rows in each consumer copy). This candidate is unactivated and does not make
the open PRs equivalent to merged main.

The original current-main manifest remains the authoritative main candidate
and remains admitted=false until the refresh PRs are merged and the final
post-merge manifest and consumer records are regenerated. Native service,
live-host, cold-boot, unified-build, activation, and soak evidence remain
separate and unverified.
