# Current source and artifact conformance audit — 2026-09-10

Classification: `confirmed component evidence; cross-consumer admission not
verified`. This record refreshes the moving companion references captured by
the candidate manifest. It is not a release, installation, service, live-host,
cold-boot, or soak claim.

## Exact source set

| Repository | Ref / PR | Revision | Remote state |
| --- | --- | --- | --- |
| ascension-watchdog | `codex/watchdog-integrated-20260910` / PR #9 | `92619c4c85984256a64c7387e0949d7d737401e1` | open draft; docs-only follow-on over implementation parent `5b235f9524ecbb9529392dafee2328545666f356` |
| sts2-gateway | `main` / PR #38 | `de1fe72345ea972d56c05d30837da5327e5f1655` | merged; PR #37 included |
| sts2-harness | `main` / PR #59 | `5cc486a66b6f11930675af06f7426cd91c609983` | merged |
| sts2-mcp-server | `main` / PR #37 | `8b6b73862494488fdd16fa5423fdf90a953260f4` | merged |
| sts2-game-mod | `main` / PR #70 | `a70a5e5bb2fa89fade7e16dbb4a58ed80e31355b` | merged |
| sts2-protocol | `main` / PR #33 | `678885687e46a43f53b9eec108dfb160fc9a13bd` | merged |
| sts2-game-core | `main` / PR #9 | `f9db577530a4d159b066d3facbd780d61c044eb0` | merged |
| ai-agent-observability | `main` / PR #16 | `d7e79e1a9663601013e513048caea7063b0de9ae` | merged |

The revisions were checked against the remote `main` refs and the listed PR
metadata before this record was written. Open PR #9 is intentionally still
separate from the merged companion revisions. The selected watchdog source
was unchanged after `92619c4`; the follow-on commit only refreshes evidence
and does not alter the tested implementation.

## Component gates

The root independently checked clean detached worktrees for the Rust
components with pinned locked dependencies:

* `cargo fmt --all -- --check` passed for gateway, harness, MCP, game-mod,
  protocol, and game-core.
* Warnings-denied locked workspace Clippy passed for those repositories.
* Locked all-target/all-feature tests passed for those repositories.
* The watchdog checkout passed
  `cargo +1.97.1 test --locked --offline --workspace --all-targets
  --all-features --no-fail-fast -- --test-threads=1`: 200 passed and 4
  explicitly ignored. The restore CLI (2 tests) and namespace-isolated Linux
  installer test also passed.
* Watchdog PR #9 hosted validation run `34514320447` and standards run
  `34514322142` passed for source head `92619c4`. The hosted service-session
  step reported `UNVERIFIED` on runner session 2.
* Gateway PR #38 hosted quality and policy runs `34510597219` and
  `34510597283` passed. A broader parallel local attempt exposed timing-sensitive
  fixture failures; the serial runtime/workspace results above are the accepted
  local gate and no production change was made for the flaky attempt.

These are source/component checks. They do not prove that a single clean build
of all binaries can be installed or run together.

## Artifact checks

SHA-256 inventories and copied artifact files were checked in the available
clean component worktrees. Runtime-v1/v2/v3/v4 and seeded-run artifacts are
byte-identical wherever each consumer carries them. The runtime-v3 schema digest
is `8e99cea36b7ede97532348fd8efe302ca79260895265a7bf14ddf7e006d8ff63`.
The worker schema digest is
`bb13d15f6c0e4b8d0f58f7391fe4ba319ebc57a0a09effc06d73ea718bbff4cf`.
Protocol and gateway now carry matching `coop-native-v1` producer artifacts.

The artifact comparison is not consumer conformance. MCP, harness, and
game-mod currently do not expose a `coop-native-v1` consumer or adapter
surface. Therefore no exact cross-consumer build or coop-native conformance
run can be truthfully reported from this source set. Existing REST/runtime-v3
component paths remain separately tested; their actual watchdog-to-harness-
to-MCP-to-gateway-to-mod host execution is still unverified.

## Boundary decision

The candidate remains `not activated`. Keep
`cross_repository_clean_build`, `cross_consumer_conformance`, native Windows and
Linux service execution, live host recovery, cold boot, activation/rollback,
and soak as `not-run` or `unverified`. The smallest next executable gate is to
publish/accept the missing consumer adapters (or explicitly scope the release
to the existing REST contract), build every selected binary from one clean
release directory, and run the operation, receipt, stale-authority, and
provider-recovery matrix before any runtime admission claim.
