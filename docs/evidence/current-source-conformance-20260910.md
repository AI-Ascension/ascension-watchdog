# Current source and artifact conformance audit — 2026-09-10 (refreshed)

Classification: `confirmed component evidence; cross-consumer admission not
verified`. This record refreshes the moving companion references captured by
the candidate manifest. It is not a release, installation, service, live-host,
cold-boot, or soak claim.

## Exact source set

| Repository | Ref / PR | Revision | Remote state |
| --- | --- | --- | --- |
| ascension-watchdog | `codex/watchdog-integrated-20260910` / PR #9 | `f5eaf5e35be025015a28da931aa973a0ade8f0ef` | open draft; activation/rollback, launch fencing, collision-safe Windows fixtures, and native worker smoke evidence; hosted Ubuntu/Windows and standards validation passed |
| sts2-gateway | `main` / PR #39 | `c8be3a72ba9e304392575a1b2bdbc262e392be21` | merged; host-lease/co-op consumer and recovery echo-response fencing |
| sts2-harness | `codex/harness-worker-endpoint-20260910` / PR #66 (base main) | `ef8c45e853d5f86c2653159a449826ffc20b5950` | open; authenticated native Linux worker endpoint; current main base `63dc563` |
| sts2-mcp-server | `main` / PR #40 | `037d10def1cbcb1c807e136d31b294355a92c010` | merged; native co-op adapter and pending-rejoin response fencing |
| sts2-game-mod | `main` / PR #65 | `888b06702021cd2bbd22773b0267733766c3b04a` | merged; operation-aware Runtime-v3 admission and dependency refresh |
| sts2-protocol | `main` / PR #38 | `f22dd7216f65de91a0ffa27f50bc2036be6c8b24` | merged; refreshed serialized co-op artifact and consumer pins |
| sts2-game-core | `main` / PR #9 | `f9db577530a4d159b066d3facbd780d61c044eb0` | merged |
| ai-agent-observability | `main` / PR #19 | `89539a6e7754b389f8eac148ba8a49c3892cddd8` | merged; OTLP bind/inode durability repair |

The revisions were checked against authoritative remote refs and PR metadata
at the refresh timestamp. Open PR #9 and open harness PR #66 are intentionally
separate from merged companion revisions. The selected watchdog source
`f5eaf5e` includes the durable release selector, strict selector/receipt
binding, request-collision rejection, authenticated activation boundary, and
the native worker smoke integration. The endpoint image used by that smoke is
SHA-256 `4b71eeb3c9ff410707ff2272e730889b1378cf4cae1a6b08c7531233f3bb48f2`.

## Component gates

The root independently checked clean detached worktrees for the Rust
components with pinned locked dependencies:

* `cargo fmt --all -- --check` passed for gateway, harness, MCP, game-mod,
  protocol, and game-core.
* Warnings-denied locked workspace Clippy passed for those repositories.
* Locked all-target/all-feature tests passed for those repositories.
* The watchdog checkout at `f5eaf5e` passed
  `cargo +1.97.1 test --locked --offline --workspace --all-targets
  --all-features --no-fail-fast`: 206 watchdog library tests passed and 4
  explicitly ignored, with all workspace integration suites passing. The
  five selector tests, restore CLI (2 tests), and namespace-isolated Linux
  installer test also passed.
* Watchdog PR #9 hosted validation runs `34525217061` and `34525218190` passed
  on both Ubuntu and Windows; standards runs `34524471775` and `34524473943`
  passed. Native service-session remains separately `UNVERIFIED`.
  (The standards runs for the latest head are `34525217025` and `34525218179`.)
* Gateway current `main` `c8be3a7`, MCP current `main` `037d10d`, game-mod
  current `main` `888b067`, protocol current `main` `f22dd72`, and observability
  current `main` `89539a6` are source-pinned. Their prior clean component gates
  remain evidence for the corresponding source families; no new unified build is
  claimed by this refresh.
* Harness PR #66 passed locked format, check, Clippy, repository policy, and
  all-target/all-feature tests; its hosted Rust-quality run `34538444783` and
  policy run `34538444761` passed. The native smoke is recorded separately.
* MCP current `main` `037d10d` passed `cargo fmt --all -- --check`, locked
  warnings-denied workspace Clippy, and locked all-target/all-feature workspace
  tests in a clean detached worktree. Its native coop adapter tests cover the
  seven-tool catalog, exact request/response relations, schema/checksum
  fixtures, and fail-closed malformed/foreign identities. The executable
  gateway-runtime test remains explicitly ignored because it requires an exact
  reviewed gateway binary.

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

The artifact comparison is not live consumer conformance. Protocol main's
`consumer-conformance.json` now binds gateway `c8be3a7`, MCP `037d10d`, and
harness main `63dc563` as serialized component consumers; the worker endpoint
PR is a separate process-boundary artifact. Game-mod has no native worker
consumer. Therefore no exact cross-consumer build or coop-native host settlement
run can be truthfully reported from this source set. Existing REST/runtime-v3
component paths remain separately tested; the actual watchdog-to-harness-to-
MCP-to-gateway-to-mod host execution is still unverified.

## Boundary decision

The candidate remains `not activated`. Keep
`cross_repository_clean_build`, `cross_consumer_conformance`, native Windows and
Linux service execution, live host recovery, cold boot, activation/rollback,
and soak as `not-run` or `unverified`. The smallest next executable gate is to
build every selected binary from one clean release directory, run the operation,
receipt, stale-authority, and provider-recovery matrix, and obtain the approved
native service/host environment before any release or gameplay admission claim.
