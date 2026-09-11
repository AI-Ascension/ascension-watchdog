# Current source and artifact conformance audit — 2026-09-10 (refreshed)

Classification: `confirmed component evidence; cross-consumer admission not
verified`. This record refreshes the moving companion references captured by
the candidate manifest. It is not a release, installation, service, live-host,
cold-boot, or soak claim.

## Exact source set

| Repository | Ref / PR | Revision | Remote state |
| --- | --- | --- | --- |
| ascension-watchdog | `codex/watchdog-integrated-20260910` / PR #9 | source `f5eaf5e35be025015a28da931aa973a0ade8f0ef`; PR head `62bf0fc49d7656e1207dc592a34a4fcd76994ee4` | open draft; activation/rollback, launch fencing, collision-safe Windows fixtures, and native worker smoke evidence; latest hosted Ubuntu/Windows and standards validation passed |
| sts2-gateway | `main` / PR #39 + merged PR #34 | `8ba5521c2ec8f158d437a7104567592703e53259` (PR #34 head `87792cf3f6e2c3b6627d3a34bf380bb337c01373`) | merged main; durable host-lease/co-op consumer, recovery echo-response fencing, and restart guard |
| sts2-harness | `main` / PR #54 + merged PR #66 | `ce86ced41d8b9e93d19f2c440f28b3223397f3ca` (endpoint merge `a0ace6712686cb30d6f0b556cb6814ad4c0721d1`; feature head `58dede2eb661133d8910a1f785e8a90346efe8dd`) | merged main after green hosted checks; durable recovery/catalog/provider repairs plus authenticated native Linux worker endpoint hardening |
| sts2-mcp-server | `main` / PR #40 | `037d10def1cbcb1c807e136d31b294355a92c010` | merged; native co-op adapter and pending-rejoin response fencing |
| sts2-game-mod | `main` / PR #65 | `888b06702021cd2bbd22773b0267733766c3b04a` | merged; operation-aware Runtime-v3 admission and dependency refresh |
| sts2-protocol | `main` / PR #38 | `f22dd7216f65de91a0ffa27f50bc2036be6c8b24` | merged; refreshed serialized co-op artifact and consumer pins |
| sts2-game-core | `main` / PR #9 | `f9db577530a4d159b066d3facbd780d61c044eb0` | merged |
| ai-agent-observability | `main` / PR #19 | `89539a6e7754b389f8eac148ba8a49c3892cddd8` | merged; OTLP bind/inode durability repair |

The revisions were checked against authoritative remote refs and PR metadata
at the refresh timestamp. Open draft PR #9 remains separate from merged
companion revisions. Harness PR #66 auto-merged after its hardening checks
passed; both its feature head and merge commit are retained above. The selected
watchdog source `f5eaf5e` includes the durable release selector, strict
selector/receipt binding, request-collision rejection, authenticated activation
boundary, and the native worker smoke integration. The post-hardening endpoint
image used by that smoke is SHA-256
`5286706d03c27c00e32493c1adf8864e972f7a53d1f863c046aed32d56a1644f`.

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
* Watchdog PR #9 latest hosted validation runs `34545569428` and
  `34545569573` passed on both Ubuntu and Windows; standards runs
  `34545569465` and `34545569607` passed. Native service-session remains
  separately `UNVERIFIED`.
* Gateway current `main` `8ba5521`, MCP current `main` `037d10d`, game-mod
  current `main` `888b067`, protocol current `main` `f22dd72`, and observability
  current `main` `89539a6` are source-pinned. Their prior clean component gates
  remain evidence for the corresponding source families; no new unified build is
  claimed by this refresh.
* Harness PR #66 hardening passed locked format, check, Clippy, repository
  policy, and all-target/all-feature tests; hosted Rust-quality run
  `34542578041` and policy run `34542578085` passed before it auto-merged. The
  native smoke is recorded separately.
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
`consumer-conformance.json` is a serialized snapshot that binds earlier gateway
`c8be3a7`, MCP `037d10d`, and harness `63dc563` component consumers; current
gateway/harness mains are `8ba5521`/`ce86ced`. The merged worker endpoint PR is a
separate process-boundary artifact. Game-mod has no native worker
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
