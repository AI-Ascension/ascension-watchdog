# Ascension Watchdog

Deterministic Rust deployment supervision and crash recovery for AI-Ascension.

This is a bounded [Ascension](https://github.com/AI-Ascension/sts2-harness)
operations component. **The Climb — by AI Ascension** does not imply that a
watchdog service, 24/7 operation, or recovery guarantee has been verified.

Status: watchdog PRs [#11](https://github.com/AI-Ascension/ascension-watchdog/pull/11)
and [#6](https://github.com/AI-Ascension/ascension-watchdog/pull/6) are merged
into `bootstrap`, and the watchdog's product and hosted quality gates pass.
The synchronized protocol/gateway/MCP/harness refreshes are merged in companion
PRs [#43](https://github.com/AI-Ascension/sts2-protocol/pull/43),
[#45](https://github.com/AI-Ascension/sts2-gateway/pull/45),
[#46](https://github.com/AI-Ascension/sts2-mcp-server/pull/46), and
[#90](https://github.com/AI-Ascension/sts2-harness/pull/90). Current-main
source-set admission and the pinned unified build/component-conformance gate
pass. The candidate remains unactivated, and no native service, live-host
recovery, host reboot, refreshed-release rollback, or completed soak validation
is claimed. See the [current-main refresh evidence](docs/evidence/current-main-refresh-source-set-20260912.md)
and [current-main machine-readable result](docs/evidence/current-main-refresh-source-set-20260912.json),
the [unified build evidence](docs/evidence/current-main-refresh-build-set-20260912.md),
and [requirement reconciliation](docs/evidence/requirement-evidence-20260912.json),
as well as the
[post-merge refresh evidence](docs/evidence/postmerge-refresh-source-set-20260911.md)
and [machine-readable release checkpoint](docs/evidence/release-set-verification-20260911.json)
for historical checkpoints and independent verification boundaries.

The OS service manager owns the watchdog. The watchdog supervises gateway and
harness executables. The gateway owns game lifecycle authority and uses a
restricted host broker. The harness owns MCP and provider processes. Uncertain
game operations remain subject to owner-side reconciliation, never blind retry.

MIT licensed. This project does not distribute game files or grant rights to them.

## Current local validation

```sh
cargo test --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo run --locked --bin watchdog -- preflight --state-directory /existing/local/state --reserve-bytes 1073741824 --staging-bytes 0 --backup-bytes 0
```

Replace the preflight path with an existing local directory and supply actual
staging/backup requirements. The command is read-only, rejects indirect paths,
and returns a nonzero exit on insufficient headroom. Its default runtime reserve
is 1 GiB. A passing probe does not reserve space, authorize host testing, verify
filesystem durability, or install/start a service. Recheck immediately before
bounded staging/backup operations; no files are automatically reclaimed.

`watchdog release inspect --manifest PATH --root PATH` checks a release document
and exact artifact bytes without activating them. Its reported manifest digest
covers the original input bytes, including whitespace. It returns nonzero on
tampering or malformed input; inspection alone grants no launch authority.

`watchdog release source-set verify --manifest PATH --repo NAME=PATH [...]`
checks a candidate source manifest against explicitly supplied clean Git
worktrees. It verifies full commit pins, GitHub remotes, the four
`coop-native-v1` contract artifact locations, their `SHA256SUMS` entries, and
current consumer-conformance bindings. For an artifact-only delivery commit,
the manifest can also pin its underlying source_revision and source_tree; the
verifier requires ancestry and rejects changes outside that repository's
declared artifact directory. A failed admission prints the complete JSON
report to stdout and exits nonzero; the command never fetches, builds, installs,
activates, or runs a companion.
The recorded resume-wave result is in
[`docs/evidence/source-set-gate-20260911.md`](docs/evidence/source-set-gate-20260911.md).

Offline backup rekey is explicit and stopped by construction:
`watchdog restore --config PATH --backup PATH [--database PATH] --rekey` verifies
the owner-local snapshot, requires a fresh deployment identity, increments the
durable generation, quarantines inherited work, and reports
`blocked_until_fenced=true`. It never swaps a running daemon's store, restores
old leases, launches a process, or activates a release.

Core tests include synthetic subprocess restart and persisted stop, not native
service recovery. Administrative IPC, platform containment, and exact companion
integration remain separate delivery gates. The watchdog now source-tests a
durable protected release selector and authenticated activation/rollback, but
that is not evidence of a sealed cross-repository or native release handoff.

The current resume wave exposes the authenticated `quarantine` operation and a
bounded read-only `diagnostics` command. These are source-tested and merged via
PR [#11](https://github.com/AI-Ascension/ascension-watchdog/pull/11).
Persistent OpenTelemetry exporter queues are now present on observability main
through merged PR [#20](https://github.com/AI-Ascension/ai-agent-observability/pull/20).
The portability fix for minimal static-probe environments is also merged in PR
[#22](https://github.com/AI-Ascension/ai-agent-observability/pull/22);
container rendering, image build, and live queue recovery remain unverified in
this environment.

An explicitly gated native Linux process-boundary smoke is recorded in
[`docs/evidence/real-harness-worker.md`](docs/evidence/real-harness-worker.md).
It launched the merged harness PR #66 hardening image `58dede2` from the watchdog process manager,
authenticated the worker endpoint, admitted one bounded dispatch, and persisted
stop/cleanup (`1 passed`, 25.33s; image SHA-256
`5286706d03c27c00e32493c1adf8864e972f7a53d1f863c046aed32d56a1644f`). Its
gateway/MCP children were synthetic HTTP-503 and `/usr/bin/true` faults, so it
does not establish gameplay, provider, service, reboot, release, or soak
evidence.

The moving companion heads captured for the next integration review are listed
in [`workspace-manifest.candidate.json`](workspace-manifest.candidate.json),
with the dated current record in
[`docs/evidence/current-source-set-20260911.md`](docs/evidence/current-source-set-20260911.md).
The candidate manifest must not be treated as an installed release.

The merged artifact-refresh branches have a separate historical candidate
manifest, [workspace-manifest.coop-refresh.candidate.json](workspace-manifest.coop-refresh.candidate.json).
The current-main post-merge gate, local regenerated candidate, and merged
current-main result are recorded separately in
[`workspace-manifest.postmerge-20260911.json`](workspace-manifest.postmerge-20260911.json),
[`workspace-manifest.postmerge-refresh-20260911.json`](workspace-manifest.postmerge-refresh-20260911.json),
[`workspace-manifest.current-main-refresh-20260911.json`](workspace-manifest.current-main-refresh-20260911.json),
[`docs/evidence/postmerge-refresh-source-set-20260911.md`](docs/evidence/postmerge-refresh-source-set-20260911.md),
[`docs/evidence/postmerge-refresh-source-set-20260911.json`](docs/evidence/postmerge-refresh-source-set-20260911.json),
and [`docs/evidence/current-main-refresh-source-set-20260911.json`](docs/evidence/current-main-refresh-source-set-20260911.json).
Current-main source-set admission passes; all runtime gates remain separate and
unactivated.
