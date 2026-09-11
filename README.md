# Ascension watchdog

Deterministic Rust deployment supervision and crash recovery for AI-Ascension.

Status: watchdog implementation patch is in review; cross-repository release
admission remains blocked. No service, live-host recovery, reboot or soak
validation is claimed. See the [current source-set evidence](docs/evidence/current-source-set-20260911.md)
and [machine-readable release checkpoint](docs/evidence/release-set-verification-20260911.json)
for exact revisions and independent verification boundaries.

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
bounded read-only `diagnostics` command. These are source-tested on PR [#11](https://github.com/AI-Ascension/ascension-watchdog/pull/11).
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
