# Ascension watchdog

Deterministic Rust deployment supervision and crash recovery for AI-Ascension.

Status: implementation in progress; no service, live-host recovery, reboot or soak
validation is claimed. See the requirement matrix and evidence records as gates
are implemented and independently verified.

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
service recovery. Administrative IPC, platform containment, exact companion
integration and protected release activation remain separate delivery gates.

The moving companion PR heads captured for the next integration review are
listed in [`workspace-manifest.candidate.json`](workspace-manifest.candidate.json)
with their non-activation evidence in
[`docs/evidence/candidate-source-set-20260910.md`](docs/evidence/candidate-source-set-20260910.md).
That candidate manifest must not be treated as an installed release.
