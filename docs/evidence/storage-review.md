# Watchdog storage and clock review

Classification: source and executable regression evidence for the watchdog
core. This document covers owner-local storage and restart-budget behavior only;
it is not native service, gateway authority, host-fence, or live-host evidence.

## Correctness boundaries

- `Store::open_read_only` uses SQLite read-only flags and never creates a
  missing database. `Store::open_for_owner` and
  `Store::initialize_for_owner` require a matching `SingletonLock` before
  opening or mutating state. The compatibility `Store::initialize` entrypoint
  acquires the same owner lock for the complete bootstrap and reuses an
  already-held same-process admission without attempting a second OS lock.
- Launch admission is exposed as a durable `prepared -> proof_recorded ->
  active -> cleaned` state machine. `prepare_launch_intent` reserves one
  component before spawn, `record_launch_proof` requires bounded non-null
  platform proof, and activation is rejected without that proof. The watchdog
  stores the opaque proof but does not interpret it or terminate processes.
- A missing or unrecognized database is reported as missing/conflict. Schema,
  deployment, configuration-compatibility, desired-mode, and positive
  generation metadata are parsed strictly; malformed values do not become
  zero/default state.
- Backup restore validates the source schema, integrity, configuration
  compatibility, and deployment metadata before copying. Reusing the source
  deployment identity is rejected; the caller must supply an explicit fresh
  watchdog namespace. An accepted restore forces desired mode to `stopped`,
  quarantines queued/running/failed jobs and all component rows, and records
  `game_authority=unchanged`. It does not revoke or rekey gateway/game leases.
- Restart events retain both audit wall time and a per-controller monotonic
  clock epoch. Wall-clock jumps cannot age or clear the budget; prior epochs
  remain counted after a process restart. Only an explicit monotonic elapsed
  observation can age current-epoch events, and backward observations are
  clamped.
- Lock contention is normalized through `fs2::lock_contended_error`, including
  Windows `ERROR_LOCK_VIOLATION` behavior, while unrelated I/O errors remain
  I/O failures.

## Regression commands

Run from the repository root with the pinned toolchain:

```text
cargo +1.97.1 fmt --all -- --check
cargo +1.97.1 check --workspace --all-targets --all-features --locked
cargo +1.97.1 test --workspace --all-targets --all-features --locked
cargo +1.97.1 clippy --workspace --all-targets --all-features --locked -- -D warnings
```

The focused regressions are `crates/watchdog/tests/storage_regressions.rs` and
`crates/watchdog/tests/clock_regressions.rs` (with their source cases retained
under the repository-level `tests/` directory). They cover non-creating read-only opens,
owner-admission/double-lock behavior, malformed metadata, fresh stopped restore
and incompatible-config rejection, forward wall-clock jumps, process restart
budget retention, monotonic aging, and backward-clock clamping.

## Remaining evidence limits

The core has no authority to inspect or rekey gateway operation journals or
game leases. Native Windows/WSL/Linux service containment, authenticated admin
transport, gateway/harness integration, host fences, and live/reboot/soak runs
remain separate workstreams and are not implied by these tests.
