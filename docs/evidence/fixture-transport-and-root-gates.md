# Fixture transport and integrated-source gates

Classification: confirmed build and synthetic-process evidence, not native
service, live game, cold reboot, or integrated companion recovery evidence.

## Integrated watchdog source

At `6f47583` (runtime code unchanged from `8ea36ad`), root ran:

- `cargo test --workspace --all-targets --all-features --locked`: exit 0,
  161 passed and two explicit native-cgroup tests ignored.
- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`:
  the first observation handle disappeared during execution. A rerun exited 0
  but reported damaged incremental-cache metadata. A further rerun with
  `CARGO_INCREMENTAL=0` exited 0 without those warnings.

The full tests still use the previously integrated fixture, not the candidate
below. A green result does not approve that old fixture's authority semantics.

## Unintegrated transport candidate

Root reviewed the complete fixture library at `a6de41c` and implemented the
isolated transport repair in `456103c`:

- Set a read deadline before the first socket peek.
- Apply one absolute read deadline across request-line, headers, and body;
  trickled bytes cannot renew it.
- Bound HTTP request-line bytes, aggregate header bytes, and header count.
- Apply absolute response-write and client-connect deadlines.
- Isolate peer timeout/disconnect failures without treating them as a fatal
  durable-store failure.
- Announce the fixture listener only after durable-store initialization.

Candidate validation:

- `cargo test --locked -p watchdog-fault-fixture --all-targets`: exit 0,
  34 passed (8 unit, 11 recovery, 13 runtime, 2 schema).
- `cargo clippy --locked -p watchdog-fault-fixture --all-targets --all-features -- -D warnings`:
  exit 0 after extracting bounded header parsing and removing a test allocation
  lint. Earlier lint failures are not represented as passes.
- `cargo fmt --all --check` and `git diff --check`: exit 0.

New tests exercise an idle socket, trickled HTTP headers, aggregate/header-count
overflow, an already-expired read deadline, and a nonreading output peer.

## Remaining review boundaries

Candidate `a6de41c` and its transport follow-up are not integrated. Independent
review is checking historical lookup/reconciliation's original-context binding
and runtime admission across multiple sessions for one instance. Runtime
archival remains absent: safe backpressure at 64 rows is not the requested
beyond-capacity archival/tombstone campaign. The raw runtime path also needs
an explicit fault-injection campaign; sideband crash tests do not prove it.

No service installation, game/provider launch, host reboot, release activation,
push, or merge was performed for this evidence item.
