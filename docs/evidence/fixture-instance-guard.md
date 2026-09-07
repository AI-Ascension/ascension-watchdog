# Runtime-v3 instance uncertainty guard

Classification: confirmed synthetic fixture evidence on branch
`codex/watchdog-fixture-instance-guard`, based on `7cc9d01`.

The runtime journal now treats an unresolved operation as an instance-wide
barrier. `ADMITTED`, `EXECUTING`, and `UNKNOWN` rows are selected by
`instance_id` without filtering on the session's `stopped` flag. The guard is
checked before a replacement session is created and again before a new
operation is admitted. An exact operation-id replay still follows the existing
identity and payload checks. Reads through an existing historical/stopped
session remain available.

The regressions prove that stopping an admitted operation leaves one `UNKNOWN`
row and prevents a same-instance replacement session from admitting another
operation; two concurrent replacement attempts are both rejected without new
rows. The reconciliation regression first obtains a real fixture-generated
effect witness/result, models receipt uncertainty by retaining those proofs
while marking only the status `UNKNOWN`, and then releases the barrier through
the runtime reconciliation path. No test fabricates a generation or witness.

Validation on the exact candidate worktree:

```text
cargo fmt --all -- --check
exit 0

git diff --check
exit 0

CARGO_TARGET_DIR=/tmp/fixture-instance-guard-target \
cargo test --locked --offline -p watchdog-fault-fixture --test runtime instance_uncertainty -- --nocapture
exit 0: 2 passed

CARGO_TARGET_DIR=/tmp/fixture-instance-guard-target \
cargo test --locked --offline -p watchdog-fault-fixture --test runtime \
releases_instance_barrier_only_after_authoritative_reconciliation -- --nocapture
exit 0: 1 passed

CARGO_TARGET_DIR=/tmp/fixture-instance-guard-all-20260907 \
cargo test --locked --offline -p watchdog-fault-fixture --all-targets -- --test-threads=1
exit 0: 40 passed (8 unit, 13 recovery, 17 runtime, 2 schema)

CARGO_TARGET_DIR=/tmp/fixture-instance-guard-clippy-20260907 \
cargo clippy --locked --offline -p watchdog-fault-fixture --all-targets \
--all-features -- -D warnings
exit 0
```

This is synthetic fixture/build evidence only. No service, host, game,
provider, schema, manifest, archive, or remote action was performed.
