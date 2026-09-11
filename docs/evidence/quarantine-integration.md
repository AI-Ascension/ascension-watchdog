# Durable quarantine integration

Integrated source: `30f992e` and `e355eed068553c77526c1a10f2da08a2f3360ae5`,
from independently reviewed candidates `8545201` and `cf5b4ca`.
Classification: confirmed owner-local storage and authenticated synthetic IPC.

The service owner commits an uncertain attempt, quarantined job, retained worker
identifier, operator receipt, and audit in one transaction. Exact request replay
returns the prior response. Read credentials and stale attempts cannot apply the
transition. A running/unknown attempt reserves its worker identifier across
store reopen; a different unreserved identifier remains separately claimable.

Root focused validation passed 34 tests:

```sh
cargo test --locked -p ascension-watchdog --test admin_quarantine --test admin_control --test job_claim_integrity --test job_submission --test storage_regressions --test core
```

An initial command named nonexistent `storage_jobs`; Cargo rejected that command
before running tests. The corrected command above passed. Full integrated gates
then passed at `e355eed`:

```sh
cargo fmt --all --check
cargo test --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features --target x86_64-pc-windows-gnu -- -D warnings
```

The Linux full workspace run retained two explicitly ignored native/cgroup tests.
Windows cross-target lint is not native Windows execution.

## Remaining operational boundary

This integration does not terminate or pause an executing harness, cancel a
provider, settle a host operation, or prove deployment-wide single-worker
admission. The existing public claim helper accepts a caller-provided worker
identifier. Automatic dispatch, stable configured worker binding, authenticated
terminal lookup and acknowledgment require the separate worker-handoff consumer.
No process quiescence or live recovery claim follows from a quarantine receipt.
