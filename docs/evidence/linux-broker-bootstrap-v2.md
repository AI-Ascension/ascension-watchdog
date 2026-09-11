# Broker bootstrap v2 implementation checkpoint

Classification: confirmed local broker-side implementation and synthetic Linux
transport/descriptor tests. Runtime selection, native systemd, service recovery,
live host, reboot and soak are not verified by this checkpoint.

Base: `54bda896364e502edef42192b138fc30ce565ac3`. The codec was implemented in an
isolated worktree by a separate agent and imported by the root integrator after
source review. Root implemented the actual broker listener/client path, durable
binding, native stdin property construction and integration regressions. No
manifest or dependency change was required.

The [protocol document](../linux-broker-bootstrap-v2.md) describes the implemented
boundary and the remaining asynchronous launch/Stop gap. Source hashes, task
ownership and exact commands are in
`docs/orchestration/broker-bootstrap-v2-20260909.json`.

Root's final focused command passed 105 tests, with zero failures and one
explicitly gated native systemd test ignored (127 unrelated tests filtered;
21.93 seconds):

```sh
CARGO_INCREMENTAL=0 cargo test --locked --offline -j1 -p ascension-watchdog --lib platform::linux_broker
```

Full workspace/all-target/all-feature strict Clippy passed, exit 0 (26.50 seconds):

```sh
CARGO_INCREMENTAL=0 cargo clippy --locked --offline -j1 --workspace --all-targets --all-features -- -D warnings
```

The new tests exercise real anonymous sealed descriptors, D-Bus FD serialization
and owned-value decoding, real authenticated Unix socket pairs with a fake
process backend, typed worker controller matching, exact frame delivery,
response loss/Inspect/Stop, immutable journal bindings and explicit unknown
client outcomes. They do not call the live system manager or launch a native
service. Format and diff checks passed before this documentation update.

An earlier integration run failed both new worker tests with `InvalidToken`:
the broker's `boot:<kernel UUID>:<ticks>` token had been split at the first colon.
Production and fixtures now extract the final decimal component; the focused
rerun above passed. Independent source review identified the same defect.
An earlier strict lint run rejected one test's `err().expect()`; it was corrected
without a lint allowance. These failed intermediate attempts are not passes.

Independent final source/executable review passed the same focused command:
105 passed, zero failed, one native test ignored, 127 filtered, exit 0 in
19.18 seconds. Its final source audit and diff check found no additional blocker
beyond the documented runtime selection and asynchronous lifecycle gaps.
Combined full-workspace tests and Windows cross-target lint on this v2 source
are running and have not yet completed.
The earlier `18bc627` source integration and its release hashes remain historical
evidence; they do not describe binaries rebuilt from these new v2 changes.
