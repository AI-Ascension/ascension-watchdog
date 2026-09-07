# Post-P7 workspace gates

Classification: confirmed Linux workspace build, synthetic/component tests,
formatting and lint. Source revision: `86ea458`.

Root executed:

- `cargo test --locked --workspace --all-targets --all-features`: exit 0,
  153 tests passed across the workspace; two cgroup-dependent native tests
  explicitly ignored. Windows-only suites ran zero tests on Linux.
- `cargo fmt --all --check`: exit 0.
- `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`:
  exit 0.

The test run includes descendant cleanup, real subprocess crash/restart,
persisted stop, CLI/daemon submission, storage rollback/restore, release-byte
validation, and the service-loop audit-capacity test (service-loop suite elapsed
125.45 seconds). This is not a soak campaign or power-loss durability proof.

This exact tree still lacks pending companion and platform repairs. In particular,
the fixture A7/A8 changes, P8 bootstrap synchronization, W10 launch-context
binding, gateway/host lease installation and catalog integration have not been
proved by these gates. Existing test coverage does not cancel known review
findings. Native Windows service, delegated Linux containment, live game,
cold-boot recovery and full integrated-release verification remain unverified.
