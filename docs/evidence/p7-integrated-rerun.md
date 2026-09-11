# P7 integrated cleanup rerun

Classification: confirmed Linux synthetic/component tests, not native service
or live-host recovery.

Root integrated P7 author commits through `da1c476` as `9223130`, `4051f3e`,
`dbd58c2`, and `76d2293`. Root commit `0f05406` wires the typed
`ProcessSpawnError` into the actual runtime launch path: cleanup uncertainty
maps to `RuntimeLaunchError::CleanupUncertain`, never ordinary rejection.
A regression verifies both mapping variants without error-string matching.

Root ran:

- `cargo test --locked -p ascension-watchdog --lib --test adversarial_core --test process_cleanup`:
  exit 0; 38 library tests passed, one native cgroup test ignored; all ten
  adversarial tests and the identity-persistence cleanup test passed.
- `cargo fmt --all --check`: exit 0.
- `git diff --check`: exit 0.

The previously failing descendant-cleanup regression now passes, along with
parent-exited cleanup, bounded inherited-pipe handling, and repeated teardown
without signaling a reaped group's numeric identifier. Full workspace and
cross-platform reruns remain required after the remaining integration changes.
