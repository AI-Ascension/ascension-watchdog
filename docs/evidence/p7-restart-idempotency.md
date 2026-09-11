# P7 observed-exit cleanup correction

Classification: confirmed Linux synthetic regression and focused repair.

Full locked workspace/all-target/all-feature tests after `34a0480` passed the
previously failing descendant suite, then failed the real crash/restart test in
`core`: the second reconciliation did not restart the synthetic component.
The full command exited 101 and did not run later suites.

Root identified that `try_wait` reaped the exited child during observation,
then `terminate` issued another non-reaping OS wait and received no-child.
Commit `b1aa2d8` now recognizes disarmed authority, rechecks group absence
read-only, and returns the Child's cached exit status. It never signals the
reaped numeric group. The repeat-cleanup regression now requires successful
idempotent completion while retaining its unchanged signal-count assertion.

Root reran `cargo test --locked -p ascension-watchdog --test core --lib`:
exit 0; all eight core tests and 38 library tests passed, with one native cgroup
test explicitly ignored. The real crash/restart and persisted-stop test passed.
A complete workspace rerun is still required; no full-green claim is made.
