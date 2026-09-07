# Core adversarial safety regressions

This evidence records the independent watchdog-core regression suite added on
top of baseline `db87af7f3b9b6787b373199358063ca3ed2ad56e`. The suite is
deliberately failing at that baseline: each assertion names a required safe
postcondition, and no test is ignored or weakened to obtain a green result.

## Commands

Run from the repository root with a target directory outside the checkout:

```text
CARGO_TARGET_DIR=$TARGET_DIR cargo fmt --all --check
CARGO_TARGET_DIR=$TARGET_DIR cargo clippy --locked --test adversarial_core -- -D warnings
CARGO_TARGET_DIR=$TARGET_DIR cargo test --locked --test adversarial_core -- --nocapture
```

The formatter and targeted Clippy command pass. On the Unix baseline, the
targeted test command builds successfully and exits 101 with **0 passed and 8
failed**, as required for this pre-repair regression commit. The failure output
is the safe assertion firing, not a harness or compilation failure.

## Regression map

| Test | Required postcondition | Baseline result | Classification |
| --- | --- | --- | --- |
| `persisted_live_child_is_cleaned_before_stop_reports_success` | A replacement controller must clean the exact persisted child before durable stop reports success. | Fails because the old `/bin/sleep` remains alive. | Deterministic synthetic process |
| `post_spawn_persistence_failure_cleans_the_child_before_returning` | A child must not remain live when launch-identity persistence fails after spawn. | Fails because dropping the child leaves it running. | Deterministic synthetic process |
| `stale_health_witnesses_are_not_reported_as_running` | Stale heartbeat/progress witnesses must produce `MarkSuspect`, not `Noop`. | Fails with `Noop`. | Deterministic policy |
| `restart_budget_does_not_reset_after_wall_clock_jump` | A clock discontinuity must not discard persisted restart-budget history. | Fails because the count becomes zero after a forward jump. | Deterministic policy/storage |
| `read_only_open_never_creates_state_in_exists_open_race` | Read-only inspection must never create an empty replacement database. | Fails when the `exists`/open race creates a zero-length file. | Timing-sensitive Unix race |
| `terminating_owned_child_cleans_background_descendants` | Owned termination must contain descendants and not leave inherited pipes attached indefinitely. | Fails because the background `sleep` survives direct-child termination. | Deterministic synthetic process |
| `restore_requires_stopped_identity_consistent_state` | Restore must not reactivate stale `Running` intent or mix deployment identities. | Fails because restored mode is `Running` from the backup. | Deterministic storage |
| `corrupt_metadata_is_reported_instead_of_defaulted` | Malformed durable metadata must block status/admission rather than become a zero/default. | Fails because malformed generation is reported as `0`. | Deterministic storage |

The read-only race uses only a temporary database and repeatedly renames that
test-owned file; it is labeled timing-sensitive so a future implementation can
keep the assertion while improving scheduling robustness. The process tests
register only their own observed PIDs with an exact cleanup guard. The guard is
test-only containment for a failing baseline and prevents leaked synthetic
children; it never uses executable names, wildcard matching, or broad process
selection.

Unix-only process/race cases are intentionally gated until native Windows
containment tests exist. The storage and pure-policy regressions remain
platform-neutral.
# Root integration follow-up

The eight assertions were rerun after integration into the watchdog branch:
initially all eight failed. Bounded cleanup through the original `Child` object
now fixes the post-spawn persistence-failure leak. The separate
`process_cleanup` integration test aborts the real reconciler's identity write
after its PID row commits, and verifies that the spawned process has exited.
That test passes. Strict workspace Clippy passes.

After storage integration and the heartbeat fix, the adversarial suite is
**7 passed, 1 failed, 0 ignored**. Background descendant cleanup remains an
active release blocker, not an expected-green exception. The real reconciler
now records a live process without a fresh heartbeat as suspect and retains its
owned handle, rather than claiming progress or launching a duplicate. Four
health-policy tests, including a real child process, pass. Phase-specific
authenticated child-health and native containment integration remain required.

Store initialization/opening in `Supervisor` now explicitly requires the held
owner lock, and CLI status/doctor use the true read-only connection path. The
existing restore fixture now supplies a fresh deployment ID; accepted restores
remain stopped and do not rekey game authority.

The drop-based persisted-child test now passes because ordinary controller
destruction cleans its child. This is **not** proof of abrupt owner-death
recovery: destructor execution must not be assumed during a process kill.
Native cgroup/Job owner-death tests remain required.
