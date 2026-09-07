# P7 root cleanup review

Classification: source-derived blockers. Author commits `37f603c` and `7efa4f1`
are not integrated by this review.

The candidate correctly introduces non-reaping exit observation and an armed
process-group lifetime. However, inspection of `process.rs` at `7efa4f1` found:

- `OwnedChild::drop` calls `child.wait()` even if its deadline-bound
  `wait_for_child_exit` failed. A timeout therefore does not bound teardown.
- `abort_spawned_child` also calls `child.wait()` unconditionally after its
  kill fallback. The same hung-termination case can block the spawning loop.
- Spawn error paths discard the cleanup result, returning the original error
  without preserving the distinction between confirmed cleanup and uncertain
  surviving containment.

The author must gate reap on confirmed non-reaping exit observation, preserve
the cleanup deadline on every fallback, and propagate cleanup uncertainty.
Requested regression: inject cleanup/exit-observation failure and verify bounded
return without signaling a recycled PGID. Existing successful cleanup tests do
not cover these failure paths.

The author-reported `InvalidColumnType("pid", Null)` in `process_cleanup` comes
from an older base. Current integration source uses a separate trigger-captured
PID witness and reads the cleaned component PID as `Option<u32>`. That source
inspection is not a new executed test pass.
