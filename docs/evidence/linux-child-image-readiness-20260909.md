# Linux child image readiness

The Linux hosted runs at `7a5bf20` and its predecessors observed an approved
child PID whose executable still named the invoking test binary. Broker fixture
authorization consequently failed, and direct process identity checks rejected
the child before the expected image became visible. This is evidence of the
observed startup race, not proof of a particular libc spawn implementation.

The direct child manager now waits at most 500 ms for the approved executable.
Only the captured invoking image and a temporarily unavailable procfs executable
can extend the wait. An unrelated third image fails immediately. The approved
image must still pass the existing identity checks. Same-image self-exec remains
supported without claiming that a path change proves exec completion. Failure
uses the existing exact-child and process-group cleanup classification.

Broker fixtures wait for their exact approved image before constructing peer
credentials. Authentication policy is unchanged. Crash-fixture phase diagnostics
are bounded and identify which step failed without increasing the crash deadline.

Author validation on the isolated CI branch:

- Full Linux library suite: 93 passed, zero failed, two ignored (before the
  final failure-path regressions).
- Process and broker focused suites: each 19 passed, zero failed, one ignored.
- Strict Clippy: passed before the final failure-path regressions.
- Final `process::tests::exec_readiness` regressions: two passed, one ignored
  child fixture. They cover persistent invoking-image timeout and immediate
  third-image rejection, with exact child reap.

Integrated candidate and hosted CI validation must be recorded separately.
No service, gameplay, reboot, or live recovery evidence is implied.

## Fixture initialization boundary

At integrated `52c1c81`, the hosted Linux library suite passed all image-readiness
regressions. Its remaining failure was the abrupt-exit helper's five-second
whole-process deadline, with the bounded diagnostic reporting
`initializing-supervisor`. The fixture now has a separate 30-second initialization
budget for synchronous SQLite/WAL/schema setup. A separate readiness marker cannot
be overwritten by later phase diagnostics. The original five-second deadline is
retained for the post-initialization abrupt-stop sequence; no production timer is
changed. Both marker and diagnostic reads are bounded to 128 bytes.

Author-focused regression passed in 10.65 seconds including setup. This is not a
ten-second stop measurement. Integrated/hosted validation of this fixture change
remains separate.
