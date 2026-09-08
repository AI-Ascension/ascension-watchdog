# Stop-uncertainty regression evidence

This evidence records the synthetic, in-crate supervision regression added on
the `watchdog-stop-uncertainty-regression` branch. It is source and synthetic
process evidence only; it is not a Windows-kernel, native-service, reboot,
live-host, or soak result.

## Covered contract

The tests exercise `Supervisor::reconcile_once` through an actual synthetic
launch and `stop_component` call. A test-only `cfg(test)` hook supplies one
platform stop result, either `RuntimeStopOutcome::TimedOut` or an exact stop
error. Both paths must:

- retain the in-memory owned child handle and unchanged complete identity;
- persist `Quarantined` with the same PID, launch nonce, executable digest,
  and creation identity;
- leave the active launch intent unsettled; and
- reject replacement launches across repeated durable `Running` reconciles.

The abrupt-exit case runs the same test binary as a helper subprocess. The
helper starts the child, records the timeout quarantine, sets durable
`Running`, and exits with a distinctive status code so `Supervisor::Drop`
cannot perform cleanup. The parent supervises that exact helper `Child` handle
with a bounded wait and null output streams; it never buffers unbounded helper
output or uses a PID-only kill.
The parent then reopens the database while the finite synthetic child is still
alive. Synthetic proof recovery must not manufacture a handle, and repeated
reconciliation must preserve the quarantine, identity, active intent, and
zero replacement starts. The child is allowed to exit naturally within a
bounded twelve-second window; the test does not issue a PID-only kill.

## Focused command

```text
CARGO_TARGET_DIR=/tmp/codex-watchdog-stop-uncertainty-target \
  cargo test --locked --offline -p ascension-watchdog --lib \
  runtime_stop_uncertainty_tests -- --nocapture --test-threads=1
```

The run is expected to report the two direct stop-result tests and the abrupt
supervisor-reopen test as passing on Unix. The Linux synthetic result must not
be represented as native Windows evidence; the Windows counterpart remains an
approved-host validation obligation.
