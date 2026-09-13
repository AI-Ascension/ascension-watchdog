# Real harness direct-process failure regression

This opt-in Linux integration test exercises the actual watchdog `WorkerClient`
against an independently built harness endpoint, not a scripted worker response.
It authenticates immutable process images and credentials, persists running
control, dispatches one job, and reopens the watchdog-owned store. The synthetic
MCP exits without launching an episode, so the real worker exits unsuccessfully.
Reconciliation and another dispatch then fail; the original non-acknowledged
handoff state remains durable after another store reopen.

This is synthetic component evidence, not successful gameplay, terminal receipt
acknowledgement, native supervision, systemd/cgroup containment, reboot, or soak
qualification. It does not close ascension-workflow issue #1. The normal test
suite compiles but ignores the opt-in entrypoints; automatic peer execution is
not wired by this source-only change.

## Reproduce

Build `sts2-harness-runtime` independently from harness revision
`7a984f6fce726638ee2158e4cf0fa466c3c04929` using its pinned toolchain and locked
dependencies. Supply the absolute image path and its SHA-256 digest:

```sh
export ASCENSION_WATCHDOG_REAL_HARNESS_DIRECT=1
export STS2_HARNESS_RUNTIME_BINARY=/absolute/path/to/sts2-harness-runtime
export STS2_HARNESS_RUNTIME_SHA256=<sha256-of-that-image>
cargo test --locked -p ascension-watchdog --test real_harness_worker_direct -- --ignored --exact real_watchdog_direct_process_harness_roundtrip --nocapture
```

Use a short, private `TMPDIR` if the default path would exceed the Unix endpoint
path limit. No provider credentials, proprietary game installation, host service
installation, or privilege elevation are needed. The immutable controller is
re-executed with an allowlisted environment in its own process group. Child waits
are bounded and group cleanup occurs before reaping the controller to avoid
signalling a recycled process-group identifier.

## Local execution, 2026-09-13

The exact opt-in test passed against the release image with SHA-256
`92905c4938e9b0ea2a455e727a2929d98ca899dda7f0241fbe48f2ad4bf08e46`.
Expected child output includes `episode launch failed` and
`worker runtime exited unsuccessfully`; those failures are the scenario under
test, not evidence of an episode completing successfully.
