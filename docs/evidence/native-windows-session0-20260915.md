# Windows native worker session-0 qualification — 2026-09-15

Both required native worker tests passed once on the STS Windows guest, running
as `NT AUTHORITY\SYSTEM` in session 0. The product verifier returned
`qualified_native=true` with no issues. This is **native worker qualification**,
not installed SCM service lifecycle, a companion release, gameplay, or soak.

The [receipt directory](native-windows-session0-20260915/) includes raw guest-agent
process results, the complete passing receipt, product evidence and verifier
output, build provenance, the failed debug attempt, and `SHA256SUMS`.

## Exact artifact and execution

- Source: `d69a5087922374b492d311fab0b05866e6b99c63`, tree
  `6d1112ecec297efb3188e239713e43aadb8a38a8`.
- Rust `1.97.1`, locked all-feature build targeting
  `x86_64-pc-windows-gnu`, cross-built with isolated Debian MinGW packages.
- Release test executable: 6,872,886 bytes; SHA-256
  `a7253178aa9ccde03db56620049b0e53c589f106d822391cb610758deeb0b030`.
- Guest-side image hashing matched before execution. The test executable imports
  Windows system DLLs only. Cross-building alone was not counted as native proof.

Both selectors below are in `runtime::runtime_worker_windows_tests` and ran with
`--exact --ignored --nocapture`. Guest-agent process status supplied exit codes
directly; captured output was not truncated.

| Test | Exit | Passed / failed / ignored | Reported duration |
| --- | --- | --- | --- |
| `native_worker_runtime_delivers_controller_bound_bootstrap_and_stops_exact_child` | 0 | 1 / 0 / 0 | 1.37 s |
| `native_worker_launch_rejects_durable_stop_before_resume_and_cleans_exact_job` | 0 | 1 / 0 / 0 | 1.53 s |

The canonical receipt concatenates each test's stdout and stderr in test order;
both stderr streams were empty. Its SHA-256 is
`605881a20e40a6ba6e67a27b5ca29140a8c9cc227652b5266451335ffdc91118`.
The same-source Windows watchdog CLI verified the evidence and receipt with
exit zero. That verifier binary used the **debug** profile; the executed native
test image used **release**. The coordinator independently verified the receipt
again with the same-source Linux CLI.

## Failed debug attempt and workflow correction

The original debug test executable was 66,615,451 bytes. Both tests failed before
worker launch with:

```text
Windows image identity deadline elapsed
```

The retained combined debug receipt reports 0 passed / 1 failed for each test.
Its first run took 13.48 seconds and its second took 12.00 seconds. The initial
PowerShell wrapper also lost individual process exit-code values; those nulls
are not presented as actual exit codes. Direct guest-agent process capture fixed
that separate collection issue for the optimized run.

`runtime_worker_bootstrap.rs` supplies a five-second controller capture deadline;
the Windows platform boundary checks it around synchronous image identity work.
The smaller optimized image passed without any Rust source or deadline change.
Image size and unoptimized hashing are plausible contributors, not separately
isolated causes.

The native workflow now uses `--release` for both tests and its verifier. It
retains the session-0 prerequisite, exact-test counts, exit-code checks, source
binding, and receipt verification. **That revised workflow was not executed in
this session.** These receipts came from manual Windows GNU execution through
the guest agent, not a registered self-hosted runner or an MSVC workflow run.

## Scope and retained state

The guest clock reported September 14 while the coordinator date was September
15. Literal guest timestamps are retained; the clock was not corrected and is
not used to claim wall-clock soak. Guest boot time remained unchanged during the
worker tests; final inventory showed zero staged processes.

The tests exercise native controller binding, Job Objects, pipe/bootstrap
delivery, durable-stop rejection, and exact-child cleanup using a self-executed
fixture. They do not exercise a real harness, install the watchdog SCM service,
launch a game/provider, or prove full release recovery. Test staging remains for
inspection; no watchdog service was installed by this procedure.

Issue #1 remains open for the broader operational acceptance. This evidence does
not change `SOAK_VERIFIED` or replace independently required service, live-host,
release, and continuous-soak evidence.
