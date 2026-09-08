# Worker image authentication validation

Confirmed on 2026-09-08 against candidate base
`ae921e3301fe6a24294326aa37d7912dd0fba7a4` plus uncommitted changes in
`admin_pipe.rs`, `native.rs`, `worker_client_auth.rs`, and
`worker_client_transport.rs`.

- `cargo test --locked --offline -p ascension-watchdog --test worker_client`:
  exit 0, 11 passed, 19.97 seconds. Covers authenticated IPC, exact process
  rejection before credential disclosure, uncertain dispatch retention, and
  terminal commit before acknowledgement.
- Native Windows platform test executable, filter `ancestor_lock_tests
  --nocapture`: exit 0, 4 passed, 1.06 seconds. Covers worker/admin namespace
  separation, expired image-validation budget, retained ancestor write exclusion,
  and byte-pipe exchange with the held-image digest assertion.
- The native executable was copied to a unique local Windows temporary directory.
  Source and copied bytes had SHA-256
  `54e3b1e1ad9b903d745635749230625dcbe2ae62a7fabbd2d01fe64dbd96e1c9`.

The WSL UNC-path invocation failed executable-identity approval. A PowerShell
copy attempt failed with WSL `UtilAcceptVsock` before test output. Direct execution
of the local Windows copy succeeded; neither failed attempt is counted as a pass.

This is native synthetic transport evidence, not service installation, complete
Windows authentication verification, live game recovery, cold boot, or soak
verification. No service installation, game launch, reboot, or release activation
was performed for these checks. The complete assignment remains incomplete.

Additional checks: Linux and Windows GNU-target workspace/all-target/all-feature
Clippy with `--locked --offline` and `-D warnings` both exited 0;
`cargo fmt --all --check` exited 0.

Open source-review finding: worker connection protects ancestor directories, but
canonicalizes the configured executable leaf before opening its image guard.
The leaf itself therefore lacks an explicit no-reparse handle check on the
original configured reference. Existing passing tests do not establish rejection
of that case. Add a retained no-follow leaf check and an executable regression
before claiming the path-reparse boundary complete. No exploit was executed.

Follow-up implementation now retains an original-path leaf handle opened with
`FILE_FLAG_OPEN_REPARSE_POINT`, rejecting directory/reparse attributes before
canonicalization. Windows-target Clippy passed after the source fix. The rebuilt
native suite passed five tests, including directory-leaf rejection and normal
byte-pipe exchange. A true reparse-leaf regression and independent review remain
outstanding; the earlier four-test executable digest does not describe this
newer build.

The explicit native regression `worker_image_leaf_rejects_real_symlink --ignored
--nocapture` was added and executed. It exited 101 at fixture creation with
Windows error 1314 (required privilege not held); no symlink rejection assertion
ran. It is opt-in because it requires symlink privilege or Developer Mode.
Run this filter on an already authorized capable Windows runner; do not count
the default ignored test as a pass or change host security to satisfy it.

The subsequent Linux `cargo test --locked --offline --workspace --all-targets
--all-features` run exited 0, including worker client, storage, service-loop,
synthetic recovery/runtime, and schema suites. Two watchdog unit tests remain
ignored: installed disposable-host Linux broker validation and delegated-cgroup
process validation. Platform-gated Windows tests do not execute in this Linux run.

## Current candidate byte identities

SHA-256, after adding the explicit symlink regression:

```text
23e91c3c996064cf416cf99c3278b76dc6d4a0d3ebd91995fbf0cebf55a03cd4  crates/platform-windows/src/admin_pipe.rs
c0ca3a34c32a239d56348ffa1a1f5e51f6772deddbc0d02cb58cd74e144acca1  crates/platform-windows/src/native.rs
0477aacee6a275ab1b31e2af004d8963e9060d62fc108a67cd126af6f47ea773  crates/watchdog/src/worker_client_auth.rs
bcca1725ec9f7a943f71e09e840f2d5a76aa705af408466e2d7860a2028de36a  crates/watchdog/src/worker_client_transport.rs
ce430f8ac197770783ed0a49d32dab280863aec84d8bca37dc455b9599893276  ascension_platform_windows-736003376af111f6.exe
```

These identify a candidate, not an activated release set. SID/session binding and
integration with the separately implemented daemon worker wiring are still required.

## Subsequent integration corrections (not covered by hashes above)

The client now exposes observed server SID from its held process handle and
session ID from the connected pipe. The native same-process exchange test passed
with a current-user SID assertion and successful session query (1 test, 1.23s).
This is readout only, not enforcement of an expected SID/session policy.

Independent review identified differing worker namespace validators. Configuration
now calls the same pure validator as the Windows transport, accepting only
`ascension-worker-` plus canonical UUIDv4. A Windows-only configuration regression
checks accepted configuration against the transport and rejects the old prefix,
wrong UUID version/variant, and suffix traversal. Windows-target Clippy passed
after the validator change. Native Windows `worker_config` execution subsequently
passed all 10 tests, including `worker_config_and_transport_share_exact_pipe_namespace`,
with exit 0. The test executable SHA-256 was
`51c6fd7b172a00bd9551dc84c74e718068b3df357918c6f3675dab54923b8fb5`.

Independent review still holds acceptance for bounded synchronous Windows I/O,
loaded-image assurance beyond a protected file hash, required SID/session
enforcement, and the unavailable real-symlink fixture. These are not closed by
passing transport or configuration tests.

Worker response framing now uses `read_frame_bounded` with the protocol's
65,536-byte limit rather than the admin channel's 256 KiB limit. A native
byte-pipe regression sends only a 65,537-byte length header and asserts an
invalid-frame error without a body; the exchange test passed (exit 0, 1.11s).
Admin framing retains its existing limit. Windows-target Clippy passed after
the production change; this is bounded-allocation evidence, not a hard I/O
deadline guarantee.

Independent follow-up review closed the namespace mismatch: configuration and
transport now share the validator. The review did not establish harness endpoint
compatibility, and its broader authentication acceptance remains on hold. This
checkpoint commit is a partial repair, not completion of Windows authentication
or any release gate.
