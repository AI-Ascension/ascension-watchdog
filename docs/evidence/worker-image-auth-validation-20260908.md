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

## SID/session enforcement candidate after the checkpoint

The worker client now requires explicit trusted account/session policy before
connecting on Windows and compares observed SID/session before credential access.
The builder reuses the existing strict Windows bootstrap identity validation.
Native tests `missing_windows_account_rejects_before_endpoint_or_credential_access`
and `windows_account_policy_is_explicit_validated_and_redacted` passed (2 tests,
exit 0). These establish missing-policy rejection and constructor/redaction
behavior, not a successful authenticated cross-process exchange. Trusted
supervisor policy propagation and native mismatched-peer coverage remain open.

Follow-up native coverage now exercises `verify_server_account` on a real
same-process byte-pipe connection: matching account/session succeeds; null SID
and a different session each return identity mismatch. The exchange test passed
(exit 0, 1.25s), and final Windows-target strict Clippy passed. Worker transport
calls this same check before credential access. This closes the local mismatch
predicate test gap, but does not prove distinct-process credential non-disclosure
or trusted supervisor policy propagation.

## Integrated supervisor propagation

Existing runtime commits were integrated as `9962fd1b36c8f0ae92f6b6ece4f602c4455024a3`
and `f2ca63bea43e12e9f6432f112b0b15cdc3de276c`. The follow-up runtime patch obtains
SID/session only from a verified native owned child, rejects a configured SID
mismatch, and supplies that policy to the client before connecting. Synthetic
Windows children cannot supply native account authority.

Independent source review found no new concrete defect in this trust path.
Linux `runtime_worker` passed six tests (exit 0, 2.22s); Windows-target strict
Clippy passed after repairing imported Debug/test-helper lint failures.
Native runtime launch, cross-process credential non-disclosure, configured SID
mismatch through the supervisor, and persisted-proof reopen remain unverified.
The Windows runtime fixture now selects the shared pipe namespace rather than
a Unix socket path. Its native build succeeded, but execution failed all five
tests with Windows I/O error 1 (`Incorrect function`), exit 101, 0.01s. No Windows
runtime test passed. The common initialization failure requires diagnosis before
these tests can establish runtime propagation evidence.

The common Windows initialization failure was traced to querying metadata for
an incomplete drive/verbatim prefix. Storage now waits for the root separator
before inspecting the volume root; normal component reparse checks remain.
The imported `timeout.exe` fixture was replaced by an explicitly invoked sleeping
test child. Its deliberate lack of native worker identity exposed a stop-ordering
defect: worker identity rejection could prevent durable operator stop cleanup.
Only during `Stopped`, that rejection is now reported while independently owned
component cleanup proceeds; other failures retain their previous handling.

Native runtime tests then passed five tests with one intentionally ignored child
fixture (exit 0, 4.14s). The Windows test explicitly checks authentication failure
followed by durable stop and removal of both owned children. It does not claim a
successful native worker endpoint connection. Linux runtime-worker six tests and
storage regression five tests subsequently passed; Windows strict Clippy passed.
The temporary diagnostic lock setup was removed after diagnosis, requiring a
final native rerun from fresh state before commit.

The final fresh-state native rerun passed five tests, one child-fixture test
ignored at the top level, exit 0, 3.96s. Test executable SHA-256:
`0144b9c7326b13a397a90d04dad971a480c90c4f4f01d72d406781f13e99a89e`.
This supersedes the diagnostic-setup run for the tested stop/storage boundaries.

Independent stop-path review found an additional retained-child case: after a
cleanup timeout, post-component worker reconciliation could repeat the same
identity failure and abort the loop. The candidate now skips that post phase
when the pre-phase identity was already rejected during durable `Stopped`.
Other modes/errors are unchanged. A retained-child timeout regression and final
rerun are required before closing this follow-up finding; earlier test passes
do not cover this newer adjustment.

The native Windows unit regression
`identity_rejection_and_stop_timeout_retain_exact_child_for_retry` now passed
(exit 0, 1.96s). It uses a real owned synthetic child and a test-only injected
stop timeout: the first stop loop retains the exact identity, the next removes
that child without launching a replacement. Injection is excluded from production.
This covers the retained-child post-phase finding, not native worker authentication.
The earlier full Linux workspace/all-target/all-feature run completed with exit 0;
it predates this final adjustment and is not evidence for the new stop test.

Independent follow-up review closed the post-phase finding. The strengthened
native regression also asserts durable desired/component state `Stopped` and no
unsettled launch intents after retry; it passed with exit 0 in 2.02s. Strict
Linux and Windows-target Clippy passed on the integrated production changes.
