# Windows library portability validation

A native watchdog library run exposed four failures beyond the earlier platform
suite: a nonexistent credential fixture, two contract tests using a Unix-only
absolute executable path, and WSL guest-path validation using the host's path
grammar.

The Windows admin test now creates owner-protected synthetic token files in its
temporary directory. Contract fixtures use their current executable as an
absolute host path. The WSL production validator uses exact Unicode POSIX guest
path syntax on either host, with the existing 2048-byte argument bound and NUL
rejection. It still rejects relative paths and Windows drive paths; no shell,
implicit distro, or wider endpoint is introduced.

Author validation: Windows-target all-target/all-feature check and strict Clippy,
Windows library test build, formatting and diff checks passed. Linux-focused
platform tests passed: 73 tests, two explicit environment skips.

Root copied and SHA-256 verified the Windows library test executable, then ran
`--test-threads=1 --nocapture` natively under a 55-second outer deadline. Result:
30 passed, zero failed, one ignored subprocess fixture, 2.95 seconds, exit 0.
Artifact SHA-256:
`28941aa2617e5e422de9957ac43c67bcea3fd391d957941836c439d3cfe49928`.

This artifact tests the isolated portability repair, not the later integrated
worker producer. WSL path-value validation is not evidence of distro launch,
termination/restart, or guest service recovery. No service installation, account
change, game/provider run, or host reboot was performed.

## Integrated candidate validation

At `27f6efccb6eb887bdec5ca6d0fe493636eb3a5d6`, the integrated Windows library
test executable ran natively: 31 passed, zero failed, four ignored, 18.84 seconds,
exit 0. SHA-256:
`cdfb71af12a5b31e6da0dd1f054b1a2abb21179affed72e13f5ce5848ca4eb2a`.
The ignores include two positive Session-0 worker tests and two child fixtures;
the desktop-session rejection test passed. Positive service-session admission
therefore remains unverified by this local run.

CI run `34300640529` on that revision passed the Linux formatting, strict Clippy,
workspace synthetic tests and locked release build, plus dependency/license
checks. Root's Linux workspace/all-target/all-feature test run also exited 0
with eight test threads. Windows CI passed formatting and strict Clippy, then
failed two library tests because their temporary-file ACL helper could not load
PowerShell's `Set-Acl`. Its library result was 29 passed, two failed, four ignored.
That hosted-fixture failure remains open; the local native pass does not waive it.

The follow-up fixture repair explicitly imports the Windows PowerShell security
module from its own `$PSHOME` before applying the unchanged protected owner-only
DACL. Its isolated Windows-target check, strict Clippy, libtest build, format
and diff checks passed. Root verified and executed that artifact natively:
31 passed, zero failed, four ignored, 19.08 seconds, exit 0, using
`--test-threads=1 --nocapture` under a 55-second outer deadline. SHA-256:
`ee9ec5a5af3b71840f3f630c1870b3768faddd4839d0906500e855cbe7eb609b`.
The hosted Windows lane still requires an exact-revision rerun.

## Preflight byte-bound fixture

CI run `34302144585` at `fe77c9e129b9a47f001f341f98a2e88c9db22e96` passed
the repaired Windows library suite, then failed the oversized-configuration
preflight assertion. Two fixture assumptions required correction: Windows
configuration reads require protected owner ACLs, and the Windows bounded-reader
error differs from the Unix reader's text. Applying ACLs alone still failed in
root's native run; that intermediate artifact is not a passing result.

The corrected test requires the platform-specific size rejection at 65,537
bytes, then rewrites the same protected file to 65,536 whitespace bytes and
requires a JSON parse error. This proves the exact bound reaches parsing and
distinguishes the oversized rejection from an unrelated ACL/path failure.
Production reader limits and security policy are unchanged.

Root's Linux `cargo test --locked -p ascension-watchdog --test preflight` passed
all six tests. The corrected Windows test compiled and ran natively with
`--exact oversized_configuration_is_rejected_before_parsing --nocapture`:
one passed, four filtered out, 0.34 seconds, exit 0. SHA-256:
`5aeea566e01ea9ac48e8c707f1bcecfe6ac83fe670f082c965b98c2646d08fc6`.
This focused native result does not establish a full Windows workspace pass.

## Direct-job authorization fixture

CI run `34303730127` at `9afd10f4c48ed3da1beec8655fda2ab5632809ef` passed
the Windows library and preflight suites, then failed
`storage_queries::production_cli_rejects_direct_job_writes_before_opening_state`.
The test's config file did not have the protected owner-only DACL required by
the Windows configuration reader. Source inspection shows configuration loading
precedes the direct-job authorization rejection; the old assertion did not
distinguish that earlier read failure.

The fixture now applies the same explicit PowerShell security-module import
and owner-only protected DACL used by the other Windows configuration tests.
Its existing `Unauthorized` assertions for submit, claim, complete and fail,
and its assertion that no state database was created, are unchanged. No
production authorization, configuration-reader or ACL policy changes were made.

Root cross-built the integrated `storage_queries` test executable, verified its
source/copy SHA-256, and ran all three tests natively using
`--test-threads=1 --nocapture` under a 55-second outer deadline: three passed,
zero failed, 0.58 seconds, exit 0. Artifact SHA-256:
`3f82a267a875188c6671cb8962104266c1ceea318b965cf831e005d64c091744`.
The isolated author also passed Linux's three tests, Windows-target all-target
check and strict Clippy, formatting and diff checks. A fresh hosted Windows
workspace run remains required; this result is native synthetic evidence only.

## Credential fixture module loading

CI run `34305449795` at `a0228c5f5c46f608656b09bfd8569c639819243c`
passed the repaired storage queries, then failed
`worker_config::derived_worker_endpoint_constructs_client_and_rejects_admin_namespace`:
Windows PowerShell could not autoload the module containing `Set-Acl`. This
credential fixture now explicitly imports the same module from `$PSHOME`.
The protected owner-only DACL and the endpoint/client assertions are unchanged.
A repository search of all five `Set-Acl` helpers found no other missing imports.

Root's Linux worker-config target passed all 11 tests. Root cross-built,
SHA-256 verified and executed the Windows target: all 13 tests passed in
0.55 seconds, exit 0, under a 55-second outer deadline. The test process's
inherited `PSModulePath` was set to a nonexistent temporary directory to exercise
the explicit import without normal module discovery. This changed no persistent
environment or machine/account policy. Artifact SHA-256:
`dd85c85aa83168abc9fbf371794604eb4dbb7f706fef3846af037943a7a1f218`.
Formatting and diff checks passed. The hosted full Windows run remains a separate
required gate, including its explicitly gated service-session tests.

## Fault-fixture lock and transport portability

CI run `34306074494` at `1be13d694a9626d9eaba4ba0e7abd8023de4211c`
failed two fault-fixture library tests on Windows. Lock contention now recognizes
the exact native error returned by `fs2::lock_contended_error`, as well as
`WouldBlock`; unrelated I/O failures remain errors. The transport test no longer
assumes that a payload larger than configured socket buffers necessarily blocks.

An intermediate native artifact with 4 KiB configured socket buffers and a
256 KiB payload still failed: Windows accepted the entire payload. Its seven
passes and one failure are not passing transport evidence. The final fixture
leaves the connection unaccepted, uses bounded nonblocking prefill to observe
actual `WouldBlock`, then requires the production deadline writer to return
`TimedOut` or `WouldBlock`. Prefill is bounded by both bytes and time. Test-only
`socket2` configures the sockets; production timeout policy is unchanged.

Root cross-built the integrated library test executable, verified source/copy
SHA-256, and executed all eight tests natively under a 55-second outer deadline:
eight passed, zero failed, 2.19 seconds, exit 0. Artifact SHA-256:
`16417be1c1131c6d633d8a09737ba4a72a6b5f8192343987355f489b50e89452`.
Root's Linux `cargo test --locked -p watchdog-fault-fixture --lib -j 2` also
passed all eight tests in 2.07 seconds. Formatting and diff checks passed.
CI now uses Cargo's `--no-fail-fast` so later test binaries still run after a
failure; failures remain fatal. A fresh exact-revision hosted workspace run
is required. These are native synthetic tests, not service or game-host proof.

### Hosted zero-window follow-up

Run `34310012164` at `6d862658a58e417237819e58a9b75fec98d238fe`
passed Linux and dependency gates but still failed the Windows transport test:
the prefilled connection later accepted its whole write. A transient nonblocking
`WouldBlock` was not proof of sustained receive-side backpressure. The same
Windows run separately failed the native leader-exit test with
`QueryFullProcessImageNameW` error 5; that is a distinct open issue.

The Windows-only fixture now accepts its peer and sets its receive buffer to
zero without posting reads, while retaining a nonzero send buffer. Microsoft's
[Winsock sample explanation](https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/netds/winsock/iocp/server/IocpServer.Cpp)
describes the resulting zero receive window. This is test setup, not a production
socket-policy change. An intermediate experiment that also disabled send
buffering exceeded the outer deadline and its exact owned test process was
stopped; that experiment is not passing evidence.

### Absolute nonblocking write deadline, 2026-09-09

Hosted run `34312926666` at `7ef567d2e492f4ccdd5e2bb58e67367ae57af4a2`
still failed the fixture writer test. Production fixture writes now use
nonblocking, bounded 16 KiB chunks with one absolute two-second deadline,
including interrupted and temporarily unwritable iterations. The original
blocking mode is restored on both success and failure. A new expired-deadline
regression requires zero bytes to be sent even when the socket is writable.

The test retains its unread accepted peer and bounds accept and prefill. Windows
uses zero receive buffering but a positive 4 KiB send buffer, with 1 KiB prefill
chunks. A diagnostic variant with zero send buffering hung inside prefill and
was stopped through its held process handle; it is not passing evidence.

After removing temporary diagnostic output, root cross-built the exact test
image, verified its staged SHA-256, and ran it natively on Windows with a
12-second outer deadline and bounded exact-process cleanup. All nine tests
passed in 2.01 seconds, exit 0; the outer deadline did not fire. Image SHA-256:
`c99e57839729839652e36e511148a48667075fc242aef536bb8e71ad771ee72c`.
The Linux library tests also passed all nine tests. Root's integrated format,
warnings-as-errors Clippy, and workspace/all-target/all-feature locked tests
exited 0; explicitly gated native tests remained ignored in the default matrix.
A fresh hosted exact-commit Windows workspace run is still required. This does
not establish Windows service installation or harness/gameplay compatibility.

Root's final native artifact passed all eight tests in five consecutive runs:
2.21, 2.27, 2.29, 2.23 and 2.29 seconds, each exit 0. Artifact SHA-256:
`a7ad4502e22057e126ec0fea41d763e1d575a513bbc53545dc03958a5a59389e`.
The source and staged executable hashes matched. The prior hosted failure
remains unresolved until a new exact-revision CI run passes; repeated local
native execution does not substitute for that result.
