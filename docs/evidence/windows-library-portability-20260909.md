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
