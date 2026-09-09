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
