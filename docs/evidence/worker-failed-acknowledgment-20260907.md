# Failed worker acknowledgment projection

Classification: confirmed local SQLite component regression; independent review
and integrated worker transport validation remain pending.

At source `3ed414b616bf327e6daf5b7a7bd9499d50bee40d`, root reproduced a successful
failed-terminal acknowledgment followed by an unreadable handoff. The next
`worker_handoff` call returned `completed worker handoff does not match the
completed job result`. The acknowledgment state had been incorrectly projected
as successful completion, regardless of the retained terminal receipt.

The repair checks acknowledged records against their retained completed/failed
outcome. It does not change dispatch admission, boot identity, terminal receipt
hashing, or retry policy. Missing terminal outcomes still reject.

`failed_terminal_acknowledgment_remains_readable_after_reopen` uses real owner-local
SQLite APIs to claim, mark possible dispatch, record terminal failure, acknowledge,
read, close/reopen, repeat acknowledgment and completion, and verify no job rerun.
It failed before the source repair (exit 101) and passed afterward. All 12 focused
worker-storage tests passed after repair.

Root also passed `cargo fmt --all --check`, `git diff --check`, and locked
workspace/all-target/all-feature Clippy with `-D warnings`, tests, and build. The test
suite includes recovery/schema conformance and bounded synthetic subprocesses;
Windows-only test binaries have zero native tests on this Linux run and are not
Windows execution evidence. A target directory unique to this repair was used.

No service, live game, provider, machine reboot, release activation, remote push,
merge, or soak is established by this component regression. Historical completion
across changed worker/watchdog boots is a separate review issue, not fixed here.
