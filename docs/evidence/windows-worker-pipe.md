# Windows worker bootstrap pipe component

Scope: the isolated `codex/watchdog-windows-worker-pipe` worktree, based on
`d559750`.  This component adds a Windows-only Harness launch overload while
leaving ordinary `WindowsProcessLauncher::launch` behavior unchanged.

The native boundary accepts one immutable, envelope-bounded frame owned by
`WorkerBootstrapLaunch`.  The watchdog remains the owner of bootstrap JSON and
identity validation; this crate only checks the fixed `ASC-WB01` envelope and
the 1..=16,384-byte payload bound.  A worker launch creates a dedicated
anonymous `CreatePipe`, clears inheritance from the parent writer, and places
only the inheritable child reader in `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.
`STARTF_USESTDHANDLES` installs that reader as stdin.  The worker frame is
written once before `ResumeThread`, while the child is suspended and already
assigned to its named Job Object.  The exact executable integrity barrier is
retained, and an explicit callback runs immediately before `ResumeThread` so a
durable owner can authorize the launch after all native preparation succeeds.

Windows anonymous `CreatePipe` does not expose overlapped I/O and its requested
buffer size is advisory.  The writer is therefore switched to the documented
`PIPE_NOWAIT` compatibility mode with `SetNamedPipeHandleState`; this is
nonblocking at the API boundary without claiming overlapped/asynchronous I/O.
`WriteFile` returns immediately, and a partial/full-buffer result fails closed
before resumption.  The bounded call checks the deadline before and after the
write, closes both parent endpoints on every path, and retains the exact Job
Object for cleanup.  A feature-gated Windows regression forces a one-byte
requested buffer with a maximum frame and proves no resume, bounded failure,
and exact planned-Job cleanup.  A production caller cannot select that test
capacity; normal launches request the complete protocol maximum and test the
maximum frame.

## Checks

```text
cargo fmt --manifest-path crates/platform-windows/Cargo.toml -- --check   PASS
cargo test --locked -p ascension-platform-windows --all-targets          PASS (Linux: 23 tests; Windows-only tests do not execute)
CARGO_TARGET_DIR=/tmp/ascension-windows-worker-pipe-target-5 cargo test --locked -p ascension-platform-windows --all-targets --target x86_64-pc-windows-gnu --no-run   PASS
CARGO_TARGET_DIR=/tmp/ascension-windows-worker-pipe-target-5 cargo clippy --locked -p ascension-platform-windows --all-targets --target x86_64-pc-windows-gnu -- -D warnings   PASS
CARGO_TARGET_DIR=/tmp/ascension-windows-worker-pipe-target-6 cargo test --locked -p ascension-platform-windows --all-targets --features native-worker-test-hooks --target x86_64-pc-windows-gnu --no-run   PASS
CARGO_TARGET_DIR=/tmp/ascension-windows-worker-pipe-target-6 cargo clippy --locked -p ascension-platform-windows --all-targets --features native-worker-test-hooks --target x86_64-pc-windows-gnu -- -D warnings   PASS
```

The Windows-target commands are cross-compilation evidence only.  No Windows
service, host, game, provider, account, or credential action was performed in
this component check.  The native synthetic tests in
`tests/native_worker_bootstrap.rs` are prepared for execution on an approved
unprivileged Windows runner and use only the checked-in temporary executable
fixture and owner-local temporary files.

## Native unprivileged execution

Root copied the cross-built test and checked-in synthetic executable into one
fresh Windows temporary directory, verified their SHA-256 digests, and executed
the tests with a 60-second owned-process outer deadline. All five tests passed
in 2.76 seconds: maximum-frame stdin delivery, rejected pre-resume authorization,
forced-small-buffer bounded rejection with exact planned-Job cleanup, and the
two pure envelope tests. The saturation test also asserts a 30-second overall
test bound. The adjacent-fixture lookup supports cross-built artifacts without
embedding a usable build-host path assumption into native execution.

| Artifact | SHA-256 |
| --- | --- |
| native worker bootstrap tests | `0afad35f133bd66e3f936feb4002d7d3799585a0db327b0f60ea87fde56b6ebe` |
| platform synthetic executable | `157358da4254715c36c48d7b2fa1046fea7e0a6666e7ac4e566b1d6d7c6782a5` |

This establishes the unprivileged pipe/Job component behavior, not Windows
service installation, root producer integration, real harness consumption,
desktop/gameplay behavior, reboot recovery, or release activation. The initial
synchronous-write candidate was rejected before integration; its advisory buffer
size was not a hard deadline guarantee. The revised nonblocking behavior was
checked against [Microsoft's CreatePipe documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
and exercised natively above.

The current-controller capture API uses only the current process handle and
retains an immutable executable/directory guard. It repeats process birth,
path, SID/session and file-identity checks under a hash/admission deadline;
queries are not kernel-preempted. Debug output redacts the path and SID.
Root executed both native capture tests successfully (1.73 seconds), including
comparison with the binary digest independently supplied by Windows Get-FileHash
and expired-deadline rejection. Test executable SHA-256:
`2a982d162185db4ee9fc23bd8fae332493c8ed579eceeff354772f1d154357dd`.
The unused no-op worker authorization overload was removed after independent
review: worker launch requires an explicit pre-resume callback. Root runtime
wiring and its exact durable binding checks remain a separate integration gate.
