# Combined worker storage integration

Classification: confirmed Linux component checks, not an end-to-end worker run.

Tested source: `9a02661`, combining watchdog candidate `8d63b47` with worker
storage `cd617e1e1989d721b67a5fe11360d7cd670b3a7f`, storage boundary splits
`3ed414b616bf327e6daf5b7a7bd9499d50bee40d`, and failed-ACK projection repair
`421f7a8c6db0c232272160d9e2ee234fc8be3527`. All three applied without conflicts
in an isolated root-owned worktree as `4ede6c3`, `b03a634` and `9a02661`.

Root executed the following with a target directory unique to this worktree:

```text
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo build --locked --workspace --all-targets --all-features
```

All commands exited 0. Native environment-dependent tests retain their explicit
gates; for example, the delegated-cgroup native descendant test was ignored
because it requires approved writable delegation and a real helper entrypoint.
This is not a native service test pass. This workspace has no `repo-policy`
package; no such checker pass is claimed.

Historical completion after worker/watchdog boot replacement is integrated as
`59672d416037fbb24390f75290e6994c4c7f3767` from independently authored candidate
`4fa327e3b80b29e5fc225708888c882d0bd7ba97`. Root inspected the production changes
and reran all four commands above successfully on source `0d5c399d02014eec69a9c4157bc540a1435baf29`.
The worker storage suite passed all 14 tests. The library suite passed 76 tests
with two native-environment gates ignored. These are component checks, including
store close/reopen, not worker-process replacement or authenticated IPC evidence.

The original parallel library run exposed a test-only descriptor-number reuse
race. Commit `0d5c399` changes the cleanup assertion to compare the original
device/inode identity: a closed descriptor may be immediately reused by another
test. No production launcher behavior changed.

A subsequent root-authored negative regression changes each current control
witness field independently and tries the fully stale witness. Both completion
and acknowledgment reject these witnesses while preserving the handoff record;
the valid current witness still finishes accounting without clearing stop.
`cargo test --locked -p ascension-watchdog --test worker_storage` passed all 15
tests after this test-only addition. Full workspace/all-target/all-feature Clippy
with warnings denied also passed again; formatting was applied and checked.

The production Supervisor still needs its dedicated worker client/configuration
wiring. Storage APIs and passing storage tests do not prove that jobs
traverse the daemon-to-harness execution/receipt/acknowledgment path.

No service installation, provider/game launch, reboot, release activation,
remote publication or full recovery soak is established by this integration.
