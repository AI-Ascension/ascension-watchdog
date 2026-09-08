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

## Later candidate status

Commit `47b3c29930ec8c1bcd203dd3c4ecba3126ebab6b` adds bounded, read-only discovery
of the oldest pending handoff and current control evidence after restart. Tests
retain prepared/uncertain records, return completed receipts awaiting ACK, exclude
acknowledged records, and rediscover the original tuple after store reopen while
stopped. The 15 worker-storage tests and full workspace Clippy passed.

Its subsequent full workspace test run failed three `adversarial_core` synthetic
process cleanup tests; a serial repeat reproduced all three failures. The exact
test processes were observed as zombies adopted by the WSL relay. This does not
prove that the cause is exclusively environmental: diagnosis remains open. The
later full-workspace gate is failed, not superseded by the earlier passing run.

Commit `52f0d6bc552e9bbea7173a4be757ae496ddac84f` integrates the independently
reviewed configuration candidate `043b0bd1db9de17164e136f6d59244e3935b0d37`.
The reviewer accepted its pure configuration scope, with eight Linux tests,
formatting, package Clippy and Windows GNU test compilation passing. Root had
also executed the eight configuration tests natively on Windows before this
integration. None of these checks prove IPC authentication or service behavior.
Client activation must validate actual protected file/endpoint identities;
lexical path separation alone is insufficient against aliases.
