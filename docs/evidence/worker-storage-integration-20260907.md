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

The production Supervisor still needs its dedicated worker client/configuration
wiring. Historical completion after worker/watchdog boot replacement remains a
separate repair. Storage APIs and passing storage tests do not prove that jobs
traverse the daemon-to-harness execution/receipt/acknowledgment path.

No service installation, provider/game launch, reboot, release activation,
remote publication or full recovery soak is established by this integration.
