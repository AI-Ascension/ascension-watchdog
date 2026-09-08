# Native protected-payload buffer repair

This source-level repair keeps the Windows protected-file read's secret-bearing
storage inside `Zeroizing` owners. The bounded reader reserves at least
`max_bytes + 1` bytes before reading, uses a zeroizing 16 KiB staging buffer,
and reports source, count, allocation, and oversize failures without exposing
payload bytes in an error. The platform helper transfers the completed vector
without copying it; a caller that retains the returned vector must put it under
its own zeroizing owner.

The repair is limited to the native protected-payload read loop. It does not
claim to erase copies outside this helper, provide OS memory locking, or close
the existing synchronous `ReadFile` deadline gap. No Windows service, host, or
game execution was performed.

## Verification

At the repair worktree, the following commands completed successfully:

```text
cargo +1.97.1 fmt --all -- --check
cargo +1.97.1 test --locked --package ascension-platform-windows --lib protected_payload::tests
cargo +1.97.1 clippy --locked --package ascension-platform-windows --all-targets -- -D warnings
cargo +1.97.1 check --locked --package ascension-platform-windows --target x86_64-pc-windows-gnu
cargo +1.97.1 test --locked --package ascension-platform-windows --target x86_64-pc-windows-gnu --no-run
cargo +1.97.1 clippy --locked --package ascension-platform-windows --target x86_64-pc-windows-gnu --all-targets -- -D warnings
```

The pure seam covers exact-bound EOF, oversize rejection, source-read failure,
zero-bound rejection, zeroizing backing type, and allocation stability. The
Windows target checks compile the native helper and tests but are not native
execution evidence.
