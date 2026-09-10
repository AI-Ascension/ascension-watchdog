# Windows integration evidence — 2026-09-10

Classification: source and cross-build evidence only; this is not native
Windows service or live-host verification.

The integrated watchdog branch `codex/watchdog-integrated-20260910` repaired a
Windows-only CI failure after draft PR #8 first ran. The failing run exposed
missing worker-boundary APIs in the current platform merge:

- `AdminPipeClient::connect_worker`, `validate_worker_endpoint`, and bounded
  worker peer identity methods were restored;
- `JobOwnedProcess::account_identity` and the protected owner-directory export
  were restored;
- the current-controller deadline/immutable-image guard boundary was made
  available to its Windows child module;
- Windows-only dead-code diagnostics were made explicit for test-only hooks.

The repair is commit `8c0f6a2` (`8c0f6a26d2c4b1ed6e0669dea91ca15f917ac0b4`).
Local checks after the repair passed:

```text
cargo +1.97.1 fmt --all -- --check
cargo +1.97.1 check --locked --offline --workspace --all-targets --target x86_64-pc-windows-gnu
cargo +1.97.1 clippy --locked --offline --workspace --all-targets --all-features --target x86_64-pc-windows-gnu -- -D warnings
```

The first post-push PR #8 rerun was still in progress when this record was
written; hosted Windows execution and service installation remain unverified.
No SCM service, named-pipe production endpoint, game, provider, reboot, or
live host was started.

## Exact hosted reruns

After the source repair, PR #8 head `c472f3aab726fa2871b46aede6d1985be4e57dae`
passed hosted run `34478258456`: Ubuntu and Windows formatting, strict Clippy,
all-target/all-feature locked workspace tests, exact locked release builds,
standards validation, and dependency/license checks all exited successfully.
The follow-up integration head `0935c66ddf4befe7fe7c17f3ba785af02057b3aa`
also passed hosted run `34480654731` with the same required jobs. These are
hosted CI results only; no Windows service, native SCM/Job Object execution,
WSL run, game/provider launch, reboot, or live-host recovery was performed.
