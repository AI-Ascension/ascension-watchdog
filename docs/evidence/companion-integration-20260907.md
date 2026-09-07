# Companion integration checkpoint

Classification: confirmed local build, test, and synthetic transport evidence.
This is not a complete cross-repository release set, native service installation,
live-game recovery, cold reboot, or soak result.

## Harness provider-result projection

Integrated source: `1cac8d3` on `codex/watchdog-harness-recovery-integration`,
including independently reviewed owner commit
`4299d0ac749ea86d0161bb3bc3e185e860130137`.

The five decision-result reads use a bounded SQL projection. Oversized BLOBs
and non-BLOB values fail as corruption; legacy NULL remains metadata-only.
This bounds the selected result and Rust copy, not total SQLite pager memory.

Root reran these commands on the integrated source, all with exit 0:

```text
cargo test --locked --offline --package sts2-harness --test execution_store
# 15 passed
cargo test --locked --offline --workspace --all-targets --all-features
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo run --locked --offline --package repo-policy -- --strict
# 394 sized files; 0 warnings; 0 errors
```

The completed-resume process-supervisor repair was subsequently independently
reviewed and integrated through `2c55c8a`. Root resolved its two missing lock
entries and separated the adversarial reader tests from process support to
satisfy strict policy. Root then passed the locked workspace/all-target/all-feature
test and Clippy gates, formatting, and strict policy (396 sized files, zero
warnings/errors), including 81 runtime tests and seven completed-resume process
tests. The process supervisor uses nonblocking bounded drains and keeps the
owned group leader waitable until group signaling. No production timeout was
increased. This remains Linux synthetic process evidence, not live recovery.

## Lease-proof vectors

Watchdog commit `e1a2147` derives the expected six proof domains from frame kind
instead of trusting vector metadata, and checks that a one-byte key change
invalidates all nine published frame proofs. Root passed the locked/offline
`host_lease_proof_vectors` test and its strict Clippy gate. This test independently
recomputes fixture hashes, canonical bytes, and HMACs; it is not a production
decoder, raw-JSON rejection suite, key-rotation implementation, or proof that
gateway and host consumers enforce the profile.

## Managed/native recovery transport

Integrated source: `076f8ed627ec530273ff829273ee484b85dbacbe` on
`codex/watchdog-mod-native-transport-tests`. It combines the managed recovery
partial split with campaign owner commits `63ce863`, `8911ced`, `75d9e24`,
and independently approved `a2d631c`.

Root rebuilt the managed probe with .NET SDK 9.0.317 (zero warnings/errors)
and the native library with locked/offline Cargo. Exact tested artifact hashes:

| Artifact | SHA-256 |
| --- | --- |
| `RecoveryTransportProbe.dll` | `a1a8ccc0fb3b92228262967ef0fcbf714c3404e7d3b31b82fb8196293c2afdc4` |
| `libai_ascension_sts2_game_mod_native.so` | `4bd59ee631a7416b5e9684e0f0e6524d77b89b533ba92be38e455dc80cbc4b7d` |

The executable campaign command uses those exact built artifacts:

```text
dotnet RecoveryTransportProbe.dll --campaign ABSOLUTE_NATIVE_LIBRARY_PATH NATIVE_SHA256
```

It returned `campaign_passed`: authentication denial 401, disabled bootstrap
403, invalid proof 401, fence/acquire/intent/dispatch/duplicate/read 200,
conflicting intent 409, `effects: 1`, `restart_effects: 0`, and clean shutdown.
Requests traversed the native HTTP listener and managed callback into a
synthetic host. No proprietary game or gameplay provider was launched.
Cleanup evidence covers the direct fixture process and redirected streams;
it does not establish arbitrary descendant containment.

Root also passed locked/offline workspace/all-target/all-feature Rust tests,
strict Clippy, formatting, and strict policy (350 sized files, zero warnings
or errors). Production host-lease consumers, gateway catalog repair, Linux
restricted broker, Windows service wiring, and the final release-set campaign
remain separate integration gates.
