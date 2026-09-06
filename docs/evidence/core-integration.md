# Initial core integration

Classification: confirmed Linux unit and synthetic-process execution; service,
companion transport, live-host, reboot and soak verification remain unverified.

Core source handoff `7e72b828c0eb4cc0d5dbf32471963f725344e5f3` was integrated
as `964743f` and linked with the release inspector and read-only preflight CLI.

The integrated workspace passed on Rust 1.97.1:

```sh
cargo fmt --all --check
cargo test --workspace --all-targets --all-features --locked --offline
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo deny --locked check advisories licenses bans sources
```

The current tests comprise eight core cases, eleven release cases, six preflight/
config cases and nine synthetic host-fixture cases. One core case starts real
synthetic subprocesses, observes a crash/restart,
persists stop and reopens the store. The preflight CLI case invokes the actual
watchdog executable and verifies success/failure exits without creating state.
These are not OS service or gateway/harness/host integration tests.

The fixture handoff `9dba55d7c01013dce4392d729d66008e5ab10a0b` was integrated
as `1dc0845` with one workspace lockfile; the redundant package lockfile was
removed and remains recoverable in Git history. The fixture is non-publishable
and excluded from default package selection. Six subprocess cases exercise
loopback response loss, malformed responses, queued stale fencing, admission and
mutation crash windows, and receipt-capacity backpressure. They have not yet
been composed with the real companion binaries.

Draft PR 2 targets the new repository bootstrap base. At remote head
`5990f8206f09f3af597b28ac56557321fd24b8f0`, Actions run `34065646530` passed
the Ubuntu Rust lane and failed Windows lint because a shared test import was
incorrectly Unix-gated. The import was corrected locally, and all-target GNU
Windows strict Clippy passed afterward. A new native CI run is still required;
cross-compilation does not replace it.

Dependency checks passed with a non-fatal duplicate `hashbrown` warning from
rusqlite's target-specific transitive dependency graph. No advisory, license or
unapproved-source failure was reported. CI workflows are configuration until
an exact remote run is recorded; local checks are not CI evidence.

An independent reviewer is inspecting core ownership, persistence, stop,
completion and cleanup semantics. Administrative commands still require owner-loop
IPC integration; platform containment and recovery references require their
adapters. Passing these cases does not certify the numbered fault matrix or
declare the implementation complete.
