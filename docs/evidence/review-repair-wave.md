# Review repair candidates, 2026-09-07

Classification: confirmed source/component results on named commits, not a
verified cross-repository release. No service installation, live game/provider
run, reboot, release activation or remote write was performed in this wave.

## Launch binding and Windows cleanup

Independent V26R reproduced two blockers in `399d59e`: Linux adapter proofs
persist `session_id: null` for the service selector `Explicit(0)`, whereas the
runtime required `Some(0)`; a proof could select the synthetic backend and
bypass native hash/session checks. Historical intent migration and original
incarnation binding passed its focused review.

Root repair `25c5a98` chooses the expected backend from trusted runtime
configuration/compiled platform, rejects proof-selected backend changes, and
allows Linux's absent session only for `Explicit(0)`. It preserves Windows
resolved-session validation. Library tests: 40 passed, one explicitly gated
native cgroup test ignored. Locked all-target/all-feature package Clippy with
warnings denied and formatting passed. Initial new tests failed because their
test setup selected HostBroker with session zero; the fixture roles were
corrected and all regressions rerun successfully.

P10R candidate `e2fc6c0` adds exact Windows Job cleanup classification,
selected-executable integrity guards, conservative post-spawn proof failure,
synthetic proof-size preflight, and native-manager rejection of synthetic
proofs. Its author reports Linux tests, Windows GNU cross-check and strict
Clippy passed. Native Windows execution remains unverified.

Combined candidate `954e321` contains both changes and the original intent
migration, on root baseline `d8e9e99`. Root ran:

```text
cargo test --locked --workspace --all-targets --all-features
```

Exit 0, including separate daemon/CLI subprocess tests and stop, launch,
storage, migration and cleanup regressions. Two native cgroup cases are ignored;
Windows-only executable tests run zero cases on Linux. Root formatting and
strict workspace all-target/all-feature Clippy passed on Linux and the Windows
GNU cross-target. V29 independent review is pending. The candidate is not yet integrated
into the primary implementation branch.

## Fixture and lease contract

V27R reproduced wrong-original-context lookup disclosure and reconciliation
mutation in fixture `a6de41c`. It also admitted two independent sessions for one
game instance. F28 owns context checks and single-instance session admission
from transport-repaired `456103c`. F28 candidate `7cc9d01` is committed with
37 passing serial fixture tests; V31 independent review is pending. Capacity 64 is safe backpressure, not
archival: runtime tombstones and longer-run retention remain incomplete.

A12 validated candidate `ef6f9aa` with a real Draft 2020-12 validator, but
rejected consumer readiness. Eight remaining issues concern protected token
persistence, install-time expiry/monotonic rules, inconsistent bounds, missing
stateful lifecycle tests, gateway-principal binding, duplicate members,
fractional timestamp parsing and semantic/schema constraints. A13 authors the
repairs; a different final reviewer is required. No consumer should treat the
candidate as an accepted interface yet. Frozen recovery-v1 remains unchanged.

## Companions and operational work

Gateway catalog candidate `97b7524` retains exact legal-actions value bytes,
binds cache admission to observation/lease context and consults durable original
operation identity before cache admission on retries. The author reports all
workspace gates passed; V30 independent review is pending. The managed catalog
and harness recovery review remain in progress.

W11 owns a bounded authenticated backup API/CLI implementation. The existing
wire enum alone does not implement backup: the current dispatcher still rejects
it. Restore/rekey and release activation are not part of W11 and remain separate
implementation gaps.

## Agent execution evidence

All nine resumed/new descendants' native session metadata records bind their
depth-1 parent to this root. Their first execution turn contexts independently
record `model: gpt-5.6-luna` and `effort: max`; exact thread IDs are in the
agent registry. Nine reserved descendants remain below the root budget of 12.
No depth-2 or depth-3 execution is observed, and the missing descendant spawn
tool remains an unmet capability requirement. No alternate-client bypass ran.
