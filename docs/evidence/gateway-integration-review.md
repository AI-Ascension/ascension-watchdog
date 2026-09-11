# Gateway integration checkpoint

Classification: confirmed build result; source-derived safety findings. This is
not synthetic end-to-end, native service, or host recovery evidence.

The inspected gateway worktree is based on
`ad842db5cb1fdfed5e8163c4cf4bd139d2c21eed` with uncommitted recovery integration
changes. It is not an immutable release candidate. Revalidate all findings after
the owning workstream commits its repair.

Root verification:

- `cargo check --workspace --all-targets --all-features --locked`: passed.
- `cargo run --locked --package repo-policy -- --strict`: failed, three size
  violations: `auth.rs` 344, `recovery_frame.rs` 323, `service.rs` 303 nonblank
  lines against the preferred 300-line bound.

## Required host-boundary repairs

`service_recovery_dispatch.rs` and `service_recovery_v3.rs` issue and advance a
local admission ticket before forwarding the old gameplay body through
`forward_mod`. The inspected forwarding calls do not transmit that ticket. Local
ticket transitions do not establish authoritative host admission or execution.
The repaired path must exercise host-side ticket and current-fence validation,
including queued stale requests, through the actual serialized boundary.

`service_recovery_receipt.rs` and `service_recovery_v3.rs` construct a new witness
identifier locally and label it `host_receipt` using gameplay response data and
a locally supplied fence. This is not a received recovery witness proving the
host checked that fence and ticket. Consume and validate the exact host recovery
proof, preserving uncertainty when it is absent or cannot be correlated.

G4R owns these repairs, existing adversarial store regressions, and the policy
failures. No fixture response, compilation result, or locally created witness
may substitute for the required host-boundary evidence. Native game, provider,
service installation, reboot, and release activation were not performed here.
