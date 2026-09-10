# Release activation and rollback validation

Classification: confirmed watchdog source and synthetic integration evidence;
native service, live-host, cold-boot, and soak activation remain unverified.

The integrated watchdog now owns a durable release selector in its owner-local
SQLite store. `release_selection_state` is `none`, `prepared`, or `active`;
the selector records the logical release ID and exact original manifest-byte
SHA-256, while retaining the previous identity for a narrowly bound rollback.
Preparation requires the singleton owner and durably stopped mode, rejects
children, unsettled launch intents, and pending worker handoffs at the admin
boundary, and records the exact request/idempotency tuple before the final
protected catalog recheck. A prepared marker survives process/reopen failure;
another request cannot leapfrog it. The prior active identity is copied into
the prepared marker and is compared again at completion, so a changed valid
metadata value cannot silently alter the rollback target.

Completion uses one immediate SQLite transaction for the active selector,
previous identity, pending-marker removal, operator receipt, and audit event.
Duplicate requests replay the retained response without another selector
transition. Rollback accepts only the exact previous ID and digest. Restore/
rekey clears active, previous, and pending selector metadata, requiring a fresh
explicit activation in the new authority namespace.

The dispatcher performs a protected catalog inspection before preparation and
again immediately before completion. The runtime launch path also treats a
configured catalog as an admission fence: no new component is launched until
the active selector is present, its exact manifest digest still matches the
protected bytes, and the release remains compatible with the current
configuration. A missing or tampered selector blocks the component rather than
falling back to a different release; activation can release a component from
that blocked state on a later reconciliation pass.

The CLI surfaces the authenticated operations:

```text
watchdog release activate --config PATH --release-id ID \
  --expected-release-digest DIGEST --idempotency-key KEY
watchdog release rollback --config PATH --release-id ID \
  --expected-release-digest DIGEST --idempotency-key KEY
```

The activation-focused validation was first executed at source commit `0542ab8`
and is retained as an ancestry record. The current PR head `f5eaf5e` contains
that source and the collision-safe Windows fixture repair; its hosted Ubuntu/
Windows and standards gates pass. The current integrated worktree records the
same activation behavior plus the separate native Linux worker smoke described
in [`real-harness-worker.md`](real-harness-worker.md).

Validation executed at watchdog source commit `0542ab8` in the integrated
worktree:

- `cargo fmt --all -- --check`: pass.
- `cargo test --locked -p ascension-watchdog --lib storage_release::tests`:
  5 passed, covering reopen/retry, exact rollback binding, changed-active
  identity rejection, response/selector binding, and request-UUID collision.
- `cargo test --locked -p ascension-watchdog --lib runtime::tests::configured_release_catalog_requires_explicit_activation_before_launch`:
  1 passed.
- `cargo test --locked -p ascension-watchdog --test admin_control real_service_read_credential_inspects_configured_release_without_store_writes`:
  1 passed; authenticated activation persisted one receipt and the active
  selector, while later artifact tampering remained a read-only conflict.
- `cargo test --locked --offline --workspace --all-targets --all-features
  --no-fail-fast`: pass (206 watchdog library tests, 4 ignored; all workspace
  integration suites).
- `cargo clippy --locked --offline -p ascension-watchdog --all-targets
  --all-features -- -D warnings`: pass.

This is not yet a complete immutable executable handoff. The protected
catalog inspector retains no-follow handles only for each inspection call, and
the selector transaction stores identity rather than transferring sealed
executable handles to every downstream component. Read-only mode therefore is
not treated as an immutable writer barrier. The remaining release gate is a
cross-repository, platform-specific sealed/immutable handoff and its native
activation/rollback campaign; no service was installed, no game/provider was
launched, and no live or reboot activation was performed for this evidence.
