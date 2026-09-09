# Descriptor-bound release staging

Classification: confirmed Linux source and focused test evidence; not release
activation, rollback, installation, or immutable executable-handoff evidence.

The public `release_staged` module validates independently approved original
manifest bytes, six distinct fixed artifact roles, configuration/profile digests,
store compatibility and configured watchdog component bindings. The watchdog
does not acquire ownership of MCP, mod or broker processes merely because their
artifacts are required by the release manifest.

Linux staging retains no-follow directory/file descriptors, rejects writable or
hard-linked artifacts, hashes with bounded positional reads, and rechecks mode,
owner, link count and identity after hashing. Nonblocking opens reject FIFOs
without waiting for a writer. Verification is read-only and safe for concurrent
readers; returned paths are diagnostic information, never launch authority.

Root integration validation on 2026-09-09:

- `cargo test --locked -p ascension-watchdog --test release_staged`: 10 passed,
  including independently approved manifest mismatch, in-place tampering,
  duplicate roles, concurrent verification and manifest/artifact FIFO rejection.
- `cargo test --locked -p ascension-watchdog --lib protection_change_after_hash_is_rejected`:
  1 passed; a protection change during hashing is rejected.
- `cargo clippy --locked -p ascension-watchdog --test release_staged --all-features -- -D warnings`:
  passed, without lint allowances.
- `cargo clippy --locked -p ascension-watchdog --lib --all-features -- -D warnings`:
  passed, without lint allowances.

The dormant release-selection prototype is deliberately not integrated into
this change. No selector, CLI activation command, runtime activation consumer,
or durable release-state transition is added here.

## Remaining protection boundary

The catalog owner is observed rather than independently authorized. Ancestors
above the catalog root are not retained. Read-only mode does not prevent the
owner from changing permissions, a pre-opened writer from modifying bytes, or a
privileged writer from doing so. Activation must enforce an independently
approved owner/ancestor policy and consume a protected or sealed byte handoff;
it must never reopen the returned paths as launch authority. Windows staging
currently fails closed because its protected-handle strategy is not implemented.

These limits remain implementation work, not external deployment blockers.
