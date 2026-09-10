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

Caller-approved owner-policy integration on 2026-09-09:

- `cargo test --package ascension-watchdog --test release_staged --locked`:
  13 passed, including approved/wrong UID and replaced above-catalog ancestor.
- `cargo test --workspace --all-targets --all-features --locked --no-fail-fast -j 2`:
  passed; explicit native/service fixture gates remain ignored by this command.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`:
  passed without lint allowances.
- The same strict Clippy command with `--target x86_64-pc-windows-gnu` passed;
  cross-compilation does not establish native Windows staging support.
- `cargo fmt --all -- --check` and `git diff --check`: passed.

The watchdog now integrates a durable release selector and authenticated
activation/rollback consumer on top of this inspection boundary. See
[`release-activation.md`](release-activation.md) for the selector tests and
runtime launch gate. The retained staging capability remains a read-only
building block; it is not itself a sealed cross-repository handoff.

## Remaining protection boundary

The inspection constructor retains an observed owner, not independent trust.
The explicit `CatalogOwnerPolicy::approved_unix_uid` constructor instead accepts
a caller-approved UID and checks it against the catalog and release objects.
Above-catalog normal path components are retained and revalidated; approved
policy permits root or the approved UID as their owner. Non-sticky group/other
writes are rejected. Sticky shared ancestors such as `/tmp` are allowed with
the approved owner checks. The initial `/` descriptor is not retained.

Read-only mode does not prevent the owner from changing permissions, a pre-opened
writer from modifying bytes, or a privileged writer from doing so. Activation
must require an independently approved owner policy and consume a protected or
sealed byte handoff; it must never reopen returned paths as launch authority.
Windows staging currently fails closed because its protected-handle strategy
is not implemented.

These limits remain implementation work, not external deployment blockers.
