# Linux worker bootstrap pipe component — 2026-09-08

Scope: `codex/watchdog-linux-worker-pipe`, based on
`4e10f6594bb5eb3c6c906567a4e362fb19ff4ed5`. This is a launcher component,
not the completed runtime producer-to-harness path.

The native API carries one validated immutable encoded bootstrap frame and its
SHA-256 digest. A dedicated anonymous pipe is nonblocking and close-on-exec in
the parent. The helper duplicates the read endpoint before READY; the parent
then closes its reader. GO precedes bounded frame writing. Only worker launches
replace target stdin. Ordinary launches preserve their prior stdin inheritance.

Independent review found regressions in ordinary stdin behavior and malformed
helper argument handling, and requested explicit worker descriptor closure before
bounded helper cleanup. Those findings were corrected. Root inspected the fixes
and independently reran the focused checks:

- `cargo fmt --all --check`: passed.
- `cargo test --locked -p ascension-watchdog --lib platform::linux_launcher::tests -- --test-threads=1`:
  27 passed, none ignored.
- `cargo clippy --locked -p ascension-watchdog --lib -- -D warnings`: passed.

Tests cover identity mismatch before spawn, exact frame/digest retention, anonymous
pipe descriptor validation, expiry before a first write, a saturated pipe deadline,
reader duplication/ownership, malformed helper argv, and the existing READY/GO,
executable binding, nonce, and descriptor-inheritance regressions.

## Explicitly unverified integration

The supervisor still needs to construct the expected controller identity, persist
the bootstrap binding against the launch intent, select this native API, and
verify binding metadata during helper authorization after GO. The launcher metadata
alone is not durable authorization. This branch does not establish an actual
watchdog-to-harness authenticated exchange or Linux service recovery. Full integrated
workspace/native gates must run after runtime and companion integration.

No service installation, game/provider launch, host reboot, or release activation
is established by this component evidence.
