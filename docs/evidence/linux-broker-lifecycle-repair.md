# Broker lifecycle repair checkpoint

Classification: partial, local branch implementation. Not integrated into
the health-consumer worktree or a companion release set; no native service test
was executed by this checkpoint.

Implemented repairs:

- The journal reopen bound covers all 128 four-transition lifecycles, including
  maximum record sizes and newlines. Aggregate overflow is rejected before
  append. A real large-record append/reopen fixture exceeds the former 1 MiB
  limit and reopens all completed requests.
- Stop-pending and stopped records cannot change the prior process binding.
  Regression cases alter PID and birth token at each transition.
- Native stop retains no-follow cgroup-v2 directory/control descriptors,
  verifies the original process, sends pidfd TERM, and escalates through the
  held kill descriptor. It reads the held population witness rather than
  trusting a replacement directory or systemd object-path alias.
- A pathname-replacement fixture verifies that membership, kill writes, and
  population reads remain attached to the original files. This is a portable
  file-identity test, not native cgroup enforcement evidence.
- The request deadline reaches native executable hashing and bounds graceful
  and forced cleanup. The real transport fixture uses a bounded 30-second
  authentication window for its large unoptimized test binary, rather than the
  two-second budget used by the tiny executable fixture.
- Failed launch postconditions cannot supply cleanup authority. Wrong-image
  and foreign-cgroup observations retain pending state with no termination.
- Original controls are captured before the initial launch acknowledgement.
  Natural exit and interrupted-stop reconciliation require their empty witness.
  A missing unit or stop-call success without that witness remains uncertain.
  Reopened owners cannot substitute fresh pathnames even for live matching units.
- Durable admission counts every unresolved lifecycle toward the 64-process
  bound. A verified retirement frees one slot without reusing the old nonce;
  an exact duplicate already occupying a slot remains available at capacity.
- Broker creation identity includes a canonical kernel boot UUID and start
  tick. This is independent of the decimal worker-IPC token. Static package
  tests cover the restricted capabilities needed for cross-UID inspection
  and exact signalling; these tests are not native service evidence.

## Earlier same-owner checkpoint

The following 49-test results precede the descriptor-store changes below and are
historical, not exact-source validation of the expanded implementation.

- Focused ledger tests: 5 passed, no failures.
- Final broker module rerun: 49 passed, no failures, 1 explicitly ignored
  native-service test in 9.66 seconds (`cargo test --locked --offline -j1
  -p ascension-watchdog --lib platform::linux_broker`).
- `cargo clippy --locked --offline -j1 -p ascension-watchdog --lib --tests --
  -D warnings`: passed.
- `cargo test --workspace --all-targets --all-features --locked --offline -j1`:
  passed after a 1 minute 58 second compilation. Explicitly gated native tests
  remain skipped; this is not installed-service or reboot evidence.
- `cargo clippy --workspace --all-targets --all-features --locked --offline -j1
  -- -D warnings`: passed in 53.90 seconds.
- `cargo deny --locked check advisories licenses bans sources`: all four checks
  passed. Existing allowed duplicate-version warnings for hashbrown and syn
  remain; no dependency or lockfile change was made in this repair.
- Formatting and diff checks passed.
- Independent source review approved the journal capacity and immutable-binding
  repair. Held-containment review identified the failed-start cleanup issue,
  which was repaired and independently closed. Retirement review identified
  owner-restart pathname reacquisition; the source now requires an existing
  capability, with absent-unit and surviving-unit regressions. Independent
  source review has closed that repair. Boot identity, package capabilities,
  and durable unresolved-capacity additions also received bounded independent
  source approval.
- Independent focused execution: `cargo test --locked --offline --all-features
  -j1 -p ascension-watchdog --lib platform::linux_broker` passed with 49 passed,
  zero failures, and one explicitly ignored native test in 9.88 seconds.

## Descriptor-store integration checkpoint

Source implementation now includes bounded real SCM_RIGHTS transfer, separate
barrier processing, positive root-PID-1 descriptor snapshots, and protected
service-policy preflight. A notification alone cannot acknowledge recoverable
containment. Exact duplicate storage is a state-level idempotence contract.

The native entry point now captures inherited descriptors before other file
opens/threads, validates complete activation metadata and optional pidfd identity,
and matches inherited directory objects against the authenticated manager store.
Policy-compatible committed/stop-pending ledger receipts bind controls recovered
through the original directory descriptor. Unreadable or unbound original
capabilities remain bounded and unauthorized; no mutable unit pathname is adopted.

The standalone Linux-descriptor crate is a narrow native-call exception, not a
workspace lint relaxation. It uses the already locked libc version and introduces
no new external dependency version. Only a fresh F_DUPFD_CLOEXEC result gains
Rust ownership; originals remain CLOEXEC and process-lifetime bounded to 128.
Independent source review found no memory-safety blocker under early, one-shot
intake. File identity, shared-open-description and CLOEXEC tests execute real
Linux syscalls but are not native cgroup/service tests.

Verified terminal retirement now removes the exact manager-store descriptor and
confirms absence. Removal failure leaves terminal state durable and retryable;
read-only inspection and unresolved retirement never remove descriptors.

Independent integration review found a failed-launch cleanup leak after receipt
commit rejection. The repaired path retains local original controls separately
from manager-store acknowledgement, persists an exact pending-to-stop-pending
cleanup receipt, stops only that containment, verifies empty, records terminal
state and removes the descriptor. Failed cleanup-intent persistence prevents
both termination and removal. A foreign same-name descriptor cannot be removed
without an original-object match. Five regressions cover commit rejection after
retention, failed transfer verification, interrupted cleanup/reopen, persistence
failure, and mismatched cleanup bindings. Independent source review closed the
finding with no remaining blocker in this reviewed scope.

Verified descriptor-store/failed-launch checkpoint (before the package-only
start-limit addition below):

- Broker-focused tests: 72 passed, zero failures, one gated native-service test
  ignored, in 10.56 seconds, including the failed-launch repair.
- Linux descriptor helper: four real-file tests passed in 0.03 seconds.
- Strict broker lib/tests Clippy passed in 24.34 seconds after the repair;
  descriptor-helper strict Clippy also passed.
- Full workspace/all-target/all-feature tests passed on the repaired source;
  full strict Clippy passed in 21.20 seconds. Gated native tests remain skipped.
- The narrow descriptor crate's Windows-target strict Clippy passed in 1.78
  seconds. This checks non-Linux cfg behavior, not Windows native execution.
- Dependency advisories, bans, licenses and sources passed. The lockfile adds
  only the local crate and its existing-version dependency edges; known allowed
  hashbrown and syn duplicate-version warnings remain.
- Independent source review covers the state-level FD-store contract, narrow
  FFI boundary, early activation intake and failed-launch cleanup repair.
  Independent final focused execution passed 72 broker tests, zero failures,
  and one native gate ignored in 10.39 seconds. Independent descriptor-helper
  execution passed four tests in 0.02 seconds.

## Explicit broker crash-loop limit

The subsequent broker package adds `StartLimitIntervalSec=600s`,
`StartLimitBurst=5`, and `StartLimitAction=none` in `[Unit]`. Its section-aware
regression also pins failure-only restart and bounded start/stop timeouts.
The focused regression passed; the expanded broker suite passed 73 tests,
zero failures, one native gate ignored, in 10.13 seconds. Strict broker
lib/tests Clippy passed in 7.44 seconds. This is source/static-package evidence,
not installed-manager enforcement or durable cross-boot retry accounting.
Independent source review approved the package placement, section-aware test,
and documented scope without a blocker. No service was installed or started.
Full workspace/all-target/all-feature locked offline tests then passed on this
source, followed by full strict Clippy in 7.05 seconds. Formatting, diff checks,
and all 19 recorded source digests matched. Native service tests remain gated.

## Remaining implementation and verification

- Obtain native descendant-cleanup/restart evidence for the original-capability
  orphan path implemented below. A missing unit remains neither cleanup
  authority nor retirement proof on its own.
- Complete retirement after original cgroup controls have become unreadable,
  and implement verified boot-boundary retirement. Original directory capabilities
  are now preserved/recovered in source, but this has no native restart evidence;
  missing/unreadable population evidence remains uncertain.
- Integrate typed bootstrap, the process adapter and durable ownership into the
  runtime; rerun integrated tests and obtain native systemd evidence on an
  explicitly authorized disposable host.
- This checkpoint does not establish full broker completion, Linux game
  compatibility, Windows service recovery, or companion release readiness.

## Original-capability orphan cleanup

The lifecycle Stop path now handles a missing/inactive/leaderless unit whose
original retained group is still readable and populated. Exact receipt and
current-policy validation precede a durable stop-pending append. The native
backend allows bounded draining, then writes only the held original kill control
and requires its positive empty witness. It does not resolve a leader PID or
replacement unit/path. Empty originals retire without another kill; malformed
or unreadable witnesses, absent capabilities, changed identities and generic
inspection errors remain fail-closed. Typed method-error matching replaces the
former `NoSuchUnit` substring test. Read-only inspection never enters cleanup.

New regressions cover durable orphan retirement/deduplication, read-only
inspection, persistence/population failures before effects, interrupted cleanup
with reopened durable intent, generic inspection errors, changed live identity,
exact typed absence and original-versus-replacement native-backend file effects.
The latter intentionally uses ordinary files: production acquisition rejects
them, and this is not evidence that kernel descendants or a service were killed.

The focused suite passed 79 tests, zero failures, one native gate ignored, in
25.45 seconds. Strict broker lib/tests Clippy passed in 46.03 seconds. Independent
source review found no concrete safety blocker in this bounded path. Final full
workspace/all-target/all-feature locked offline tests passed (1m21s compilation),
followed by full strict Clippy in 30.38 seconds. Independent final focused execution
passed 79 tests, zero failures, one native gate ignored, in 11.25 seconds, including
the native-backend malformed-population and already-empty assertions. All 20
recorded source digests matched.

The final locked offline workspace release build passed in 5m21s. The
watchdog, Linux broker and two synthetic-tool artifact digests are recorded in
`docs/orchestration/linux-broker-repair-20260909.json`. This is a local Linux
build, not an integrated companion release, Windows native build, service
installation or deployment.
Dependency advisories, bans, licenses and sources were rerun afterward and all
passed; existing permitted hashbrown/syn duplicate-version warnings remain.
