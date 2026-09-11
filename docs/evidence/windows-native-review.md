# Windows native boundary review

Review baseline: `fa15ee641b3e5216d61feba46861ccbcc8e4ff61`
(`codex/watchdog-windows-regressions`).  This is a source review of the
standalone `crates/platform-windows` crate.  No Windows service was installed,
no host/game/provider action was taken, and no native Windows execution was
available in this review.  Linux execution and Windows GNU cross-compilation
are reported separately below; neither is live Windows evidence.

The classifications below are review severity, not proof of exploitability in
every deployment.  Where the result depends on the service account, ACLs,
desktop topology, or filesystem permissions, that dependency is called out.

## Findings

### 1. P1 — role and session policy are conflated

**Source anchors.** `crates/platform-windows/src/contract.rs:183-197` gives
every role the same `SessionSelector`; `:245-251` rejects `Explicit(0)` for
every role.  `crates/platform-windows/src/native.rs:331-354` then treats every
selected session identically, including the comment that HostBroker follows
the same explicit policy.

**Evidence and impact.** Windows services run in session 0, while an interactive
desktop host belongs in an active user session.  The public contract has no
background/service selector and rejects the only session that a service-owned
background component can target.  It therefore cannot express a safe policy
that permits Gateway/Harness background work while requiring HostBroker to use
an interactive desktop.  `background_roles_can_target_service_session_zero`
is a portable regression assertion and is expected to fail on this baseline.
This is a contract-level conclusion; no Windows launch was performed.

### 2. P4 — owner-death cleanup is only partially exercised

**Source anchors.** `crates/platform-windows/src/native.rs:402-421` creates a
named Job Object and sets `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.  Reopen is
implemented at `:194-245`, but the existing native test only reopens while the
original owner is still alive (`crates/platform-windows/tests/native_synthetic.rs:145-161`).

**Evidence and impact.** Closing the last job handle is the intended fail-stop
behavior: it terminates the contained processes.  The existing test proves
reopen with two simultaneous handles, not that descendants terminate when the
owner process itself exits.  The ignored
`native_owner_death::windows_owner_death_terminates_owned_child` test uses a
subprocess helper to close the owner process and observes the exact child's
creation identity until it exits; it requires an interactive Windows session
and is not run by default.  This is an evidence gap, not a claim that
`KILL_ON_JOB_CLOSE` should be removed or that owner-death adoption is required.

See [Microsoft's Job Object documentation](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
for the documented containment/close semantics.

### 3. P1 — path equality is not executable identity or a TOCTOU defense

**Source anchors.** `ProcessIdentity` stores a path but no digest or immutable
file identity (`crates/platform-windows/src/contract.rs:173-181`), and
`WindowsLaunchSpec` likewise has no expected digest (`:183-197`).  Launch only
canonicalizes and compares paths (`crates/platform-windows/src/native.rs:317-326`;
canonicalization is `:1113-1126`); reopen verifies PID, creation time, and
normalized image path (`:248-267`).

**Evidence and impact.** A path can be replaced, redirected, or have its
dependent files changed after canonicalization and before/during process
creation.  The recorded identity cannot prove that the approved release bytes
were launched, and reopen cannot detect a same-path replacement beyond the
process creation token.  A release digest plus a handle-based file identity
check (and a policy for dependent DLLs) is required.  This is a source-level
gap; filesystem replacement was not attempted.

### 4. P1 — named-pipe peer authentication is optional and not wired to config

**Source anchors.** `authorized_peer_executable` is merely required to be an
absolute path by `crates/platform-windows/src/contract.rs:256-294`; it is not
passed into the pipe server.  `NamedPipeServer::accept` captures a peer at
`crates/platform-windows/src/native.rs:636-674`, while
`authenticate_peer` is a separate caller-invoked method at `:677-700`.
`read_request` consumes frames without calling it at `:703-723`.

**Evidence and impact.** Any caller holding a connected server object can call
`read_request` before authentication, and there is no API tying the expected
executable to `WindowsPlatformConfig`.  The owner-only ACL is a user boundary,
not a substitute for mandatory protocol authorization; its sufficiency also
depends on the service account and intended peer account.  Lifecycle control
must make authentication a state transition required before reads and bind it
to an approved executable identity/digest and session.  This conclusion is
from the public call graph; no pipe client was run.

### 5. P1 — lifecycle frames have no replay protection or capabilities

**Source anchors.** `LifecycleRequest` contains only Start, Stop, and Heartbeat
fields (`crates/platform-windows/src/contract.rs:30-49`), and validation checks
only IDs (`:51-80`).  `read_request` decodes each frame independently
(`crates/platform-windows/src/native.rs:703-723`); `write_request` sends the
same request shape as an acknowledgement (`:725-741`).

**Evidence and impact.** Start/Stop carry no request nonce, epoch, or
monotonic sequence, and Heartbeat's sequence is never compared with prior
state.  There is no capability or operation authorization attached to a frame.
An authenticated peer can replay an old Start/Stop or send a frame from a
different lifecycle epoch unless a consumer outside this crate adds a separate
fence.  The native boundary exposes no such required state, so this is a P1
protocol gap rather than a claim that every current consumer is exploitable.

### 6. P1 — message-mode reads can block reconciliation indefinitely

**Source anchors.** The endpoint is synchronous message-mode/`PIPE_WAIT`
(`crates/platform-windows/src/native.rs:614-623`), and `accept` blocks in
`ConnectNamedPipe` (`:636-646`).  `read_request` calls the unbounded-in-time
`read_exact` twice (`:703-723`); `read_exact` loops on synchronous `ReadFile`
without a deadline or cancellation (`:1007-1035`).

**Evidence and impact.** A peer can connect and send only part of the four-byte
length or payload, pinning the caller in `ReadFile` and preventing bounded
reconciliation.  In message read mode, a buffer smaller than a message can
also produce `ERROR_MORE_DATA`; this implementation does not drain a message
or use an overlapped/cancellable operation.  The frame size limit bounds the
allocation, but not the time spent waiting for bytes.  No adversarial pipe
client was run.

See [Microsoft's named-pipe message-mode documentation](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-type-read-and-wait-modes)
and [ReadFile documentation](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile)
for the message and synchronous-read behavior.

### 7. P1 — user-token launch does not select an interactive desktop

**Source anchors.** `spawn_suspended_with_job` initializes only `cb` and the
attribute list (`crates/platform-windows/src/native.rs:481-489`), then calls
`CreateProcessAsUserW` with that startup structure (`:494-508`).  No
`lpDesktop`/window-station selection or desktop-access setup appears in the
launch path.

**Evidence and impact.** `CreateProcessAsUserW` launched from a service needs
an appropriate interactive window station/desktop when the target is a GUI
host.  Without an explicit desktop and its access policy, a process can start
in a noninteractive/default service desktop or fail to create a usable window;
the user-token branch therefore does not prove graphical host launch.  See
[Microsoft's CreateProcessAsUser documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw).
This is an API-path review finding; no desktop launch was available.

### 8. P2 — SCM health recovery only requests STOP and has no bounded status path

**Source anchors.** Installation configures two restart actions (`crates/platform-windows/src/native.rs:807-826`), but
`ScmHealthChecker::request_recovery_if_stale` opens only STOP/QUERY_STATUS
access and calls `stop()` (`:841-870`); it never starts/restarts or waits for a
settled state.  The service entry reports Running and then Stopped around the
unbounded callback (`:919-945`) without STOP_PENDING/checkpoint/wait-hint
progress.

**Evidence and impact.** A stale heartbeat causes a stop request, not a
verified recovery.  Failure actions apply to service failure, not necessarily
to a clean SCM stop, and this API does not establish that the service reached
Stopped or returned to Running.  A slow reconciliation callback also gives SCM
no bounded stop progress.  The result is an availability/evidence gap rather
than proof that SCM restart actions never work in a particular installation.

The code also does not configure the SCM failure-actions flag described by
[Microsoft's `SERVICE_FAILURE_ACTIONS_FLAG` documentation](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actions_flag),
so the intended restart behavior needs an explicit live-service check.

### 9. P2 — reopen does not verify persisted session/owner policy or job limits

**Source anchors.** `JobOwnedProcess::reopen` opens only the name derived from
the caller-supplied nonce and checks active count (`crates/platform-windows/src/native.rs:194-245`).
`verify_identity` checks PID, creation time, and executable, but not
`ProcessIdentity.session_id` (`:248-267`).

**Evidence and impact.** The `max_processes` argument is compared with the
current active count, not the Job Object's configured limit, and the reopened
record is not checked against the persisted session or a role/owner binding.
The named object ACL still controls who can open it, but a caller with that
authority can supply a nonce/identity pair without this method proving the
session and configured containment policy.  This is a source-level hardening
gap; no forged identity or cross-session launch was attempted.

### 10. P2 — partial pipe acceptance and service installation leave cleanup gaps

**Source anchors.** After `ConnectNamedPipe` succeeds, `accept` can return an
error from PID/session lookup, `OpenProcess`, or image lookup before setting a
recoverable connected state (`crates/platform-windows/src/native.rs:644-674`),
and it does not call `DisconnectNamedPipe` on those paths.  Installation creates
or opens a service and mutates its configuration in stages (`:796-805`), then
updates failure actions (`:807-827`) without rollback or delete-on-partial-failure.

**Evidence and impact.** A failed peer probe can leave the one-instance pipe
connected and unable to accept the next client.  A later service configuration
failure leaves a partially changed SCM record.  Both need explicit cleanup and
unknown-outcome reporting.  No pipe or SCM mutation was performed in this
review.

### 11. P2 — aggregate launch bounds, environment policy, and loader policy are missing

**Source anchors.** The contract limits count and each argument/value separately
(`crates/platform-windows/src/contract.rs:6-11,214-235`), while launch builds
the complete command line and environment without a total check
(`crates/platform-windows/src/native.rs:437-450`).  The environment builder
accepts all caller-supplied names/values and only checks NUL/equal syntax
(`:1244-1262`).  The startup path has no DLL search restriction
(`:481-508`).  Finally, `WindowsLaunchSpec` derives `Debug` over its full
environment (`crates/platform-windows/src/contract.rs:183-197`).

**Evidence and impact.** Eight individually valid 8 KiB arguments or values
can produce a command line/environment far larger than the intended bounded
launch surface.  Arbitrary environment variables can alter child runtimes,
and absent safe DLL-directory policy leaves dependent-module loading dependent
on executable/current-directory state.  A secret environment value is also
printed by `Debug`, violating the no-secrets-in-logs boundary.  The three
portable regression tests
`aggregate_command_line_arguments_are_rejected_before_process_creation`,
`aggregate_environment_block_is_rejected_before_process_creation`, and
`launch_spec_debug_does_not_expose_environment_values` are expected to fail on
this baseline.  See [Microsoft's CreateProcess documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
for the platform command-line/environment constraints.

### 12. P4 — the native synthetic test reports headless as success

**Source anchors.** `crates/platform-windows/tests/native_synthetic.rs:97-105`
maps `WaitingForSession` to a skip message, and
`:114-118` returns `Ok(())` when no interactive session is available.

**Evidence and impact.** A headless Windows runner can report a green native
test result without exercising launch, Job Object containment, crash/restart,
or cleanup.  The result is an evidence gap, not a product exploit.  Native
tests should be explicitly ignored with documented prerequisites or report a
distinct skipped/unverified outcome; they must not turn unavailable host state
into pass evidence.

## Regression and validation evidence

The new test file is intentionally limited to portable contract assertions plus
one explicitly ignored Windows subprocess test.  The four portable tests are
expected failures against this review baseline because they assert the required
post-fix contract.  The owner-death test is not part of the default run and
must be invoked by an operator on an approved interactive Windows test host.

Commands run from this worktree:

This standalone baseline has no committed `Cargo.lock`; Cargo generated a
temporary crate lockfile for the locked checks below.  It was removed before
the evidence commit, so it is not part of the reviewed change.

```text
rustup run 1.97.1 cargo fmt --manifest-path crates/platform-windows/Cargo.toml -- --check
  PASS (format check)

rustup run 1.97.1 cargo test --manifest-path crates/platform-windows/Cargo.toml --lib
  PASS (portable library tests)

rustup run 1.97.1 cargo test --manifest-path crates/platform-windows/Cargo.toml --test windows_safety_regressions
  EXPECTED FAIL: 4 portable safety assertions fail on fa15ee6

rustup run 1.97.1 cargo test --manifest-path crates/platform-windows/Cargo.toml --test windows_safety_regressions --no-run --target x86_64-pc-windows-gnu --locked
  PASS (Windows GNU cross-compilation; no execution)

rustup run 1.97.1 cargo check --manifest-path crates/platform-windows/Cargo.toml --target x86_64-pc-windows-gnu --locked
  PASS (Windows GNU cross-compilation; no execution)

rustup run 1.97.1 cargo clippy --manifest-path crates/platform-windows/Cargo.toml --all-targets --target x86_64-pc-windows-gnu --locked -- -D warnings
  PASS (Windows GNU cross-compilation; no execution)
```

The native owner-death test was not executed here.  Its bounded invocation is:

```text
rustup run 1.97.1 cargo test --manifest-path crates/platform-windows/Cargo.toml \
  --test windows_safety_regressions \
  native_owner_death::windows_owner_death_terminates_owned_child \
  -- --ignored --exact --nocapture
```

That command requires an approved interactive Windows session and must be
reported as native execution only when the test actually runs there.  The
portable regression failures and the cross-compile results do not establish
Windows service, desktop, SCM, ACL, reboot, or live-host evidence.
