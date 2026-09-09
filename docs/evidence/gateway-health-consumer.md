# Gateway health consumer validation

Classification: confirmed focused unit and synthetic TCP evidence; source-derived
protocol review. Daemon wiring is implemented locally; integrated native execution
is not yet verified.

The client performs one bounded loopback HTTP exchange with a fresh challenge,
per-launch monotonic request sequence, request HMAC, and authenticated response.
It sends neither the launch key nor a bearer credential. Response validation
requires the approved deployment, instance, launch nonce, release/config/profile/
schema digests and advancing heartbeat. Closed JSON fields and required nullable
members are checked only after the response MAC succeeds.

The caller must validate retained native child ownership before and after the
exchange. A callback is a contract, not native identity proof: this module does
not implement that validation. Callback execution is deadline-checked afterward,
not preempted. Heartbeat proves response-loop activity, not meaningful application
progress, host readiness, mutation authority, or operation settlement.

Confirmed on 2026-09-09:

```text
cargo test --package ascension-watchdog --lib --test gateway_health --locked -j1 gateway_health
cargo test --package ascension-watchdog --test gateway_health --locked -j1
cargo clippy --package ascension-watchdog --lib --test gateway_health --locked -j1 -- -D warnings
cargo fmt --all -- --check
git diff --check
```

All commands exited zero. The first command ran five focused unit tests; its
integration target had all four tests filtered out. The second command separately
ran all four real-loopback integration tests, with zero failures (0.22 seconds).
These cover authenticated request/response without bearer disclosure, a stalled
heartbeat despite a fresh MAC, signed wrong-release and unauthenticated response
rejection, and trickled headers unable to extend the absolute I/O deadline.

Independent source review found matching producer/consumer HMAC domains, length
prefixes, status encoding, challenge, nonce and sequence. It also checked bounded
HTTP framing, duplicate header rejection, forbidden transfer/compression encoding,
exact content length/EOF, closed JSON, and release identity validation.

The TCP fixture is synthetic and uses public dummy keys. No real gateway process,
native child binding, service installation, game/provider execution, reboot,
activation, or live recovery is proved here. Producer bootstrap cancellation and
daemon/native-adapter integration are separate acceptance gates.

## Windows bootstrap integration checkpoint

The same isolated integration tree now includes the Windows launch adapter's
typed 56-byte health bootstrap and private stdin pipe. Independent production
source review checked suspended creation, explicit reader-only inheritance,
Job containment, pre-resume identity checks, and exact-Job cleanup on errors.
The barrier callback itself is not preemptively deadline-bounded.

Root review corrected two latent fixture defects: a structurally valid UUIDv4
was listed as invalid, and a timestamp mask could produce an overlong UUID.
The native fixture now checks that the child marker is absent inside the
pre-resume barrier, and covers timestamp extremes in its nonce formatter.

The pure bootstrap codec is compiled on all platforms; native launch code stays
Windows-only. The following Linux-hosted command exited zero with five passed
tests, zero failures, and 16 filtered tests (0.02 seconds):

```text
cargo test --locked --offline -j1 -p ascension-platform-windows --lib native_gateway_health_bootstrap
```

These tests cover exact framing, role/nonce/key rejection, decode binding, and
non-secret Debug output. Their launch-spec fixture intentionally omits OS-path
validation, which belongs to the native launcher tests. This is executable codec
evidence, not native pipe, process, Job, service, or daemon-wiring evidence.

## Approved configuration checkpoint

The optional closed `gateway_health` configuration binds a loopback endpoint,
bounded probe deadline, canonical deployment/instance identities, and approved
release/config/profile/schema/executable digests to the gateway launch
environment. Static launch nonces and case-aliased binding environment keys are
rejected; the runtime must generate each nonce and secret afresh.

Gateway and watchdog store references must be separate absolute bounded paths.
Lexical checks reject traversal, pseudo-files and shared references on Linux,
and remote namespaces, alternate streams, dotted aliases and case/separator
aliases of the watchdog store on Windows. These checks do not prove filesystem
identity or reject hard links/reparse points by themselves. Native admission and
store opening still require protected handle-based checks.

On 2026-09-09 this command exited zero, with seven tests passed and none failed
or ignored (0.01 seconds):

```text
CARGO_INCREMENTAL=0 cargo test --locked --offline -j1 -p ascension-watchdog --test gateway_health_config
```

The focused lint and formatting gates also exited zero:

```text
CARGO_INCREMENTAL=0 cargo clippy --locked --offline -j1 -p ascension-watchdog --lib --test gateway_health_config -- -D warnings
cargo fmt --all --check
git diff --check
```

The tests also verify omission preserves default serialization, closed and
duplicate JSON fields fail, binding does not modify the configuration digest,
and validation creates no database. Windows-specific alias regressions are
present but were not executed by this Linux-hosted test run. Configuration
acceptance alone does not prove native launch binding.

## Daemon integration in progress

The daemon now creates fresh nonce-bound health material, persists its non-secret
frame digest and watchdog boot identity before launch, and delivers the key via
the typed native bootstrap. The binding is immutable and requires the exact
prepared gateway intent and durable Running mode. Missing extension schema needs
explicit stopped-owner migration; ordinary startup never repairs it. The new
schema is created during new-store initialization.

Windows admission holds a SQLite writer reservation through ResumeThread. The
Linux helper dispatcher retains the same kind of guard through target exec;
database descriptors must be close-on-exec. A recovered child handle is cleanup
authority only: a health key and sequence state are never reconstructed from
persisted data. Probe callbacks inspect retained native ownership before and
after the authenticated exchange, and failed exchanges retain their consumed
request sequence.

Gateway liveness can veto new worker claims. Authority readiness cannot be a
prerequisite for the harness work that establishes the host fence: a live,
authenticated, non-draining gateway may accept bootstrap/recovery work while
its authority readiness remains blocked. Health never grants mutation authority.
The report preserves readiness, phase, queue, lease and progress diagnostics
without interpreting them as host-effect settlement.

Integrated native child/daemon execution and final full-workspace gates remain
pending. Earlier focused results above are not those broader acceptance gates.

### Explicit maintenance and quarantine follow-up

Run `watchdog migrate gateway-health --config PATH` as the state-directory owner
with the daemon stopped and durable desired mode already Stopped. Use the
currently approved configuration; this command does not approve a changed
configuration or release. It acquires singleton ownership, opens existing state
without automatic schema upgrades, and invokes the transactional health migration.
Running mode, a competing owner, malformed/partial schema, and extra arguments
are rejected. Repeating a completed migration does not duplicate its audit entry.
This offline operation uses OS-protected state access, not a remote admin token.

Fresh worker claims additionally require the durable gateway component state to
be Running. An authenticated heartbeat from a retained quarantined child cannot
override quarantine; absent/unreadable component state also fails closed.
Gateway authority readiness remains a separate downstream concern.

The Linux stdin-failure fixture now snapshots the native shell interpreter and
passes its private test script as the argument. A shebang script cannot reopen
the sealed executable descriptor after its deliberate close-on-exec. The focused
cleanup regression passed after this fixture correction; production descriptor
inheritance policy was not relaxed.

Post-follow-up Linux verification on the frozen source:

- `cargo fmt --all --check`: passed.
- `CARGO_INCREMENTAL=0 cargo test --locked --offline -j1 -p ascension-watchdog
  --lib --test gateway_health_config --test gateway_health_storage
  --test gateway_health`: passed. Library 144 passed, 5 ignored; health transport
  4 passed, configuration 8 passed, storage/CLI migration 5 passed.
- This is not the full workspace gate, Windows-native execution, a service
  installation, or live-host evidence. Configuration/release activation and
  Linux non-escape containment review remain incomplete.

### Native Windows bootstrap checkpoint

Two tests executed on Windows and passed in 0.39 seconds with a captured process
exit code of zero. The synthetic gateway received the exact 56-byte bootstrap
after the admission callback, and its Job-owned child was force-stopped. The
other test checks the fixture nonce format. A fresh restricted execution
directory contained hash-verified test and fixture executables; the outer test
process had a 45-second deadline and a five-second kill/reap allowance.

- Test image SHA-256: `0a0e02fdb401903056d9974e49c65eb76c9538a6a67f7f75ca6af2f7098e8c6a`.
- Fixture image SHA-256: `b1034701ec74cd7e1f6feb13515542b0be404b3ff91b6965c972bb6501396e9d`.
- Build: locked/offline `ascension-platform-windows` test
  `native_gateway_health_bootstrap`, Windows GNU target, dev/test debug information
  disabled. Native execution used `--nocapture --test-threads=1`.

This verifies a native synthetic bootstrap boundary, not Session 0 or an
installed service, an actual gateway HMAC exchange, game recovery, or complete
Windows admission failure coverage. An initial wrapper failed to capture exit
status despite a passing test log; the recorded result is the subsequent run
using a retained process handle. A transient WSL interop failure before staging
is not counted as a test execution.

Full Linux workspace tests and strict Linux/Windows cross-target workspace
Clippy passed before the small explicit-configuration migration guard was added.
The guard's six storage/CLI tests now pass; its final lint check is tracked in
the machine-readable checkpoint. No changes were published or deployed.

### Expanded native and Linux regression checkpoint

The expanded Windows synthetic bootstrap suite passed all four tests in 0.92
seconds, captured exit code zero. Added cases reject admission before target
execution and reject a changed nonce before the admission callback. Exact
planned Job cleanup is checked in both cases. Test image SHA-256:
`f8a0c5b2a38ae36cefa63a25e982dbb9e112bed5d9ee041d54f80ca4f1664921`;
fixture SHA-256:
`7e1e985281515e7fdf80ddb9688ac2787af95e29a1031c7bd02b9f17b6139d75`.
Full Windows cross-target strict workspace Clippy passed on that source.
This remains synthetic user-session evidence, not native service validation.

The subsequent Linux full-workspace run passed strict Clippy but failed the
immediate pipe-reader closure assertion in one library test (143 passed,
1 failed, 5 ignored). That test passed alone. Concurrent forks can retain a
CLOEXEC descriptor until exec; the test now self-executes in a bounded isolated
test process and requires the precise `BrokenPipe` error after both reader
handles are dropped. The updated parallel library suite passed: 144 passed,
0 failed, 5 ignored. Full-workspace strict Clippy and all-target/all-feature tests
subsequently passed with locked offline dependencies after the correction
(combined process exit zero). Formatting, whitespace and checkpoint JSON checks
also passed. Ignored native/service gates remain unverified, not passed.

The pinned `cargo-deny 0.20.2` dependency gate passed advisories, licenses, bans
and sources (`cargo deny --locked check advisories licenses bans sources`, exit
zero). It reported allowed duplicate-version warnings for `hashbrown` and `syn`.

The locked offline workspace release build subsequently passed in 3m34s. Binary
SHA-256 values are recorded in the machine-readable checkpoint; no release was
activated. Independent Windows source review found no blocker and identified a
minor positive-test gap, now corrected by comparing every received nonce byte
with the requested UUID. The reviewer approved that assertion. The strengthened
native four-test suite passed in 0.80 seconds, captured exit zero, using test
image `30a0cc21b7aac3ed50fd886cf673e81aeaf83aa104f56b527239f4431a3ffea0`
and fixture `07ea2da2420922791581828832352c8d5edd4da53cbad7dbcc0c5ce2e96889ee`.

Strict Clippy requested an allocation-free formatting loop for that test
assertion. After replacing the intermediate formatted strings with `write!`,
full Windows cross-target strict workspace Clippy passed and all four native
tests passed again in 0.83 seconds, exit zero. Final test image SHA-256:
`cf524061636a6644269d03968ae231bc417f97b902de40328ec5d22ac13bf11b`;
fixture unchanged. No production code changed during this follow-up.

An independent reviewer then executed the same frozen final images from a fresh
restricted Windows directory. All four tests passed in 0.90 seconds, exit zero,
with empty stderr and retained process-handle verification. Root inspected the
result and stdout files directly. The result JSON SHA-256 is
`c4645656bfbdd1c8ca13ac068ba1e5ab91d1242bd6b54d60306dc1c123e1c386`;
stdout SHA-256 is
`0d12bdc2abc1a42c3050090372a9f930ffd0fb0556406bd9a3860c39a68e9ff5`.
Private execution paths and raw machine metadata remain outside the repository.
