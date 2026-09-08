# Linux PID-namespace synthetic validation

Classification: confirmed Linux/WSL synthetic process-runner evidence. This is
not native service, Windows, live-host, reboot, or soak evidence.

Base commit: `76daced0642beddf9106a798137ebf9224744978`
Implementation branch: `codex/watchdog-pid-namespace-reaper`
Runner: `crates/watchdog/examples/synthetic-test-reaper.rs`

## Runner contract

The test-only runner must be started as PID 1 with a private `/proc`, using a
fresh user and PID namespace. It rejects ordinary execution, an inherited
`/proc`, or a namespace whose PID descriptors do not match. Once admitted, it
uses rustix `wait(WNOHANG)`, not process-group-scoped `waitpid(None)`, so a
`setsid` descendant is still reaped. A target exit is not sufficient by
itself: the runner requires the target status, a quiet private-`/proc`
interval, and no remaining namespace child. Workload and drain deadlines are
bounded. The runner sends no signals; a timeout exits namespace init, allowing
Linux to terminate only that namespace's children.
The root review correction caps the workload at 3,600,000 ms and descendant drain
at 60,000 ms; zero and larger values fail before any child is launched. Defaults
remain 300,000 ms and 5,000 ms. This is a short synthetic runner, not the soak runner.

## Executed checks

All commands ran from the implementation worktree with the locked offline
dependency set.

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | exit 0 |
| `cargo test --locked --offline -p ascension-watchdog --example synthetic-test-reaper` | 3 passed, 0 failed |
| `cargo clippy --locked --offline -p ascension-watchdog --example synthetic-test-reaper -- -D warnings` | exit 0 |
| `cargo build --locked --offline -p ascension-watchdog --example synthetic-test-reaper` | exit 0 |

The ordinary, non-namespace invocation was also checked:

```text
target/debug/examples/synthetic-test-reaper -- /bin/true
exit 125: synthetic test reaper must run as PID 1 in its namespace
```

## Namespace process probes

Each probe used:

```text
unshare --user --map-root-user --pid --fork --mount-proc \
  target/debug/examples/synthetic-test-reaper \
  --workload-timeout-ms=10000 --drain-timeout-ms=1000 -- <target> <args>
```

Results:

- `/bin/sh -c 'exit 7'`: exit 7, preserving the target failure status.
- `/bin/sh -c 'sleep 0.05 & exit 0'`: exit 0, reaping an adopted ordinary
  descendant.
- `/bin/sh -c 'setsid /bin/sh -c "sleep 0.05" >/dev/null 2>&1 & exit 0'`:
  exit 0, reaping a detached process-group/session descendant.
- `/bin/sh -c 'sleep 30 & echo $! > <marker>; exit 0'` with
  `--drain-timeout-ms=200`: exit 125. The marker is a namespace PID and cannot
  establish host-PID absence by indexing host `/proc` directly. That original
  absence claim is withdrawn. Independent W44 validation instead matched the
  child namespace and `NSpid` mapping (namespace PID 3, host PID 143369), then
  observed `/proc/143369` absent after teardown. No signal was issued by the runner.

Independent W44 reviewed exact source commit
`9741b8fde228cee5fac224ab5cfbaf5cfe55e6ca`, not only its base. The original reviewed
source SHA-256 was `a04c8bc80f9d8e59398e60e6d4905da7a3cef7f03789617971c873b87639c55f`;
the reviewer's built runner SHA-256 was
`645efd91aa17c42385ee15d2a012b96326bcf6b9b9a6ebb3fbae1eaaa9c27ac0`.
These hashes describe the pre-timeout-cap review, not rebuilt correction bytes.

## Root timeout correction validation

The corrected runner source SHA-256 is
`81a1372e62fdf74038ec466a2d1ad3a28da2f973c8c5e055920106da3c1edce1`;
the rebuilt debug runner SHA-256 is
`871f3c3571bad63865118e094b9c50cbd5338c0d4766dcff1c443a069847040e`.
These identify the timeout-cap correction over integration base `c7d2d0c`.

Root validation passed formatting, locked/offline workspace all-target/all-feature
Clippy with warnings denied, and the locked example build. The corrected example
has four passing unit tests, including exact timeout bounds and rejection of zero
and overflowing values. Namespace probes preserved exit 7 and reaped a detached
`setsid` descendant; an oversized drain timeout rejected with exit 125.

Workspace tests were partitioned because broker fixtures intentionally reject
mapped-root peer identity. Ordinary execution passed workspace library, binary,
and example tests with all features (watchdog: 77 passed, two delegated-cgroup
tests ignored; runner: four passed), all 26 other watchdog integration targets,
and all-target/all-feature platform-Windows and fault-fixture package tests.
The three process integration targets `adversarial_core`, `process_cleanup`, and
`launch_stop` passed together in the private PID namespace: 10, one, and two tests
respectively. Ignored cgroup tests and native Windows-only paths are not verified
by these results. This is partitioned synthetic coverage, not a claim that one
unqualified whole-workspace invocation passed inside the namespace.

## Unchanged watchdog suites

The requested suites were run unchanged inside the fresh namespace:

```text
unshare --user --map-root-user --pid --fork --mount-proc \
  target/debug/examples/synthetic-test-reaper \
  --workload-timeout-ms=300000 --drain-timeout-ms=5000 -- \
  cargo test --locked --offline -p ascension-watchdog \
  --test adversarial_core --test process_cleanup
```

Result: `adversarial_core` 10 passed, 0 failed; `process_cleanup` 1 passed,
0 failed. The test safety-net `kill` calls reported expected `No such process`
for children already cleaned by the implementation; no test was modified or
skipped.

Additional unchanged process-adjacent checks passed separately:

- `cargo test --locked --offline -p ascension-watchdog --test launch_stop`:
  2 passed, 0 failed, in the namespace.
- The ordinary (non-namespace) daemon/CLI process test
  `actual_daemon_and_cli_processes_submit_complete_reopen_replay_and_deny_read`:
  1 passed, 0 failed. Its run under the mapped user namespace was not used as
  acceptance because the daemon exited during startup; the namespace runner
  and the requested cleanup suites remained passing.

An exploratory `--lib` invocation was not an acceptance gate: 14 broker unit
fixtures reject a mapped-root peer as non-distinct, while 62 unrelated unit
tests passed. No production source, manifest, lockfile, or normative file was
changed for this runner.
