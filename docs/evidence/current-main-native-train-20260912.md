# Current-main native worker smoke on Train — 2026-09-12

Classification: `native Linux process-boundary pass; release not activated`.
This is current-source native evidence for the watchdog-to-harness worker
boundary. It is not an installed service, live game/provider execution,
live-host recovery, reboot/cold-boot, activation/rollback, or completed-soak
result.

## Exact inputs

The native smoke used the admitted source-set product revisions:

- `ascension-watchdog`: `f6b15a355688a86b1219cde570a9a6b1063ae78a`.
- `sts2-harness`: `64ce7d03a01e568db1de20d0316c1d03fec77812`.

Fresh, separately built and guest-side hash-verified binaries were staged in a
new owner-local directory with mode `0500`:

| Image | SHA-256 |
| --- | --- |
| Watchdog | `b6d01639aefd239cf698374619f8f28a53fa723b957a1320944b7a0bb0892059` |
| Harness runtime | `21e1f9f4746b4a8dd4e41cc23269f95814fe970b777824645283944ee92bcc42` |
| Native smoke test | `177f4cf6425a95b08065a85f51dd5f132c25785fb77c12b23cb192b9bb6020d4` |

The supplied Linux guest was Ubuntu 24.04 with an active unprivileged user
systemd manager and cgroup-v2 user scope. The test ran through its explicit
`ASCENSION_WATCHDOG_REAL_HARNESS_SMOKE=1` gate as that user, with a 150-second
outer bound. It did not install a system service or change the guest's boot
configuration.

## Result

`real_watchdog_native_launch_reaches_built_harness_worker` passed:

```text
1 passed; 0 failed; 0 ignored; 5 filtered out; 58.80 seconds
```

The test exercised the real watchdog process manager and staged runtime image,
authenticated worker control/admission, one durable dispatch handoff, durable
`Stopped` intent, daemon/worker exit, endpoint removal, cleared process
identity, and retained handoff validation. The stage and captured test result
were retained for inspection.

Its gateway is the test's bounded loopback HTTP-503 fixture and its MCP input
is `/usr/bin/true`; no gameplay or provider settlement was attempted. The
result therefore does not close cross-consumer live-host recovery, installed
systemd/SCM behavior, cold boot, release activation/rollback, or the required
full-duration soak.
