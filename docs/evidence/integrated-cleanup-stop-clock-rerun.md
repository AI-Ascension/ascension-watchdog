# Integrated cleanup, stop and clock rerun

Classification: confirmed Linux synthetic/component execution, not native
service, live-host, reboot or soak evidence.

Root reran the integration source at `9ae0aef`. The subsequent `12fb770`
changes orchestration records only. Pending P7 process-group commits were not
present in these tests.

| Command | Result |
| --- | --- |
| `cargo test --locked -p ascension-watchdog --test process_cleanup` | exit 0; 1 passed |
| `cargo test --locked -p ascension-watchdog --test job_submission_process --test launch_stop --test clock_regressions` | exit 0; 9 passed |

The first command executes the real reconciler with an injected identity-write
failure and proves the spawned child's cleanup using a separate PID witness.
This supersedes the stale null-PID test failure reported from the P7 author base.

The second command covers backward/forward clock handling and durable restart
budgets (3), real CLI/daemon submission and protected-payload/descendant cleanup
(4), and persisted nonrunning launch intent plus explicit resume (2).

These focused passes do not resolve the separately reviewed P7 timeout paths,
prove a complete workspace gate, or establish cross-repository recovery.
