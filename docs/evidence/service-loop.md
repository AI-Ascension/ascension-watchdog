# Watchdog loop health integration

Classification: confirmed Linux subprocess integration; native systemd service
installation, SCM recovery, child phase health, live host and reboot unverified.

The `watchdog daemon` command now runs `ServiceLoop`. It advances the shared
health sequence only after `Supervisor::reconcile_once` succeeds. Database or
singleton failure leaves readiness false and does not advance that sequence.
The actual daemon thread emits systemd READY/WATCHDOG notifications after this
completed iteration and STOPPING after durable stop and verified child cleanup.
There is no timer thread issuing watchdog notifications. A healthy paused or
blocked controller remains observable; watchdog-loop readiness is explicitly not
game, gateway, harness, provider, or mutation readiness.

`crates/watchdog/tests/service_loop.rs` verifies:

- paused loop progress without child starts;
- repeated status reads cannot advance the heartbeat;
- competing ownership cannot become ready;
- injected audit persistence failure cannot advance completed-loop health;
- an actual `watchdog daemon` subprocess sends READY/WATCHDOG then STOPPING to a
  real Unix datagram receiver after a stopped reconciliation.

Commands executed using Rust 1.97.1 and locked dependency resolution:

```sh
cargo +1.97.1 test --locked -p ascension-watchdog --test service_loop
cargo +1.97.1 clippy --workspace --all-targets --locked -- -D warnings
cargo +1.97.1 fmt --all --check
```

Targeted tests: 4 passed, 0 failed, 0 ignored. Strict workspace Clippy passed.
No OS service was installed or restarted. The datagram receiver is a test of
the actual daemon notification path, not proof of systemd recovery or a soak.
Authenticated admin dispatch and native process adapter integration are separate
gates still being implemented. Foreground daemon exit-on-stop behavior is retained.
