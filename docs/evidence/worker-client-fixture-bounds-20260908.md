# Bounded worker-client fixture verification

Classification: confirmed synthetic local-process/IPC test evidence only.

Source revision: `27000a9a50de419b2f9a38b6bb101ca0000409fc`.
Test file SHA-256: `f67054d7c0237fa90a4b978235a1d996973659f31b0ae2aca70b661f95bbb7c3`.
The fixture now bounds accept to 30 seconds and connected reads/writes to five
seconds. The lost-response fixture explicitly closes its accepted stream before
waiting for the next probe. These are test bounds, not production deadlines.

Commands used the pinned toolchain, locked offline dependencies, an isolated
existing target directory, and `CARGO_INCREMENTAL=0`:

```sh
cargo test --locked --offline -p ascension-watchdog --test worker_client uncertain_dispatch_is_retained_and_never_resent -- --nocapture --test-threads=1
cargo test --locked --offline -p ascension-watchdog --test worker_client -- --test-threads=1
```

Both exited 0. Focused test: 1 passed, 10 filtered, 4.79 seconds execution.
Full test target: 11 passed, 0 failed/ignored/filtered, 87.25 seconds execution.
Formatting and `git diff --check` passed before the source commit.

This result does not validate pending supervisor changes, harness listener
integration, the bootstrap transport, Windows native execution, service recovery,
live gameplay, cold boot, or soak behavior. It is not a full-workspace gate.
An older independently launched test process remained live during this check;
it was not restarted or treated as the source of this passing result.
