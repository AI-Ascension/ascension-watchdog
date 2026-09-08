# Worker client namespace and pipe-mode correction

The Windows worker consumer now uses `AdminPipeClient::connect_worker`, a
separate connection profile for local `ascension-worker-<UUIDv4>` byte pipes.
Admin connections and servers retain their existing namespace and message mode.
No credential, frame, schema, or gameplay-authority contract is widened.

The previous consumer selected the admin profile, which rejected the worker
namespace and requested message-read mode on a byte-type server. These prevented
the intended cross-consumer connection before worker authentication.

## Confirmed bounded native evidence

On 2026-09-08 the Windows GNU platform test executable passed:

- `worker_and_admin_namespaces_remain_separate`: one test, 24 filtered out.
- `worker_client_exchanges_frames_with_byte_pipe`: one test, 25 filtered out.

The latter creates an owned local byte-mode test pipe, connects through the real
worker client method with its expected executable path, and checks length-prefixed
request and response bytes. Both runs exited zero. This is a same-process native
transport test, not a watchdog-to-harness authentication or service test.

Commands:

```text
cargo test --locked --offline -p ascension-platform-windows --target x86_64-pc-windows-gnu --lib --no-run
cargo clippy --locked --offline --workspace --all-targets --target x86_64-pc-windows-gnu -- -D warnings
cargo fmt --all --check
```

Run the resulting executable on Windows with each test name and `--nocapture`.
The listed build, Windows-target Clippy and formatting checks passed. Linux
`cargo test --locked --offline --workspace --all-targets --all-features` exited
zero, including the worker client, storage, recovery, runtime and schema suites.
Explicitly ignored cgroup-dependent tests were not run and remain unverified.
Linux `cargo clippy --locked --offline --workspace --all-targets --all-features
-- -D warnings` also passed. Neither Linux result is native Windows proof.

## Remaining gates

The worker path still needs approved server SID/session checks and held immutable
image validation before credential release. Do not infer complete peer security
from PID, creation time, path comparison, or hashing a replaceable pathname.
Cross-consumer authenticated exchange, independent review, native fault coverage,
services, reboot and live recovery remain unverified for this client correction.
