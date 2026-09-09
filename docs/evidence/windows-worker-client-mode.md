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

## Remaining gates at the initial correction

The worker path still needs approved server SID/session checks and held immutable
image validation before credential release. Do not infer complete peer security
from PID, creation time, path comparison, or hashing a replaceable pathname.
Cross-consumer authenticated exchange, independent review, native fault coverage,
services, reboot and live recovery remain unverified for this client correction.

## Connected worker identity follow-up, 2026-09-09

Source-derived: the worker client now checks the retained server process for
exit and re-queries the connected pipe server PID during identity validation.
Frame reads and writes revalidate identity; the watchdog transport validates the
configured server account/session before reading its credential. Protected-image
ancestor inspection and pipe waiting share the connection's absolute deadline.
The admin connection profile retains its existing timeout and message mode.

Independent source review passed for the integrated `admin_pipe.rs` bytes with
SHA-256 `db8fefcd870f4a1273e406db70e3e755e3543502633afcf6c586bf7a4f98c05c`.
New regression cases exercise expired connection budgets, submillisecond wait
conversion, exited/changed server observations, and failed-wait error reporting.

Confirmed integrated checks:

```text
cargo fmt --all -- --check
git diff --check
cargo clippy --locked --offline -j 1 -p ascension-platform-windows -p ascension-watchdog --all-targets --all-features --target x86_64-pc-windows-gnu -- -D warnings
cargo test --quiet --workspace --all-targets --all-features --locked -j1
```

These checks exited zero. The workspace test run is Linux synthetic evidence;
explicitly ignored native gates did not run, and Windows-only tests are
platform-filtered on Linux. Native execution of this follow-up has not run;
the earlier native results above do not validate the changed implementation.
Cross-consumer authentication, native process-race coverage, installed service,
reboot, and live recovery are not established by this follow-up.
