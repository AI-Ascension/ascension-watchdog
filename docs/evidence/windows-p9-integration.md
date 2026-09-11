# Windows containment P9 integration

Classification: source-derived repair; confirmed portable tests and Windows
cross-compilation. Native Windows process/service execution is unverified.

Root reviewed and integrated author commit `1ea7c8a` as `4a2d977`.
The repair checks Job Object active membership rather than leader liveness
before declaring cleanup complete. Prepared recovery opens only the exact
nonce-derived Job, verifies owner and configured limits, and performs bounded
termination. Access and query failures remain uncertain; only explicit
missing-object errors prove absence.

Root reran on the integrated source:

- `cargo test --locked -p ascension-platform-windows`: exit 0; eight portable
  tests passed. Windows-only transport and native synthetic tests ran zero
  tests on Linux and are not passes for native behavior.
- `cargo check --locked -p ascension-platform-windows --all-targets --target x86_64-pc-windows-gnu`:
  exit 0, including Windows test source checking.
- `cargo fmt --all --check`: exit 0.

Remaining gates include the runtime caller wiring for prepared cleanup,
independent native-boundary review, and actual authorized Windows synthetic
execution. No service was installed, host rebooted, or release activated by
this validation.
