# Platform and backup integration check

Date: 2026-09-07. Tested source: `25fa75b`.

This source combines authenticated backup receipt hardening (`c9964a1`) with
Windows pre-execution integrity and cleanup (`eb265e7`) and the clarification
that Job assignment happens during `CreateProcess` (`25fa75b`).

Root independently completed these gates, each with exit status zero:

```text
cargo test --locked --offline --workspace --all-targets --all-features
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

Classification: confirmed Linux build and synthetic test evidence. Windows-only
native test binaries contain zero runnable tests on this platform. The two
Linux tests requiring approved delegated cgroups remain explicitly ignored.
Neither omission is a native-service pass. The separately reviewed Windows
cross-build is not native execution evidence.

No services were installed, releases activated, hosts rebooted, or game/provider
processes launched by these checks. The newer fault-fixture branch is not yet
part of this tested source; its integration requires a separate rerun.

## Full fixture and lease-contract integration

Root repeated all three commands above against `bab3dcb` after adding the
reviewed fault-fixture chain through `8339513` and host-lease reference contract
through `217da28`. All three commands exited zero. The integrated fixture source,
artifacts, conformance inputs, schemas, and runtime/recovery/schema tests match
the reviewed fixture revision exactly; the host-lease test is an additional file.

The fixture suites passed: 8 library, 8 host-lease reference, 13 recovery,
17 runtime transport, and 3 schema tests (49 total). The entire workspace test
command passed as well. The native-service exclusions above remain unchanged.
This is synthetic integration evidence, not production host-lease consumer or
live crash/reboot evidence. Linux distinct-user broker isolation remains open.
