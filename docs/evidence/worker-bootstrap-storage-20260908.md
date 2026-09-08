# Worker bootstrap launch-binding storage

Classification: confirmed storage implementation and focused native execution;
producer/consumer launch integration remains unverified.

Base revision: `4e10f6594bb5eb3c6c906567a4e362fb19ff4ed5`.

The extension binds a validated bootstrap frame digest and watchdog boot to one
prepared component/launch nonce. Binding and audit are atomic, repeated identical
binding is idempotent, and durable stop prevents new binding. The explicit library
migration requires the matching owner lock and stopped mode, does not backfill old
intents, and refuses partial or changed installed schema. Frozen DDL validation
includes the actual immutability-trigger body, not merely its name.

Focused command:

```text
cargo test --locked -p ascension-watchdog --test worker_bootstrap_storage
```

Result: exit 0; five tests passed on Linux, none ignored. Coverage includes reopen,
replacement rejection, stop, wrong migration owner, partial schema, same-name
no-op trigger, late binding, update rejection, idempotent audit counts, and injected
audit failures rolling back binding or the entire migration.

Windows build command:

```text
cargo test --locked -p ascension-watchdog --target x86_64-pc-windows-gnu --test worker_bootstrap_storage --no-run
```

The resulting executable was copied to a fresh Windows temporary directory and
executed natively with `--test-threads=1`: exit 0, five passed, none ignored,
1.56 seconds. Executable SHA-256:
`848e3b24cf548a85eb917003bfbc68a531442b6026f2e9d075f7a28eb71b22a8`.
No service was installed or changed by these storage tests.

Strict Linux workspace/all-target/all-feature Clippy and Windows-target library
plus focused-test Clippy passed with `--locked` and `-D warnings`. An initial
Linux lint failure for a needless borrow in a new test was corrected and rerun.
Formatting and `git diff --check` passed after formatting that correction.

The final source also passed `cargo test --locked --workspace --all-targets
--all-features` and `cargo build --locked --workspace` (both exit 0). The workspace
run includes the owner-published bootstrap schema/conformance test. Platform-gated
zero-test Windows binaries and ignored Linux privileged tests in this run are not
native platform passes; the separate five-test Windows execution above is the
native evidence for this storage change.

Validated source SHA-256 values:

| File | SHA-256 |
| --- | --- |
| `crates/watchdog/src/storage.rs` | `ee5936f218454160a4553c3ce63e8a3cb729b37ab29326900717d7ccee297176` |
| `crates/watchdog/src/storage_worker_bootstrap.rs` | `d4d68924d99b8fcdbd73741dfc4e59fad28281c12385020bb7c48caa33991464` |
| `crates/watchdog/tests/worker_bootstrap_storage.rs` | `a05369c8c716752f7c8a3294ffab904e1a8ff721d8e9113919136604a6c59422` |

Independent review found that the initial binding double-hashed the frame because
the existing `hex_digest` helper already hashes its input. This was corrected to
hash the encoded frame directly, with an independent SHA-256 regression. Review
of that correction and the five-test independent rerun passed. The initial native
executable hash is superseded by the corrected run above. The independent test
oracle was also adjusted for the pinned digest array's lack of `LowerHex` and the
strict hex-formatting lint; final Linux/Windows lint and native reruns passed.

This change does not wire an operator migration command, launch producer,
anonymous-pipe inheritance, or harness consumer. It does not establish Windows
service, live-host recovery, cold boot, release activation, or soak success.
