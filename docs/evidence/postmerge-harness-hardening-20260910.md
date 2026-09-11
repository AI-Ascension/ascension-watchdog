# Post-merge harness endpoint hardening — 2026-09-10

Classification: `confirmed native Linux process-boundary evidence; not a live
release or gameplay acceptance`. This addendum supersedes the earlier endpoint
image reference in the Wave 48 evidence records without changing their
historical source identities.

Harness PR #66 hardening was committed at
`58dede2eb661133d8910a1f785e8a90346efe8dd` and then auto-merged after green
hosted checks as main merge commit
`a0ace6712686cb30d6f0b556cb6814ad4c0721d1`. The feature added true bootstrap
EOF enforcement, bounded authentication slots and deadlines, and a sealed
runtime-image snapshot so a later pathname replacement cannot change the image
used for a child launch.

Hosted checks for the exact feature head passed:

- Rust quality gates: run `34542578041`.
- Repository policy: run `34542578085`.

The watchdog's explicitly gated native test was rerun against a release binary
built from that hardening source:

```text
ASCENSION_WATCHDOG_REAL_HARNESS_SMOKE=1
STS2_HARNESS_RUNTIME_BINARY=/home/timot/sts2-harness-runtime-endpoint-image-hardening
STS2_HARNESS_RUNTIME_SHA256=5286706d03c27c00e32493c1adf8864e972f7a53d1f863c046aed32d56a1644f
cargo test --offline --locked -p ascension-watchdog --test real_harness_worker -- \
  --ignored --exact real_watchdog_native_launch_reaches_built_harness_worker --nocapture
```

Result: `1 passed, 0 failed, 0 ignored; 25.33s`. The run demonstrates the
native Linux watchdog-to-harness bootstrap, peer/authentication checks, control
exchange, one durable dispatch admission, persisted stop, and owned cleanup.
The gateway was an HTTP-503 fixture and the MCP child was `/usr/bin/true`; no
gameplay, provider settlement, installed service, release activation, reboot,
or soak claim follows from this test.

The image is owner-local and retained outside the repository at mode `0500`.
Its digest was recomputed before the run and is the digest recorded above.
