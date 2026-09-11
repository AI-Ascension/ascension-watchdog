# Worker endpoint namespace validation — 2026-09-08

Scope: the launch-specific endpoint selection change on
`codex/watchdog-client-process-candidate`, based on
`3cd7a693b0ed06ce485e9cad71ba787f1af7f954`. This is component evidence, not
native watchdog-to-harness bootstrap integration or service validation.

## Confirmed focused checks

- `cargo fmt --all --check`: passed.
- `cargo test --locked -p ascension-watchdog --test worker_config --test worker_endpoint --test runtime_worker`:
  19 Linux tests passed. Covers closed legacy-field rejection, exact nonce-specific
  paths, absent/current/prior worker endpoints, and preserved owned-stop cleanup.
- `cargo clippy --locked -p ascension-watchdog --lib --test worker_config --test worker_endpoint --test runtime_worker -- -D warnings`:
  passed.
- The cross-built Windows `worker_config` test executable was copied to a fresh
  test-only directory and executed natively with `--test-threads=1`: 12 passed.
  SHA-256: `b0419f04f47436f9aa2d917de578deae8c4dae141a7fd17d4785e0b13e1a7bec`.
  The construction regression uses a synthetic owner-only protected credential
  file and exercises `WorkerClientConfig::new`, not just endpoint derivation.

## Review correction

Independent review found that Windows worker-client configuration still invoked
the admin-pipe namespace validator. The corrected Windows path invokes the worker
validator. The native regression constructs the derived worker client and rejects
the admin namespace. No production authentication check was relaxed.

## Remaining gates

Independent re-review found no endpoint derivation blocker. It confirmed matching
Linux consumer semantics and legacy environment rejection, but identified missing
configuration agreement: watchdog must validate that the harness launch environment
namespace equals the approved worker namespace and contains no legacy endpoint key.
Shared machine-readable conformance vectors remain an integration requirement.

Full workspace checks, companion publication, and exact
release-set integration must be recorded separately. Harness listener derivation
is being validated in its owning repository; this evidence does not substitute for
that consumer's tests. The native bootstrap producer still requires runtime/store
wiring and an actual authenticated exchange from the integrated launcher.

No service installation, release activation, game/provider launch, host reboot,
or live soak is established by these checks. Legacy configuration requires an
explicit approved replacement; startup performs no configuration migration.

## Configuration-agreement follow-up

The namespace agreement gap above was subsequently corrected and independently
reviewed. The watchdog now requires the exact launch namespace value and rejects
legacy/case-variant reserved environment keys without injecting values. Focused
Linux configuration/runtime tests passed (18 total), and Clippy passed. The Windows
configuration executable passed 13 tests natively, including environment agreement;
SHA-256: `6c0cdb5c41b7f602c608465626f11a84402a3aa713423f2122eddb8ba0587cee`.

The full Linux workspace/all-target/all-feature test command also exited zero for
the preceding endpoint commit `0b26404ca22e882d4d7056995bbb922578913c52`.
That result predates the Linux pipe cherry-pick and configuration-agreement change;
it is not a full gate for subsequent bootstrap producer integration.
