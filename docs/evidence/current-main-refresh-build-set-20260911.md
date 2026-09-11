# Current-main unified build and conformance result — 2026-09-11

Classification: `unified cross-repository build and component-conformance passed;
release not activated`. This is compile and component-test evidence for the
exact admitted current-main source set. It is not an installed service,
activation, live-host, reboot, rollback, or soak result.

## What was run

The `watchdog release build-set` orchestration
([workflow](build-set-workflow.md)) verified the admitted source-set manifest,
then ran each repository's declared ordered steps — a locked release build
followed by that repository's conformance test — in the repository's own
worktree:

```text
watchdog release build-set \
  --manifest workspace-manifest.current-main-refresh-20260911.json \
  --plan workspace-build-plan.current-main-refresh-20260911.json \
  --repo ascension-watchdog=... --repo sts2-gateway=... --repo sts2-harness=... \
  --repo sts2-mcp-server=... --repo sts2-game-mod=... --repo sts2-protocol=... \
  --repo sts2-game-core=... --repo ai-agent-observability=... \
  --scratch <external-scratch>
```

Every step ran `cargo +1.97.1` with `CARGO_TARGET_DIR={scratch}/target`, so no
companion worktree was written to.

## Result

- Orchestrator version 2; toolchain `1.97.1`.
- Admission: `admitted=true`; manifest SHA-256
  `1e4d7bc10a6bb4c319c026417d87e5599cd3b150b9cc05d1a5f1fb11f6cc4d18`.
- Build plan SHA-256
  `a4c7bd6953b1d3317b6ebaa0fb28add0b634145a0027aafde613dcf030d71fb2`.
- `built=true`; 7 repositories; 0 issues.

| Repository | Status | Steps |
| --- | --- | --- |
| `ascension-watchdog` | pass | build 206461 ms; schema-conformance (`-p watchdog-fault-fixture --test schema`) 35276 ms |
| `sts2-gateway` | pass | build 125605 ms; recovery-conformance (`--test recovery`) 41450 ms |
| `sts2-harness` | pass | build 159276 ms; recovery-conformance (`completed_resume_process`, `execution_store`, `replay`, `phase2_recovery`) 85026 ms |
| `sts2-mcp-server` | pass | build 11112 ms; artifact-conformance (`--test runtime_v2_artifact`) 28226 ms |
| `sts2-protocol` | pass | build 18947 ms; consumer-conformance (`--test coop_native_consumer_conformance`) 29991 ms |
| `sts2-game-mod` | pass | build 15665 ms |
| `sts2-game-core` | pass | build 10986 ms |

`ai-agent-observability` is admitted by the source-set gate but is not a Cargo
workspace, so it has no step.

The machine-readable orchestrator report is
[`current-main-refresh-build-set-20260911.json`](current-main-refresh-build-set-20260911.json).
Absolute host worktree paths were redacted to `<host-path>` before commit;
counts, digests, exit codes, statuses, timeouts, and durations are unchanged.

## Postconditions

All eight companion worktrees and the pinned watchdog worktree were clean after
the run (`git status --porcelain` empty), and the orchestrator removed its
scratch directory. The build target was external, so no `target/` tree was left
in any companion repository.

## Boundary

A passing build-set is compile and component-conformance evidence for the pinned
inputs. It does not install or start a service, activate or roll back a release,
exercise the game/provider path, recover a live host, survive a cold boot, or run
a soak. Those axes remain unverified and separately reported.
