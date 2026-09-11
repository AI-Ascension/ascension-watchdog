# Current-main unified build-set result — 2026-09-11

Classification: `unified cross-repository build passed; release not activated`.
This is compile evidence for the exact admitted current-main source set. It is
not an installed service, activation, live-host, reboot, rollback, or soak
result.

## What was run

The new `watchdog release build-set` orchestration
([workflow](../evidence/build-set-workflow.md)) verified the admitted
source-set manifest, then ran each repository's declared locked build in that
repository's own worktree:

```text
watchdog release build-set \
  --manifest workspace-manifest.current-main-refresh-20260911.json \
  --plan workspace-build-plan.current-main-refresh-20260911.json \
  --repo ascension-watchdog=... --repo sts2-gateway=... --repo sts2-harness=... \
  --repo sts2-mcp-server=... --repo sts2-game-mod=... --repo sts2-protocol=... \
  --repo sts2-game-core=... --repo ai-agent-observability=... \
  --scratch <external-scratch>
```

Every step ran `cargo +1.97.1 build --locked --release` with
`CARGO_TARGET_DIR={scratch}/target`, so no companion worktree was written to.

## Result

- Tool: pinned `1.97.1`.
- Admission: `admitted=true`; manifest SHA-256
  `1e4d7bc10a6bb4c319c026417d87e5599cd3b150b9cc05d1a5f1fb11f6cc4d18`.
- Build plan SHA-256
  `332507b47b91c3a3dbbb349c150649aecd7cd5892d1bbbec5137b59713a05dfc`.
- `built=true`; 7 repositories; 0 issues.

| Repository | Status | Exit | Duration |
| --- | --- | ---: | ---: |
| `ascension-watchdog` | pass | 0 | 333973 ms |
| `sts2-gateway` | pass | 0 | 209769 ms |
| `sts2-harness` | pass | 0 | 276568 ms |
| `sts2-mcp-server` | pass | 0 | 34705 ms |
| `sts2-game-mod` | pass | 0 | 37594 ms |
| `sts2-protocol` | pass | 0 | 29689 ms |
| `sts2-game-core` | pass | 0 | 21359 ms |

`ai-agent-observability` is admitted by the source-set gate but is not a Cargo
workspace, so it has no build step.

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

A passing build-set is compile evidence for the pinned inputs. It does not
install or start a service, activate or roll back a release, exercise the
game/provider path, recover a live host, survive a cold boot, or run a soak.
Those axes remain unverified and separately reported.
