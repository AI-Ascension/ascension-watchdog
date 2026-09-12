# Current-main unified build and conformance result — 2026-09-12

Classification: `unified cross-repository build and conformance passed; release
not activated`. This is compile and component-test evidence for the exact
admitted current-main source set. It is not an installed service, activation,
live-host, reboot, rollback, or soak result.

## What was run

The pinned `watchdog release build-set` orchestration verified the admitted
source-set manifest and then ran every repository step from
[`workspace-build-plan.current-main-refresh-20260911.json`](../../workspace-build-plan.current-main-refresh-20260911.json).
Each command used the repository's own clean worktree and an external scratch
target:

```text
watchdog release build-set \
  --manifest workspace-manifest.current-main-refresh-20260912.json \
  --plan workspace-build-plan.current-main-refresh-20260911.json \
  --repo ascension-watchdog=... --repo sts2-gateway=... --repo sts2-harness=... \
  --repo sts2-mcp-server=... --repo sts2-protocol=... --repo sts2-game-mod=... \
  --repo sts2-game-core=... --repo ai-agent-observability=... \
  --scratch <external-scratch>
```

Every step ran with `cargo +1.97.1` and `--locked`. No companion worktree was
written.

## Result

- Orchestrator version: `2`.
- Admission: `admitted=true`.
- Manifest SHA-256: `f4458966fbf94765ffa82a641949d21b73ea96560b31a942a1c197689f1dd44d`.
- Build-plan SHA-256: `a4c7bd6953b1d3317b6ebaa0fb28add0b634145a0027aafde613dcf030d71fb2`.
- `built=true`; seven repositories; zero issues.

| Repository | Status | Steps |
| --- | --- | --- |
| `ascension-watchdog` | pass | release build 231534 ms; schema conformance (3 passed) 36334 ms |
| `sts2-gateway` | pass | release build 156910 ms; recovery conformance (7 passed) 54360 ms |
| `sts2-harness` | pass | release build 183142 ms; recovery conformance (60 passed) 95363 ms |
| `sts2-mcp-server` | pass | release build 9326 ms; runtime-v2 artifact (1 passed) 27233 ms |
| `sts2-protocol` | pass | release build 19931 ms; consumer conformance (1 passed) 30047 ms |
| `sts2-game-mod` | pass | release build 17046 ms |
| `sts2-game-core` | pass | release build 11124 ms |

`ai-agent-observability` is admitted by the source-set gate but is not a Cargo
workspace, so it has no build step.

The complete machine-readable result is
[`current-main-refresh-build-set-20260912.json`](current-main-refresh-build-set-20260912.json).

## Boundary

This closes the current-main locked build and component-conformance gate. It
does not install or start a native service, activate or roll back a release,
exercise the game/provider path, recover a live host, survive a cold boot, or
complete a long-running soak. Those evidence axes remain separate.
