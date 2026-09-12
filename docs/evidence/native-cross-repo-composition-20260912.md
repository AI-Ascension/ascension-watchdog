# Native cross-repo executable composition — 2026-09-12

Classification: `native cross-repo executable composition with a synthetic
provider and a test-support fake mod server`. This is real gateway/MCP/harness
process composition; it is not gameplay, not the watchdog service, and not the
24-hour soak.

## What ran

The harness operator test
`executable_runtime_v4_composes_unknown_reconcile_and_foreign_state_fence`
(from `sts2-harness`, `--ignored --exact`) was executed natively on the supplied
Train host with explicitly built companion binaries:

| Role | Revision | SHA-256 |
| --- | --- | --- |
| gateway | `8940fba823a0893b31d1a96301831c182d37ed32` | `ae662c2d3e4c311e029bb123c2312959d57de9bc44aff2dfc2e4abc8ef491ab4` |
| mcp | `f3b6eaa8bcf2241b8d6c47587c958388a8fe1031` | `712ee2ae518d3ba0ba21b9f21f94f9cd76317af79c60d6b14b7ce11dd5648174` |
| harness | `544605b3c631dd2ce7c4db9c520238fd80b6c411` | `d9e360a7071c1ce6b27ce8cbf8dc7320b10f7dabe1b056572f3e3dfeb486e0c2` |
| harness composition test binary (debug) | `544605b3…` | `a002fb067fc5e696d424f9ccf7a88d07e1e281df621e44ef168cb52f40faa30a` |

The test starts the real gateway binary, launches MCP through `STS2_MCP_BINARY`,
runs the real harness runtime, and drives a test-support fake mod server and a
`synthetic` provider. It then verifies the success composition (unknown outcome
reconciled without a second effect) and that foreign expert state is rejected.

Result on the host:

```text
running 1 test
test executable_runtime_v4_composes_unknown_reconcile_and_foreign_state_fence ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.63s
```

## Provenance note (external drift)

The admitted current-main source set pinned harness `4584c4cb…`. The companion
harness worktree has since advanced to `main` `544605b3…` (PR #87 merged) and no
longer contains the pinned object, so the composition above was built and run at
harness `544605b3…` while gateway and MCP remain at their admitted pins. This is
therefore "current companion main" composition evidence, not an admitted
release-set claim; a fresh admission and release staging would be required to
tie it to a release.

## Boundary

Verified: real gateway/MCP/harness processes compose over their wire contracts
with a synthetic provider and fake mod server, reconcile an unknown outcome, and
fence foreign state. Not verified: gameplay/provider settlement against a real
game, the watchdog service path, cold boot, Windows SCM, WSL, or the 24-hour
cross-repo soak.
