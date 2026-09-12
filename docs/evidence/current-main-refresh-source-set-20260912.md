# Current-main artifact refresh source-set admission — 2026-09-12

Classification: `current-main source-set admitted; release not activated`.
This is the read-only source-set and synchronized-artifact result for the
merged companion refreshes. The exact same manifest was then passed to the
locked build-set documented in
[`current-main-refresh-build-set-20260912.md`](current-main-refresh-build-set-20260912.md).

## Manifest and merged delivery

The exact manifest is
[`workspace-manifest.current-main-refresh-20260912.json`](../../workspace-manifest.current-main-refresh-20260912.json).
Its SHA-256 is
`f4458966fbf94765ffa82a641949d21b73ea96560b31a942a1c197689f1dd44d`.

| Repository | PR | Current-main merge commit | Represented source commit |
| --- | ---: | --- | --- |
| `sts2-protocol` | [#43](https://github.com/AI-Ascension/sts2-protocol/pull/43) | `5688e0b1387704d3af123d01cfa022b6825a2966` | synchronized artifact and consumer-conformance assertion |
| `sts2-gateway` | [#45](https://github.com/AI-Ascension/sts2-gateway/pull/45) | `79c31ca5984e51c33dc1a3c53a952c5eb6784649` | `8940fba823a0893b31d1a96301831c182d37ed32` |
| `sts2-mcp-server` | [#46](https://github.com/AI-Ascension/sts2-mcp-server/pull/46) | `1417cbbb508b976d056e0bd646ea001f324a34ba` | `f3b6eaa8bcf2241b8d6c47587c958388a8fe1031` |
| `sts2-harness` | [#90](https://github.com/AI-Ascension/sts2-harness/pull/90) | `174a61d79dd399e5356eb607b2407835ca84cb17` | `9e85c29049e942140b97d8fbab2e52ba95475964` |

All four companion PRs passed their required hosted quality and policy checks
before merging. The source-set gate admitted eight clean, exact worktrees:
watchdog, the four refreshed companions, game-mod, game-core, and
observability.

## Artifact checks

The admission result reports identical contract and golden bytes, with complete
checksum inventories (34 protocol entries and 25 entries in each consumer
copy). The synchronized `consumer-conformance.json` digest is
`c9a98f1ae62495e28c24ec2627daba10647cd5e2c03ea81e87266a8c8977015e`.

The machine-readable result is
[`current-main-refresh-source-set-20260912.json`](current-main-refresh-source-set-20260912.json).

## Boundary

Current-main source admission and the unified locked build are closed. The
release remains deliberately unactivated. Native Linux/Windows service
execution, live-host recovery, cold-boot recovery, activation/rollback, and a
completed target-duration soak remain separate evidence gates.
