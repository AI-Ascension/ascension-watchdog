# Current-main artifact refresh source-set admission — 2026-09-11

Classification: `current-main source-set admitted; release not activated`.
This is a read-only source-set and artifact verification result. It is not
native service, live-host, reboot, activation, rollback, or soak evidence.

## Manifest and merged delivery

The exact current-main manifest is
[`workspace-manifest.current-main-refresh-20260911.json`](../../workspace-manifest.current-main-refresh-20260911.json).
Its SHA-256 is
`1e4d7bc10a6bb4c319c026417d87e5599cd3b150b9cc05d1a5f1fb11f6cc4d18`.

| Repository | PR | Current-main merge commit | Represented source commit |
| --- | ---: | --- | --- |
| `sts2-protocol` | [#42](https://github.com/AI-Ascension/sts2-protocol/pull/42) | `219510c4d4f9c96a54f510cca085a48a92bfe490` | merge contains synchronized artifact and conformance assertion |
| `sts2-gateway` | [#44](https://github.com/AI-Ascension/sts2-gateway/pull/44) | `8940fba823a0893b31d1a96301831c182d37ed32` | `d5dedd264115472799b780b49fd9a545cb6a1507` |
| `sts2-mcp-server` | [#45](https://github.com/AI-Ascension/sts2-mcp-server/pull/45) | `f3b6eaa8bcf2241b8d6c47587c958388a8fe1031` | `f376105ab779ea692855557a5ad6fdab32f9891d` |
| `sts2-harness` | [#86](https://github.com/AI-Ascension/sts2-harness/pull/86) | `4584c4cbc2f6bcb900f99092cafa80d32ca0cce8` | `4e738133822a48b99bea9a710aa49cf635e7cd2d` |

All four PRs passed their required hosted quality and policy checks before
merging. The exact run IDs are preserved in the machine-readable report.

## Admission result

The watchdog verifier returned `admitted=true` for eight clean, exact
worktrees: four current-main companion heads plus watchdog, game-mod,
game-core, and observability. There are four artifacts, with complete checksum
inventories of 34 protocol entries and 25 entries in each consumer copy.
Contract and golden bytes are identical across all copies. The synchronized
`consumer-conformance.json` digest is
`b9563c67bb0d571ade708529489fb3fe8233a9363aa73fb277474b5aef62c8d6`.

The full machine-readable result is
[`current-main-refresh-source-set-20260911.json`](current-main-refresh-source-set-20260911.json).

## Remaining boundary

This closes current-main source-set admission for the refreshed artifacts, but
does not activate a release. A unified cross-consumer build is not available
in this workspace. Native Windows/Linux service execution, live-host recovery,
cold boot, rollback, and soak evidence remain unverified.
