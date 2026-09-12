# Current-main archive evidence build and conformance result — 2026-09-12

Classification: `unified cross-repository build and conformance passed; release
not activated`. This records compile and component-test evidence for the exact
admitted current-main source set after the gateway archive-batch regression and
the synchronized consumer artifact refreshes. It is not native-service,
activation, live-host, reboot, rollback, or soak evidence.

## Source-set admission

[`workspace-manifest.current-main-archive-evidence-20260912.json`](../../workspace-manifest.current-main-archive-evidence-20260912.json)
was admitted by `watchdog release source-set verify` with eight clean,
remote-identified worktrees and four checksum-verified, byte-identical co-op
native artifact copies.

- Manifest SHA-256: `26177c266a3e51db9cd8accb230a8d5af056e7aa40036bffd47e40e44003e357`.
- Admission: `admitted=true`.
- Gateway delivery/source revisions: `0133f860093514327c560288caf990d53cd2b827` /
  `fb50a327484bc44ff4539d266c8a5d6816db6a46`.
- Protocol, MCP, and harness artifact delivery revisions: `cb2ce5162caf75503199f85c708624e9811a34b8`,
  `6f4e8858185bb994db40c5422c5cd872560e012b`, and
  `64ce7d03a01e568db1de20d0316c1d03fec77812`.

## Locked build plan

The pinned `watchdog release build-set` plan ran with Rust `1.97.1` and
`--locked`. Its final report was `admitted=true`, `built=true`,
`repository_count=7`, and no issues. Plan SHA-256:
`a4c7bd6953b1d3317b6ebaa0fb28add0b634145a0027aafde613dcf030d71fb2`.

| Repository | Result |
| --- | --- |
| `ascension-watchdog` | release build; schema conformance |
| `sts2-gateway` | release build; recovery conformance |
| `sts2-harness` | release build; recovery conformance |
| `sts2-mcp-server` | release build; runtime-v2 artifact conformance |
| `sts2-protocol` | release build; co-op native consumer conformance |
| `sts2-game-mod` | release build |
| `sts2-game-core` | release build |

`ai-agent-observability` is included in source admission but has no Cargo build
step.

## Boundary

This closes the refreshed current-main source/build gate. Native service and
live-host recovery, cold boot, staged activation and rollback, and a completed
target-duration soak remain unverified and must not be inferred from this
component evidence.
