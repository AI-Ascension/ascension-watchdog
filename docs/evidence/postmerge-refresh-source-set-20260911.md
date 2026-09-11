# Post-merge artifact refresh candidate — 2026-09-11

Classification: `candidate source-set admission passed; release not activated`.
This is a read-only verification of clean local delivery worktrees. The four
refresh commits are local branches and have not been pushed or merged. This is
not a service installation, live-host, reboot, activation, or soak result.

## Manifest and delivery commits

The exact candidate is recorded in
[`workspace-manifest.postmerge-refresh-20260911.json`](../../workspace-manifest.postmerge-refresh-20260911.json).
Its SHA-256 is
`35b7c06d5d34f1c24f75c5253b23a2b7446d18a9a89a4b61de9260883a687d33`.

| Repository | Delivery commit | Represented source commit |
| --- | --- | --- |
| `sts2-protocol` | `3301018a0625c9631e92be2769c7586928c10493` | source/artifact owner |
| `sts2-gateway` | `d987ac4212435e0e451f3411002a792e5f2d92c1` | `d5dedd264115472799b780b49fd9a545cb6a1507` |
| `sts2-mcp-server` | `c403163d1749af90376064c17e9d037cba8a2130` | `f376105ab779ea692855557a5ad6fdab32f9891d` |
| `sts2-harness` | `9defafd4d0a368a42fe74a17c7def3a2877fdb89` | `4e738133822a48b99bea9a710aa49cf635e7cd2d` |

The consumer-conformance record now binds those current merged source heads
and their exact trees. The synchronized artifact copies update only their
post-merge conformance metadata, README provenance, and checksum inventory;
the protocol copy also updates its source conformance expectation to the new
serialized record.

## Admission result

The watchdog source-set verifier returned `admitted=true` for all eight clean
worktrees. The four artifact inventories pass with 34 protocol entries and 25
entries in each consumer copy. Contract and golden bytes are identical across
all copies, and the synchronized `consumer-conformance.json` digest is
`b9563c67bb0d571ade708529489fb3fe8233a9363aa73fb277474b5aef62c8d6`.

This is a candidate admission only. It does not promote the current main
branches, activate a release, or establish cross-consumer build/runtime
compatibility.

## Remaining gates

Merge the four refresh branches, regenerate the exact post-merge manifest
against the resulting remote heads, and rerun the verifier. A unified
cross-consumer build, native Windows/Linux service execution, live gateway–MCP–
harness recovery, cold boot, rollback, and soak evidence remain separate and
unverified. Nested depth-2/3 delegation also remains unavailable.
