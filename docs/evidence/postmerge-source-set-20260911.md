# Post-merge source-set revalidation — 2026-09-11

Classification: `source-set admission rejected; release not activated`.
This is a read-only verification of clean fetched worktrees. It is not a
build, service installation, live-host, reboot, activation, or soak result.

## Exact revisions

The manifest is [`workspace-manifest.postmerge-20260911.json`](../../workspace-manifest.postmerge-20260911.json).
The checked revisions are:

| Repository | Revision |
| --- | --- |
| `ascension-watchdog` | `28e20fa8cfb9a43635a5c167e03ade6219d87a5a` |
| `sts2-gateway` | `d5dedd264115472799b780b49fd9a545cb6a1507` |
| `sts2-harness` | `4e738133822a48b99bea9a710aa49cf635e7cd2d` |
| `sts2-mcp-server` | `f376105ab779ea692855557a5ad6fdab32f9891d` |
| `sts2-game-mod` | `afa44d6f8da66625b67a10d758725da01492a27a` |
| `sts2-protocol` | `d6ec03d1edfe5ebd881fcdf57c4b6185a937f72e` |
| `sts2-game-core` | `f5daf69f4f2c43fddbb04e7799d32503f7066110` |
| `ai-agent-observability` | `6fad79d00ef4fa84097cb00e8342521f85f6e48e` |

## Gate result

The watchdog source-set verifier ran against eight clean worktrees and
returned `admitted=false`, manifest SHA-256
`4e2acc7216bdda3a892cd9c5d4d88e5ab870181edfb36b3d3f256f7c64a53c00`.

The four `coop-native-v1` contract copies are present, checksum inventories
pass (34 protocol entries and 25 entries in each consumer copy), and all
contract and golden bytes are identical. The serialized consumer record still
binds the older source revisions:

| Consumer | Serialized revision | Current delivery revision |
| --- | --- | --- |
| gateway | `f4d14091ce1f3b5327925a7a536e2c7bf7b0c56b` | `d5dedd264115472799b780b49fd9a545cb6a1507` |
| MCP | `98ab84b3fad371b45b141e6d81dd9124769a4c59` | `f376105ab779ea692855557a5ad6fdab32f9891d` |
| harness | `00bd9e123a86fca39bbffb65b370aac7ed2c8218` | `4e738133822a48b99bea9a710aa49cf635e7cd2d` |

The gateway delivery merge is artifact-only relative to its serialized source
revision. The current MCP and harness deliveries include non-artifact source
changes after their serialized revisions (27 and 96 changed paths,
respectively), so the verifier rejects them under the artifact-only ancestry
rule. This is a real post-merge refresh gap, not a reason to edit bytes in
place.

## Required next action

Regenerate the protocol artifact and consumer-conformance copies from the final
post-merge gateway/MCP/harness source heads, update their checksum inventories,
run each component's locked gates, and rerun this verifier against a clean
manifest. Keep the result unactivated until native service, live-host,
cold-boot, rollback, and soak evidence is separately collected.

The remaining platform/runtime axes are unchanged: Windows SCM/pipe/Job Object,
installed Linux systemd/broker cleanup, live gateway–harness–MCP recovery,
cold-boot/reboot, and long-run bounded telemetry/archive soak remain
unverified. Nested depth-2/3 delegation also remains unavailable in the current
tool surface.
