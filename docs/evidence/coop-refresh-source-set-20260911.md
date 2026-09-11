# Coop-native refresh candidate source-set gate — 2026-09-11

Classification: candidate source-set admission passed for exact fetched
worktrees, but this is not merged delivery, release activation, native
execution, or live-host evidence.

The candidate manifest is
workspace-manifest.coop-refresh.candidate.json. Its SHA-256 is
bc1683c17c7ee819121362e51901118581391bae2e44932efb737e344652c4f5.
The exact checked-out revisions are the four open artifact-refresh PR heads
plus the selected watchdog and current companion source revisions:

| Repository | Checked-out revision | Consumer-bound source revision/tree |
| --- | --- | --- |
| ascension-watchdog | 538346e8909a2f4fc23e5b3ea9ec2960b8b34530 | same source revision |
| sts2-protocol | 57edfcb30028d910087121f46b9649564155e328 | exact refresh head |
| sts2-gateway | 72c79fd0bda286265201f25cf77f13f2a4fc6f14 | f4d14091ce1f3b5327925a7a536e2c7bf7b0c56b / 98fe7bbd0b57c44761238d86f9bf0b5594c97da4 |
| sts2-mcp-server | a0e24fcd8ba05fa45782755855aed7ef0a8def41 | 98ab84b3fad371b45b141e6d81dd9124769a4c59 / 796ee080b34d0add13e53cc9324fe8122bc05f59 |
| sts2-harness | 48afc354f9df2d5e93fc653e1bcd757dbb1127e8 | 00bd9e123a86fca39bbffb65b370aac7ed2c8218 / 2f253945e301c509ca098d740b8797f16bff9a30 |
| sts2-game-mod | bd8e90542dfc89366f820150c5c755e32716b1b0 | current main |
| sts2-game-core | f5daf69f4f2c43fddbb04e7799d32503f7066110 | current main |
| ai-agent-observability | 630431716ebfbf86280f9fd56f19d6016ad7aeb2 | current main |

The verifier command was run with the eight explicitly supplied isolated
worktrees and the candidate manifest. It exited 0 and reported:

- admitted: true
- repository count: 8
- artifact count: 4
- issues: none
- contract files identical: true
- protocol artifact checksum entries: 34
- each consumer artifact checksum entries: 25
- every artifact consumer boundary: pass
- every consumer binding: pass

The new source-set semantics are intentionally narrow. The checked-out
revision remains the immutable worktree identity. A source_revision/source_tree
pair is permitted only when the source commit is present, is an ancestor of
the delivery commit, the tree matches exactly, and every intervening change is
inside that repository's declared coop-native artifact directory. Unit tests
cover both an accepted artifact-only commit and rejection of an unexpected
source change.

The four staged contract copies have these identical hashes:

| File | SHA-256 |
| --- | --- |
| manifest.json | ae6b0df82965acaf8bc1c033e9201f8d2570a2def2c29a69c2ed1990573a52bc |
| schema.json | 2f3bc99e53080fa11b39592b64fb0ab964a16f568719a2622d0b2caf766ab629 |
| conformance.json | 8da68488ca75de12a73521eee30d3464d8c8c9f3a623a6233f2cf97fb68f43b3 |
| consumer-conformance.json | c4350934fce24b11aa7f72ab8a99784c364323313d6390d59f33e8ab952e78a6 |

The underlying delivery PRs remain open and must not be represented as merged:
protocol #41, gateway #43, MCP #44, and harness #85. The candidate therefore
does not promote release admission. The exact cross-repository clean build,
native service execution, live settlement/recovery, cold boot, activation,
and soak gates remain separate and unverified.
