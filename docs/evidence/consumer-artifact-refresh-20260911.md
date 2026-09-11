# `coop-native-v1` consumer artifact refresh — 2026-09-11

Captured at `2026-09-11T11:17:06Z`. This is PR-only delivery evidence for
the serialized component contract. It is not source-set admission, a merged
release, a service result, a native live-host result, or a soak result.

## Proposed current-main snapshot

The four refresh branches are based on the exact source heads used by the
candidate manifest and contain only the artifact metadata/documentation
refresh (plus the protocol snapshot assertion):

| Repository | PR | Refresh commit | Base source head |
| --- | --- | --- | --- |
| `sts2-protocol` | [#41](https://github.com/AI-Ascension/sts2-protocol/pull/41) | `57edfcb30028d910087121f46b9649564155e328` | `0bc689eabc5542ede2b09b030d9ea32daa8a73e7` |
| `sts2-gateway` | [#43](https://github.com/AI-Ascension/sts2-gateway/pull/43) | `72c79fd0bda286265201f25cf77f13f2a4fc6f14` | `f4d14091ce1f3b5327925a7a536e2c7bf7b0c56b` |
| `sts2-mcp-server` | [#44](https://github.com/AI-Ascension/sts2-mcp-server/pull/44) | `a0e24fcd8ba05fa45782755855aed7ef0a8def41` | `98ab84b3fad371b45b141e6d81dd9124769a4c59` |
| `sts2-harness` | [#85](https://github.com/AI-Ascension/sts2-harness/pull/85) | `48afc354f9df2d5e93fc653e1bcd757dbb1127e8` | `00bd9e123a86fca39bbffb65b370aac7ed2c8218` |

The serialized record binds the source-only managed producer capture to
`sts2-game-mod` commit `d23ca838a7be875f32242123955b4a27782bac04`, tree
`23336ca834b5870d15ee6369c101d5c67ff34caf`, and binds the current main
consumer identities and trees listed in the four existing source-set
records. `live_status` remains `unverified`.

The conformance entries intentionally identify the tested current main
consumer revisions, not the metadata-refresh branch commits. Once a refresh
PR merges, that repository's main revision changes; the final manifest and
consumer record must therefore be regenerated against the post-merge heads
before source-set admission is reconsidered.

## Contract evidence

The four staged artifact copies have identical hashes for the source-set
contract files:

```text
manifest.json             ae6b0df82965acaf8bc1c033e9201f8d2570a2def2c29a69c2ed1990573a52bc
schema.json               2f3bc99e53080fa11b39592b64fb0ab964a16f568719a2622d0b2caf766ab629
conformance.json          8da68488ca75de12a73521eee30d3464d8c8c9f3a623a6233f2cf97fb68f43b3
consumer-conformance.json c4350934fce24b11aa7f72ab8a99784c364323313d6390d59f33e8ab952e78a6
```

The protocol copy has 34 checksum rows and each consumer copy has 25 rows;
all four complete `SHA256SUMS` inventories pass. The consumer copies retain
their owner-local layout and do not receive the protocol-only `capture/`
directory. README metadata was updated to match the refreshed producer and
consumer record, with owner-local capture wording preserved.

The existing producer capture remains pinned to its recorded source commit:
the managed `.NET` probe was not rerun because `dotnet` is not installed in
this environment. The probe-bound producer and game-loader source paths were
checked for differences between that commit and current game-mod main and
were unchanged; the existing producer capture checksum is
`d414cc148f6724032514a33c6dadd1ff99b88a69eb962453e83a92679f7b7d7f`.

## Local gates

These exact refreshed worktrees passed:

```text
cargo +1.97.1 test --locked --package sts2-protocol --all-targets --all-features -- --test-threads=1
cargo +1.97.1 test --locked --package sts2-gateway --all-targets --all-features -- --test-threads=1
cargo +1.97.1 test --locked --package sts2-mcp-server --all-targets --all-features -- --test-threads=1
cargo +1.97.1 test --locked --package sts2-harness --all-targets --all-features -- --test-threads=1
```

The protocol snapshot test now checks the refreshed gateway, MCP, and
harness identities. The gateway, MCP, and harness runs also exercised their
native route/mapping/coordination code and copied artifact verification.

## Hosted delivery state at capture

Protocol PR #41, gateway PR #43, and MCP PR #44 had both their repository
policy and Rust/component quality checks passing. Harness PR #85 had its
policy check passing and its Rust quality check still in progress at capture;
the PR itself remains open. No PR was merged or deployed by this refresh.

At this capture, the candidate source-set worktrees remained on the previously
recorded main commits, so the root read-only verifier result was
`admitted=false` until the refresh PRs were reviewed/merged and a post-merge
manifest, artifact record, and gate run were produced. Native service
installation, authorized two-peer host settlement, Windows SCM execution,
cold boot, Docker/Podman, and soak evidence remain unverified.

## Hosted check completion — 2026-09-11 11:21 UTC

All required hosted checks subsequently completed successfully:

| PR | Quality run | Policy run |
| --- | --- | --- |
| protocol #41 | `34593088663` | `34593088687` |
| gateway #43 | `34593088287` | `34593088090` |
| MCP #44 | `34593088598` | `34593088569` |
| harness #85 | `34593088740` | `34593088688` |

The PRs remain open and unmerged. These green checks validate the individual
repository refresh branches; they do not change the root candidate's
`admitted=false` result or establish a unified build or live native session.

## Exact refresh candidate — 2026-09-11 11:42 UTC

The source-set verifier now accepts the refresh branches as an exact
unactivated candidate through
workspace-manifest.coop-refresh.candidate.json. The checked-out delivery
revision remains authoritative, while source_revision/source_tree records the
underlying source bytes used by consumer conformance. The verifier requires
the source commit to be ancestral, the source tree to match, and all
intervening changes to remain within the declared artifact directory.

The eight-worktree gate exited 0 with admitted=true, no issues, four identical
contract files, and complete checksum inventories. The full result is
recorded in docs/evidence/coop-refresh-source-set-20260911.md. This does not
promote the PR heads to merged main or change the separate native, live,
activation, reboot, and soak evidence boundaries.

## Post-merge regeneration candidate — 2026-09-11 20:20 UTC

After the companion merges, the synchronized copies were regenerated locally
against gateway `d5dedd264115472799b780b49fd9a545cb6a1507`, MCP
`f376105ab779ea692855557a5ad6fdab32f9891d`, and harness
`4e738133822a48b99bea9a710aa49cf635e7cd2d`. The resulting local delivery
commits are protocol `3301018a0625c9631e92be2769c7586928c10493`, gateway
`d987ac4212435e0e451f3411002a792e5f2d92c1`, MCP
`c403163d1749af90376064c17e9d037cba8a2130`, and harness
`9defafd4d0a368a42fe74a17c7def3a2877fdb89`.

All four copies now have identical `consumer-conformance.json` bytes at
`b9563c67bb0d571ade708529489fb3fe8233a9363aa73fb277474b5aef62c8d6`.
Their contract and golden bytes are identical, and the checksum inventories
pass with 34 protocol entries and 25 entries in each consumer copy. The exact
candidate manifest and verifier result are recorded in
[`workspace-manifest.postmerge-refresh-20260911.json`](../../workspace-manifest.postmerge-refresh-20260911.json)
and [`postmerge-refresh-source-set-20260911.json`](postmerge-refresh-source-set-20260911.json);
the manifest digest is
`35b7c06d5d34f1c24f75c5253b23a2b7446d18a9a89a4b61de9260883a687d33`, and the
verifier returned `admitted=true` for eight clean worktrees.

The four delivery commits are local and remain unpushed/unmerged. This closes
the local artifact-refresh admission check only; it does not establish a
current-main release, unified build, native service, live-host, cold-boot,
rollback, or soak result.
