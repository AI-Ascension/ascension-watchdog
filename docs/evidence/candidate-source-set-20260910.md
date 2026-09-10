# Candidate source set — 2026-09-10

This record pins the remote pull-request heads used for the next integration
review. It is deliberately a candidate source set, not an activated release:
the JSON manifest records each exact revision, ref, PR, and current state in
`workspace-manifest.candidate.json`.

The pins were refreshed from remote PR and branch metadata on 2026-09-10. The
watchdog integration branch is draft PR #9 at docs head
`c271f0a3284566af41f6c47ef6ebc21e52cf854c` (source-tested implementation
`5b235f9524ecbb9529392dafee2328545666f356`); the root reran the locked
workspace, restore, and Linux installer checks at the docs head. Hosted
validation runs `34510904205`/`34510905823` and standards runs
`34510904309`/`34510905804` passed. The hosted service-session step was
explicitly `UNVERIFIED` on runner session 2; it is not native service proof.

The selected current-main companion revisions are gateway
`de1fe72345ea972d56c05d30837da5327e5f1655` (PR #38, including PR #37), harness
`5cc486a66b6f11930675af06f7426cd91c609983` (PR #59), MCP
`8b6b73862494488fdd16fa5423fdf90a953260f4`, game-mod
`a70a5e5bb2fa89fade7e16dbb4a58ed80e31355b`, protocol
`678885687e46a43f53b9eec108dfb160fc9a13bd` (PR #33), game-core
`f9db577530a4d159b066d3facbd780d61c044eb0`, and observability
`d7e79e1a9663601013e513048caea7063b0de9ae`. PR #33 is now merged. Locked
component gates and runtime-v2/v3/v4/seeded-run artifact bytes are recorded in
[`release-set-verification-20260910.json`](release-set-verification-20260910.json).
These revisions remain independently built source components: protocol and
gateway carry the coop-native-v1 producer/consumer artifact, but MCP, harness,
and game-mod do not expose that consumer surface. No claim is made that the
full set composes, installs, activates, or runs on a live host.

Required next gate: rebuild and test this exact set together, verify immutable
artifact digests, then run the separately authorized native Windows/Linux/WSL,
activation/rollback, cold-boot, and soak lanes. Until those gates pass, do not
change the manifest classification to an activated release.
