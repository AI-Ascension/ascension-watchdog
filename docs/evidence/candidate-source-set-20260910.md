# Candidate source set — 2026-09-10

This record pins the remote pull-request heads used for the next integration
review. It is deliberately a candidate source set, not an activated release:
the JSON manifest records each exact revision, ref, PR, and current state in
`workspace-manifest.candidate.json`.

The pins were refreshed from remote PR metadata on 2026-09-10. The watchdog
integration source is draft PR #9 at
`5b235f9524ecbb9529392dafee2328545666f356`; local locked workspace, restore,
Linux installer, and Windows cross-target checks pass. Hosted validation runs
`34510068432`/`34510068442` passed at this exact head, including the Windows
restore publication and fail-closed collision fixtures. The hosted
service-session step was explicitly `UNVERIFIED` on runner session 2; it is not
native service proof. Gateway PR #37
and harness PR #59 have since merged; their selected current-main revisions
are `5f3eadabede9954bc834a62e3c4c1003444826ca` and
`5cc486a66b6f11930675af06f7426cd91c609983`, respectively. Protocol draft PR #33 remains at
`09819e2216354136ab5a799413dcd98499f56580` with green hosted checks.

The selected merged companion revisions are gateway `5f3eadabede9954bc834a62e3c4c1003444826ca`,
harness `5cc486a66b6f11930675af06f7426cd91c609983`, MCP
`8b6b73862494488fdd16fa5423fdf90a953260f4`, game-mod
`a70a5e5bb2fa89fade7e16dbb4a58ed80e31355b`, game-core
`f9db577530a4d159b066d3facbd780d61c044eb0`, and observability
`d7e79e1a9663601013e513048caea7063b0de9ae`. Locked component gates and
runtime-v2/v3/v4/seeded-run artifact bytes are recorded in
[`release-set-verification-20260910.json`](release-set-verification-20260910.json).
These revisions and the open protocol follow-up are still independent source
components: no claim is made that they compose, install, activate, or run on a
live host.

Required next gate: rebuild and test this exact set together, verify immutable
artifact digests, then run the separately authorized native Windows/Linux/WSL,
activation/rollback, cold-boot, and soak lanes. Until those gates pass, do not
change the manifest classification to an activated release.
