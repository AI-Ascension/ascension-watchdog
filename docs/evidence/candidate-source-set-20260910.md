# Candidate source set — 2026-09-10

This record pins the remote pull-request heads used for the next integration
review. It is deliberately a candidate source set, not an activated release:
the JSON manifest records each exact revision, ref, PR, and current state in
`workspace-manifest.candidate.json`.

The pins were refreshed from remote PR metadata on 2026-09-10. The watchdog
integration source is draft PR #9 at
`fa0787620e768266c683da178c81b5af7198bc39`; local locked workspace, restore,
and Linux installer tests pass, while the latest hosted Ubuntu/Windows runs
were still in progress when this record was captured. The gateway follow-up is
draft PR #37 at `0524b67ec28791c007d2ea025e26860672358247` and the harness
follow-up is draft PR #59 at
`fcd1f6819fdd2672816a1b7e2235f7069aa93708`; both have green hosted quality and
policy checks. Protocol draft PR #33 remains at
`09819e2216354136ab5a799413dcd98499f56580` with green hosted checks.

The selected merged companion revisions are gateway main `2cf9127`, harness
PR #58 merge `4342789`, MCP PR #37 merge
`a6b9215db1ddeeddabe4c111ed3b49476fb86e54`, game-mod PR #70 merge
`e532f4d9186e367bd3dc045d2377a2bd3ac9e4e5`, game-core PR #9 merge
`f9db577530a4d159b066d3facbd780d61c044eb0`, and observability PR #16 merge
`a126715501d65a2d25f9d6ecf9c6bd142cc5f590`. These revisions and the open
follow-ups are still independent source components: no claim is made that they
compose, install, activate, or run on a live host.

Required next gate: rebuild and test this exact set together, verify immutable
artifact digests, then run the separately authorized native Windows/Linux/WSL,
activation/rollback, cold-boot, and soak lanes. Until those gates pass, do not
change the manifest classification to an activated release.
