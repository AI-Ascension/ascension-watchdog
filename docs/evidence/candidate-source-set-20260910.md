# Candidate source set — 2026-09-10

This record pins the remote pull-request heads used for the next integration
review. It is deliberately a candidate source set, not an activated release:
the JSON manifest records each exact revision, ref, PR, and current state in
`workspace-manifest.candidate.json`.

The pins were refreshed from remote PR metadata on 2026-09-10. The watchdog
integration source pin is draft PR #9 at
`38252ddfc5eb4f47233bad80f153739728a43742`, based on the `bootstrap` default
branch. The last PR head observed when this candidate source set was captured
was `acd4976c88eab958f4b6dcae657ab83ffe2baa91`, a documentation-only
follow-up; its Ubuntu, Windows, standards, and dependency workflows were
green. Subsequent documentation-only commits do not change the source pin.
Gateway draft PR #35 is current-main-based at
`7272c17f07e1d7e79c82f498eac0855794d476f5` with Rust-quality and policy checks
green. The harness integration is draft PR #56 at
`427176512eac67257a1b065f8508f37d2ed2255c`, combining the recovery and worker
admission repairs on current main; Rust-quality and policy checks are green.
MCP PR #37 at `16ca0cb06dc93564c14963bc544bef282b38d26d` is merged as
`a6b9215db1ddeeddabe4c111ed3b49476fb86e54`. Game-mod draft PR #70 is
current-main-based at `152c555633672bddcfa8280b290f6bd67afd564c` with all
three hosted checks green. Protocol draft PR #31 is current-main-based at
`5e43193cb5da17a5b772caa0f0fff49180cf716d` with hosted checks green; stale
conflicting PR #24 is not selected. These heads are still independent source
components: no claim is made that they compose, install, activate, or run on a
live host.

Required next gate: rebuild and test this exact set together, verify immutable
artifact digests, then run the separately authorized native Windows/Linux/WSL,
activation/rollback, cold-boot, and soak lanes. Until those gates pass, do not
change the manifest classification to an activated release.
