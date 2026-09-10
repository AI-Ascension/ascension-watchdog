# Candidate source set — 2026-09-10

This record pins the remote pull-request heads used for the next integration
review. It is deliberately a candidate source set, not an activated release:
the JSON manifest records each exact revision, ref, PR, and current state in
`workspace-manifest.candidate.json`.

The pins were read from remote PR metadata on 2026-09-10. The watchdog source
is PR #2 at `dda3a915f7ea25bc291727f0e151b421344cc007`; its dependency,
Ubuntu, Windows, and standards checks passed in runs `34467741617` and
`34467741618`. The gateway is PR #35 at `8ce3f78bf8b0f0970b5c6a47f7d46e5010c05711`,
the harness recovery-catalog repair is PR #53 at
`6fcd059b420a1099ec225a907ee3aea5e799f0e7`, and MCP workflow authority is
PR #37 at `16ca0cb06dc93564c14963bc544bef282b38d26d`; their hosted checks
passed on the recorded heads. The game-mod, protocol, game-core, and
observability entries are likewise exact PR heads, with protocol #24 marked
conflicting against the current main and therefore not an integrated release.
No claim is made that these moving heads compose, install, activate, or run on
a live host.

Required next gate: rebuild and test this exact set together, verify immutable
artifact digests, then run the separately authorized native Windows/Linux/WSL,
activation/rollback, cold-boot, and soak lanes. Until those gates pass, do not
change the manifest classification to an activated release.
