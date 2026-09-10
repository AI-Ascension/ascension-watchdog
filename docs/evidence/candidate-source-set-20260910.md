# Candidate source set — 2026-09-10

This record pins the remote pull-request heads used for the next integration
review. It is deliberately a candidate source set, not an activated release:
the JSON manifest records each exact revision, ref, PR, and current state in
`workspace-manifest.candidate.json`.

The pins were read from remote PR metadata on 2026-09-10. The watchdog
integration is draft PR #8 at
`c472f3aab726fa2871b46aede6d1985be4e57dae`, based on
`codex/watchdog-implementation`. The serial all-feature workspace gate and
hosted run `34478258456` (Ubuntu, Windows, standards, dependency audit, and
locked release builds) passed at this exact tip. The gateway remains draft PR #35 at
`8ce3f78bf8b0f0970b5c6a47f7d46e5010c05711`. The harness follow-up is draft PR
#54 at `5798e3d0ecd6e64cbd1b6d354311be64a12f8929`, with its hosted checks
green; it follows merged PR #50. MCP PR #37 at
`16ca0cb06dc93564c14963bc544bef282b38d26d` is now merged as
`a6b9215db1ddeeddabe4c111ed3b49476fb86e54`. The game-mod, protocol,
game-core, and observability entries remain exact PR heads; protocol #24 is
conflicting against its recorded/current main and is not an integrated
release. No claim is made that these moving heads compose, install, activate,
or run on a live host.

Required next gate: rebuild and test this exact set together, verify immutable
artifact digests, then run the separately authorized native Windows/Linux/WSL,
activation/rollback, cold-boot, and soak lanes. Until those gates pass, do not
change the manifest classification to an activated release.
