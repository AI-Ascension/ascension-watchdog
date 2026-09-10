# Candidate source set — 2026-09-10

This record pins the remote pull-request heads used for the next integration
review. It is deliberately a candidate source set, not an activated release:
the JSON manifest records each exact revision, ref, PR, and current state in
`workspace-manifest.candidate.json`.

The pins were read from remote PR metadata on 2026-09-10. The watchdog
integration is draft PR #8 at
`0935c66ddf4befe7fe7c17f3ba785af02057b3aa`, based on
`codex/watchdog-integrated-20260910`. The serial all-feature workspace gate and
hosted run `34480654731` (Ubuntu, Windows, standards, dependency audit, and
locked release builds) passed at this exact tip. Gateway draft PR #35 is now
current-main-based at `7272c17f07e1d7e79c82f498eac0855794d476f5` with fresh
Rust-quality and repository-policy checks green. It remains open and unmerged.
The harness integration is draft PR #56 at
`427176512eac67257a1b065f8508f37d2ed2255c`, combining the recovery and worker
admission repairs on current main; Rust-quality and policy checks are green.
PRs #54 and #55 remain open drafts with unchanged heads. MCP PR #37 at
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
