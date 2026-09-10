# Candidate source set — 2026-09-10

This record pins the remote pull-request heads used for the next integration
review. It is deliberately a candidate source set, not an activated release:
the JSON manifest records each exact revision, ref, PR, and current state in
`workspace-manifest.candidate.json`.

The pins were read from the remote PR metadata on 2026-09-10. The watchdog
fault-fixture branch is at `9083ffd87bdd5f60364df83db860c3e0b6912555`; the
preceding source commit `572a62dd1bbc5bd39ca13b5f30455ba1e786ef8c` had green
hosted dependency, Ubuntu, Windows, and standards checks, while the current
documentation-only head is awaiting its replacement run. The
companion set includes open draft PRs and one merged harness PR head. No claim
is made that these moving heads compose, install, activate, or run on a live
host.

Required next gate: rebuild and test this exact set together, verify immutable
artifact digests, then run the separately authorized native Windows/Linux/WSL,
activation/rollback, cold-boot, and soak lanes. Until those gates pass, do not
change the manifest classification to an activated release.
