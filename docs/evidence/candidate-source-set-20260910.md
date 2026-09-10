# Candidate source set — 2026-09-10

This record pins the remote pull-request heads used for the next integration
review. It is deliberately a candidate source set, not an activated release:
the JSON manifest records each exact revision, ref, PR, and current state in
`workspace-manifest.candidate.json`.

The pins were read from the remote PR metadata on 2026-09-10. The candidate
source pin in the manifest is implementation head
`3ae1a22f685228420074e7703b9db492cc16b861`. Its hosted dependency, Ubuntu,
Windows, and standards checks passed in runs `34466829755` and `34466829733`;
later documentation-only pin-alignment commits do not change that source
candidate. The preceding source commit
`572a62dd1bbc5bd39ca13b5f30455ba1e786ef8c` also had green hosted checks. The
companion set includes open draft PRs, the merged harness PR head, and the
unmerged harness recovery-catalog PR #53 at
`6fcd059b420a1099ec225a907ee3aea5e799f0e7`; that PR's hosted Rust and policy
checks pass. No claim is made that these moving heads compose, install,
activate, or run on a live host.

Required next gate: rebuild and test this exact set together, verify immutable
artifact digests, then run the separately authorized native Windows/Linux/WSL,
activation/rollback, cold-boot, and soak lanes. Until those gates pass, do not
change the manifest classification to an activated release.
