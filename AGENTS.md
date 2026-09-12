# Ascension watchdog contributor instructions

Follow the implementation objective in `prompts/IMPLEMENTATION.md` and organization
policy. This repository owns deterministic deployment supervision, owner-local
storage, restricted process adapters, operational commands, and integration tests.
It does not own gameplay, game leases, provider execution, or experiment semantics.

Use Rust for product logic and tests; thin shell/PowerShell service wrappers are
permitted. No Python or proprietary game material. License original source MIT.
Keep unsafe code forbidden except a separately reviewed platform boundary with
explicit invariants. No production panic, unwrap, expect, todo, or unimplemented.

Read `docs/architecture.md` before changing boundaries. Persist intent before
effects, retain unknown outcomes, and never restart against durable stop intent.
Use separate databases owned by watchdog, gateway, and harness. Never import
sibling implementation crates by path. Keep secrets and local paths out of commits.

Work on isolated branches/worktrees; preserve unrelated changes. Root owns shared
manifests, lockfile, normative schemas and integration. Commit explicit paths only.
Do not merge, deploy, install services, run games, or reboot hosts without the
applicable authorization. Synthetic child processes are authorized by the objective.

Required gates: pinned-toolchain locked build, fmt check, Clippy with warnings
denied, all workspace tests, schema conformance and relevant fault tests. Label
build, synthetic, native service, live host, reboot and soak evidence separately.

Development descendants use `gpt-5.6-luna` with reasoning effort `max` through native
spawn arguments. Root reserves at most 12 total descendants including waiting
managers. Depth 3 is a leaf and must not spawn. No alternate-client ancestry reset.
Every task has an owner, allowed paths, base commit and explicit acceptance evidence.

## Workspace, branch, and artifact hygiene

Before creating an isolated checkout, declare the exact absolute worktree path and the exact branch name. Create it only with `git worktree add <absolute-path> -b <branch-name>` (or attach the explicitly named existing branch). Do not create branch copies, sibling checkouts, backup trees, archive trees, or `*-tmp*` directories as substitutes for a Git worktree; do not use generated or random paths for branch isolation.

Perform edits and validation only in the declared checkout. Put build output, test fixtures, logs, and other derived artifacts in the repository's designated rebuildable output directory (such as `target/`) or a single declared task scratch path, never beside repositories or directly under `/home/agent`. Remove task scratch/output after it is no longer needed, and remove the worktree with `git worktree remove <the-same-absolute-path>` once its branch is integrated or abandoned. Preserve source, committed evidence, and any path explicitly retained by the task owner.
