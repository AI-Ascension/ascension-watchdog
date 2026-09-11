# Unified cross-repository build-set workflow

Classification: `implemented orchestration; build and component-conformance
evidence only`. This record describes the reproducible workflow that turns the
read-only source-set gate into an executable, repeatable integrated build and
conformance run. It is not an installed service, activation, live-host, reboot,
rollback, or soak result, and it makes no such claim.

## Purpose

The prior workspace could verify an exact source set (commit pins, clean
worktrees, artifact checksums, and the serialized `coop-native-v1` consumer
contract) but had no executable way to compile that same admitted set. The
`watchdog release build-set` command closes that gap: it refuses to build an
unadmitted set and, only after admission, runs each repository's declared
ordered steps — typically a locked build followed by that repository's
conformance test — in the repository's own worktree.

## Command

```text
watchdog release build-set \
  --manifest PATH \
  --plan PATH \
  --repo NAME=PATH [...] \
  [--artifact NAME=PATH [...]] \
  [--scratch PATH]
```

- `--manifest` is the exact source-set manifest accepted by
  `watchdog release source-set verify`.
- `--plan` is a declarative JSON plan (below). It never carries a worktree path,
  so a stale absolute path cannot be committed.
- `--repo`/`--artifact` are the same `NAME=PATH` worktree inputs used by the
  source-set gate.
- `--scratch` is the only writable location the orchestrator creates; it
  defaults to the process temporary directory. Repository worktrees are never
  written to.

The command prints a JSON `BuildSetReport` on both success and failure. Success
requires `admitted`, `built`, and an empty `issues` array; any other result exits
non-zero with the report on standard output.

## Build plan schema (v2)

```json
{
  "schema_version": 2,
  "classification": "current-main-refresh-build-and-conformance-not-activated",
  "toolchain": "1.97.1",
  "repositories": {
    "sts2-gateway": [
      {"name": "build", "program": "cargo", "args": ["+{toolchain}", "build", "--locked", "--release"],
       "env": {"CARGO_TARGET_DIR": "{scratch}/target"}, "timeout_seconds": 3600},
      {"name": "recovery-conformance", "program": "cargo",
       "args": ["+{toolchain}", "test", "--locked", "-p", "sts2-gateway", "--test", "recovery"],
       "env": {"CARGO_TARGET_DIR": "{scratch}/target"}, "timeout_seconds": 3600}
    ]
  }
}
```

- A repository maps to an ordered list of steps. A single object is also
  accepted (a one-step sequence), and an optional `default` step list is used for
  repository entries set to `null`.
- `program` must name an executable on `PATH`; absolute paths are rejected so a
  committed plan cannot smuggle a local path.
- A step with an empty program, an absolute program, or a zero timeout is
  rejected before any command runs; a repository with no steps is rejected.
- Placeholders: `{toolchain}` resolves from `toolchain`, `{root}` resolves to the
  canonical repository worktree, and `{scratch}` resolves to that repository's
  scratch directory. An unresolved placeholder fails before the command starts.
- Steps run in order with a bounded wall-clock timeout, a null standard input,
  and bounded stdout/stderr tails in the report. After a failed step the
  remaining steps for that repository are recorded as `skipped`, so a
  conformance result is never reported for an unbuilt revision.

## Admission first, build second

The orchestrator calls the same `source_set::verify_document` verifier used by
`release source-set verify`. When the manifest is not admitted, the report has
`admitted=false`, `built=false`, an empty `repositories` map, and the verifier's
issues; no build command is executed. This ordering is the point of the tool: a
green build or conformance result can never be attached to an unverified source
set.

## Committed plan for the admitted current-main set

`workspace-build-plan.current-main-refresh-20260911.json` pins a locked
`cargo +1.97.1 build --locked --release` step for the seven repositories that
carry a root `Cargo.toml` in
`workspace-manifest.current-main-refresh-20260911.json`, plus a conformance test
step for the repositories that expose one:

| Repository | Conformance step |
| --- | --- |
| `ascension-watchdog` | `-p watchdog-fault-fixture --test schema` (schema conformance) |
| `sts2-gateway` | `--test recovery` (lease/fence/restart) |
| `sts2-harness` | `completed_resume_process`, `execution_store`, `replay`, `phase2_recovery` |
| `sts2-mcp-server` | `--test runtime_v2_artifact` |
| `sts2-protocol` | `--test coop_native_consumer_conformance` |
| `sts2-game-mod`, `sts2-game-core` | build only |

`ai-agent-observability` is admitted by the source-set gate but is not a Cargo
workspace, so it has no step. Build and test output is directed to
`{scratch}/target`, keeping every companion worktree clean.

## Boundary

A passing build-set is compile and component-conformance evidence for the exact
pinned inputs. It does not install a service, activate a release, exercise the
game/provider path, recover a live host, survive a cold boot, roll back, or run a
soak. Those axes remain separately reported in the requirements ledger.
