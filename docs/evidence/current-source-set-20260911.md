# Current source set and verification boundary — 2026-09-11

Captured at `2026-09-11T06:53:43Z`. This is a resumable integration record,
not an activated release. Every revision below is an exact local source
revision; a component passing its own gates does not establish cross-consumer,
service, live-host, reboot, or soak evidence.

## Exact source set

| Repository | Ref / delivery | Revision | State |
| --- | --- | --- | --- |
| `ascension-watchdog` | `codex/watchdog-resume-20260911` / PR [#11](https://github.com/AI-Ascension/ascension-watchdog/pull/11) | `06c130726faaef2dd792881c7e9d3d039b6c732f` | open; CLI quarantine/diagnostics patch; local and hosted source gates pass |
| `sts2-gateway` | `main` | `5f531f602298de674bd31ed3f28a88359b02ca9d` | current remote main; component gates pass |
| `sts2-harness` | `main` | `00bd9e123a86fca39bbffb65b370aac7ed2c8218` | current remote main; component gates pass |
| `sts2-mcp-server` | `main` | `98ab84b3fad371b45b141e6d81dd9124769a4c59` | current remote main; component gates pass |
| `sts2-game-mod` | `main` | `bd8e90542dfc89366f820150c5c755e32716b1b0` | current remote main; component gates pass |
| `sts2-protocol` | `main` | `0bc689eabc5542ede2b09b030d9ea32daa8a73e7` | current remote main; artifact/conformance tests pass |
| `sts2-game-core` | `main` | `f5daf69f4f2c43fddbb04e7799d32503f7066110` | current remote main; component gates pass |
| `ai-agent-observability` | `main` / merged PR [#20](https://github.com/AI-Ascension/ai-agent-observability/pull/20), [#22](https://github.com/AI-Ascension/ai-agent-observability/pull/22) | `630431716ebfbf86280f9fd56f19d6016ad7aeb2` | current remote main; persistent Collector queue/WAL, materialization repairs, and static-probe portability merged |

A gateway safety follow-up was opened after this source-set capture: PR
[#42](https://github.com/AI-Ascension/sts2-gateway/pull/42), commit
`83539a9dd669eb4c8da69033c06d45f114300c45`, is based on gateway main
`5f531f602298de674bd31ed3f28a88359b02ca9d`. It checks that the durable host
install and renewal transitions changed exactly one row before exposing a
host-effect candidate. Its local component gates and hosted Rust quality and
repository-policy checks pass (workflow run `34573234477` and
`34573234541`). This pending branch is not part of the exact source set or
release admission until the owning repository reviews and merges it.

The source set was fetched into isolated worktrees. No changes were made to
the companion `main` worktrees. The earlier observability review branch PR #21
was closed as superseded by merged PR #20; its persistence work is represented
by current observability main. The static-probe fallback is now merged in PR
#22, but neither observability change is silently treated as an activated
release artifact.

## Gates executed

The watchdog passed pinned-toolchain format, standards validation, workspace
check, strict Clippy, and the full serial all-target/all-feature test command:

```text
cargo +1.97.1 fmt --all -- --check
cargo +1.97.1 run --locked --manifest-path standards/tools/standards-sync/Cargo.toml -- validate --root .
cargo +1.97.1 check --locked --workspace --all-targets --all-features
cargo +1.97.1 clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo +1.97.1 test --locked --workspace --all-targets --all-features --no-fail-fast -- --test-threads=1
```

The final test command exited zero; it included 206 watchdog library tests,
all watchdog integration suites, fault-fixture suites, and the platform
packages, with only the repository's four expected ignored watchdog tests and
the separately labeled platform-boundary ignores. The new executable CLI
quarantine path and read-only diagnostics test are included.

Gateway, harness, MCP, game-mod, protocol, and game-core each passed their
locked workspace format, strict Clippy, and all-target/all-feature test gates
in their isolated source worktrees. The observability main worktree passed its shell
syntax, validation-regression, bootstrap, installer-guard, materialization-
guard, query-provision, and Collector persistence fixture suites on merged
main. Its health-probe fixture passed on current main after the portable
`readelf` fallback was merged. The official
`otel/opentelemetry-collector-contrib:0.160.0` binary validated the updated
Collector configuration with
`--feature-gates=+extension.healthcheck.useComponentStatus`.

Docker and Podman are not installed here. Therefore Compose rendering, image
build, live named-volume permissions, queue restart recovery, and service
health are not claimed. `tests/compose-invariants.sh` failed only at its
required `docker` invocation (`command not found`); this is an environment
blocker, not a passing Compose result.

## Artifact and consumer boundary

The inspected `coop-native-v1` copies agree on the schema and conformance
bytes:

```text
schema.json       2f3bc99e53080fa11b39592b64fb0ab964a16f568719a2622d0b2caf766ab629
conformance.json  8da68488ca75de12a73521eee30d3464d8c8c9f3a623a6233f2cf97fb68f43b3
```

The consumer binding is not one byte-identical current set: the protocol
artifact has manifest `ae6b0df...` and consumer-conformance
`ca8a60ba...`; current gateway/MCP copies have manifest `50a7a2b...` and
consumer-conformance `377be44...`; current harness has the same manifest and
consumer-conformance `10f71cbc...`. This is preserved as an admission
failure, not normalized by editing consumer bytes. A unified clean
cross-repository build and current consumer-conformance run were not available
in the repository layout.

## Completion axes

| Axis | Current classification |
| --- | --- |
| `IMPLEMENTATION_COMPLETE` | watchdog implementation patch complete and tested; full cross-repository assignment not complete |
| `SYNTHETIC_INTEGRATION_VERIFIED` | partial; watchdog and component synthetic suites pass, exact current consumer set is not unified |
| `WINDOWS_SERVICE_VERIFIED` | unverified; no installed SCM session |
| `LINUX_SERVICE_ADAPTER_VERIFIED` | source/unit and synthetic adapter tests pass; installed systemd adapter unverified |
| `LIVE_HOST_RECOVERY_VERIFIED` | unverified |
| `COLD_BOOT_RECOVERY_VERIFIED` | unverified |
| `SOAK_VERIFIED` | unverified |
| `REMOTE_DELIVERY_STATUS` | watchdog PR #11 open with hosted gates green; gateway PR #42 open with local and hosted gates green; observability PRs #20 and #22 merged; no activation |
| `BLOCKED_EXTERNAL` | yes: native authorized hosts, Docker/Podman, unified consumer build, and nested spawn surface are unavailable |

The historical native Linux process-boundary smoke remains linked from the
README and is not promoted here: it used a synthetic gateway/MCP downstream
and did not verify a service, gameplay, provider, reboot, release, or soak.
Only depth-1 delegation was observed in the available orchestration records;
no depth-2 or depth-3 child was created, and no depth-4 bypass was attempted.
