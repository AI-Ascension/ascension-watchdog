# Open independent review findings

Classification: confirmed reproduction findings on the named revisions. These
are release blockers, not completed requirements. Passing existing tests did not
establish the missing safety properties.

## Watchdog core

Independent V4 review of `7e72b828c0eb4cc0d5dbf32471963f725344e5f3` reproduced:

| Finding | Affected source | Required correction / owner |
| --- | --- | --- |
| Live persisted orphan survives stop while daemon exits | `runtime.rs` orphan recovery and stopped-loop exit | Exact platform-owned cleanup and truthful stopped postcondition; root/platform |
| Spawn precedes durable identity and failure can leave an untracked child | `runtime.rs` launch; `process.rs` drop | Durable launch intent, containment and cleanup across partial launch; root/platform |
| Runtime supplies no actual heartbeat/progress evidence | `runtime.rs` observations; `policy.rs` suspect handling | Authenticated owner-loop health, meaningful phase policy and dependency admission; root/companions |
| Descendants survive direct-child kill and pipe readers detach | `process.rs` termination/readers | Job/cgroup containment and bounded reader cleanup; root/platform |
| Forward wall-clock jump clears restart budget | `storage.rs` restart records; `policy.rs` cooldown | Conservative persisted accounting with monotonic elapsed observations; W3 |
| Read-only status can create a missing database under unlink race | `storage.rs` open; `cli.rs` status/doctor | Noncreating read-only connection and explicit owner writes; W3/root admin |
| Restore revives backed-up running intent and can mix deployment identity | `storage.rs` restore | Stopped/quarantined restore admission, identity validation and fresh namespace; W3 |
| Malformed metadata becomes healthy-looking empty/zero status | `storage.rs` metadata parsing | Strict corruption errors; W3 |

V4's isolated reproduction checks deliberately demonstrated bad behavior; their
passing result is not a safety pass. V6 is converting them into persistent tests
that assert safe postconditions. W3 fixes and native platform integration require
independent revalidation before these entries can close.

Native Windows CI at `db87af7f3b9b6787b373199358063ca3ed2ad56e` passed lint
but failed `lock_allows_one_controller`. Run `34065906618`, Windows job
`101574487204`, did not return the expected typed `Busy` outcome for lock
contention. W3 owns cross-platform contention classification and verification.

## Synthetic host fidelity

Independent A5 review of fixture source integrated at `db87af7` found missing
frame-schema checks, incorrect response capability/proof construction, invalid
action digest fixtures, inconsistent deployment/instance identities, incomplete
lease renewal/revocation checks at queued execution, inconsistent witness reuse,
and under-specified reconciliation. The frozen runtime-v3 adapters always return
synthetic unknown and cannot yet drive a real companion workflow.

A6 repairs the fixture in isolation. Its current nine passing tests therefore
prove only their narrow subprocess cases, not contract conformance, faithful
companion integration, or the required fault matrix. No fake-host result is
live-game, native-service, reboot or soak evidence.

## V18/V19 release blockers, 2026-09-07

Independent source review of the current integration and uncommitted companion
handoffs identified the following unresolved requirements. Passing component
tests do not close these findings; exact repaired release-set tests are required.

- Linux helper authorization still needs trusted delegated-root and bootstrap
  identity binding. Matching a supplied leaf and actual membership is insufficient
  to authorize an arbitrary sibling subtree or caller-selected configuration.
- Native post-spawn proof failures must not clean the durable intent while the
  process remains owned/alive. Windows prepared Job cleanup, incarnation binding,
  and leader-exit descendant proof also remain under repair (P8/P9).
- The proposed synthetic group cleanup `37f603c` is **not integrated**: it signals
  numeric group IDs after leader reaping and repeats signals during Drop, leaving
  a group-ID reuse risk. P7 must preserve exact ownership through cleanup.
- Gateway bootstrap currently creates local authority without forwarding the
  bootstrap required by managed host initialization. Host-fence admission then
  cannot complete in the actual MCP/gateway/host path.
- Gateway's runtime-v3 adapter substitutes the profile digest for the action
  catalog digest; the host uses a different ad-hoc catalog serialization. Both
  must consume the same exact approved catalog bytes for the verified boundary.
- Gateway validates witness gameplay generation against authority fence
  generation, conflating independent counters. Historical witnesses need exact
  original operation/fence context, not incidental equality of these counters.
- Asynchronous host settlement is not queried by gateway reconciliation, so the
  gateway can remain uncertain indefinitely even when the host retained a witness.
- Managed lease validation omits supplied deployment, instance, and authority
  generation checks. Managed bootstrap also lacks a safe authority replacement
  path. Wall-clock lease expiry, release-byte pinning, timer relationship checks,
  and game-thread persistence remain review concerns.

V20 is reviewing the gateway handoff before source repair resumes. The mod
handoff remains uncommitted. No live host, native service, reboot or soak pass
is implied by this source evidence.

## Follow-up wave, 2026-09-10

The gateway response-classification repair `4c4d465a6cda59dee97e9932444f557bb51c7028`
is included in current-main merge commit `7272c17f07e1d7e79c82f498eac0855794d476f5` and
now maps malformed, oversized, unauthenticated, or otherwise invalid
post-write host-lease replies to the durable `unknown` outcome, with 20 host-
lease tests, 173 runtime tests, and 13 recovery-safety tests passing in its
isolated worktree. This closes only that response-classification defect; the
current-main-based branch is clean/open draft and the host-ticket,
execution-witness, and asynchronous-settlement findings remain open.

The Linux watchdog repair `156917bd52adb302ba0d51d008f0ae44f8c896fb` also
retains missing planned containment as cleanup uncertainty rather than treating
absence as `AlreadyExited`. Focused and serialized workspace tests passed, and
hosted watchdog run `34480654731` passed after publication. Native cgroup,
Windows SCM/Job Object/WSL, service, live-host, reboot, and soak evidence remain
unverified.

## Restore publication follow-up, 2026-09-10

Hosted Windows execution of watchdog predecessor `cacb2b9` found four restore
tests failing with `Access is denied` during staging-file publication. The
failure was a source-handle lifetime defect in the new atomic restore path: the
publisher called `sync_all` and renamed the staging file before dropping the
reopened handle. Commit `fa0787620e768266c683da178c81b5af7198bc39` now drops
that handle before `rename`; local restore, CLI, Linux installer, full test,
format, Clippy, and standards checks pass. Hosted reruns
`34501110421`/`34501117723` were pending at capture. This repair closes the
specific publication defect only; it does not establish native service,
cross-repository, live-host, reboot, or soak evidence.
