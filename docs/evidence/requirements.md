# V32 requirements and evidence audit

Classification: `partial` / `unverified` source-and-test audit. Historical
entries below are retained for traceability; the Wave 48 addendum and the
machine-readable release-set record carry the current source pins. This audit
does not declare an implementation or release complete.

## Wave 48 current refresh — 2026-09-10

The authoritative watchdog source is PR #9 source
`f5eaf5e35be025015a28da931aa973a0ade8f0ef` with current docs/evidence head
`62bf0fc49d7656e1207dc592a34a4fcd76994ee4` (open draft, latest hosted
Ubuntu/Windows and standards checks passed). The exact Linux worker producer is
merged harness PR #66 feature head
`58dede2eb661133d8910a1f785e8a90346efe8dd`, now harness main
`a0ace6712686cb30d6f0b556cb6814ad4c0721d1` (endpoint merge; current main is
`ce86ced41d8b9e93d19f2c440f28b3223397f3ca` after merged PR #54); its hosted Rust quality/policy
checks passed. Current companion main pins are gateway `8ba5521`, MCP `037d10d`,
game-mod `888b067`, protocol `f22dd72`, game-core `f9db577`, and observability
`89539a6`. See [`release-set-verification-20260910.json`](release-set-verification-20260910.json)
and [`candidate-source-set-20260910.md`](candidate-source-set-20260910.md) for
the full revisions and states.

The explicitly gated native Linux watchdog-to-harness smoke passed **1/1 in
23.21s** with harness image SHA-256
`4b71eeb3c9ff410707ff2272e730889b1378cf4cae1a6b08c7531233f3bb48f2`. This is
confirmed process-boundary evidence only: downstream HTTP-503 gateway and
`/usr/bin/true` MCP fixtures do not establish gameplay/provider settlement,
service installation, release activation, reboot, or soak. The nested
depth-2/depth-3 Luna-Max delegation smoke remains unobserved, and all native
Windows, live-host, cold-boot, and soak axes remain unverified.

### Post-merge endpoint hardening refresh — 2026-09-10 23:40Z

Harness PR #66 hardening feature head `58dede2eb661133d8910a1f785e8a90346efe8dd`
auto-merged after hosted runs `34542578041` and `34542578085` passed; current
harness `main` is `a0ace6712686cb30d6f0b556cb6814ad4c0721d1`. The refresh adds
true bootstrap EOF enforcement, bounded authentication slots/deadlines, and a
sealed runtime-image snapshot. The explicitly gated watchdog native Linux smoke
was rerun against image SHA-256
`5286706d03c27c00e32493c1adf8864e972f7a53d1f863c046aed32d56a1644f` and passed
1/1 in 25.33s. This remains process-boundary evidence with synthetic HTTP-503
gateway and `/usr/bin/true` MCP fixtures; it does not establish gameplay,
provider settlement, service installation, release activation, reboot, or soak.

Gateway restart-fencing follow-up PR #34 is complete at
`87792cf3f6e2c3b6627d3a34bf380bb337c01373`, rebased on current main with hosted
CI/policy and local 270-test validation passing; it subsequently merged to
gateway `main` as `8ba5521c2ec8f158d437a7104567592703e53259`.

### External merge refresh — 2026-09-11 00:24Z

The latest authoritative companion heads are gateway `8ba5521c2ec8f158d437a7104567592703e53259`
(PR #34 merged) and harness `ce86ced41d8b9e93d19f2c440f28b3223397f3ca`
(PR #54 merged after endpoint PR #66). The watchdog evidence head observed for
the hosted run set is `62bf0fc49d7656e1207dc592a34a4fcd76994ee4`; these source
updates still require a clean cross-repository build and native/live gates.

## Scope and evidence boundary

The historical audit snapshot below began from an isolated implementation
branch. Its original commit and PR references are retained in the matrix for
traceability; the current PR/source status is the Wave 48 refresh above and in
`requirement-evidence.json`. The current root record reports:

- `cargo test --workspace --all-targets --all-features --locked --no-fail-fast
  -- --test-threads=1` exit 0;
  the watchdog library ran 200 cases (196 passed, 4 ignored), and all
  watchdog, platform, fixture, recovery, runtime, host-lease, and schema
  integration suites passed.
- Pinned fmt, locked offline workspace check, and strict Clippy passed on Linux.
  A Windows GNU all-target check and strict Clippy cross-build also passed;
  that is compile evidence, not native Windows execution evidence. Two Linux
  cgroup tests remain ignored.
- Draft watchdog PR #9 at `f5eaf5e` re-ran standards, Ubuntu, Windows, and
  dependency jobs; all current hosted checks passed.
- No service installation, release activation, game/provider launch, host
  reboot, live recovery, or soak was performed.
- The fault fixture is a synthetic host/test tool. The watchdog branch now has
  authenticated worker and Gateway-health consumers plus release staging, and
  the harness endpoint PR has a native Linux process-boundary smoke. Companion
  source pins remain a separate candidate set; this is not a cross-repository
  runtime or live-host claim.

Historical review context: the earlier host-lease and gateway catalog findings
remain open at the production-consumer boundary. The current watchdog branch
adds authenticated worker/Gateway-health storage and release-staging checks,
while the companion harness follow-up was PR #54 at `5798e3d` and is now merged
to `ce86ced`, while gateway PR #35 was previously merged at `8ce3f78`. Those source/component results do
not constitute a cross-repository runtime proof. The current matrix remains
conservative: 49 `partial` and 7 `unverified`.

Evidence abbreviations used below:

| Ref | Evidence record or owned boundary |
| --- | --- |
| `CP` | `docs/orchestration/consolidated-integration-checkpoint.json`; exact integrated source/evidence boundary and companion heads |
| `AR` | `docs/orchestration/agent-registry.json`; requested/accepted/observed model and depth evidence |
| `TD` | `docs/orchestration/task-dag.json`; ownership and open integration tasks |
| `FF` | `docs/evidence/fault-fixture.md`; synthetic recovery fixture boundaries and fault controls |
| `FG` | `docs/evidence/fixture-instance-guard.md`; synthetic instance-wide uncertainty guard |
| `SI` | `docs/evidence/platform-backup-integration.md`; root integration and current platform/test boundary |
| `SL` | `docs/evidence/service-loop.md`; real daemon subprocess and notification-path evidence |
| `SR` | `docs/evidence/storage-review.md`; owner-local SQLite, restore, lock and clock evidence |
| `SA` | `docs/evidence/storage-admin.md`; authenticated operator ledger and bounded admission |
| `RI` | `docs/evidence/recovery-baseline.md`; source-derived companion baseline and contract-only limits |
| `OR` | `docs/evidence/open-review-findings.md`; confirmed independent blockers and missing consumer proof |
| `RW` | `docs/evidence/review-repair-wave.md`; current companion/fixture/platform gaps |
| `WI` | `docs/evidence/windows-integration-20260910.md`; repaired Windows cross-build boundary and hosted-CI classification |
| `README` | `README.md`; explicit implementation-in-progress and unclaimed runtime axes |

Status meanings: `partial` means an owned source/test slice is evidenced but
the normative requirement is wider; `unverified` means no admissible evidence
for the required scope exists; `confirmed-synthetic` is used only for a narrow
fixture/process fact and never means native, live, reboot, or release proof.

## Highest-priority missing evidence and implementation

1. Implement and integrate the real host-lease consumer path. The reference
   fixture and host-lease schema do not implement gateway-issued install,
   renew, revoke, host-fence, operation, or managed-mod consumers. Rebuild the
   exact gateway/harness/mod/protocol release set and run cross-consumer
   conformance across current gateway `8ba5521`, harness `ce86ced`, and
   game-mod `888b067` rather than assuming those heads are integrated. (`CP`, `OR`,
   `RW`)
2. Integrate and verify the existing harness recovery-sideband implementation:
   durable canonical payload/context, current-authority reconciliation, explicit
   continuation vs reconstruction vs interrupted-unknown, provider accounting,
   and divergence rejection. The harness source/tests are outside the watchdog
   release set; later H19/H20 repairs remain active. (`CP`, `RW`)
3. Close platform gates: restricted Linux broker/delegated-root identity and
   uncertain cleanup, native Linux service execution, native Windows service/
   Job Object/pipe execution, WSL termination, and configured stop across those
   paths. (`CP`, `OR`, `RW`)
4. Add bounded archival/tombstone semantics beyond the fixture's 64-entry
   backpressure point, persistent telemetry integration, and a real long-running
   campaign. Durable watchdog release activation/rollback is now source-tested,
   but the sealed cross-repository handoff and native campaign remain open.
   (`SL`, `SI`, `RW`)
5. The requested three descendant Luna-Max layers were not observed. The
   registry records nine depth-1 descendants with requested/accepted
   `gpt-5.6-luna`/`max`, but no depth-2 or depth-3 execution because the spawn
   surface was unavailable. (`AR`, `CP`)

## Section requirements S01-S17

| ID | Actionable subrequirements | Owned source and executable tests | Evidence available | Status | Precise gap / next action |
| --- | --- | --- | --- | --- | --- |
| S01 | **S01-a** deterministic Rust watchdog; **S01-b** integrated crash-resilient watchdog/gateway/harness/MCP/mod runtime; **S01-c** Windows-primary topology plus Linux synthetic adapter and one-instance isolation | Watchdog `crates/watchdog/src/{runtime,storage,policy,service,cli}.rs`; `tests/core.rs`, `service_loop.rs`, `job_submission_process.rs`; fixture `src/lib.rs` and `tests/{recovery,runtime}.rs` | `README`; `SL`; `FF`; `CP` | partial | The watchdog and synthetic fixture are concrete, but companion consumers and host-lease/broker paths are not integrated. Produce one exact release set and run the integrated recovery matrix; then separately run native Windows/Linux service gates. |
| S02 | **S02-a** preserve dirty state and isolated ownership; **S02-b** authorized publication/PR/merge state; **S02-c** gated host, reboot, and gameplay tests with no overclaim | Isolated audit worktree; `AGENTS.md`; no product source proves publication or host authorization | `README`; `CP` says no remote/delivery, install, activation, or host action | partial | Isolation is evidenced for this audit and claims are conservative; publication, PR/merge, approved-host authorization, and gated live tests are absent. Record exact remote/PR state and execute only approved host workflows. |
| S03 | **S03-a** requested/accepted/observed Luna-Max settings; **S03-b** genuine depth 1→2→3 ancestry with depth-4 denial; **S03-c** aggregate 12-thread ownership and registry | `docs/orchestration/agent-registry.json`, `task-dag.json`; no depth-2/3 source/test implementation | `AR` records nine depth-1 contexts and missing spawn capability; `CP` | partial | Model/depth-1 evidence is real, but nested depth is unmet and no depth-4 smoke exists. Re-run with supported native nested spawn, capture accepted and observed metadata, and verify depth restrictions. |
| S04 | **S04-a** exact repo/source revisions; **S04-b** executable baseline wiring; **S04-c** current deployment topology and companion runtime evidence | `workspace-manifest.json`; `docs/evidence/{baseline,recovery-baseline}.md`; watchdog executable/source inventory | `RI` is source-derived and explicitly says no runtime claim; `CP` pins root-tested source and companion heads | partial | Root pins a source baseline, but the manifest is not an activated release set and companion heads are moving/unintegrated. Refresh all heads immediately before release and execute actual wiring, not type-existence checks. |
| S05 | **S05-a** ownership architecture; **S05-b** cohesive Rust packages and required docs/schemas/config/deploy/tests; **S05-c** no placeholder/fake-green production paths | Packages `watchdog`, `fault-fixture`, `platform-windows`; `Cargo.*`, `schemas`, `config`, `deploy/linux`, package-level `tests/` suites and docs; package-level tests are the prompt's permitted equivalent to conventional `tests/unit|integration|faults` directories; `deploy/windows` remains absent | `docs/architecture.md`; `README`; `CP` | partial | Windows packaging and cross-repo consumer implementation remain open. Validate the existing equivalent package test suites and add/verify Windows packaging rather than treating directory naming as a gap. |
| S06 | **S06-a** assign executable tests to INV-01..15; **S06-b** cover failure paths and evidence axes, not only happy-path synthetic tests | Invariant mapping below; watchdog and fixture test suites | `FF`, `FG`, `SL`, `SR`, `SA`, `OR` | partial | Many synthetic invariants have narrow tests, but companion/native/live/reboot/soak scope is not covered. Close each invariant's listed next action and rerun the integrated release set. |
| S07 | **S07-a** owner-local SQLite WAL/FULL, lock, migrations, integrity/backup/restore; **S07-b** watchdog jobs/attempts/budgets/operator records; **S07-c** gateway/harness stores and stable identity namespaces; **S07-d** bounded archival without silent reset | `crates/watchdog/src/storage.rs`, `storage_admin.rs`, `storage_backup_admin.rs`; `tests/core.rs`, `storage_*`, `admin_backup.rs`, `job_submission*`; fixture SQLite rows in `crates/fault-fixture/src/lib.rs` | `SR`; `SA`; `FF`; `CP` | partial | Watchdog and synthetic fixture stores are tested, but harness/gateway owner stores are not integrated here; watchdog archival and fixture tombstones remain incomplete. Add owner-specific migrations/identity tests, explicit archival/tombstone protocol, and cross-owner release tests. |
| S08 | **S08-a** fresh durable boot/fence/lease and invalidation; **S08-b** historical read/reconcile without old authority; **S08-c** restore/rekey and rollback protection; **S08-d** real gateway/host consumer | Fixture bootstrap/fence/lease/operation handlers and `tests/recovery.rs`, `runtime.rs`; watchdog `storage.rs` restore | `FF`; `RI`; `OR`; `CP` | partial | The fixture models protocol semantics and watchdog restore rekeys its own store, but no production gateway lease consumer or host handshake is integrated. Implement gateway-issued authority and managed host-fence consumers, then test restart/rollback/rekey on the exact release. |
| S09 | **S09-a** actual v3 persist-before-send journal and uncertainty; **S09-b** host execution-time fence/witness; **S09-c** restricted broker and >64 archival/retention | Fixture operation/ticket/effect tables and fault tests; watchdog has no gameplay journal; companion gateway/mod heads are outside this source | `FF`; `FG`; `RI`; `OR`; `CP` | partial | Synthetic journal ordering and stale-fence tests pass, but the fixture is not the actual v3 path, host broker, or gateway consumer; 64 is backpressure, not archival. Wire and run the real harness→MCP→gateway→mod→host path and exceed receipt capacity with tombstones. |
| S10 | **S10-a** harness explicit resume; **S10-b** MCP sole-owner bounded reconnect; **S10-c** provider identity/accounting; **S10-d** continuation/reconstruction/interrupted-unknown and replay divergence | Current harness main `ce86ced` includes PR #54 recovery/catalog/provider repairs and merged endpoint PR #66; source/component tested but remains outside this watchdog checkout | `CP` records the merged source tests and native worker smoke, but no cross-repository release run | unverified | Do not count companion component tests as release proof. Integrate and independently verify the harness sideband/recovery source, named resume/reconstruction/divergence/provider tests, and cross-repo gates. |
| S11 | **S11-a** persisted desired-state reconciler and separate component/attempt/deployment states; **S11-b** meaningful phase health/timers/budgets; **S11-c** authenticated full operator CLI/API; **S11-d** restart ownership and native service recovery | `crates/watchdog/src/{policy,runtime,service,cli,admin}.rs`; `tests/{core,health_policy,service_loop,admin_control,job_submission*}.rs`; release selector gate | `SL`; `SA`; `README`; `docs/evidence/release-activation.md` | partial | Synthetic daemon/IPC/health, lifecycle commands, and release activation dispatch pass source tests, but other dispatcher operations, scheduler-to-harness handoff, and installed systemd/SCM recovery remain open. |
| S12 | **S12-a** Windows SCM/health checker/Job Object/named pipe/session; **S12-b** WSL exact distro/direct invocation/termination; **S12-c** Linux systemd notify/cgroup/protected state; **S12-d** native synthetic execution | `crates/platform-windows/src/{native,admin_pipe}.rs`; Windows tests; `crates/watchdog/src/platform/{linux,linux_launcher,linux_process,wsl}.rs`; `deploy/linux/ascension-watchdog.service` | `SI`; `SL`; `docs/platform.md`; `docs/evidence/{windows-p9-integration,native-integration-review}.md`; `CP` | partial | Linux portable/source tests and notifications are evidenced, but two cgroup tests are ignored and Windows-native execution is zero on Linux; no service install/WSL failure campaign. Run approved native Windows/Linux/WSL gates and retain skipped status until they execute. |
| S13 | **S13-a** persistent telemetry collector queues/backends; **S13-b** immutable release-set activation/rollback; **S13-c** idempotent install/uninstall/log/disk operations; **S13-d** authenticated backup/restore/rekey | Watchdog `release.rs`, `release_staged.rs`, `storage_release.rs`, `storage_backup_admin.rs`, CLI; `deploy/linux/install.sh`, `uninstall.sh`; observability is external | `docs/evidence/{release-inspection,release-activation,collector-recovery,platform-backup-integration}.md`; `docs/operations-backup.md`; `tests/{cli_restore,admin_control}.rs`; selector unit tests | partial | Protected inspection, durable prepared/active selector, exact previous-release rollback binding, authenticated activation receipt, backup creation, and restore/rekey are source-tested. A sealed cross-repository handoff, collector backend durability, uninstall persistence, and native install/activation tests remain open. |
| S14 | **S14-a** threat model; **S14-b** local authenticated capability separation; **S14-c** closed/bounded/duplicate-safe contracts and path/digest checks; **S14-d** native ACL/reparse/secret controls | `docs/threat-model.md`; `admin/{auth,protocol,endpoint,server}.rs`; `release.rs`, config/path validators, platform boundary tests | `SA`; `docs/admin-control.md`; `docs/windows-process-integrity.md`; `OR` | partial | Watchdog local controls are substantially tested, but real gateway/harness/mod consumers and native Windows ACL/pipe behavior are not executed; known platform/auth review findings remain. Integrate and run native security matrix plus cross-consumer negative tests. |
| S15 | **S15-a** every requirement has source, failure test, evidence class; **S15-b** synthetic fault host covers 24 scenarios; **S15-c** independent review/fix/rerun; **S15-d** native/live/reboot/soak evidence | Fixture recovery/runtime/schema suites, authenticated worker/Gateway-health tests, release-staging tests, platform tests, review docs; no single 24-case acceptance run | `CP`/`SI` current workspace suites; `FF`; `OR`; `RW`; `AR` | partial | Root has broad synthetic evidence and independent findings, but no complete 24-scenario matrix, no nested agent smoke, and no native/live/reboot/soak. Execute the missing named scenarios and record each result, including explicit skips. |
| S16 | **S16-A** capability/baseline; **S16-B** contracts/failing tests; **S16-C** executable vertical slice; **S16-D** authority/journal; **S16-E** harness recovery; **S16-F** platform/operations; **S16-G** integrated verification; **S16-H** remote delivery | Root checkpoint/test commands, package tests, source checkpoints; companion heads explicitly marked unintegrated | `CP`; `TD`; `README`; `OR` | partial | A-D and portions of F have Linux/synthetic slices; E, G, H are not verified, and full release is false. Complete companion integration and independent review, rerun clean release-set gates, then record remote PR/merge/deployment state. |
| S17 | **S17-a** separate completion axes; **S17-b** exact revisions/PRs/artifacts/digests/commands; **S17-c** install/start/status/stop/uninstall/recovery and measured soak; **S17-d** blockers and actual action status | `README`, `docs/evidence/*.md`, `CP`, `workspace-manifest.json`, orchestration records | `CP` explicitly marks release/live/cold-boot/soak/remote delivery false; evidence docs preserve classifications | partial | Evidence axes and blockers are documented, but the final handoff cannot be complete until companion commits, native/live/reboot/soak runs, release artifacts, and remote delivery are verified. |

## Runtime invariants INV-01..INV-15

| ID | Concrete owned source/test boundary | Evidence available | Status | Missing evidence / next action |
| --- | --- | --- | --- | --- |
| INV-01 | `storage::SingletonLock`; `tests/core.rs::lock_allows_one_controller`; `tests/service_loop.rs::competing_controller_is_rejected_before_readiness`; fixture instance/session guards in `tests/runtime.rs` | `SR`; `FG`; `SI` | partial | Watchdog/fixture ownership is tested, but gateway/host lease authority is not integrated. Make the real gateway store/fence competition test prove only one mutating controller. |
| INV-02 | `Store::restore_from_for_owner`, `tests/core.rs::backup_restore_reestablishes_wal_full_and_rekeys_generation`, `storage_regressions.rs::restore_requires_fresh_identity_and_quarantines_old_work`; fixture `lease_policy_and_epoch_history_survive_restart` | `SR`; `FF` | partial | Watchdog restore and fixture lease invalidation do not prove real gateway authority. Add old-boot/lease rejection after gateway restart, restore, expiry, and revoke. |
| INV-03 | `Store::prepare_launch_intent` / `record_launch_proof`; fixture operation intent/dispatch transactions and `recovery.rs::crash_after_admission_is_quarantined_after_restart`; runtime queue | `SR`; `FF` | partial | The production watchdog launch identity is not the gameplay mutation journal. Integrate gateway persist-before-send and verify a crash between each durable boundary. |
| INV-04 | Fixture `response_loss_keeps_effect_witness_and_client_uncertainty`, `malformed_response_does_not_erase_the_durable_receipt`, `crash_after_mutation_retains_witness_without_receipt_or_second_effect` | `FF`; `OR` | partial | Synthetic response loss retains uncertainty, but real gateway transport and host receipt persistence are not proven in the integrated release. Run the same cases through actual gateway/MCP/mod consumers. |
| INV-05 | Fixture `crash_after_mutation...`, `reconcile_rejects_a_reference_with_the_wrong_original_context`; runtime replay and instance barrier tests | `FF`; `FG` | partial | No production reconciliation path is proven at this release endpoint. Add real operation lookup/reconcile that uses original id/digest and asserts zero second dispatch. |
| INV-06 | Fixture lookup/reconcile returns historical data with `mutation_authorized:false`; `recovery.rs::lookup_rejects_a_reference_with_the_wrong_original_context`; watchdog read/admin separation | `FF`; `SA`; `RI` | partial | Fixture/read API is not proven as the real gateway recovery credential path in the integrated release. Integrate current-authorized historical read and prove old receipt/lease cannot admit mutation. |
| INV-07 | Fixture stale queued fence tests and runtime `http_runtime_rejects_queued_old_lease_after_authority_rotation`; platform process identity/launch proof code | `FF`; `FG`; `docs/platform.md` | partial | The authoritative game-host/mod game-thread boundary is not proven in the integrated release. Implement and execute gateway-issued ticket/fence checks immediately before managed mutation. |
| INV-08 | `ServiceLoop`, `Supervisor::reconcile_once`, `SingletonLock`; platform adapters; `service_loop.rs::actual_daemon_notifies_only_after_reconciliation...` | `SL`; `SR` | partial | Synthetic daemon loop has one owner, but SCM/systemd/native launch ownership and companion process supervisors are not all integrated. Run native service/WSL ownership tests. |
| INV-09 | Store jobs/attempts/restart records; `tests/core.rs::claims_and_completion_are_atomic_and_idempotent`, `job_submission.rs::submission_replays_original_job_after_completion_and_stop`, admin control stop/replay tests | `SR`; `SA`; `SL` | partial | Watchdog records are tested; provider/episode completion, budgets, and attempt lineage require integrated evidence from the companion harness. Integrate and execute its provider/job crash and completion tests. |
| INV-10 | Watchdog launch state `prepared/proof_recorded/active/cleaned`; fixture `runtime_releases_instance_barrier_only_after_authoritative_reconciliation` | `FG`; `RI`; `RW` | partial | The watchdog slice has no integrated harness evidence for in-place continuation vs reconstruction vs interrupted-unknown. Integrate the companion policy and execute divergence-stop tests. |
| INV-11 | `service_loop.rs::persistence_failure_cannot_advance_completed_loop_health`; store transactional admission and `storage_admin.rs` rollback tests | `SL`; `SA` | partial | Watchdog persistence gating is synthetic/local; telemetry failure independence and gateway persistence admission are unproven. Add independent telemetry outage and real gateway-store failure tests. |
| INV-12 | `release.rs` compatibility/tamper/path tests; `release_staged.rs` protected inspection; `storage_release.rs` prepared/active selector and rollback; `Store::restore_from`; `cli_restore.rs` rekey/quarantine; config closed validation | `SR`; `docs/evidence/{release-inspection,release-activation}.md`; `docs/operations-backup.md` | partial | Watchdog release selection, protected recheck, replay, rollback binding, and restore clearing are source-tested. Protected saves/consent/model/credential policy across companions and a sealed cross-repository/native activation handoff remain open. |
| INV-13 | Queue/frame/output bounds in admin, platform, and fixture; `receipt_capacity_backpressures_the_sixty_fifth_operation`; runtime history backpressure | `FF`; `SA`; `docs/admin-control.md` | partial | Bounds exist in slices, but archival/tombstones beyond 64, provider/telemetry/log limits, and long-run growth are open. Execute capacity-plus-archival and soak tests. |
| INV-14 | Authenticated admin queue/ledger; `admin_control.rs::real_service_dispatch_persists_stop_and_old_start_cannot_revive_it`, `job_submission_process.rs::actual_daemon_and_cli_processes...`, launch-stop tests | `SA`; `SL`; `docs/admin-control.md` | partial | Durable watchdog operator control is evidenced, but uninstall/native service restart and full command implementation are not. Complete unsupported dispatcher operations and native stop/pause/uninstall tests. |
| INV-15 | Evidence classifications in `README`, `FF`, `SL`, `SI`, `CP`; separate test commands and explicit ignored/native labels | `CP`; `README` | partial | Classification discipline is present, but no live/reboot/soak axes exist to verify. Run and record each axis independently; never promote component or synthetic evidence. |

## Fault matrix FAULT-01..FAULT-24

| ID | Concrete source/test/evidence available | Status | Precise missing next action |
| --- | --- | --- | --- |
| FAULT-01 | `AR` records nine depth-1 Luna/max contexts and no depth-2/3; `task-dag.json` records nested delegation unavailable | unverified | Execute a native depth-3 routing smoke with depth-4 denial and capture accepted/observed model, effort, ancestry, and concurrency metadata. |
| FAULT-02 | `tests/core.rs::lock_allows_one_controller`; `service_loop.rs::competing_controller_is_rejected_before_readiness`; fixture owner lock and instance guards | partial | Add the same competition test to the real gateway authority store and host-fence consumer; retain `BUSY` and no-second-controller postconditions on native platforms. |
| FAULT-03 | Fixture fault points `before/after-admission`, `before/after-mutation`, `before/after-receipt`; recovery tests cover admission and mutation crashes; watchdog transaction-failure tests cover selected stores | partial | Add crash tests for every listed boundary in the actual gateway, harness checkpoint/provider, watchdog job completion, and storage-durability paths; distinguish process death from power loss. |
| FAULT-04 | `recovery.rs::response_loss_keeps_effect_witness_and_client_uncertainty`; malformed response/receipt retention tests | partial | Run response-loss through real gateway→host transport and assert no second effect after reconciliation; synthetic fixture alone is insufficient. |
| FAULT-05 | Fixture `conflicting_expected_boundary_reuse_is_rejected`; runtime replay; watchdog job idempotency/conflict tests | partial | Integrate operation identity into gateway/harness and test same payload retained result, conflicting payload rejection, and no second dispatch across reconnect/restart. |
| FAULT-06 | Fixture stale queued fence, revoked ticket, lease epoch history, runtime old-lease rejection, host-lease reference lifecycle | partial | Execute old boot/lease/session/incarnation proofs through actual gateway/managed host queues after replacement, including pre-crash queued work. |
| FAULT-07 | Fixture `lookup_rejects_a_reference_with_the_wrong_original_context`, `reconcile_rejects_a_reference_with_the_wrong_original_context`, historical lookup mutation flag | partial | Wire current `recovery_read`/`recovery_reconcile` credentials in real gateway and prove old authority/receipt cannot mutate or rewrite identity. |
| FAULT-08 | Fixture `malformed-response` is host-side only; current harness main `ce86ced` includes source/component-tested PR #54 recovery/provider repairs but is not cross-repository integrated | unverified | Verify MCP death, inference stall, invalid credentials, quota, outage, timeout, cancellation, and conservative billing tests at the harness/provider boundary in the exact release set. |
| FAULT-09 | Watchdog completed-job replay tests (`job_submission*`); provider/episode ownership is in the companion harness, not this watchdog checkout | partial | Integrate and execute companion harness crash-after-provider-result and crash-after-completed-episode tests with durable result fingerprint and no duplicate inference/job completion. |
| FAULT-10 | Fixture crash/restart and authority rotation tests model a synthetic host; the production gateway path is not integrated at this endpoint | unverified | Kill/restart the real gateway while host/broker survives; require fresh boot/fence, retain UNKNOWN, and verify no mutation before reconciliation. |
| FAULT-11 | Watchdog synthetic subprocess crash/cleanup, Linux adapter source/tests, WSL argument validator; `CP` says native tests/host absent | partial | Run approved game/broker/watchdog/service-manager/WSL failure campaign with exact child ownership and uncertainty postconditions; install no service until authorized. |
| FAULT-12 | `storage_regressions.rs` corruption/missing/restore, `storage_progress.rs` rollback, admin backup integrity/capacity tests, release inspection | partial | Add disk-full/read-only/torn-record/busy-lock/migration-interruption/incompatible-backup tests to every owner store; prove no silent delete/reset and explicit operator recovery. |
| FAULT-13 | `clock_regressions.rs`, launch binding and identity tests, platform partial-launch cleanup source; Linux cgroup cases ignored | partial | Add boot/suspend-resume/clock adjustment/PID-port reuse/partial-launch/hung-cleanup tests on native service targets, with fresh authority after ambiguity. |
| FAULT-14 | Admin lifecycle durable stop/pause/replay tests, `launch_stop.rs`, backup command tests; no uninstall/native restart | partial | Exercise stop/pause/uninstall at every recovery stage across daemon and machine restart; implement and verify uninstall's durable no-restart intent and data option. |
| FAULT-15 | `collector-recovery.md` proves synthetic Collector queue overflow/process replacement in external repo; no watchdog telemetry integration | partial | Integrate persistent collector queue/backend outage/drop accounting and independently fail telemetry while authoritative persistence remains healthy. |
| FAULT-16 | Admin queue/frame/output bounds, fixture 64-receipt bound, runtime operation-history backpressure, process bounded readers | partial | Cover logs, telemetry, child output, provider queues, and retention in one bounded campaign; prove unresolved operations remain and memory does not grow unbounded. |
| FAULT-17 | `recovery.rs::receipt_capacity_backpressures_the_sixty_fifth_operation` returns `BOUNDS_EXCEEDED` without evicting unresolved work | partial | Add explicit archival/tombstone horizon tests beyond 64 resolved receipts and verify deduplication after archive; capacity backpressure alone is not tombstone semantics. |
| FAULT-18 | No integrated harness reconstruction evidence at this endpoint; `RW` leaves reconstruction/divergence open; fixture only reconciles synthetic witnesses | unverified | Integrate and verify the companion checkpoint/verified-prefix reconstruction with new attempt/incarnation lineage and changed seed/build/catalog/divergent action rejection tests. |
| FAULT-19 | Fixture response loss, UNKNOWN after mutation/revocation/stale lease, runtime `not_found`/recovery-required paths | partial | Run the actual host/gateway path and assert unknown/not-found/generation changes cannot settle or prove non-execution; preserve original operation identity. |
| FAULT-20 | Admin duplicate/unknown/oversized frame tests, config/path/reparse tests, release path tests, platform bounded-input tests | partial | Compose a cross-repo unauthorized/malformed/credential/path/reparse/launch-bypass matrix and execute native Windows ACL/named-pipe and Linux identity lanes. |
| FAULT-21 | `release.rs` mixed profile/schema/build compatibility tests; fixture schema/manifest digests; `RI` contract rules | partial | Build a clean exact release set with gateway/harness/mod/protocol digests and prove partial upgrades/identical names with changed bytes are rejected before mutation readiness. |
| FAULT-22 | `health_policy.rs`, `service_loop.rs`, progress persistence and blocked/paused tests; no native watchdog hang/SCM lane | partial | Inject a real control-loop hang and validate bounded OS recovery, while healthy blocked/paused loops are not restarted; run systemd/SCM rather than Unix test doubles. |
| FAULT-23 | No live campaign; `CP` explicitly says no host launch/reboot and `README` disclaims live recovery | unverified | Execute the approved disposable-host crash and cold-reboot campaign with session availability and versioned evidence; do not substitute synthetic subprocesses. |
| FAULT-24 | Accelerated 4,106 paused-loop reconciliations and Collector process replacement exist, but neither is a 24-hour end-to-end soak; `CP` says soak false | unverified | Run configurable 24-hour cross-repo soak across restart, archive, budget, and telemetry outage; record elapsed duration, bounds, and duplicate-effect evidence. |

## Current-wave addendum — 2026-09-10

The historical matrix above remains intentionally conservative. The earlier
component snapshot at `92619c4c85984256a64c7387e0949d7d737401e1` and its
implementation parent `5b235f9524ecbb9529392dafee2328545666f356` are retained
for traceability; the current watchdog source-tested commit is `0542ab87f58d7aa38be35ccd407d202e224e2789`.
Pinned-toolchain checks passed: standards validation, format, strict Clippy,
206 watchdog library tests, all workspace integration suites, the five selector
tests, the two restore CLI tests, the namespace-isolated Linux installer test,
and the current 10-case adversarial suite (4 expected workspace tests ignored).
Hosted validation runs `34524471744` and `34524473975` passed on both Ubuntu
and Windows; standards runs `34524471775` and `34524473943` passed. The hosted
service-session step remains explicitly `UNVERIFIED` on runner session 2; the
session-0 tests did not execute.

The refreshed current-main companion set is gateway
`de1fe72345ea972d56c05d30837da5327e5f1655` (PR #38, including #37), harness
`5cc486a66b6f11930675af06f7426cd91c609983` (PR #59), MCP
`9fa09faed351a27bfeaebc2344af7ffd12ac784d` (PR #38), game-mod
`a70a5e5bb2fa89fade7e16dbb4a58ed80e31355b` (PR #70), protocol
`678885687e46a43f53b9eec108dfb160fc9a13bd` (PR #33), game-core
`f9db577530a4d159b066d3facbd780d61c044eb0` (PR #9), and observability
`d7e79e1a9663601013e513048caea7063b0de9ae` (PR #16); all are merged. Current
component gates pass in isolated worktrees, but the conformance audit found
that protocol, gateway, and MCP expose source-level coop-native-v1 surfaces;
harness and game-mod have no matching native coop consumer, and the shared
consumer-conformance record remains component-pending. A unified
cross-consumer build remains unavailable.

The nested delegation requirement remains unmet: descendant contexts exposed no
native spawn surface, so only depth 1 was observed and no depth-4 bypass was
attempted. No cross-repository build, service installation, live host, cold
boot, activation, rollback, or soak evidence is promoted by these
source/component results.

See `docs/orchestration/integration-wave-20260910.json` and
`docs/evidence/current-source-conformance-20260910.md` for the resumable task
record, exact current refs, component gates, artifact comparison, and boundary.

### Activation addendum — source commit `0542ab8`

The source working tree extends the prior current-main snapshot with a durable
release selector and runtime admission fence. At source commit `0542ab8`,
`storage_release.rs` persists a
prepared marker before the final protected catalog check, retains the exact
previous identity, atomically commits the active/previous selector with the
authenticated operator receipt and audit row, replays the same idempotency key,
and restricts rollback to the recorded previous release. `Store` validates the
selector on owner and read-only opens, and restore/rekey clears it. The
dispatcher and CLI expose authenticated `release activate` and `release
rollback`; configured-catalog launches remain blocked until an active selector
still matches protected bytes and configuration compatibility.

Current source tests are `storage::storage_release::tests` (5 passed),
`runtime::tests::configured_release_catalog_requires_explicit_activation_before_launch`
(1 passed), and
`admin_control.rs::real_service_read_credential_inspects_configured_release_without_store_writes`
(1 passed). The complete locked workspace all-target/all-feature suite (206
watchdog library tests passed, 4 ignored) and warnings-denied Clippy pass after
this integration. This moves the watchdog portions of S11,
S13, INV-12, and FAULT-21 from “not implemented” to confirmed source-tested
partial evidence; it does not promote the wider rows because no sealed
cross-repository handoff, native service activation, live host, reboot, or soak
run has occurred.

## Delivery decision

This audit supports `IMPLEMENTATION_COMPLETE = unverified`,
`SYNTHETIC_INTEGRATION_VERIFIED = partial` (Linux/synthetic source and tests at
`0542ab8`, with native Windows execution still pending), `WINDOWS_SERVICE_VERIFIED = unverified`,
`LINUX_SERVICE_ADAPTER_VERIFIED = partial` (portable/source tests with two
ignored cgroup cases), `LIVE_HOST_RECOVERY_VERIFIED = unverified`,
`COLD_BOOT_RECOVERY_VERIFIED = unverified`, `SOAK_VERIFIED = unverified`, and
`REMOTE_DELIVERY_STATUS = watchdog PR #9 remains open draft; gateway, harness,
MCP, game-mod, game-core, protocol, and observability companion changes are
merged`. The exact next gate is a clean cross-repository release-set rebuild
after the remaining consumer/release adapters are integrated (or the release is
explicitly scoped to the existing REST contract), followed by the independent
native/live/reboot/soak matrix. No row above should be changed to complete from
a source-only, component, fake-host, cross-build, or ignored-test result.

## Resume-wave addendum — 2026-09-11

The cross-machine resume wave is pinned by
`docs/evidence/current-source-set-20260911.md` and
`docs/evidence/release-set-verification-20260911.json`. The watchdog source
commit is `a5bbd7614204c83874dd9ead850829b2f8685b82` on PR #11. It exposes the
already-authenticated quarantine operation through the executable CLI, adds a
bounded read-only diagnostics command, and makes the Linux protected-tempdir
fixture portable to minimal containers. It also checks affected-row counts for
the paired durable attempt/job transitions in completion, known failure, and
interruption quarantine, with six SQLite trigger regressions proving a
suppressed transition rolls the transaction back. Pinned format, standards,
check, warnings-denied Clippy, and serial full workspace all-target/all-feature
tests pass, including those regressions.

The exact companion source heads are gateway
`5f531f602298de674bd31ed3f28a88359b02ca9d`, harness
`00bd9e123a86fca39bbffb65b370aac7ed2c8218`, MCP
`98ab84b3fad371b45b141e6d81dd9124769a4c59`, game-mod
`bd8e90542dfc89366f820150c5c755e32716b1b0`, protocol
`0bc689eabc5542ede2b09b030d9ea32daa8a73e7`, and game-core
`f5daf69f4f2c43fddbb04e7799d32503f7066110`; each passed isolated locked
format, strict Clippy, and all-target/all-feature test gates. Observability
main at `630431716ebfbf86280f9fd56f19d6016ad7aeb2` contains the persistent
bounded Collector queue/WAL and materialization repairs merged in PR #20. Its
available persistence fixtures and pinned 0.160.0 binary configuration
validation pass; the minimal static-probe fallback is merged in PR #22.
Docker/Podman, Compose rendering, image build, live queue recovery, and
external service execution remain unavailable.

A gateway persist-before-effect follow-up is now open as PR [#42](https://github.com/AI-Ascension/sts2-gateway/pull/42)
at source commit `83539a9dd669eb4c8da69033c06d45f114300c45`, based on current
gateway main `5f531f602298de674bd31ed3f28a88359b02ca9d`. It adds affected-row
checks to host lease install and renewal preparation plus SQLite suppression
regressions; its local component gates and hosted Rust quality/repository-policy checks pass.
The branch is intentionally excluded from the exact
release source set until merged.

The current `coop-native-v1` schema and conformance bytes agree, but current
consumer-conformance bindings differ between protocol, gateway/MCP, and
harness. No unified cross-consumer build was found. Consequently S11, S13,
S16-G/H, INV-12, FAULT-15, FAULT-21, and the native/live portions of S17 remain
partial or unverified. The separate axes remain
`IMPLEMENTATION_COMPLETE = watchdog patch complete; assignment incomplete`,
`SYNTHETIC_INTEGRATION_VERIFIED = partial`,
`WINDOWS_SERVICE_VERIFIED = unverified`,
`LINUX_SERVICE_ADAPTER_VERIFIED = partial`,
`LIVE_HOST_RECOVERY_VERIFIED = unverified`,
`COLD_BOOT_RECOVERY_VERIFIED = unverified`, `SOAK_VERIFIED = unverified`, and
`REMOTE_DELIVERY_STATUS = watchdog PR #11 open with local and hosted gates
green for a5bbd76 (Rust/synthetic run 34574717898; standards run 34574717909);
gateway PR #42 open with local and hosted gates green;
observability PRs #20 and #22 merged; not activated`. Nested-agent depth 2/3 remains unobserved because no
spawn surface is exposed; no depth-4 bypass was attempted.
