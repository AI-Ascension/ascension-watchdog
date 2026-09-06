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
