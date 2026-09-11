# Source baseline

Classification: source-derived at `workspace-manifest.json` revisions. Root read
actual executable service wiring before implementation. No runtime claim follows.

| Owner | Current executable evidence | Required addition |
| --- | --- | --- |
| Gateway | `crates/gateway/src/bin/runtime_support/service.rs` loads `journal::load` into a RuntimeV2 ledger only; v3 constructs a fresh forwarder | Durable boot authority and actual v3 persist-before-send |
| Gateway | `service_v3.rs::runtime_v3_request` checks a lease, validates a body and calls `forward_mod` directly | Current fence handshake, durable v3 identity/uncertainty and historical recovery |
| Gateway | `journal.rs` owns bounded atomic-file v2 snapshots and an exclusive file lock | Owner-local transactional authority/operation store and explicit restore/rekey |
| Harness | `runtime_v3_ledger.rs::OperationRecord` is an in-memory record of state, generation and action | Durable episode/pending identities and completion/accounting |
| Harness | `runtime_v3_recovery.rs` reconnects MCP at most twice for reads with existing configured lease/session | Explicit worker resume with fresh authority and historical operation access |
| Watchdog | New private repository was created after an exact-name remote query and full organization inventory | Full implementation and independently executed integration |

Open PR and issue queries returned no open gateway/harness entries before this
assignment's companion work. All six shared product checkouts contain unrelated
changes. New isolated worktrees use freshly fetched default branch revisions.

Platform, mod, MCP, release and observability detailed audit is in progress; do not
infer absent capabilities from this initial map. Native game/service evidence has
not been produced by this assignment.
