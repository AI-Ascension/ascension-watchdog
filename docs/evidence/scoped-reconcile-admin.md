# Scoped watchdog reconciliation admission

This note records the authenticated watchdog-local reconciliation slice. It is
source and synthetic-test evidence only; it does not prove gateway, host,
native-service, live-game, reboot, or soak recovery.

`AdminCommand::Reconcile` now maps to the durable `OperatorCommand::Reconcile`
ledger path. Before a receipt is created, the owning reconciliation thread
validates the target:

- `deployment` is the configured owner-local deployment and has no identifier;
- `component` must name one configured component;
- `job` must exist in the owner-local jobs table (checked by exact ID, not a
  bounded list projection); and
- `attempt` must have an exact retained attempt summary.

Unknown scoped identifiers return `NOT_FOUND` and leave the command ledger and
audit log unchanged. A valid request records a bounded accepted response,
request/key/principal/capability/fingerprint, and audit event in one SQLite
transaction. Reusing the same key and command returns the retained response
without a second admission. The normal owning loop remains the only place that
performs process effects; this command never invokes gateway, host, or gameplay
operations.

Focused verification:

```text
cargo +1.97.1 test --locked --offline -p ascension-watchdog runtime_admin::tests -- --nocapture
```

Result: 3 focused tests passed, including valid deployment idempotency and
unknown job/attempt rejection. The exact source change was checked with the
locked offline workspace build; native Windows execution remains unverified.
