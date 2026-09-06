# Synthetic host fault-fixture evidence

Classification: synthetic-process evidence only. This package is a test tool;
it is not a watchdog, gateway, MCP server, game mod, live host, service, or
provider implementation.

## Contract and boundary

The fixture consumes the accepted `watchdog-recovery-v1` sideband envelope with
schema digest
`fb934d3157485aaf6e13e6ebbb213ec8a14c7fc6f5eeebc06b7a22c1f0009217`. It keeps
the frozen runtime-v3 digest
`8e99cea36b7ede97532348fd8efe302ca79260895265a7bf14ddf7e006d8ff63` in action
and route responses. Recovery request kinds include bootstrap, host fence,
lease acquire/renew/revoke, operation intent/dispatch/lookup/reconcile, and a
controlled host tick. Frozen runtime-v3 route kinds are accepted as bounded
unknown-result adapters; they do not claim a settled game action.

The server uses one closed JSON frame per authenticated loopback TCP connection.
The SQLite database uses WAL and `synchronous=FULL`. Operations, admission
tickets, queued work, effect witnesses, and receipts are separate durable rows.
The effect row is committed before the receipt row, so a crash in that window
leaves an operation unknown with a witness instead of fabricating exactly-once
semantics. Historical lookup always returns `mutation_authorized: false`.

## Fault controls

`fault-fixture-server --fault` accepts only these test-local one-shot controls:

`before-admission`, `after-admission`, `before-mutation`, `after-mutation`,
`before-receipt`, `after-receipt`, `response-loss`, and `malformed-response`.
Crash controls exit with status 70 after the named durable boundary. Response
loss and malformed-response affect a host-tick response only. No production
watchdog API imports or exposes these controls.

The receipt retention bound is 64. A 65th new dispatch receives
`BOUNDS_EXCEEDED`; unresolved operations are not evicted.

## Executed commands

From this package worktree, with the pinned toolchain:

```text
RUSTUP_TOOLCHAIN=1.97.1 cargo test --offline --all-targets -- --test-threads=1
```

Result: 9 tests passed (3 library tests and 6 real subprocess/loopback tests).
The subprocess tests cover response loss with a durable witness and receipt,
malformed responses with durable receipt, stale queued-fence rejection with
zero effect, 64-receipt backpressure, crash after admission and restart, and
crash after mutation with witness-only reconciliation and no second effect.

This evidence does not establish integration with the real gateway, harness,
MCP, mod, watchdog, native service manager, game host, reboot, or soak lanes.
Root must compose those binaries and rerun the cross-repository acceptance
matrix after publishing the exact protocol artifact.
