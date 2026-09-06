# Recovery contract baseline and evidence

Classification: source-derived baseline plus proposed contract. The contract
artifacts are committed in this worktree; no companion implementation, live
service, game, host, reboot, or soak claim follows from schema validation.

## Source revisions inspected

The isolated worktrees were freshly fetched from their default branches and
recorded in `workspace-manifest.json` at the following revisions:

| Owner | Revision |
| --- | --- |
| gateway | `33ea48f3b549f08e19db80d8c68c1438fa12a60a` |
| harness | `cb17b6c15262ce9356f1e85fd475af997aedc445` |
| MCP | `eb89ab251665f263c2fe3e6b735eeae3d3e40c83` |
| mod | `c41064a7e76aec4ce0b862a9a1cb160236b16d9d` |
| protocol | `8874b0951289fd943c7e14dea36557fa24c401d1` |
| game-core | `87e0f3d9355c0827e989d9fbc31804440852519b` |
| observability | `b25880376d3a3334c77f58637267db93581c4c77` |
| organization policy | `0cbdf744d515b16c042eb6e16b1537d8ccf11771` |
| site/release context | `bbe475998b0cd279309666f5cec3dc433d90a4a4` |

## Existing executable wiring and gaps

- Gateway `crates/gateway/src/bin/runtime_support/process_supervisor.rs:45-155`
  stores only an in-memory `BTreeMap<InstanceId, ProcessHandle>`; restart
  force-stops and replaces a handle without durable boot/incarnation, launch
  nonce, orphan reconciliation, or containment.
- Gateway `crates/gateway/src/bin/runtime_support/identity.rs:70-145` keeps
  lease state in memory. `control.rs:18-62` allocates in-memory ids and starts
  `LeaseEpoch::new(1)`. `service_lease.rs:6-49` uses the configured authority
  context rather than a durable fresh boot authority.
- Gateway `service_v3.rs:8-62` and `runtime_v3_gameplay_forwarder.rs:30-155`
  validate and forward the v3 request directly. The existing journal is wired
  to v2; it does not provide a v3 operation ledger.
- Gateway `journal.rs:11-100` is an atomic JSON snapshot with an exclusive file
  lock, not an owner-local SQLite WAL/`synchronous=FULL` authority store with
  migration, rekey, and explicit missing-state behavior.
- Mod `RuntimeV3GameplayHost.cs:121-241` and
  `LiveCombatSource.Dispatch.cs:18-76` retain pending operation/ticket/effect
  state in memory; there is no durable admission ticket or execution-time
  sideband fence.
- Harness `runtime_v3_ledger.rs` records operation state in memory and the
  recovery path reconnects for bounded reads; neither is a watchdog recovery
  implementation or a durable cross-owner journal.

## Contract evidence produced here

- `schemas/recovery-v1/frame.schema.json` is a closed draft-2020-12 schema with
  bounded fields, explicit request/response kinds, release digests, fresh boot
  and incarnation identities, lease/fence contexts, operation uncertainty,
  historical lookup, reconciliation, and effect-witness types.
- `schemas/recovery-v1/manifest.json` records the exact frame schema digest
  `fb934d3157485aaf6e13e6ebbb213ec8a14c7fc6f5eeebc06b7a22c1f0009217`, the
  256 KiB frame limit, the 64 KiB action limit, and the bounded wire integer.
- Canonical action bytes use the explicitly bounded RCJ-1 profile in
  `docs/recovery-contract.md`, chosen because the frozen runtime-v3 action
  grammar is ASCII identity/enum fields plus `null` (`schema.json:81-87,
  186-195`); no unimplemented JCS library is implied. Immutable artifact
  digests hash exact approved bytes.
- Valid and invalid fixture expectations are documented in
  `schemas/recovery-v1/fixtures/README.md`.

## Validation commands

The following checks ran against this package:

```text
jq empty schemas/recovery-v1/frame.schema.json
sha256sum schemas/recovery-v1/frame.schema.json
printf '%s' '{"action":{"kind":"end_turn"},"action_id":"action-1"}' | sha256sum
for f in schemas/recovery-v1/fixtures/valid/*.json; do
  jsonschema -V Draft202012Validator -i "$f" schemas/recovery-v1/frame.schema.json
done
for f in schemas/recovery-v1/fixtures/invalid/*.json; do
  ! jsonschema -V Draft202012Validator -i "$f" schemas/recovery-v1/frame.schema.json
done
```

The expected frame-schema digest is the value in `manifest.json`; the expected
RCJ-1 digest for the fixture action is
`0ae6049620ef967aea198c3904254965b42ad665d642f9738bbe17ff64adfda2`.
Schema-validator execution for every fixture is a required companion gate; it
must reject the three files under `fixtures/invalid` and accept all files under
`fixtures/valid`. Semantic tests must additionally check cross-field digest
equality, identity equality, capability authorization, state transitions,
durable ordering, and crash windows because JSON Schema cannot express them.

## Remaining implementation gates

Gateway, host/mod, harness, and watchdog owners must publish the artifact through
their real consumers, implement current-fence and digest checks, and add
executable crash/restart/duplicate/rollback tests. Protocol publication is not
claimed by this contract-only package. Native Windows/Linux, live-host, cold
reboot, and 24-hour soak evidence remain unverified until those gates execute.
