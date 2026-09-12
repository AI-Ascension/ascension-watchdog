# Reproducible release staging workflow

Classification: `implemented release staging; activation remains a separate
audited operation`. This completes the executable pipeline from an admitted
source set to an immutable, activatable release directory.

## Command

```text
watchdog release stage-set \
  --manifest PATH \
  --catalog PATH \
  --release-id ID \
  --config PATH \
  --compatibility PATH \
  --role watchdog=PATH --role gateway=PATH --role harness=PATH \
  --role mcp=PATH --role mod=PATH --role host_broker=PATH \
  --repo NAME=PATH [...] [--artifact NAME=PATH [...]]
```

The command:

- verifies the exact source set first (`release source-set` admission) and
  refuses to stage for an unadmitted set;
- requires exactly the six fixed roles `watchdog`, `gateway`, `harness`, `mcp`,
  `mod`, `host_broker`, and copies each role's exact bytes into a **new**
  `CATALOG/ID` directory (an existing release is never overwritten);
- binds each artifact's SHA-256 and byte length, all source-set revisions, the
  fixed profile names (`runtime-v3-gameplay`, `watchdog-recovery-v1`), the
  caller-supplied compatibility digests, and the exact deployment
  `configuration_sha256` into a closed `release-manifest.json`;
- validates the assembled manifest with the product's own
  `ReleaseManifest::validate` before writing it, and prints a machine-readable
  report (`manifest_sha256`, artifact map, counts, config digest).

It never activates, launches, or mutates an existing release, and it does not
change ownership: stage under a catalog whose owner policy you control (root for
a production catalog).

## Compatibility profile

```json
{
  "game_build": "sts2-2-minimum",
  "runtime_profile_sha256": "<64 hex>",
  "recovery_profile_sha256": "<64 hex>",
  "provider_adapter": "codex-local",
  "provider_adapter_sha256": "<64 hex>",
  "stores": [
    {"owner": "watchdog", "minimum_schema": 1, "maximum_schema": 2},
    {"owner": "gateway", "minimum_schema": 1, "maximum_schema": 1},
    {"owner": "harness", "minimum_schema": 1, "maximum_schema": 1}
  ]
}
```

Profile names are fixed by the release contract and are not read from the file,
so a caller cannot invent a profile identity.

## Pipeline

`release source-set verify` (admission) -> `release build-set` (locked build and
component conformance) -> `release stage-set` (immutable release directory) ->
`release activate` / `release rollback` (authenticated selector).

## End-to-end result (2026-09-12)

The stager was run against the admitted current-main source set with the role
artifacts from the build step. It produced `native-activation-20260912-c` with
manifest SHA-256
`abaa7741a37e9064eab1dad99107267a633e4a16010bde93b14c1e1e66c0cff4` and
`configuration_sha256`
`c390c90166eef35f567d357f22e3f6b0c8a42f9864cff7e479ab209fd1b5e3c3`, matching the
deployment configuration used on the host. After copying it read-only into the
root-owned catalog, `release inspect` returned `compatible=true` and
`release activate` returned `OK`, with the selector recording
`active=native-activation-20260912-c` and `previous=native-activation-20260912-a`.

## Boundary

Staging is filesystem and manifest work only. It does not install, activate,
launch, or prove immutable handoff, and it makes no live-host, cold-boot,
Windows, or soak claim.
