# Recovery v1 fixtures

Validate each JSON file against `../frame.schema.json`.

Expected results:

- `valid/*.json`: schema-valid. Release/catalog values are deterministic fixture
  values; implementations must additionally compare the frame digest to their
  installed manifest and compare action/payload digests after decoding with
  RCJ-1.
- `invalid/unknown-field.json`: reject for a closed-object violation.
- `invalid/stale-contract.json`: reject for the wrong contract version.
- `invalid/oversized-action.json`: reject because `canonical_json_b64` exceeds
  the 65536-character action bound.

Duplicate-member, digest-equality, capability, transition, stale-authority, and
durability rules require parser/owner tests in addition to JSON Schema.
