# Host lease-control fixtures

The `valid` fixtures have the exact closed frame shape for each lifecycle
operation and its acknowledgment. The `invalid` fixtures are schema-negative;
a JSON Schema validator must reject their unknown field. The
`semantic-invalid` fixtures intentionally have valid closed shape, while
consumer semantic validation must reject their context, digest, and expiry
violations because JSON Schema cannot express those invariants.

The grant digest is SHA-256 over the HCJ-1 compact canonical bytes of the
`payload.grant` object. HCJ-1 sorts object keys by unsigned UTF-8 byte order,
emits no whitespace, preserves array order, emits wire-safe integers in decimal,
and uses JSON string escaping. All fixture grant strings are ASCII, so the
canonical bytes are directly inspectable in the contract test.

Every retry keeps the same `installation_id` and exact grant. Duplicate
acknowledgments retain the original durable acknowledgment identity and
timestamp; only the bounded status distinguishes the duplicate result.
