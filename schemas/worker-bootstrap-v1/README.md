# Worker bootstrap v1 fixtures

These synthetic payloads contain invented process identities and paths, no
credentials, and no authority. They are not usable deployment configuration.
Original fixtures are MIT-licensed with the repository.

`schema.json` checks closed structural shape. The codec additionally enforces
duplicate-key rejection, framing, UTF-8 byte bounds, canonical numeric u64/SID
bounds, and the one-frame limit described in `docs/worker-bootstrap-v1.md`.
Schema validation alone is insufficient for accepting startup input.

Consumers must wrap each valid JSON fixture's exact UTF-8 bytes with `ASC-WB01`
and its four-byte big-endian byte count. Decode and re-encode must preserve typed
values, not necessarily JSON whitespace or field order. Both owner and consumer
tests must use these same payloads; neither may change them implicitly.

Negative cases must include duplicate top-level and peer keys (including escaped
equivalent names), unknown fields/platforms, malformed/old-version frames,
truncation and trailing frames, noncanonical UUIDs/numbers, oversized UTF-8 paths,
and invalid SID authority/subauthority bounds. Those cases must reach the actual
byte decoder, not a JSON map that already discarded duplicate keys.
