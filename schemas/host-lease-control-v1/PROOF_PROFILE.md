# Host lease-control proof profile v1

This additive implementation profile fixes the proof recipe for the named
gateway and managed-host consumers. It does not change the frame schema or
establish consumer, host, or live recovery validation. The deterministic key in
`proof-vectors.json` is public test data and must never be a deployment key.

Use a separately configured, protected 32-byte shared key for this sideband.
For each of the six frame kinds, select its request or acknowledgment domain
from the fixed table in `docs/host-lease-control-contract.md` (repository root).
Do not accept a caller-selected domain. Compute:

```text
unsigned_frame = complete frame with only auth.proof omitted
message = UTF8(domain) || one zero byte || HCJ1(unsigned_frame)
auth.proof = lowercase hexadecimal HMAC-SHA256(key, message)
```

The proof is exactly 64 lowercase hexadecimal characters. Verify in constant
time after closed-shape, kind, size, identity, and canonical-input validation,
and before mutation. Every other field remains covered, including contract,
schema digest, message/correlation IDs, sent time, actor, authentication
principal/capability, and the complete payload. A proof never replaces current
fence/deadline checks or durable-before-ack ordering. Duplicate operations keep
their durable identity even when a newly authenticated response frame is made.

HCJ-1 byte rules for these consumers:

- Sort object member names by unsigned UTF-8 bytes; preserve array order.
- Emit no whitespace and no UTF-8 BOM.
- Accept only integer number tokens from 0 through 9007199254740991. Reject
  negative zero, negative values, decimal points, and exponent notation before
  parsing can normalize them.
- Emit `null`, `true`, and `false` literally.
- Emit valid non-ASCII Unicode scalar values as literal UTF-8, including U+2028
  and U+2029. Do not normalize Unicode. Reject unpaired surrogate escapes.
- Escape quotation mark and backslash. Use the short escapes for backspace,
  tab, newline, form feed, and carriage return; use lowercase `\u00xx` for
  the remaining U+0000 through U+001F values. Do not escape slash or other
  scalar values.
- Reject duplicate member names at every nesting level, invalid UTF-8, trailing
  bytes, and inputs exceeding the frame's existing size/depth limits.

The vectors contain three canonicalization edge cases, nine proofs over the
existing immutable valid frame fixtures, and raw JSON inputs that must fail
canonical-input validation. Fixture hashes pin the exact inputs. The original
fixtures' placeholder proof fields are omitted for signing; they are not valid
proofs under this profile. Frame, canonical-byte, and signed-message hashes let
consumers distinguish an input mismatch from a canonicalization or HMAC bug.

Changing any signed field must invalidate a retained proof. A request proof
must not verify as an acknowledgment or under another operation's domain.
Cross-language consumer verification remains required; generated vectors alone
are not proof that either production consumer implements this profile.
