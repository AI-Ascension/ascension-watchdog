# Host lease proof vector verification

Classification: confirmed test-vector and synthetic conformance evidence;
production cross-language consumers and live-host recovery remain unverified.

The additive profile/vector commit is `35892a076e2eea09c83011b864c6d597a17ce6a6`.
The executable regression is `525e75a`, in
`crates/fault-fixture/tests/host_lease_proof_vectors.rs`. It independently
recomputes three canonicalization hashes and nine fixture, unsigned-frame,
signed-message, and HMAC-SHA256 results. It uses a fixed public test key and a
test-only HMAC implementation, not a production verifier. Its parsed-value
serializer does not establish raw-input duplicate-key or number-token rejection.

Root validation at `525e75a`:

```text
cargo test --locked --offline -p watchdog-fault-fixture --test host_lease_proof_vectors
1 passed
cargo clippy --locked --offline -p watchdog-fault-fixture --test host_lease_proof_vectors -- -D warnings
exit 0
cargo test --locked --offline -p watchdog-fault-fixture --all-targets --all-features
51 passed; 0 failed
```

Independent review A19 approved the profile/vector artifacts at `35892a0`.
Its separate Rust checker recomputed all three canonical and nine proof vectors,
checked six-domain separation and alternate-key rejection, and changed all 25
unsigned scalar fields to verify proof sensitivity. It rejected the eight
published raw-invalid inputs plus nested duplicates, trailing bytes, BOM, and
invalid UTF-8. The existing host-lease semantic suite passed 8/8 in that review.
The review changed no tracked source. These results do not substitute for tests
of the gateway and managed host implementations against the same vectors.
