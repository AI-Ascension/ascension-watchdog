# Rust profile guidance

This profile applies to the six STS2 Rust repositories and to Rust recipes that carry their own
lockfile. Each target keeps its own `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `rustfmt.toml`,
`clippy.toml`, policy tool, architecture docs, and accepted contract decisions.

## Toolchain and checks

The current target policy pins Rust 1.97.1. Verify the target's file before running a command and
do not change the compiler or declared MSRV as a style change. The ordinary local sequence is:

```bash
cargo metadata --locked --no-deps --format-version 1
cargo run --locked --offline --package repo-policy -- --strict
cargo fmt --all --check
cargo clippy --locked --offline --workspace --lib --bins --all-features -- -D warnings -F clippy::unwrap_used -F clippy::expect_used -F clippy::panic -F clippy::todo -F clippy::unimplemented
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline --workspace --all-targets --all-features
cargo test --locked --offline --workspace --all-features --doc
```

Use the target's documented online command only when the dependency graph and toolchain are
already authorized and available. A missing tool, target, or dependency is `unverified` with its
prerequisite recorded; it is not a successful empty lane. A feature matrix is an owner-specific
extended check: inventory the features and their side effects before adding `--all-features` to a
profile. The six generated Rust profiles retain their existing `--all-features` gates after
metadata inspection found no declared features. Reassess side effects when a feature
is introduced; these commands do not authorize live provider, game or privileged work.
The separate production Clippy invocation forbids local suppression of the five
prohibited constructs while the all-target invocation retains scoped test allowances.

## Boundaries and failure behavior

Keep pure core code free of transport, process, filesystem, clock, provider, and host imports.
The gateway owns instances, sessions, leases, fencing, readiness, routing, and cleanup. MCP owns
framing and mapping. The harness owns coordination, provider ports, episodes, replay, scoring, and
artifacts. The game-mod owns host and ABI authority. `sts2-protocol` owns only accepted,
language-neutral, transport-neutral contracts with named consumers.

Production code must not use `unwrap`, `expect`, `panic!`, `todo!`, or `unimplemented!` for ordinary
failures. Use typed errors and explicit cancellation/reconciliation outcomes. Preserve
`accepted`, `settled`, `completed`, and `unknown` as distinct states. Use `unsafe` only inside a
written, owner-approved native boundary with fixed-width values, ownership rules, callback
retention, unload order, thread affinity, and focused tests; a global forbid cannot be weakened by
a local allow.

## Files and contracts

Treat JSON schemas, golden vectors, artifact manifests, `SHA256SUMS`, protocol fields, MCP names,
HTTP routes, headers, and ABI exports as protected contracts. A formatter or lint migration must
not rewrite their bytes. Generated files name their generator, source revision, and digest. The
Rust profile does not authorize a protocol path dependency, a common crate, or a copied sibling
implementation.
