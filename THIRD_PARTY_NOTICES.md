# Licensing and provenance

Original source is MIT licensed by AI-Ascension contributors. The implementation
objective was supplied by the operator. No game binaries, assets, saves, private
provider output or copied sibling implementation source may be distributed here.

Dependency revisions and transitive packages are pinned in Cargo.lock. The
dependency checker evaluates licenses, advisory data, unknown sources and
wildcards against deny.toml. SQLite, where enabled through the bundled Rust
adapter, is distributed under its public-domain blessing; the adapter retains
its own license. Native Windows and Linux wrappers retain their package notices.

Credential-buffer cleanup uses RustCrypto's `zeroize` 1.9.0, licensed under
MIT OR Apache-2.0. Only its `alloc` feature is enabled; default features and
derive macros are disabled. Its exact registry checksum is pinned in Cargo.lock.

Dependency checks are evidence at their recorded revision and advisory snapshot,
not a guarantee that future vulnerabilities do not exist. Release packaging must
include this notice and the repository license alongside the immutable manifest.
