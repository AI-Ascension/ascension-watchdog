# standards-sync

standards-sync is the small, pinned-dependency validator and local distributor for the
AI-Ascension standards bundle. It is a Rust binary so Rust-only repositories can use the same
checker without Python, a sibling checkout, a network fetch, or a provider call. Its manifest is
an isolated Cargo workspace with Rust 1.97.1, serde 1.0.229, serde_json 1.0.151, serde_yaml
0.9.34, sha2 0.10.9, toml 1.1.4, and pulldown-cmark 0.10.3 pinned in Cargo.lock.

## Validate a local adoption

From a repository containing standards/, standards-profile.toml, and standards.lock.json:

    cargo +1.97.1 run --locked --manifest-path standards/tools/standards-sync/Cargo.toml -- validate --root .

Validation checks exact source/profile metadata, safe and sorted lock paths, every local file's
SHA-256, the bundle digest, the exact root profile configuration digest, required rules and profile IDs, all 13 reviewed repository records,
self-identifying schemas, and valid/negative fixture inventory. A mismatch exits nonzero. The
checker reports metadata validation only; it does not execute the profile commands or approve
manual semantic rules. Use `--as-of YYYY-MM-DD` when a reproducible exception date is needed. The
checker never updates a lock or changes a source file.

## Distribute locally

An operator with a local canonical .github checkout may copy its standards/ bytes to an adopter
and create the two root metadata files in one deterministic operation:

    cargo +1.97.1 run --locked --manifest-path standards/tools/standards-sync/Cargo.toml -- \
      sync --source-root /path/to/.github --target-root /path/to/adopter \
      --repository AI-Ascension/sts2-gateway --profile-id rust-service \
      --owner GW --source-commit <40-lowercase-hex-commit>

The command verifies that the supplied commit is a local Git commit whose complete standards/
tree is byte-identical to the source checkout, then computes the bundle digest over sorted
standards/<path>, NUL, file bytes, NUL records; emits published:false; and refuses to overwrite a
differing managed file. It accepts only the reviewed repository/profile/owner combinations and
rejects explicitly excluded repositories. A caller must stage the resulting paths explicitly and
obtain owner review before a local adopter claims ready.

The command has no GitHub, registry, deployment, game, host, mail, or provider access. Remote
publication is a separate operation and is never inferred from published:false or a passing local
check.

## Bootstrap documentation/configuration

`check-bootstrap --root .` first validates the pinned adoption, then parses the actual tracked, untracked
and ignored Markdown/JSON/TOML/YAML inputs in the two reviewed bootstrap repositories. It requires
the known source files, checks local Markdown file/directory links without fetching external URLs,
rejects symlink escapes and unexpected product manifests/source, and reports nonempty counts.
Anchor existence and client-specific TOML option support remain unverified. Code examples are
not interpreted as executable source. This does not initialize a product workspace.

The 15 unit tests include actual disposable Git source commits, sync idempotence and conflict
refusal, metadata weakening, missing targets, narrow generated-output handling, symlinks,
CRLF/digest changes, and unapproved/expired exceptions. The profile digest binds generated
configuration bytes; it does not authenticate a PR author or pin every owner-native configuration.
Native gates and protected owner review remain necessary. Review branch protection activation
separately; this tool cannot stop an authorized repository editor from replacing a workflow.
