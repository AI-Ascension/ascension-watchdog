# AI-Ascension coding baseline

Status: proposed baseline revision 1, implemented locally on 2026-09-07;
owner review and remote adoption remain pending.

This directory is the maintained source bundle for the organization coding standards. It gives
each repository a small, pinned profile while leaving ownership of architecture, public
contracts, language boundaries, and product behavior in the target repository. A profile is an
adoption record; it is not permission to move code between repositories or to replace a local
policy.

## Authority and evidence

Apply sources in this order: an owner decision recorded in an issue, pull request, or decision
record; shared project rules and the target's owner-local policy; target architecture
and accepted decisions; then design or planning guidance. Shared guidance does not
silently supersede owner policy. The aggregate
naming authority at `planning/naming_conventions/NAMING_CONVENTIONS.md` and its
`naming-registry.yaml` supplies the organization-wide spelling and identity map. It remains an
aggregate authority and is not copied into this repository.

Use exactly one evidence state for every claim:

| State | Use |
| --- | --- |
| `confirmed` | A named command or test ran at a named commit and its result is reproducible. |
| `source-derived` | The target's current source or policy states the fact; it was not rerun. |
| `proposed` | Intended design or future rule that is not yet implemented. |
| `inferred` | Reasoned from confirmed facts but not directly exercised. |
| `unverified` | Not checked or unavailable in this environment. |
| `unsupported` | Outside the target's declared compatibility boundary. |

Build, static checks, host/runtime checks, deployment, and release are separate evidence. A green
lint or test job cannot promote a host, provider, game, deployment, or release claim.

## Required behavior

- Preserve owner boundaries and keep compile-time dependencies separate from runtime calls.
- Keep identifiers typed and namespaced. Preserve lifetime, restart, collision, and fencing
  semantics; equal suffixes do not establish equal identity.
- Bound request bodies, responses, queues, retries, subprocess waits, and lock waits. Keep
  cancellation and shutdown owned by the component that owns the work.
- Return structured, safe errors. Map raw exceptions, secrets, host paths, prompts, and private
  records to reviewed diagnostics before they cross a boundary.
- Keep validation fail-closed. A parse, acknowledgement, reachable process, or model response is
  not an effect witness or settled result.
- Use one deterministic formatter per file type. Keep line endings and encoding explicit and
  protect schemas, golden fixtures, checksum inventories, protocol names, ABI exports, and
  historical evidence bytes.
- Run checks from a local checkout using the exact source commit and lock digests. Normal checks
  never fetch a floating branch, resolve `latest`, or require a sibling checkout.
- Keep third-party notices and source provenance next to imported or generated material. Never
  add proprietary game files, host assemblies, saves, credentials, personal paths, private
  transcripts, or model output.

## Rule classes

`standards/rules.yaml` is the machine-readable rule ledger. A `mandatory` rule blocks its listed
check when it fails. An `advisory` rule reports guidance after an approved migration; it must not
be silently promoted to a blocking failure. Each rule has a stable ID, purpose, scope, checker,
verification mode, and exception eligibility. An `automated` rule names an executable command that
covers the assertion. A `manual` rule has `command: null` and remains unverified until an owner
review or source-linked test records the semantic result. `standards-sync validate` checks metadata
and bytes; it never reports identity, ownership, lifecycle, privacy, evidence, or review approval
as passed merely because the metadata parses. The schemas under `standards/schemas/` define the
accepted shape.

## Exceptions

An exception is valid only when it names exact rule IDs and repository-relative paths, a named
owner, a concrete reason, compensating tests, review evidence from a separate maintainer, review
and expiry dates, and removal criteria. `pending`, self-authored text, a broad ignore, or an
unreadable review link is not approval. Rules covering secrets, protected bytes, ownership
boundaries, or unsafe authorization are not suppressible. A failed exception validation remains a
failure; the checker cannot manufacture approval.

## Profiles and locks

`standards-profile.toml` records the target's scopes and actual fast, required, and extended
commands. `standards.lock.json` binds that profile to the exact source commit and a SHA-256 over
the sorted local bundle. The source is distributed to an adopter under its root `standards/`
directory by the local sync command. The lock records `published: false` until that source commit
is present on the canonical remote branch.

The sync/check tool uses pinned parsing and digest dependencies and has no model dependency.
It copies bytes only when the
destination is absent or identical, rejects symlinks and traversal, writes sorted manifests, and
refuses an unexpected overwrite. Run it from this repository's checkout:

```text
cargo run --locked --manifest-path standards/tools/standards-sync/Cargo.toml -- validate --root .
```

The command validates the canonical profile, lock, rule ledger, repository inventory, schemas,
and conformance fixture inventory. It accepts `--as-of YYYY-MM-DD` for deterministic exception
expiry checks. Production validation does not accept a `local-review:` fixture token or an unqueried
GitHub review URL as independent approval evidence. It has no network, provider, game, mail, service,
or deployment side effect.
