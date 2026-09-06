# Release inspection module validation

Classification: confirmed module tests on Linux; integrated executable activation
and Windows execution remain unverified.

The release inspector enforces six fixed artifact roles, required exact source
revisions, runtime/recovery/config/provider digests, owner-local migration ranges,
bounded manifest/artifact sizes and bounded-memory hashing. It rejects unknown
and duplicate struct fields, duplicate revisions/roles/paths, traversal, alternate
Windows path syntax, symlinks/reparse points and byte tampering.

Eleven release tests passed with Rust 1.97.1 after integration into the core
workspace, together with eight core tests and disk-preflight tests. Locked offline
tests and Clippy with warnings denied passed. Earlier isolated-module validation
was rerun against the integrated source, but this is not a companion release-set
build or service activation test.

The eleventh test invokes the operational `release inspect` command against a
staged synthetic release, checks the exact manifest digest, then tampers with an
artifact and asserts a nonzero exit. No activation or store creation occurs.

Independent review found ancestor-link and dot-identity gaps. Regression tests now
cover ancestor links, canonical portable paths and Windows case/device aliases,
parent identities, unapproved companion repositories, and exact original manifest
byte digests. `inspect_document` hashes the original approved artifact bytes;
struct inspection documents that its digest covers generated JSON encoding.

`check_deployment_compatibility` additionally compares the candidate's exact build,
profile, configuration and provider identities against independent approved input,
and checks all three current owner schema versions against both accepted ranges.
Tests reject identical profile names with changed digests, changed builds, schema
rollback incompatibility, unknown/duplicate/missing owners, without changing the
candidate. This API requires authentic owner-reported schema versions; it does
not discover database state or approve a release on its own.

The inspector intentionally returns an inspection record, not launch authority.
Immutable protected storage, durable activation intent, actual schema checks,
draining, atomic selection and interrupted-activation recovery are additional
requirements and are not proven by digest checking. A matching hash before launch
alone does not prevent time-of-check/time-of-use replacement.
