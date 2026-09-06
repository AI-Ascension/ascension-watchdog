# Release inspection module validation

Classification: confirmed module tests on Linux; integrated executable activation
and Windows execution remain unverified.

The release inspector enforces six fixed artifact roles, required exact source
revisions, runtime/recovery/config/provider digests, owner-local migration ranges,
bounded manifest/artifact sizes and bounded-memory hashing. It rejects unknown
and duplicate struct fields, duplicate revisions/roles/paths, traversal, alternate
Windows path syntax, symlinks/reparse points and byte tampering.

Seven tests passed with Rust 1.97.1 in a separate validation harness that imports
the exact module and test source. Locked offline tests and Clippy with warnings
denied passed. This temporary harness is not a product dependency or integrated
release build. Root must rerun these tests after the core workspace is integrated.

The inspector intentionally returns an inspection record, not launch authority.
Immutable protected storage, durable activation intent, actual schema checks,
draining, atomic selection and interrupted-activation recovery are additional
requirements and are not proven by digest checking. A matching hash before launch
alone does not prevent time-of-check/time-of-use replacement.
