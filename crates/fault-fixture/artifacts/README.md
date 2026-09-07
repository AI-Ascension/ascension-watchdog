# Fault-fixture artifact packaging

The two artifact directories below this directory are frozen test inputs. Their
schemas, manifests, fixtures, and `SHA256SUMS` files are copied from the
accepted protocol artifacts and must remain byte-identical when the fixture is
updated.

The first two entries in each checksum file intentionally point outside the
individual artifact directory:

```text
crates/fault-fixture/
├── conformance/cases/{runtime-v3-gameplay,watchdog-recovery-v1}.json
├── schemas/{runtime-v3-gameplay,watchdog-recovery-v1}.schema.json
└── artifacts/{runtime-v3-gameplay,watchdog-recovery-v1}/
```

Those neutral source bytes were copied from `AI-Ascension/sts2-protocol` at
commit `2a30eb96240f579eea9c776b3291d31a3bd9ac38` and checked against the
frozen hashes before they were added here. The package-local copies are only
for deterministic checksum verification; this crate does not become the owner
of either protocol.

Run each check from its artifact root so the paths in `SHA256SUMS` are resolved
relative to that root:

```sh
(cd crates/fault-fixture/artifacts/runtime-v3-gameplay && sha256sum --check SHA256SUMS)
(cd crates/fault-fixture/artifacts/watchdog-recovery-v1 && sha256sum --check SHA256SUMS)
```

The `schema` integration test repeats this verification without depending on
the caller's working directory and rejects missing, mismatched, absolute, or
package-escaping checksum paths.
