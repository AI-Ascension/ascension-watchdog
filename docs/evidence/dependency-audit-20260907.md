# Recovery candidate dependency audit

Classification: confirmed lockfile advisory checks, not release acceptance.

Tool: cargo-audit 0.22.2, built with locked dependencies in an isolated tooling
directory. The default C compiler wrapper supplied incomplete OpenSSL headers;
a per-command `CC=/usr/bin/cc CXX=/usr/bin/c++` override allowed the build to
finish. No global compiler configuration or project dependency changed.

RustSec database: `8a1eb4f933fb5821add5b4e98601ebd90b8b3538`, 1,242 advisories.
The first audit fetched the database; later audits used the same clean database
checkout with `--no-fetch`. Root verified its Git HEAD after the initial four checks;
three additional companion checks below used that same checkout.

## Exact audited inputs

| Repository | Candidate revision | Dependencies | Cargo.lock SHA-256 |
| --- | --- | --- | --- |
| ascension-watchdog | `f9a32a0c8a420b11d315398c33308145bdd68be8` | 170 | `b53a5d4791b35ad7028cc9ba8cd6a0e8a00a3c4d73898d34d5b0f678c12aecac` |
| sts2-harness | `83369562baedd31bc8a0c4aae9e54550d0e79a1e` | 126 | `d19e690f50502932fe3872c629018127ec566e3b36eac9694d56853351d088e5` |
| sts2-gateway | `3faaab4f7479efdd0925eb4ace927c24e6ae33c2` | 117 | `c1ef3604aad45e640f613ad831ce9acbefa59743e1169f19822212805451c084` |
| sts2-game-mod | `13a488fd815415f7453b820d771196dc5883528a` plus uncommitted source/test repairs | 27 | `b5226df852265862ffbfc7afc25cbc234b4e037cac06061f9392fa8a4f56c4bc` |
| sts2-mcp-server | `2433d4c42cd4ffdb1db8b38cfe5c85f54d2d513f` | 2 | `3d44d64f06bb04c83cb07a1236fd2c0d315b2cbf1134f5211455dfd98efd48f4` |
| sts2-protocol | `cd0f517ce8872181119d423341bc1d0ab1c8ced0` | 22 | `93bacb662c5647aa9856bab4a8667301c716b236c8a1250d1327e5b62c58eb65` |
| sts2-game-core | `571573e8ca9f94f68fecd9ac1335f87701e18637` | 17 | `fadd1942dd4271865ffa2c7ffce7c6754b09df28f9511132d9de05d75bdcc926` |

The mod repairs do not change Cargo.lock. This audit does not identify or accept
that dirty source snapshot as an immutable release.

From each candidate checkout, using the isolated tool executable:

```text
cargo-audit audit --db <pinned-advisory-checkout> --file Cargo.lock --deny warnings --format json
```

Every command except the first harness audit additionally used `--no-fetch`. All seven
commands exited 0, reported `vulnerabilities.found: false`, count 0, and empty
warnings. No advisory IDs were ignored and no target OS/architecture filter was
applied. License metadata and runtime/security review remain separate checks.

This result covers these lockfiles at this database revision. It is not proof
that dependencies contain no undisclosed defects, nor that native binaries,
managed dependencies, service packaging, or the integrated release are secure.
Changed lockfiles or a later release require a fresh audit.
