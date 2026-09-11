# Organization policy inspection — 2026-09-11

Classification: `confirmed` for the public source files and tree listings named
below. This is a read-only inspection performed with GitHub's public API; it
does not inspect private repositories, execute organization tooling, or apply
metadata changes.

## Inspected repositories

| Repository | Default branch | Inspected head | Visibility/state |
| --- | --- | --- | --- |
| [`AI-Ascension/.github`](https://github.com/AI-Ascension/.github) | `main` | [`9043802`](https://github.com/AI-Ascension/.github/commit/9043802204128452c8bdef6b8b0b3d0c304cc96d) | public, not archived |
| [`AI-Ascension/AI-Ascension.github.io`](https://github.com/AI-Ascension/AI-Ascension.github.io) | `main` | [`87e3c84`](https://github.com/AI-Ascension/AI-Ascension.github.io/commit/87e3c849ff97af4d5b53bbcdb913b1049bed6062) | public, not archived |

The recursive default-branch trees were enumerated. The `.github` tree
contains shared contributor, security, governance, metadata, workflow-template,
and policy-as-code surfaces; the site tree contains hand-authored static pages,
the two site workflows, public evidence, and the two deterministic recipe
fixtures. Neither tree contains an `AGENTS.md` file, so the repository-local
instructions remain authoritative for the product repositories.

## Shared policy boundary

The inspected `.github` files were:

- [`README.md`](https://github.com/AI-Ascension/.github/blob/9043802204128452c8bdef6b8b0b3d0c304cc96d/README.md)
- [`CONTRIBUTING.md`](https://github.com/AI-Ascension/.github/blob/9043802204128452c8bdef6b8b0b3d0c304cc96d/CONTRIBUTING.md)
- [`SECURITY.md`](https://github.com/AI-Ascension/.github/blob/9043802204128452c8bdef6b8b0b3d0c304cc96d/SECURITY.md)
- [`GOVERNANCE.md`](https://github.com/AI-Ascension/.github/blob/9043802204128452c8bdef6b8b0b3d0c304cc96d/GOVERNANCE.md)
- [`STATUS.md`](https://github.com/AI-Ascension/.github/blob/9043802204128452c8bdef6b8b0b3d0c304cc96d/STATUS.md)
- [`metadata/EXECUTION_BOUNDARIES.md`](https://github.com/AI-Ascension/.github/blob/9043802204128452c8bdef6b8b0b3d0c304cc96d/metadata/EXECUTION_BOUNDARIES.md)
- [`metadata/README.md`](https://github.com/AI-Ascension/.github/blob/9043802204128452c8bdef6b8b0b3d0c304cc96d/metadata/README.md)
- [`metadata/TOOLING.md`](https://github.com/AI-Ascension/.github/blob/9043802204128452c8bdef6b8b0b3d0c304cc96d/metadata/TOOLING.md)
- [`workflow-templates/policy-check.yml`](https://github.com/AI-Ascension/.github/blob/9043802204128452c8bdef6b8b0b3d0c304cc96d/workflow-templates/policy-check.yml)
- [`workflow-templates/link-check.yml`](https://github.com/AI-Ascension/.github/blob/9043802204128452c8bdef6b8b0b3d0c304cc96d/workflow-templates/link-check.yml)

The relevant source-derived constraints are:

- Every claim uses one evidence label: `confirmed`, `source-derived`,
  `proposed`, `inferred`, or `unverified`; runtime/host/game claims stay
  `unverified` until a real host run is recorded and reproduced.
- Product boundaries, no proprietary game files, no copied harness source, one
  task per branch, pull-request-only delivery, and no agent merge/publish/
  deploy authority apply across the organization.
- The authority order is owner/maintainer decision, shared policy and
  repository policy-as-code, repository documents/decision records, then site
  guidance. A public site cannot override a repository contract.
- Metadata execution is authorized through `tools/metadata.py`; internal
  execution classes do not provide a second privileged command, untrusted PR
  code must not run with administrative credentials, and durable intent,
  authenticated journal chaining, readback, and uncertainty rules apply.
- The shared metadata journal uses `fcntl` and is supported on Linux/WSL;
  native Windows metadata execution remains explicitly unimplemented or
  unverified. This does not authorize changing organization metadata for the
  watchdog task.

## Public-site boundary

The inspected site files were:

- [`README.md`](https://github.com/AI-Ascension/AI-Ascension.github.io/blob/87e3c849ff97af4d5b53bbcdb913b1049bed6062/README.md)
- [`VERIFICATION.md`](https://github.com/AI-Ascension/AI-Ascension.github.io/blob/87e3c849ff97af4d5b53bbcdb913b1049bed6062/VERIFICATION.md)
- [`architecture.html`](https://github.com/AI-Ascension/AI-Ascension.github.io/blob/87e3c849ff97af4d5b53bbcdb913b1049bed6062/architecture.html)
- [`.github/workflows/validate.yml`](https://github.com/AI-Ascension/AI-Ascension.github.io/blob/87e3c849ff97af4d5b53bbcdb913b1049bed6062/.github/workflows/validate.yml)
- [`.github/workflows/pages.yml`](https://github.com/AI-Ascension/AI-Ascension.github.io/blob/87e3c849ff97af4d5b53bbcdb913b1049bed6062/.github/workflows/pages.yml)

The site describes itself as a hand-authored static site with no build step or
external requests. Its validation workflow runs the Node tests and compares the
two pinned Rust recipe outputs; its Pages workflow deploys the repository root
from `main`. `VERIFICATION.md` is explicitly a historical static/proof record,
not a current live-game or release claim. The site README and architecture
page likewise preserve separate labels for source, synthetic, native, live,
reboot, release, and soak evidence.

## Integration consequence

This inspection confirms the root watchdog records are using the required
conservative evidence vocabulary and PR-only delivery boundary. It does not
promote the pending harness PR, unify the consumer artifact set, authorize
metadata mutation, or establish Windows service, live-host, cold-boot, or soak
evidence. The exact source-set and pending-delivery records remain in
[`current-source-set-20260911.md`](current-source-set-20260911.md) and
[`resumed-integration-checkpoint-20260911.json`](../orchestration/resumed-integration-checkpoint-20260911.json).
