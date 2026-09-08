# Testing and CI baseline

Profiles expose three lanes so local work remains quick and every required check stays visible.

| Lane | Purpose | Typical contents |
| --- | --- | --- |
| Fast | Read-only feedback before a change is staged. | `git diff --check`, local standards validation, metadata, format check. |
| Required | Blocking pull-request evidence. | Repository policy, lint/analyzer, unit/integration tests, protected-byte checks. |
| Extended | Explicitly authorized or environment-specific evidence. | Host/build probes, browser runs, Compose/Docker checks, contract campaigns. |

Commands in a profile are executed in the target's checkout at the locked source revision. A
missing compiler, SDK, feature, browser, container engine, fixture, or permission is reported as
`unverified` with its exact prerequisite. Empty globs, zero tests, unavailable targets, and
cancelled/skipped jobs cannot silently become green. A stable aggregate check waits for every
intended required job and distinguishes failure, cancellation, and not-applicable cases.

Actions use immutable commit references, read-only tokens where possible, explicit permissions,
bounded timeouts, and correctly keyed caches. Never run untrusted pull-request code with
privileged credentials or through a dangerous `pull_request_target` workflow. Treat branch names,
PR text, and issue content as data. A pull request must not disable its own mandatory enforcement.
Keep existing required check names until an owner-approved transition is complete.

## Evidence recording

Record command, exact source commit, tool version, exit code, target/feature set, case count, and
prerequisites. Keep raw logs private and put sanitized findings in `docs/standards/`. Source,
build, CI, adoption, host/runtime, deployment, and release states remain separate. Independent
review reruns the meaningful checks against the actual diff and cannot approve its own changes.
