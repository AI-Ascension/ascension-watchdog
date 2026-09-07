# Job process integration review

Reviewed source: `62f7d160e203552df19f8a1d3d034ef44577bad0`, integrated as
`e94e477` on top of claim-integrity fix `9948f07`.

Confirmed synthetic process evidence:

```sh
cargo test --locked -p ascension-watchdog --test job_submission_process --test job_submission --test job_claim_integrity
```

Exit 0: nine tests passed. Two tests invoke the compiled daemon and CLI as
separate processes. They cover authenticated admission, same-key replay,
daemon reopen, read-credential denial, redacted listing, and rejection of a
symlinked payload-file ancestor. The corruption test exercises four payload
cases and checks that failed claims create neither attempts nor audit entries.
`cargo fmt --all -- --check` and
`cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
also exited 0 on Linux after integration.

The process test completes the job through an owner-held `Store` while the
daemon is stopped. It does **not** prove automatic scheduler-to-harness handoff,
worker completion acknowledgment, native containment, or service recovery.

## Open review findings

These are source-derived findings, not executed failure reproductions:

- The Linux final payload-file open lacks nonblocking mode. A FIFO can block
  before regular-file validation. Require a bounded subprocess regression.
- Windows payload-file reading explicitly returns unsupported. This is safe
  interim behavior, not completion of the primary Windows deployment target.
  The shared path validator also rejects Windows prefix components.
- CLI test invocations use unbounded `Command::output`. Introduce deadline-bound
  child ownership and bounded output capture so regressions cannot hang CI.
- `DaemonGuard::stop` removes its child handle before fallible cleanup calls.
  Preserve cleanup ownership on errors rather than dropping an unreaped handle.

All four findings were returned to the job-admission author for a separate
follow-up commit. No service installation, host restart, game/provider launch,
or release activation was performed by this validation.
