# Same-pass worker heartbeat

Classification: confirmed local source and synthetic tests; authenticated native
job-handoff regression remains unverified. Independent review is pending.

The real-worker smoke reached authenticated Running control but could not claim
a subsequently queued job. The component observation always supplied a missing
heartbeat, causing policy to mark the component Suspect. Existing claim admission
correctly requires a durable Running component.

The repair records a local monotonic witness after an authenticated worker probe.
It binds the component, complete owned process identity, launch nonce and worker
boot. Each reconciliation clears the previous witness. Failed worker exchanges
clear the current witness; fresh readiness and control checks remain mandatory
before a claim. The witness does not prove game-thread progress, host settlement,
or successful experiment execution.

Root integrated the candidate over watchdog commit
`280906818eacca46b48998ffbe452194b851cba5` and ran:

```text
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features --no-fail-fast -j 2
```

All commands exited zero. The watchdog library reported 115 passed and five
explicitly ignored tests. Five new Linux-only private Supervisor tests exercise
missing ownership, exact child/boot binding, wrong nonce, wrong boot, and
per-reconciliation reset. Four portable policy tests cover fresh/missing/stale
heartbeat observations and Stop/Quarantine precedence. Those four policy tests
do not authenticate a peer, exercise control failure, or prove a queue claim.

The full local gate also compiled the uncommitted opt-in real-worker smoke and
ran its fixture digest check; the native smoke remained ignored. Its cleanup
helper is being repaired separately. No service, game, provider, reboot, or
release activation was performed for these gates. A clean hosted run of the
committed draft head remains a separate delivery check.
