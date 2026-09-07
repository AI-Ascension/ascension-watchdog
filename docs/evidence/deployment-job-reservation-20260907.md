# Single-instance job reservation regression

Classification: confirmed synthetic owner-local storage behavior. Base:
`fc59c7f`. This is a prerequisite to the accepted worker handoff contract, not
an implementation or validation of scheduler-to-harness IPC.

The old claim query filtered unresolved attempts by caller-supplied worker ID.
A replacement ID could therefore claim a second job while the first attempt
remained running or unknown. The claim now checks all unresolved attempts in
the single-deployment store under the same immediate transaction used to claim.
No migration or history rewrite is required.

Root regression command, before the production correction, exited 101 because
the replacement worker obtained a second claim:

`cargo test --locked --offline -p ascension-watchdog --test admin_quarantine running_attempt_reserves_deployment`

After correction, `cargo test --locked --offline -p ascension-watchdog --test admin_quarantine`
exited 0 with five tests passed. Tests cover running reservations, changed
worker identities, store reopen, unknown quarantine retention, and release only
after matching terminal completion. The preexisting quarantine test's assertion
that another worker could claim was corrected to the accepted contract.

`cargo test --workspace --all-targets --all-features --locked --offline` exited 0.
`cargo fmt --all -- --check` and
`cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings`
also exited 0.
The two delegated-cgroup tests remained explicitly ignored; no native service,
live-host, reboot, or soak validation is implied. The automatic scheduler and
authenticated harness completion consumer remain separate unfinished work.
