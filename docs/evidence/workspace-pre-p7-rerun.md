# Workspace rerun before P7 integration

Classification: confirmed failing Linux synthetic test run.

Root ran `cargo test --locked --workspace --all-targets --all-features` on
integration revision `967c467`, with Rust 1.97.1. Exit status: 101.

Compilation completed. Windows portable suites passed eight tests; Windows-only
suites ran zero tests. Watchdog library passed 35 with one explicitly ignored
native cgroup test. Admin configuration and control suites passed 3 and 9 tests.

`adversarial_core` passed seven tests and failed
`terminating_owned_child_cleans_background_descendants`: a background descendant
survived owned-child termination. The suite stopped there; later workspace
suites did not execute in this command. Focused passes recorded separately
remain scoped to their own invocations.

This confirms that P7 process-group cleanup remains required on the integration
tree. Candidate P7 commits are still withheld pending typed uncertainty
propagation and parallel-safe fault injection. A new full workspace run is
required after integration; no workspace-green claim is made here.
