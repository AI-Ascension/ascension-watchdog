//! Owner-local worker handoff durability and uncertainty tests.
//!
//! The former single-file suite is split along its cohesive seams; every test
//! scenario and assertion is preserved and only the module boundary moved:
//!
//! * `common` — shared durable fixtures and witnesses;
//! * `binding` — worker-digest independence and historical binding retention;
//! * `claim_completion` — exact-preflight claims, dispatch marking and terminal
//!   acknowledgment/completion idempotence;
//! * `recovery` — reopen, reconciliation, replacement and durable-stop recovery;
//! * `integrity` — forged identity, stale boot and malformed-input refusal.
//!
//! The children carry explicit `#[path]` attributes because this file is the
//! integration-test entrypoint while the modules live under `support/`.

#[path = "support/worker_storage/binding.rs"]
mod binding;
#[path = "support/worker_storage/claim_completion.rs"]
mod claim_completion;
#[path = "support/worker_storage/common.rs"]
mod common;
#[path = "support/worker_storage/integrity.rs"]
mod integrity;
#[path = "support/worker_storage/recovery.rs"]
mod recovery;
