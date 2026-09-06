// Keep the acceptance tests in the repository-level `tests/` area while
// exposing them to Cargo's package test harness.
#[path = "../../../tests/core.rs"]
mod repository_acceptance;
