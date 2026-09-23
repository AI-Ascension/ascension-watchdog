//! Durable broker idempotence journal.
//!
//! This module is a thin facade. The cohesive pieces live in flat sibling
//! modules and are re-exported here under their original names so every
//! existing path into the ledger keeps resolving:
//!
//! - [`ledger_binding`] owns the `StartTransientUnit` job identity and its
//!   bounded object-path parser.
//! - [`ledger_records`] owns the persisted record types, the strict line
//!   decoder and the ledger path guards.
//! - [`ledger_store`] owns the append/commit persistence and reservation
//!   admission of [`BrokerLedger`].
//! - `tests` exercises the journal against the real on-disk encoding.

#[path = "ledger_binding.rs"]
mod ledger_binding;
#[path = "ledger_records.rs"]
mod ledger_records;
#[path = "ledger_store.rs"]
mod ledger_store;

#[cfg(test)]
#[path = "ledger_tests.rs"]
mod tests;

pub use ledger_binding::JobBinding;
pub(super) use ledger_records::{LedgerState, LifecycleRecord, same_process_binding};
pub use ledger_store::BrokerLedger;
