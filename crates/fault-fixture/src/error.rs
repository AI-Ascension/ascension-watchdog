//! Typed fixture errors for the recovery contract.
//!
//! Owns `FixtureError` and its contract status vocabulary, `Display` and
//! `std::error::Error` implementations.  Extracted verbatim from `lib.rs` by
//! the recovery-validation, encoding-and-typed-errors split (issue #79); the
//! crate root re-exports the type unchanged.

use std::fmt::{Display, Formatter};

/// Typed fixture failures map to the contract's bounded status vocabulary.
#[derive(Debug)]
pub enum FixtureError {
    Io(std::io::Error),
    Sql(rusqlite::Error),
    Json(String),
    Invalid(String),
    Bounds(&'static str),
    ContractMismatch,
    Forbidden,
    Conflict,
    Busy,
    Stale(&'static str),
    HostNotReady,
    ResponseLost,
}

impl FixtureError {
    #[must_use]
    pub fn status(&self) -> &'static str {
        match self {
            Self::ContractMismatch => "CONTRACT_MISMATCH",
            Self::Forbidden => "FORBIDDEN",
            Self::Conflict => "CONFLICT",
            Self::Busy => "BUSY",
            Self::Stale("lease" | "fence") => "STALE_LEASE",
            Self::Stale("revoked lease") => "LEASE_EXPIRED",
            Self::Stale("boot") => "STALE_BOOT",
            Self::Stale(_) => "STALE_INCARNATION",
            Self::HostNotReady => "HOST_NOT_READY",
            Self::Bounds(_) => "BOUNDS_EXCEEDED",
            Self::ResponseLost => "UNKNOWN",
            Self::Io(_) | Self::Sql(_) => "PERSISTENCE_UNAVAILABLE",
            Self::Json(_) | Self::Invalid(_) => "INVALID",
        }
    }
}

impl Display for FixtureError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O: {error}"),
            Self::Sql(error) => write!(formatter, "SQLite: {error}"),
            Self::Json(error) => write!(formatter, "JSON: {error}"),
            Self::Invalid(error) => write!(formatter, "invalid: {error}"),
            Self::Bounds(value) => write!(formatter, "bounds: {value}"),
            Self::ContractMismatch => formatter.write_str("contract mismatch"),
            Self::Forbidden => formatter.write_str("forbidden"),
            Self::Conflict => formatter.write_str("conflict"),
            Self::Busy => formatter.write_str("busy"),
            Self::Stale(value) => write!(formatter, "stale {value}"),
            Self::HostNotReady => formatter.write_str("host not ready"),
            Self::ResponseLost => formatter.write_str("response lost"),
        }
    }
}

impl std::error::Error for FixtureError {}
