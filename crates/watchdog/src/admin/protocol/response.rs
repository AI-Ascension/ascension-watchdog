//! Bounded response envelope, dispatcher contract and sanitized failures.

use super::MAX_ID_BYTES;
use super::commands::AdminCommand;
use super::request::DispatchContext;
use super::validation::{validate_identifier, validate_uuid_v4};
use super::views::{AdminResult, ContractVersion, HealthSnapshot, MainLoopHealth, ReplyStatus};
use crate::admin::MAX_FRAME_BYTES;
use crate::error::WatchdogError;
use serde::{Deserialize, Serialize};

/// Bounded response envelope.  It never contains the request credential.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminResponse {
    pub contract: ContractVersion,
    pub request_id: String,
    pub idempotency_key: String,
    pub status: ReplyStatus,
    pub result: Option<AdminResult>,
    pub health: HealthSnapshot,
}

impl AdminResponse {
    /// Construct a successful main-loop response.
    pub fn success(
        context: &DispatchContext,
        result: AdminResult,
        health: &MainLoopHealth,
    ) -> Self {
        Self {
            contract: ContractVersion::V1,
            request_id: context.request_id.to_string(),
            idempotency_key: context.idempotency_key.clone(),
            status: if matches!(
                result,
                AdminResult::Accepted(_) | AdminResult::JobSubmitted(_)
            ) {
                ReplyStatus::Accepted
            } else {
                ReplyStatus::Ok
            },
            result: Some(result),
            health: health.snapshot(),
        }
    }

    /// Construct an error for an already-authenticated token-free context.
    #[must_use]
    pub fn context_error(
        context: &DispatchContext,
        status: ReplyStatus,
        health: &MainLoopHealth,
    ) -> Self {
        Self::error(
            context.request_id.to_string(),
            context.idempotency_key.clone(),
            status,
            health,
        )
    }

    /// Construct an error without carrying arbitrary detail.
    #[must_use]
    pub fn error(
        request_id: impl Into<String>,
        idempotency_key: impl Into<String>,
        status: ReplyStatus,
        health: &MainLoopHealth,
    ) -> Self {
        Self {
            contract: ContractVersion::V1,
            request_id: request_id.into(),
            idempotency_key: idempotency_key.into(),
            status,
            result: None,
            health: health.snapshot(),
        }
    }

    /// Refresh only the live loop health for a replayed response.  The cached
    /// result itself is never re-dispatched.
    #[must_use]
    pub fn with_current_health(mut self, health: &MainLoopHealth) -> Self {
        self.health = health.snapshot();
        self
    }

    /// Validate response structure before framing.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.contract != ContractVersion::V1 {
            return Err("unsupported response contract".to_string());
        }
        if self.request_id.is_empty() {
            if self.result.is_some() {
                return Err("successful response requires request_id".to_string());
            }
        } else {
            validate_uuid_v4(&self.request_id, "request_id")?;
        }
        if !self.idempotency_key.is_empty() {
            validate_identifier(&self.idempotency_key, "idempotency_key", MAX_ID_BYTES)?;
        }
        self.health.validate()?;
        if let Some(result) = &self.result {
            result.validate()?;
        }
        if self.status == ReplyStatus::Ok || self.status == ReplyStatus::Accepted {
            if self.result.is_none() {
                return Err("successful response requires a result".to_string());
            }
        } else if self.result.is_some() {
            return Err("error response cannot contain a result".to_string());
        }
        Ok(())
    }

    /// Encode and enforce the response frame bound.
    pub fn encode(&self) -> std::result::Result<Vec<u8>, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err("response exceeds frame bound".to_string());
        }
        Ok(bytes)
    }
}

/// A main-loop dispatcher.  Implementations must be the watchdog's sole
/// SQLite writer and must not use this trait to invoke gateway/game lifecycle
/// operations.  All commands are already closed and capability-checked.
pub trait AdminDispatcher {
    /// Execute one accepted command on the actual reconciliation thread.
    fn dispatch(
        &mut self,
        context: &DispatchContext,
        command: &AdminCommand,
    ) -> std::result::Result<AdminResult, AdminDispatchError>;
}

/// Sanitized dispatcher failures.  No arbitrary detail is sent to clients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminDispatchError {
    Invalid,
    Unauthorized,
    NotFound,
    Conflict,
    Busy,
    PersistenceUnavailable,
    Unsupported,
    Timeout,
    Internal,
}

impl AdminDispatchError {
    /// Map to the wire status enum without exposing internal details.
    #[must_use]
    pub const fn status(self) -> ReplyStatus {
        match self {
            Self::Invalid => ReplyStatus::Invalid,
            Self::Unauthorized => ReplyStatus::Unauthorized,
            Self::NotFound => ReplyStatus::NotFound,
            Self::Conflict => ReplyStatus::Conflict,
            Self::Busy => ReplyStatus::Busy,
            Self::PersistenceUnavailable => ReplyStatus::PersistenceUnavailable,
            Self::Unsupported => ReplyStatus::Unsupported,
            Self::Timeout => ReplyStatus::Timeout,
            Self::Internal => ReplyStatus::Internal,
        }
    }
}

impl From<&WatchdogError> for AdminDispatchError {
    fn from(error: &WatchdogError) -> Self {
        match error {
            WatchdogError::InvalidInput(_) => Self::Invalid,
            WatchdogError::MissingState(_) | WatchdogError::NotFound(_) => Self::NotFound,
            WatchdogError::Busy(_) => Self::Busy,
            WatchdogError::Unauthorized(_) => Self::Unauthorized,
            WatchdogError::Conflict(_) | WatchdogError::IdentityMismatch(_) => Self::Conflict,
            WatchdogError::Timeout(_) => Self::Timeout,
            WatchdogError::Unsupported(_) => Self::Unsupported,
            WatchdogError::Sqlite(_) | WatchdogError::Io(_) => Self::PersistenceUnavailable,
            WatchdogError::Json(_) | WatchdogError::VerificationFailed(_) => Self::Invalid,
        }
    }
}
