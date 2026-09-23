//! Worker client session lifecycle, transport deadline selection and request
//! header construction.
//!
//! The watchdog boot identity is generated once per session and appears on
//! every request.  A phase deadline can only shorten the frozen transport
//! bound, never extend it.

use crate::error::{Result, WatchdogError};
use crate::worker_protocol::{CONTRACT, Command, Direction, Header, SCHEMA_DIGEST, Scope};
use std::fmt;
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::config::WorkerClientConfig;
use super::validation::{duration_millis, validate_uuid4};

/// A configured watchdog worker session.  The watchdog boot identity is
/// generated once per client/session and appears on every request.
#[derive(Clone)]
pub struct WorkerClient {
    pub(super) config: WorkerClientConfig,
    pub(super) watchdog_boot_id: String,
    /// Optional absolute deadline supplied by the owning reconciliation
    /// phase.  A phase deadline is never extended by rebuilding a client for
    /// another request.
    pub(super) deadline: Option<Instant>,
}

impl fmt::Debug for WorkerClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerClient")
            .field("config", &self.config)
            .field("watchdog_boot_id", &self.watchdog_boot_id)
            .field("deadline", &self.deadline)
            .finish()
    }
}

/// Result classification used by the owning reconciliation phase.  Only
/// failures raised by the worker transport itself are deferrable.  Validation,
/// identity, and durable-store failures remain fatal to that reconciliation.
#[derive(Debug)]
pub(crate) enum WorkerPhaseError {
    Unavailable(WatchdogError),
    Fatal(WatchdogError),
}

impl WorkerPhaseError {
    pub(super) fn transport(error: WatchdogError) -> Self {
        match error {
            WatchdogError::Io(_)
            | WatchdogError::Timeout(_)
            | WatchdogError::Unauthorized(_)
            | WatchdogError::Unsupported(_) => Self::Unavailable(error),
            error => Self::Fatal(error),
        }
    }

    pub(super) fn into_watchdog_error(self) -> WatchdogError {
        match self {
            Self::Unavailable(error) | Self::Fatal(error) => error,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn from_client_error(error: WatchdogError) -> Self {
        Self::transport(error)
    }
}

impl From<WatchdogError> for WorkerPhaseError {
    fn from(error: WatchdogError) -> Self {
        Self::Fatal(error)
    }
}

impl WorkerClient {
    /// Construct a client bound to an explicit watchdog boot identity.
    pub fn new(config: WorkerClientConfig, watchdog_boot_id: impl Into<String>) -> Result<Self> {
        let client = Self {
            config: config.validate()?,
            watchdog_boot_id: watchdog_boot_id.into(),
            deadline: None,
        };
        validate_uuid4(&client.watchdog_boot_id, "watchdog boot id")?;
        Ok(client)
    }

    /// Construct a client with a fresh UUIDv4 watchdog boot identity.
    pub fn with_new_boot(config: WorkerClientConfig) -> Result<Self> {
        Self::new(config, Uuid::new_v4().to_string())
    }

    /// Client configuration, with secrets retained only by the transport
    /// reference.
    #[must_use]
    pub fn config(&self) -> &WorkerClientConfig {
        &self.config
    }

    /// Watchdog boot identity carried by this session.
    #[must_use]
    pub fn watchdog_boot_id(&self) -> &str {
        &self.watchdog_boot_id
    }

    /// Bind this client to one absolute reconciliation deadline.  The worker
    /// transport still honors the shorter configured per-exchange bound.
    #[allow(dead_code)]
    pub(crate) fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    pub(super) fn exchange_timeout(&self) -> Duration {
        self.deadline.map_or(self.config.timeout, |deadline| {
            self.config
                .timeout
                .min(deadline.saturating_duration_since(Instant::now()))
        })
    }
}

impl WorkerClient {
    pub(super) fn header(
        &self,
        command: Command,
        scope: Scope,
        worker_boot_id: Option<&str>,
    ) -> Header {
        Header {
            contract: CONTRACT.to_owned(),
            schema_digest: SCHEMA_DIGEST.to_owned(),
            direction: Direction::Request,
            command,
            scope,
            request_id: Uuid::new_v4().to_string(),
            timeout_ms: duration_millis(self.config.timeout),
            watchdog_boot_id: self.watchdog_boot_id.clone(),
            worker_boot_id: worker_boot_id.map(str::to_owned),
        }
    }
}
