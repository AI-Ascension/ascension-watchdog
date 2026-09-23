//! Authenticated request envelope and its token-free dispatch context.

use super::commands::AdminCommand;
use super::identity::{AuthenticatedPrincipalClass, Capability};
use super::validation::{command_fingerprint, validate_identifier, validate_uuid_v4};
use super::views::ContractVersion;
use super::{MAX_ID_BYTES, MAX_TOKEN_BYTES};
use crate::admin::{MAX_DEADLINE_MS, MAX_PAYLOAD_BYTES};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Request envelope.  The token is only used for transport authentication and
/// has no `Serialize`-safe status/audit representation.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRequest {
    pub contract: ContractVersion,
    pub request_id: String,
    pub idempotency_key: String,
    pub capability: Capability,
    pub token: String,
    pub deadline_ms: u32,
    pub command: AdminCommand,
}

/// Token-free, validated identity handed to the watchdog reconciliation loop.
///
/// A transport may retain the raw request only while authenticating it.  Once
/// this context is constructed, the request credential is dropped and cannot
/// be observed by an [`AdminDispatcher`] implementation.  The command
/// fingerprint is canonical: it covers the v1 contract, claimed capability,
/// and closed command payload, while excluding the request UUID, deadline,
/// transport identity, and credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchContext {
    pub(super) request_id: Uuid,
    pub(super) idempotency_key: String,
    capability: Capability,
    principal: AuthenticatedPrincipalClass,
    command_fingerprint: String,
}

impl DispatchContext {
    /// Construct and validate a queue context from an authenticated request.
    pub fn from_request(
        request: &AdminRequest,
        principal: AuthenticatedPrincipalClass,
    ) -> std::result::Result<Self, String> {
        request.validate()?;
        if !request
            .capability
            .includes(request.command.name().required_capability())
        {
            return Err("capability does not authorize the command".to_string());
        }
        let request_id = Uuid::parse_str(&request.request_id)
            .map_err(|_| "request_id is not a UUID".to_string())?;
        let context = Self {
            request_id,
            idempotency_key: request.idempotency_key.clone(),
            capability: request.capability,
            principal,
            command_fingerprint: request.fingerprint(),
        };
        context.validate()?;
        Ok(context)
    }

    /// Validate every field before the context crosses the transport queue.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.request_id.get_version_num() != 4 {
            return Err("request_id must be a UUIDv4".to_string());
        }
        validate_identifier(&self.idempotency_key, "idempotency_key", MAX_ID_BYTES)?;
        if self.command_fingerprint.len() != 64
            || !self
                .command_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("command fingerprint must be a SHA-256 hex digest".to_string());
        }
        Ok(())
    }

    /// Request UUID assigned by the authenticated caller.
    #[must_use]
    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    /// Durable idempotency key for the accepted command.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Claimed capability after transport authorization.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.capability
    }

    /// Coarse authenticated identity; no raw credential or OS path is exposed.
    #[must_use]
    pub const fn principal(&self) -> AuthenticatedPrincipalClass {
        self.principal
    }

    /// Canonical SHA-256 command fingerprint used for idempotency/audit.
    #[must_use]
    pub fn command_fingerprint(&self) -> &str {
        &self.command_fingerprint
    }
}

impl fmt::Debug for AdminRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminRequest")
            .field("contract", &self.contract)
            .field("request_id", &self.request_id)
            .field("idempotency_key", &self.idempotency_key)
            .field("capability", &self.capability)
            .field("token", &"<redacted>")
            .field("deadline_ms", &self.deadline_ms)
            .field("command", &self.command)
            .finish()
    }
}

impl AdminRequest {
    /// Validate closed values before queue admission.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.contract != ContractVersion::V1 {
            return Err("unsupported admin contract".to_string());
        }
        validate_uuid_v4(&self.request_id, "request_id")?;
        validate_identifier(&self.idempotency_key, "idempotency_key", MAX_ID_BYTES)?;
        if self.token.is_empty()
            || self.token.len() > MAX_TOKEN_BYTES
            || self.token.as_bytes().contains(&0)
            || !self.token.is_ascii()
        {
            return Err("token is empty or exceeds its bound".to_string());
        }
        if self.deadline_ms == 0 || self.deadline_ms > MAX_DEADLINE_MS {
            return Err(format!("deadline_ms must be 1..={MAX_DEADLINE_MS}"));
        }
        self.command.validate()?;
        if serde_json::to_vec(&self.command)
            .map_err(|error| error.to_string())?
            .len()
            > MAX_PAYLOAD_BYTES
        {
            return Err("command payload exceeds payload bound".to_string());
        }
        Ok(())
    }

    /// Digest the logical request without including credentials, request
    /// transport identity, or local deadline.  Reusing an idempotency key with
    /// a different command is a conflict, never a second dispatch.
    pub fn fingerprint(&self) -> String {
        command_fingerprint(self.capability, &self.command)
    }

    /// Build the token-free context used by the main-loop dispatcher after
    /// transport authentication has selected a principal class.
    pub fn dispatch_context(
        &self,
        principal: AuthenticatedPrincipalClass,
    ) -> std::result::Result<DispatchContext, String> {
        DispatchContext::from_request(self, principal)
    }

    /// Construct a request using a fresh UUID identity.
    pub fn new(
        capability: Capability,
        token: String,
        idempotency_key: String,
        command: AdminCommand,
        deadline_ms: u32,
    ) -> std::result::Result<Self, String> {
        let request = Self {
            contract: ContractVersion::V1,
            request_id: Uuid::new_v4().to_string(),
            idempotency_key,
            capability,
            token,
            deadline_ms,
            command,
        };
        request.validate()?;
        Ok(request)
    }
}
