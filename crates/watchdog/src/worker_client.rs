//! Authenticated watchdog-to-harness worker client.
//!
//! This module is the first production consumer of the frozen
//! `ascension-watchdog-worker-handoff-v1` frames.  It owns no worker database
//! and never retries an uncertain dispatch.  The owner-local [`Store`] is
//! updated before a dispatch send and after a matching terminal response.

#[path = "worker_client_auth.rs"]
mod auth;
#[path = "worker_client_transport.rs"]
mod transport;

use crate::error::{Result, WatchdogError};
use crate::storage::{
    Store, WorkerClaimWitness, WorkerControlMode, WorkerControlWitness, WorkerHandoff,
    WorkerHandoffState, WorkerHandoffTuple, WorkerTerminalReceipt, WorkerTerminalStatus,
};
use crate::worker_protocol::{
    AcknowledgeRequest, AcknowledgeResponse, AcknowledgeStatus, CONTRACT, Command, ControlScope,
    Direction, DispatchRequest, DispatchResponse, DispatchStatus, EMPTY_PARAMETERS_DIGEST, Frame,
    HandoffTuple, Header, LookupRequest, LookupResponse, LookupStatus, MAX_TIMEOUT_MS,
    OPERATION_RUNTIME_V3_EPISODE, ProbeRequest, ProbeResponse, SCHEMA_DIGEST, Scope,
    SetControlModeRequest, SetControlModeResponse, TerminalReceipt, TerminalStatus, WorkerMode,
};
use serde_json::Value;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::{Uuid, Variant};

pub use auth::WorkerPeerIdentity;

const DEFAULT_TIMEOUT_MS: u64 = MAX_TIMEOUT_MS;

/// Immutable client settings for one configured worker component.
///
/// The `binding` must come from the owner-approved worker profile, while the
/// peer identity must come from the configured supervised executable.  No
/// request can replace either value.  Credential bytes are read only when an
/// exchange starts and are not retained by this configuration.
#[derive(Clone)]
pub struct WorkerClientConfig {
    endpoint: PathBuf,
    credential_path: PathBuf,
    binding: crate::storage::WorkerBinding,
    peer: WorkerPeerIdentity,
    timeout: Duration,
}

impl fmt::Debug for WorkerClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerClientConfig")
            .field("endpoint", &"<protected-endpoint>")
            .field("credential_path", &"<protected-reference>")
            .field("binding", &self.binding)
            .field("peer", &self.peer)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl WorkerClientConfig {
    /// Construct a client configuration with the five-second contract bound.
    pub fn new(
        endpoint: impl Into<PathBuf>,
        credential_path: impl Into<PathBuf>,
        binding: crate::storage::WorkerBinding,
        peer: WorkerPeerIdentity,
    ) -> Result<Self> {
        let config = Self {
            endpoint: endpoint.into(),
            credential_path: credential_path.into(),
            binding,
            peer,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
        };
        config.validate()
    }

    /// Use a shorter per-connection deadline.  A caller cannot extend the
    /// frozen five-second worker transport bound.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self> {
        self.timeout = timeout;
        self.validate()
    }

    /// Protected worker endpoint reference.
    #[must_use]
    pub fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    /// Protected credential reference.  The credential bytes are never
    /// exposed through this API.
    #[must_use]
    pub fn credential_path(&self) -> &Path {
        &self.credential_path
    }

    /// Immutable profile/release/config/schema binding.
    #[must_use]
    pub fn binding(&self) -> &crate::storage::WorkerBinding {
        &self.binding
    }

    /// Configured worker process identity.
    #[must_use]
    pub fn peer(&self) -> &WorkerPeerIdentity {
        &self.peer
    }

    /// Per-exchange deadline.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    fn validate(self) -> Result<Self> {
        crate::admin::validate_endpoint_path(&self.endpoint)?;
        auth::validate_credential_reference(&self.credential_path)?;
        validate_binding(&self.binding)?;
        if self.timeout.is_zero() || self.timeout > Duration::from_millis(MAX_TIMEOUT_MS) {
            return Err(WatchdogError::InvalidInput(
                "worker client timeout must be between 1ms and 5000ms".to_owned(),
            ));
        }
        Ok(self)
    }
}

fn validate_binding(binding: &crate::storage::WorkerBinding) -> Result<()> {
    if binding.schema_digest != SCHEMA_DIGEST {
        return Err(WatchdogError::Conflict(
            "worker client binding is not the frozen worker-handoff-v1 schema".to_owned(),
        ));
    }
    for (digest, field) in [
        (&binding.worker_profile_digest, "worker profile digest"),
        (&binding.release_digest, "worker release digest"),
        (&binding.config_digest, "worker config digest"),
        (&binding.schema_digest, "worker schema digest"),
    ] {
        crate::config::validate_digest(digest).map_err(|message| {
            WatchdogError::InvalidInput(format!("{field} is invalid: {message}"))
        })?;
    }
    if binding.deployment_id.is_empty()
        || binding.worker_owner_id.is_empty()
        || binding.deployment_id.len() > 128
        || binding.worker_owner_id.len() > 128
        || !binding
            .deployment_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || !binding
            .worker_owner_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(WatchdogError::InvalidInput(
            "worker client binding contains an invalid identity".to_owned(),
        ));
    }
    Ok(())
}

/// A configured watchdog worker session.  The watchdog boot identity is
/// generated once per client/session and appears on every request.
#[derive(Clone)]
pub struct WorkerClient {
    config: WorkerClientConfig,
    watchdog_boot_id: String,
}

impl fmt::Debug for WorkerClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerClient")
            .field("config", &self.config)
            .field("watchdog_boot_id", &self.watchdog_boot_id)
            .finish()
    }
}

impl WorkerClient {
    /// Construct a client bound to an explicit watchdog boot identity.
    pub fn new(config: WorkerClientConfig, watchdog_boot_id: impl Into<String>) -> Result<Self> {
        let client = Self {
            config: config.validate()?,
            watchdog_boot_id: watchdog_boot_id.into(),
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

    /// Read-only bootstrap probe.  It never claims a job or changes worker
    /// control state.
    pub fn probe(&self) -> Result<ProbeResponse> {
        let request = Frame::ProbeRequest(ProbeRequest {
            header: self.header(Command::Probe, Scope::Probe, None),
        });
        let response = transport::exchange(
            &self.config.endpoint,
            &self.config.credential_path,
            &self.config.peer,
            self.config.timeout,
            &request,
        )?;
        let Frame::ProbeResponse(response) = response else {
            return Err(WatchdogError::Conflict(
                "worker probe returned a different response command".to_owned(),
            ));
        };
        let request_header = match &request {
            Frame::ProbeRequest(request) => &request.header,
            _ => {
                return Err(WatchdogError::Conflict(
                    "worker probe request construction changed".to_owned(),
                ));
            }
        };
        validate_response_header(request_header, &response.header, None)?;
        let expected = self.config.binding();
        if response.deployment_id != expected.deployment_id
            || response.worker_owner_id != expected.worker_owner_id
            || response.worker_profile_digest != expected.worker_profile_digest
            || response.release_digest != expected.release_digest
            || response.config_digest != expected.config_digest
        {
            return Err(WatchdogError::Conflict(
                "worker probe binding differs from the configured worker".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Send an authenticated control update to the current worker boot.  The
    /// owner-local control row is intentionally not changed by this method;
    /// use [`Self::set_control_mode_and_persist`] after the response is
    /// authenticated to commit the matching witness.
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_control_mode(
        &self,
        worker_boot_id: &str,
        scope: ControlScope,
    ) -> Result<SetControlModeResponse> {
        validate_uuid4(worker_boot_id, "worker boot id")?;
        validate_control_scope(&scope)?;
        if scope.deployment_id != self.config.binding.deployment_id
            || scope.worker_owner_id != self.config.binding.worker_owner_id
            || scope.worker_profile_digest != self.config.binding.worker_profile_digest
        {
            return Err(WatchdogError::Conflict(
                "worker control scope differs from the configured worker".to_owned(),
            ));
        }
        let request = Frame::SetControlModeRequest(SetControlModeRequest {
            header: self.header(
                Command::SetControlMode,
                Scope::Control,
                Some(worker_boot_id),
            ),
            scope,
        });
        let response = transport::exchange(
            &self.config.endpoint,
            &self.config.credential_path,
            &self.config.peer,
            self.config.timeout,
            &request,
        )?;
        let Frame::SetControlModeResponse(response) = response else {
            return Err(WatchdogError::Conflict(
                "worker control returned a different response command".to_owned(),
            ));
        };
        let Frame::SetControlModeRequest(request) = request else {
            return Err(WatchdogError::Conflict(
                "worker control request construction changed".to_owned(),
            ));
        };
        validate_response_header(&request.header, &response.header, Some(worker_boot_id))?;
        if response.scope != request.scope {
            return Err(WatchdogError::Conflict(
                "worker control response scope does not match the request".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Authenticate a control response and then commit the exact witness in
    /// the watchdog owner-local store.
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_control_mode_and_persist(
        &self,
        store: &mut Store,
        worker_boot_id: &str,
        scope: ControlScope,
        now_ms: u64,
    ) -> Result<WorkerControlWitness> {
        let response = self.set_control_mode(worker_boot_id, scope.clone())?;
        if response.status != crate::worker_protocol::ControlStatus::Accepted {
            return Err(WatchdogError::Conflict(
                "worker rejected the requested control mode".to_owned(),
            ));
        }
        let control = WorkerControlWitness {
            deployment_id: response.scope.deployment_id,
            worker_owner_id: response.scope.worker_owner_id,
            worker_profile_digest: response.scope.worker_profile_digest,
            watchdog_boot_id: self.watchdog_boot_id.clone(),
            worker_boot_id: worker_boot_id.to_owned(),
            mode: storage_control_mode(response.scope.mode),
            mode_sequence: response.scope.mode_sequence,
        };
        store.set_worker_control_at(&control, now_ms)
    }

    /// Send one dispatch after the owner-local admission marker has committed.
    /// This is deliberately private: callers cannot bypass the durable claim,
    /// binding, probe, or `may_have_been_dispatched` ordering.
    fn dispatch(&self, handoff: &WorkerHandoff) -> Result<DispatchResponse> {
        validate_handoff_for_client(self, handoff)?;
        let tuple = protocol_tuple(handoff);
        let request = Frame::DispatchRequest(DispatchRequest {
            header: self.header(
                Command::Dispatch,
                Scope::Dispatch,
                Some(&handoff.worker_boot_id),
            ),
            tuple,
            mode_sequence: handoff.mode_sequence,
            operation: OPERATION_RUNTIME_V3_EPISODE.to_owned(),
            parameters: Value::Object(serde_json::Map::new()),
        });
        let response = transport::exchange(
            &self.config.endpoint,
            &self.config.credential_path,
            &self.config.peer,
            self.config.timeout,
            &request,
        )?;
        let Frame::DispatchResponse(response) = response else {
            return Err(WatchdogError::Conflict(
                "worker dispatch returned a different response command".to_owned(),
            ));
        };
        let Frame::DispatchRequest(request) = request else {
            return Err(WatchdogError::Conflict(
                "worker dispatch request construction changed".to_owned(),
            ));
        };
        validate_response_header(
            &request.header,
            &response.header,
            Some(&handoff.worker_boot_id),
        )?;
        if response.tuple != request.tuple {
            return Err(WatchdogError::Conflict(
                "worker dispatch response tuple does not match the request".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Historical read-only lookup against the current authenticated worker
    /// boot.  It never starts or resumes an episode.
    pub fn lookup(
        &self,
        tuple: &WorkerHandoffTuple,
        current_worker_boot_id: &str,
    ) -> Result<LookupResponse> {
        validate_storage_tuple(tuple)?;
        validate_tuple_for_client(self, tuple)?;
        validate_uuid4(current_worker_boot_id, "worker boot id")?;
        if current_worker_boot_id == self.watchdog_boot_id {
            return Err(WatchdogError::IdentityMismatch(
                "worker lookup target cannot reuse the watchdog boot identity".to_owned(),
            ));
        }
        let request = Frame::LookupRequest(LookupRequest {
            header: self.header(Command::Lookup, Scope::Lookup, Some(current_worker_boot_id)),
            tuple: protocol_tuple_from_storage(tuple),
        });
        let response = transport::exchange(
            &self.config.endpoint,
            &self.config.credential_path,
            &self.config.peer,
            self.config.timeout,
            &request,
        )?;
        let Frame::LookupResponse(response) = response else {
            return Err(WatchdogError::Conflict(
                "worker lookup returned a different response command".to_owned(),
            ));
        };
        let Frame::LookupRequest(request) = request else {
            return Err(WatchdogError::Conflict(
                "worker lookup request construction changed".to_owned(),
            ));
        };
        validate_response_header(
            &request.header,
            &response.header,
            Some(current_worker_boot_id),
        )?;
        if response.tuple != request.tuple {
            return Err(WatchdogError::Conflict(
                "worker lookup response tuple does not match the request".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Acknowledge a durable terminal receipt on the current worker boot.
    /// This is private so terminal delivery cannot be sent without one of the
    /// store-backed claim or recovery orchestration paths below.
    fn acknowledge(
        &self,
        tuple: &WorkerHandoffTuple,
        current_worker_boot_id: &str,
        terminal_digest: &str,
    ) -> Result<AcknowledgeResponse> {
        validate_storage_tuple(tuple)?;
        validate_uuid4(current_worker_boot_id, "worker boot id")?;
        validate_tuple_for_client(self, tuple)?;
        if current_worker_boot_id == self.watchdog_boot_id {
            return Err(WatchdogError::IdentityMismatch(
                "worker acknowledgment target cannot reuse the watchdog boot identity".to_owned(),
            ));
        }
        crate::config::validate_digest(terminal_digest).map_err(|message| {
            WatchdogError::InvalidInput(format!("terminal digest is invalid: {message}"))
        })?;
        let request = Frame::AcknowledgeRequest(AcknowledgeRequest {
            header: self.header(
                Command::Acknowledge,
                Scope::Acknowledge,
                Some(current_worker_boot_id),
            ),
            tuple: protocol_tuple_from_storage(tuple),
            terminal_digest: terminal_digest.to_owned(),
        });
        let response = transport::exchange(
            &self.config.endpoint,
            &self.config.credential_path,
            &self.config.peer,
            self.config.timeout,
            &request,
        )?;
        let Frame::AcknowledgeResponse(response) = response else {
            return Err(WatchdogError::Conflict(
                "worker acknowledgment returned a different response command".to_owned(),
            ));
        };
        let Frame::AcknowledgeRequest(request) = request else {
            return Err(WatchdogError::Conflict(
                "worker acknowledgment request construction changed".to_owned(),
            ));
        };
        validate_response_header(
            &request.header,
            &response.header,
            Some(current_worker_boot_id),
        )?;
        if response.tuple != request.tuple {
            return Err(WatchdogError::Conflict(
                "worker acknowledgment response tuple does not match the request".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Claim one eligible job, durably mark it before transport, and dispatch
    /// exactly once.  A response-loss/transport error leaves the durable
    /// reservation held for [`Self::reconcile_handoff`].
    pub fn claim_and_dispatch(
        &self,
        store: &mut Store,
        witness: &WorkerClaimWitness,
        now_ms: u64,
    ) -> Result<Option<WorkerDispatchResult>> {
        validate_claim_witness_for_client(self, witness)?;
        self.probe_for_claim(witness)?;
        let Some(claim) = store.claim_next_worker_handoff(witness, now_ms)? else {
            return Ok(None);
        };
        let tuple = claim.tuple();
        let marked = store.mark_worker_handoff_may_have_been_dispatched_at(&tuple, now_ms)?;
        let response = self.dispatch(&marked)?;
        let mut final_handoff = marked;
        let mut acknowledged = false;
        match response.status {
            DispatchStatus::Accepted => {
                final_handoff = store.mark_worker_handoff_admitted_at(&tuple, now_ms)?;
            }
            DispatchStatus::Terminal | DispatchStatus::AlreadyCompleted => {
                let receipt = response.terminal.as_ref().ok_or_else(|| {
                    WatchdogError::Conflict(
                        "terminal worker dispatch response has no receipt".to_owned(),
                    )
                })?;
                let completion =
                    store.complete_worker_handoff_at(&tuple, &storage_receipt(receipt), now_ms)?;
                let ack_response =
                    self.acknowledge(&tuple, &witness.worker_boot_id, &completion.terminal_digest)?;
                if !matches!(
                    ack_response.status,
                    AcknowledgeStatus::Acknowledged | AcknowledgeStatus::AlreadyAcknowledged
                ) {
                    return Err(WatchdogError::Conflict(
                        "worker rejected terminal acknowledgment".to_owned(),
                    ));
                }
                let _ack = store.acknowledge_worker_handoff_at(
                    &tuple,
                    &completion.terminal_digest,
                    now_ms,
                )?;
                acknowledged = true;
                final_handoff = store.worker_handoff(&tuple.handoff_id)?.ok_or_else(|| {
                    WatchdogError::Conflict(
                        "worker handoff disappeared after acknowledgment".to_owned(),
                    )
                })?;
            }
            DispatchStatus::Busy | DispatchStatus::Rejected => {
                // The send was authorized and may have reached the worker.
                // Retain the may-have-been-dispatched reservation even when a
                // nonterminal response says it did not admit execution.
            }
        }
        Ok(Some(WorkerDispatchResult {
            handoff: final_handoff,
            status: response.status,
            terminal: response.terminal,
            acknowledged,
        }))
    }

    /// Resolve one held handoff by historical lookup, then complete and
    /// acknowledge a matching terminal receipt.  This method has no dispatch
    /// path and therefore cannot start a completed episode again.
    pub fn reconcile_handoff(
        &self,
        store: &mut Store,
        tuple: &WorkerHandoffTuple,
        current_control: &WorkerControlWitness,
        now_ms: u64,
    ) -> Result<WorkerReconcileResult> {
        validate_recovery_witness_for_client(self, current_control)?;
        let Some(existing) = store.lookup_worker_handoff(tuple)? else {
            return Err(WatchdogError::NotFound(format!(
                "worker handoff {}",
                tuple.handoff_id
            )));
        };
        let response = self.lookup(tuple, &current_control.worker_boot_id)?;
        let mut handoff = existing;
        let mut acknowledged = false;
        if response.status == LookupStatus::Terminal {
            let receipt = response.terminal.as_ref().ok_or_else(|| {
                WatchdogError::Conflict("terminal lookup response has no receipt".to_owned())
            })?;
            let completion = store.complete_worker_handoff_with_recovery_at(
                tuple,
                &storage_receipt(receipt),
                current_control,
                now_ms,
            )?;
            let ack_response = self.acknowledge(
                tuple,
                &current_control.worker_boot_id,
                &completion.terminal_digest,
            )?;
            if !matches!(
                ack_response.status,
                AcknowledgeStatus::Acknowledged | AcknowledgeStatus::AlreadyAcknowledged
            ) {
                return Err(WatchdogError::Conflict(
                    "worker rejected terminal acknowledgment".to_owned(),
                ));
            }
            let _ack = store.acknowledge_worker_handoff_with_recovery_at(
                tuple,
                &completion.terminal_digest,
                current_control,
                now_ms,
            )?;
            acknowledged = true;
            handoff = store.worker_handoff(&tuple.handoff_id)?.ok_or_else(|| {
                WatchdogError::Conflict(
                    "worker handoff disappeared after reconciliation".to_owned(),
                )
            })?;
        }
        Ok(WorkerReconcileResult {
            handoff,
            status: response.status,
            terminal: response.terminal,
            acknowledged,
        })
    }

    fn probe_for_claim(&self, witness: &WorkerClaimWitness) -> Result<()> {
        let response = self.probe()?;
        if !response.ready {
            return Err(WatchdogError::Conflict(
                "worker probe is not ready for admission".to_owned(),
            ));
        }
        if response.header.worker_boot_id.as_deref() != Some(witness.worker_boot_id.as_str()) {
            return Err(WatchdogError::IdentityMismatch(
                "worker probe boot differs from the durable claim witness".to_owned(),
            ));
        }
        Ok(())
    }

    fn header(&self, command: Command, scope: Scope, worker_boot_id: Option<&str>) -> Header {
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

/// Outcome of one bounded claim/dispatch exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerDispatchResult {
    pub handoff: WorkerHandoff,
    pub status: DispatchStatus,
    pub terminal: Option<TerminalReceipt>,
    pub acknowledged: bool,
}

/// Outcome of lookup-based historical reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerReconcileResult {
    pub handoff: WorkerHandoff,
    pub status: LookupStatus,
    pub terminal: Option<TerminalReceipt>,
    pub acknowledged: bool,
}

fn validate_response_header(
    request: &Header,
    response: &Header,
    expected_worker_boot_id: Option<&str>,
) -> Result<()> {
    let worker_boot_matches = match expected_worker_boot_id {
        Some(expected) => response.worker_boot_id.as_deref() == Some(expected),
        // A probe does not target a worker boot, so the live boot is selected
        // by the worker and must be returned as a fresh, valid identity.
        None => response
            .worker_boot_id
            .as_deref()
            .map(|value| validate_uuid4(value, "worker boot id"))
            .transpose()?
            .is_some(),
    };
    if response.direction != Direction::Response
        || response.command != request.command
        || response.scope != request.scope
        || response.contract != CONTRACT
        || response.schema_digest != SCHEMA_DIGEST
        || response.request_id != request.request_id
        || response.watchdog_boot_id != request.watchdog_boot_id
        || response.timeout_ms != request.timeout_ms
        || !worker_boot_matches
    {
        return Err(WatchdogError::IdentityMismatch(
            "worker response identity or correlation does not match the request".to_owned(),
        ));
    }
    Ok(())
}

fn protocol_tuple(handoff: &WorkerHandoff) -> HandoffTuple {
    HandoffTuple {
        handoff_id: handoff.handoff_id.clone(),
        deployment_id: handoff.deployment_id.clone(),
        job_id: handoff.job_id.clone(),
        attempt_id: handoff.attempt_id.clone(),
        attempt_number: u64::from(handoff.attempt_number),
        worker_owner_id: handoff.worker_owner_id.clone(),
        worker_profile_digest: handoff.worker_profile_digest.clone(),
        run_id: handoff.run_id.clone(),
        episode_id: handoff.episode_id.clone(),
        trajectory_id: handoff.trajectory_id.clone(),
        payload_digest: handoff.payload_digest.clone(),
    }
}

fn protocol_tuple_from_storage(tuple: &WorkerHandoffTuple) -> HandoffTuple {
    HandoffTuple {
        handoff_id: tuple.handoff_id.clone(),
        deployment_id: tuple.deployment_id.clone(),
        job_id: tuple.job_id.clone(),
        attempt_id: tuple.attempt_id.clone(),
        attempt_number: u64::from(tuple.attempt_number),
        worker_owner_id: tuple.worker_owner_id.clone(),
        worker_profile_digest: tuple.worker_profile_digest.clone(),
        run_id: tuple.run_id.clone(),
        episode_id: tuple.episode_id.clone(),
        trajectory_id: tuple.trajectory_id.clone(),
        payload_digest: tuple.payload_digest.clone(),
    }
}

fn validate_handoff_for_client(client: &WorkerClient, handoff: &WorkerHandoff) -> Result<()> {
    if handoff.state != WorkerHandoffState::MayHaveBeenDispatched {
        return Err(WatchdogError::Conflict(
            "worker dispatch requires a committed may_have_been_dispatched handoff".to_owned(),
        ));
    }
    if handoff.operation != OPERATION_RUNTIME_V3_EPISODE
        || handoff.parameters != Value::Object(serde_json::Map::new())
        || handoff.payload_digest != EMPTY_PARAMETERS_DIGEST
        || handoff.job.worker_id.as_deref() != Some(handoff.worker_owner_id.as_str())
    {
        return Err(WatchdogError::Conflict(
            "worker handoff is not the configured empty runtime-v3 episode".to_owned(),
        ));
    }
    if handoff.watchdog_boot_id != client.watchdog_boot_id {
        return Err(WatchdogError::Conflict(
            "worker handoff is not bound to this watchdog session".to_owned(),
        ));
    }
    validate_storage_tuple(&handoff.tuple())?;
    validate_tuple_for_client(client, &handoff.tuple())?;
    validate_uuid4(&handoff.worker_boot_id, "worker boot id")?;
    if handoff.mode_sequence == 0 {
        return Err(WatchdogError::InvalidInput(
            "worker mode sequence must be positive".to_owned(),
        ));
    }
    Ok(())
}

fn validate_tuple_for_client(client: &WorkerClient, tuple: &WorkerHandoffTuple) -> Result<()> {
    if tuple.deployment_id != client.config.binding.deployment_id
        || tuple.worker_owner_id != client.config.binding.worker_owner_id
        || tuple.worker_profile_digest != client.config.binding.worker_profile_digest
    {
        return Err(WatchdogError::Conflict(
            "worker handoff tuple differs from the configured worker".to_owned(),
        ));
    }
    Ok(())
}

fn validate_claim_witness_for_client(
    client: &WorkerClient,
    witness: &WorkerClaimWitness,
) -> Result<()> {
    if witness.deployment_id != client.config.binding.deployment_id
        || witness.worker_owner_id != client.config.binding.worker_owner_id
        || witness.worker_profile_digest != client.config.binding.worker_profile_digest
        || witness.release_digest != client.config.binding.release_digest
        || witness.config_digest != client.config.binding.config_digest
        || witness.schema_digest != client.config.binding.schema_digest
        || witness.watchdog_boot_id != client.watchdog_boot_id
    {
        return Err(WatchdogError::Conflict(
            "worker claim witness differs from the configured client binding".to_owned(),
        ));
    }
    validate_uuid4(&witness.watchdog_boot_id, "watchdog boot id")?;
    validate_uuid4(&witness.worker_boot_id, "worker boot id")?;
    if witness.watchdog_boot_id == witness.worker_boot_id || witness.mode_sequence == 0 {
        return Err(WatchdogError::InvalidInput(
            "worker claim witness has an invalid boot or mode sequence".to_owned(),
        ));
    }
    for (digest, field) in [
        (&witness.worker_profile_digest, "worker profile digest"),
        (&witness.release_digest, "worker release digest"),
        (&witness.config_digest, "worker config digest"),
        (&witness.schema_digest, "worker schema digest"),
    ] {
        crate::config::validate_digest(digest).map_err(|message| {
            WatchdogError::InvalidInput(format!("{field} is invalid: {message}"))
        })?;
    }
    Ok(())
}

fn validate_recovery_witness_for_client(
    client: &WorkerClient,
    recovery: &WorkerControlWitness,
) -> Result<()> {
    if recovery.deployment_id != client.config.binding.deployment_id
        || recovery.worker_owner_id != client.config.binding.worker_owner_id
        || recovery.worker_profile_digest != client.config.binding.worker_profile_digest
        || recovery.watchdog_boot_id != client.watchdog_boot_id
    {
        return Err(WatchdogError::Conflict(
            "worker recovery witness differs from the configured client binding".to_owned(),
        ));
    }
    validate_uuid4(&recovery.watchdog_boot_id, "watchdog boot id")?;
    validate_uuid4(&recovery.worker_boot_id, "worker boot id")?;
    if recovery.watchdog_boot_id == recovery.worker_boot_id || recovery.mode_sequence == 0 {
        return Err(WatchdogError::InvalidInput(
            "worker recovery witness has an invalid boot or mode sequence".to_owned(),
        ));
    }
    crate::config::validate_digest(&recovery.worker_profile_digest).map_err(|message| {
        WatchdogError::InvalidInput(format!("worker profile digest is invalid: {message}"))
    })?;
    Ok(())
}

fn validate_storage_tuple(tuple: &WorkerHandoffTuple) -> Result<()> {
    for (value, field) in [
        (&tuple.handoff_id, "handoff id"),
        (&tuple.run_id, "run id"),
        (&tuple.episode_id, "episode id"),
        (&tuple.trajectory_id, "trajectory id"),
    ] {
        validate_uuid4(value, field)?;
    }
    if tuple.handoff_id == tuple.run_id
        || tuple.handoff_id == tuple.episode_id
        || tuple.handoff_id == tuple.trajectory_id
        || tuple.run_id == tuple.episode_id
        || tuple.run_id == tuple.trajectory_id
        || tuple.episode_id == tuple.trajectory_id
    {
        return Err(WatchdogError::InvalidInput(
            "worker handoff tuple UUIDs must be pairwise distinct".to_owned(),
        ));
    }
    if tuple.attempt_number == 0 || tuple.payload_digest != EMPTY_PARAMETERS_DIGEST {
        return Err(WatchdogError::InvalidInput(
            "worker handoff tuple has an invalid attempt or payload digest".to_owned(),
        ));
    }
    crate::config::validate_digest(&tuple.worker_profile_digest).map_err(|message| {
        WatchdogError::InvalidInput(format!("worker profile digest is invalid: {message}"))
    })?;
    crate::config::validate_digest(&tuple.payload_digest).map_err(|message| {
        WatchdogError::InvalidInput(format!("payload digest is invalid: {message}"))
    })?;
    Ok(())
}

fn storage_receipt(receipt: &TerminalReceipt) -> WorkerTerminalReceipt {
    WorkerTerminalReceipt {
        status: match receipt.status {
            TerminalStatus::Completed => WorkerTerminalStatus::Completed,
            TerminalStatus::Failed => WorkerTerminalStatus::Failed,
        },
        checkpoint_sequence: receipt.checkpoint_sequence,
        terminal_ref: receipt.terminal_ref.clone(),
        result_digest: receipt.result_digest.clone(),
    }
}

fn storage_control_mode(mode: WorkerMode) -> WorkerControlMode {
    match mode {
        WorkerMode::Running => WorkerControlMode::Running,
        WorkerMode::Paused => WorkerControlMode::Paused,
        WorkerMode::Draining => WorkerControlMode::Draining,
        WorkerMode::Stopped => WorkerControlMode::Stopped,
    }
}

fn validate_control_scope(scope: &ControlScope) -> Result<()> {
    if scope.deployment_id.is_empty()
        || scope.worker_owner_id.is_empty()
        || scope.worker_profile_digest.len() != 64
        || scope.mode_sequence == 0
    {
        return Err(WatchdogError::InvalidInput(
            "worker control scope is outside its bounds".to_owned(),
        ));
    }
    crate::config::validate_digest(&scope.worker_profile_digest).map_err(|message| {
        WatchdogError::InvalidInput(format!("worker profile digest is invalid: {message}"))
    })
}

fn validate_uuid4(value: &str, field: &str) -> Result<()> {
    let uuid = Uuid::parse_str(value)
        .map_err(|_| WatchdogError::InvalidInput(format!("{field} must be a canonical UUIDv4")))?;
    if uuid.get_version_num() != 4
        || uuid.get_variant() != Variant::RFC4122
        || uuid.to_string() != value
    {
        return Err(WatchdogError::InvalidInput(format!(
            "{field} must be a lowercase canonical UUIDv4"
        )));
    }
    Ok(())
}

fn duration_millis(timeout: Duration) -> u64 {
    let millis = timeout.as_millis();
    match u64::try_from(millis) {
        Ok(value) => value,
        Err(_) => DEFAULT_TIMEOUT_MS,
    }
}
