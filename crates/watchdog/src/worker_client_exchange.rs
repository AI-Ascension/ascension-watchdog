//! Authenticated request/response exchange against one worker boot.
//!
//! Each method builds one frozen protocol frame, exchanges it through the
//! bounded transport and validates the correlated response header.  The
//! `_phase` variants retain the transport/persistence failure classification
//! for the supervisor's bounded reconciliation phase.

use crate::error::{Result, WatchdogError};
use crate::storage::{WorkerHandoff, WorkerHandoffTuple};
use crate::worker_protocol::{
    AcknowledgeRequest, AcknowledgeResponse, Command, ControlScope, DispatchRequest,
    DispatchResponse, Frame, LookupRequest, LookupResponse, OPERATION_RUNTIME_V3_EPISODE,
    ProbeRequest, ProbeResponse, Scope, SetControlModeRequest, SetControlModeResponse,
};
use serde_json::Value;

use super::session::{WorkerClient, WorkerPhaseError};
use super::transport;
use super::validation::{
    protocol_tuple, protocol_tuple_from_storage, validate_control_scope,
    validate_handoff_for_client, validate_response_header, validate_storage_tuple,
    validate_tuple_for_client, validate_uuid4,
};

impl WorkerClient {
    fn exchange(&self, request: &Frame) -> Result<Frame> {
        let timeout = self.exchange_timeout();
        if timeout.is_zero() {
            return Err(WatchdogError::Timeout(
                "worker reconciliation deadline expired".to_owned(),
            ));
        }
        if let Some(deadline) = self.deadline {
            transport::exchange_until(
                &self.config.endpoint,
                &self.config.credential_path,
                &self.config.peer,
                deadline,
                request,
            )
        } else {
            transport::exchange(
                &self.config.endpoint,
                &self.config.credential_path,
                &self.config.peer,
                timeout,
                request,
            )
        }
    }

    /// Read-only bootstrap probe.  It never claims a job or changes worker
    /// control state.
    pub fn probe(&self) -> Result<ProbeResponse> {
        self.probe_phase()
            .map_err(WorkerPhaseError::into_watchdog_error)
    }

    /// Probe with the transport/persistence boundary retained for the
    /// supervisor's bounded worker phase.
    pub(crate) fn probe_phase(&self) -> std::result::Result<ProbeResponse, WorkerPhaseError> {
        let request = Frame::ProbeRequest(ProbeRequest {
            header: self.header(Command::Probe, Scope::Probe, None),
        });
        let response = self
            .exchange(&request)
            .map_err(WorkerPhaseError::transport)?;
        let Frame::ProbeResponse(response) = response else {
            return Err(WorkerPhaseError::Fatal(WatchdogError::Conflict(
                "worker probe returned a different response command".to_owned(),
            )));
        };
        let request_header = match &request {
            Frame::ProbeRequest(request) => &request.header,
            _ => {
                return Err(WorkerPhaseError::Fatal(WatchdogError::Conflict(
                    "worker probe request construction changed".to_owned(),
                )));
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
            return Err(WorkerPhaseError::Fatal(WatchdogError::Conflict(
                "worker probe binding differs from the configured worker".to_owned(),
            )));
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
        self.set_control_mode_phase(worker_boot_id, scope)
            .map_err(WorkerPhaseError::into_watchdog_error)
    }

    /// Send control while retaining transport failure classification for the
    /// supervisor phase.  No durable control witness is written here.
    pub(crate) fn set_control_mode_phase(
        &self,
        worker_boot_id: &str,
        scope: ControlScope,
    ) -> std::result::Result<SetControlModeResponse, WorkerPhaseError> {
        validate_uuid4(worker_boot_id, "worker boot id")?;
        validate_control_scope(&scope)?;
        if scope.deployment_id != self.config.binding.deployment_id
            || scope.worker_owner_id != self.config.binding.worker_owner_id
            || scope.worker_profile_digest != self.config.binding.worker_profile_digest
        {
            return Err(WorkerPhaseError::Fatal(WatchdogError::Conflict(
                "worker control scope differs from the configured worker".to_owned(),
            )));
        }
        let request = Frame::SetControlModeRequest(SetControlModeRequest {
            header: self.header(
                Command::SetControlMode,
                Scope::Control,
                Some(worker_boot_id),
            ),
            scope,
        });
        let response = self
            .exchange(&request)
            .map_err(WorkerPhaseError::transport)?;
        let Frame::SetControlModeResponse(response) = response else {
            return Err(WorkerPhaseError::Fatal(WatchdogError::Conflict(
                "worker control returned a different response command".to_owned(),
            )));
        };
        let Frame::SetControlModeRequest(request) = request else {
            return Err(WorkerPhaseError::Fatal(WatchdogError::Conflict(
                "worker control request construction changed".to_owned(),
            )));
        };
        validate_response_header(&request.header, &response.header, Some(worker_boot_id))?;
        if response.scope != request.scope {
            return Err(WorkerPhaseError::Fatal(WatchdogError::Conflict(
                "worker control response scope does not match the request".to_owned(),
            )));
        }
        Ok(response)
    }
    /// Send one dispatch after the owner-local admission marker has committed.
    /// This is deliberately private: callers cannot bypass the durable claim,
    /// binding, probe, or `may_have_been_dispatched` ordering.
    pub(super) fn dispatch(&self, handoff: &WorkerHandoff) -> Result<DispatchResponse> {
        self.dispatch_phase(handoff)
            .map_err(WorkerPhaseError::into_watchdog_error)
    }

    /// Dispatch with transport failure classification retained for the
    /// supervisor's phase adapter.  The caller still has to commit the
    /// durable admission marker before invoking this method.
    pub(crate) fn dispatch_phase(
        &self,
        handoff: &WorkerHandoff,
    ) -> std::result::Result<DispatchResponse, WorkerPhaseError> {
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
        let response = self
            .exchange(&request)
            .map_err(WorkerPhaseError::transport)?;
        let Frame::DispatchResponse(response) = response else {
            return Err(WorkerPhaseError::Fatal(WatchdogError::Conflict(
                "worker dispatch returned a different response command".to_owned(),
            )));
        };
        let Frame::DispatchRequest(request) = request else {
            return Err(WorkerPhaseError::Fatal(WatchdogError::Conflict(
                "worker dispatch request construction changed".to_owned(),
            )));
        };
        validate_response_header(
            &request.header,
            &response.header,
            Some(&handoff.worker_boot_id),
        )?;
        if response.tuple != request.tuple {
            return Err(WorkerPhaseError::Fatal(WatchdogError::Conflict(
                "worker dispatch response tuple does not match the request".to_owned(),
            )));
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
        self.lookup_phase(tuple, current_worker_boot_id)
            .map_err(WorkerPhaseError::into_watchdog_error)
    }

    /// Historical lookup with transport failure classification retained for
    /// the supervisor's recovery phase.
    pub(crate) fn lookup_phase(
        &self,
        tuple: &WorkerHandoffTuple,
        current_worker_boot_id: &str,
    ) -> std::result::Result<LookupResponse, WorkerPhaseError> {
        validate_storage_tuple(tuple)?;
        validate_tuple_for_client(self, tuple)?;
        validate_uuid4(current_worker_boot_id, "worker boot id")?;
        if current_worker_boot_id == self.watchdog_boot_id {
            return Err(WorkerPhaseError::Fatal(WatchdogError::IdentityMismatch(
                "worker lookup target cannot reuse the watchdog boot identity".to_owned(),
            )));
        }
        let request = Frame::LookupRequest(LookupRequest {
            header: self.header(Command::Lookup, Scope::Lookup, Some(current_worker_boot_id)),
            tuple: protocol_tuple_from_storage(tuple),
        });
        let response = self
            .exchange(&request)
            .map_err(WorkerPhaseError::transport)?;
        let Frame::LookupResponse(response) = response else {
            return Err(WorkerPhaseError::Fatal(WatchdogError::Conflict(
                "worker lookup returned a different response command".to_owned(),
            )));
        };
        let Frame::LookupRequest(request) = request else {
            return Err(WatchdogError::Conflict(
                "worker lookup request construction changed".to_owned(),
            )
            .into());
        };
        validate_response_header(
            &request.header,
            &response.header,
            Some(current_worker_boot_id),
        )?;
        if response.tuple != request.tuple {
            return Err(WorkerPhaseError::Fatal(WatchdogError::Conflict(
                "worker lookup response tuple does not match the request".to_owned(),
            )));
        }
        Ok(response)
    }

    /// Acknowledge a durable terminal receipt on the current worker boot.
    /// This is private so terminal delivery cannot be sent without one of the
    /// store-backed claim or recovery orchestration paths below.
    pub(super) fn acknowledge(
        &self,
        tuple: &WorkerHandoffTuple,
        current_worker_boot_id: &str,
        terminal_digest: &str,
    ) -> Result<AcknowledgeResponse> {
        self.acknowledge_phase(tuple, current_worker_boot_id, terminal_digest)
            .map_err(WorkerPhaseError::into_watchdog_error)
    }

    /// Acknowledge with transport failure classification retained for the
    /// supervisor's terminal-delivery phase.
    pub(crate) fn acknowledge_phase(
        &self,
        tuple: &WorkerHandoffTuple,
        current_worker_boot_id: &str,
        terminal_digest: &str,
    ) -> std::result::Result<AcknowledgeResponse, WorkerPhaseError> {
        validate_storage_tuple(tuple)?;
        validate_uuid4(current_worker_boot_id, "worker boot id")?;
        validate_tuple_for_client(self, tuple)?;
        if current_worker_boot_id == self.watchdog_boot_id {
            return Err(WorkerPhaseError::Fatal(WatchdogError::IdentityMismatch(
                "worker acknowledgment target cannot reuse the watchdog boot identity".to_owned(),
            )));
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
        let response = self
            .exchange(&request)
            .map_err(WorkerPhaseError::transport)?;
        let Frame::AcknowledgeResponse(response) = response else {
            return Err(WorkerPhaseError::Fatal(WatchdogError::Conflict(
                "worker acknowledgment returned a different response command".to_owned(),
            )));
        };
        let Frame::AcknowledgeRequest(request) = request else {
            return Err(WatchdogError::Conflict(
                "worker acknowledgment request construction changed".to_owned(),
            )
            .into());
        };
        validate_response_header(
            &request.header,
            &response.header,
            Some(current_worker_boot_id),
        )?;
        if response.tuple != request.tuple {
            return Err(WorkerPhaseError::Fatal(WatchdogError::Conflict(
                "worker acknowledgment response tuple does not match the request".to_owned(),
            )));
        }
        Ok(response)
    }
}
