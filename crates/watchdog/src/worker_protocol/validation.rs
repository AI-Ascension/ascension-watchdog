use super::types::{
    ControlScope, DispatchStatus, Frame, HandoffTuple, Header, LookupStatus, ProtocolError,
    TerminalReceipt,
};
use super::{
    CONTRACT, Command, Direction, EMPTY_PARAMETERS_DIGEST, MAX_ATTEMPT_NUMBER, MAX_IDENTITY_BYTES,
    MAX_OPERATION_BYTES, MAX_REFERENCE_BYTES, MAX_TERMINAL_BYTES, MAX_TIMEOUT_MS,
    OPERATION_RUNTIME_V3_EPISODE, SCHEMA_DIGEST, Scope,
};
use serde_json::Value;
use uuid::{Uuid, Version};

pub fn validate_frame(frame: &Frame) -> Result<(), ProtocolError> {
    match frame {
        Frame::ProbeRequest(value) => validate_header(
            &value.header,
            Direction::Request,
            Command::Probe,
            Scope::Probe,
            false,
        ),
        Frame::ProbeResponse(value) => {
            validate_header(
                &value.header,
                Direction::Response,
                Command::Probe,
                Scope::Probe,
                true,
            )?;
            validate_identity("deployment_id", &value.deployment_id)?;
            validate_identity("worker_owner_id", &value.worker_owner_id)?;
            validate_digest("worker_profile_digest", &value.worker_profile_digest)?;
            validate_digest("release_digest", &value.release_digest)?;
            validate_digest("config_digest", &value.config_digest)?;
            if value.admitting {
                return Err(ProtocolError::InvalidControl(
                    "probe cannot authorize admission".to_owned(),
                ));
            }
            Ok(())
        }
        Frame::DispatchRequest(value) => {
            validate_header(
                &value.header,
                Direction::Request,
                Command::Dispatch,
                Scope::Dispatch,
                true,
            )?;
            validate_tuple(&value.tuple)?;
            validate_mode_sequence(value.mode_sequence)?;
            if value.operation != OPERATION_RUNTIME_V3_EPISODE
                || value.operation.len() > MAX_OPERATION_BYTES
            {
                return Err(ProtocolError::InvalidSchema(
                    "dispatch operation is not runtime_v3_episode".to_owned(),
                ));
            }
            validate_parameters(&value.parameters)?;
            if EMPTY_PARAMETERS_DIGEST != value.tuple.payload_digest {
                return Err(ProtocolError::InvalidDigest(
                    "payload_digest must bind the empty runtime_v3_episode parameters".to_owned(),
                ));
            }
            Ok(())
        }
        Frame::DispatchResponse(value) => {
            validate_header(
                &value.header,
                Direction::Response,
                Command::Dispatch,
                Scope::Dispatch,
                true,
            )?;
            validate_tuple(&value.tuple)?;
            validate_dispatch_terminal(value.status, value.terminal.as_ref(), &value.tuple)
        }
        Frame::LookupRequest(value) => {
            validate_header(
                &value.header,
                Direction::Request,
                Command::Lookup,
                Scope::Lookup,
                true,
            )?;
            validate_tuple(&value.tuple)
        }
        Frame::LookupResponse(value) => {
            validate_header(
                &value.header,
                Direction::Response,
                Command::Lookup,
                Scope::Lookup,
                true,
            )?;
            validate_tuple(&value.tuple)?;
            match value.status {
                LookupStatus::Terminal => validate_receipt(
                    value.terminal.as_ref().ok_or_else(|| {
                        ProtocolError::InvalidTerminal(
                            "terminal lookup requires a receipt".to_owned(),
                        )
                    })?,
                    &value.tuple,
                ),
                LookupStatus::Running | LookupStatus::Unknown | LookupStatus::Rejected => {
                    if value.terminal.is_some() {
                        return Err(ProtocolError::InvalidTerminal(
                            "nonterminal lookup cannot carry a receipt".to_owned(),
                        ));
                    }
                    Ok(())
                }
            }
        }
        Frame::AcknowledgeRequest(value) => {
            validate_header(
                &value.header,
                Direction::Request,
                Command::Acknowledge,
                Scope::Acknowledge,
                true,
            )?;
            validate_tuple(&value.tuple)?;
            validate_digest("terminal_digest", &value.terminal_digest)
        }
        Frame::AcknowledgeResponse(value) => {
            validate_header(
                &value.header,
                Direction::Response,
                Command::Acknowledge,
                Scope::Acknowledge,
                true,
            )?;
            validate_tuple(&value.tuple)
        }
        Frame::SetControlModeRequest(value) => {
            validate_header(
                &value.header,
                Direction::Request,
                Command::SetControlMode,
                Scope::Control,
                true,
            )?;
            validate_control_scope(&value.scope)
        }
        Frame::SetControlModeResponse(value) => {
            validate_header(
                &value.header,
                Direction::Response,
                Command::SetControlMode,
                Scope::Control,
                true,
            )?;
            validate_control_scope(&value.scope)
        }
    }
}

pub fn validate_parameters(parameters: &Value) -> Result<(), ProtocolError> {
    if !matches!(parameters, Value::Object(object) if object.is_empty()) {
        return Err(ProtocolError::InvalidSchema(
            "runtime_v3_episode parameters must be exactly {}".to_owned(),
        ));
    }
    Ok(())
}

fn validate_header(
    header: &Header,
    direction: Direction,
    command: Command,
    scope: Scope,
    target_required: bool,
) -> Result<(), ProtocolError> {
    if header.contract != CONTRACT {
        return Err(ProtocolError::InvalidSchema(
            "unsupported contract".to_owned(),
        ));
    }
    if header.schema_digest != SCHEMA_DIGEST {
        return Err(ProtocolError::InvalidDigest(
            "schema digest does not match release".to_owned(),
        ));
    }
    if header.direction != direction || header.command != command {
        return Err(ProtocolError::InvalidSchema(
            "frame discriminator mismatch".to_owned(),
        ));
    }
    if header.scope != scope {
        return Err(ProtocolError::InvalidScope(
            "frame scope does not match command".to_owned(),
        ));
    }
    validate_uuid("request_id", &header.request_id)?;
    validate_uuid("watchdog_boot_id", &header.watchdog_boot_id)?;
    match (&header.worker_boot_id, target_required) {
        (Some(value), true) => validate_uuid("worker_boot_id", value),
        (None, false) => Ok(()),
        (Some(_), false) => Err(ProtocolError::InvalidIdentity(
            "probe request cannot target a worker boot".to_owned(),
        )),
        (None, true) => Err(ProtocolError::InvalidIdentity(
            "command requires a target worker boot".to_owned(),
        )),
    }?;
    if header.timeout_ms == 0 || header.timeout_ms > MAX_TIMEOUT_MS {
        return Err(ProtocolError::InvalidNumber(
            "timeout_ms must be between 1 and 5000".to_owned(),
        ));
    }
    Ok(())
}

fn validate_tuple(tuple: &HandoffTuple) -> Result<(), ProtocolError> {
    validate_uuid("handoff_id", &tuple.handoff_id)?;
    validate_identity("deployment_id", &tuple.deployment_id)?;
    validate_existing_id("job_id", &tuple.job_id)?;
    validate_existing_id("attempt_id", &tuple.attempt_id)?;
    if tuple.attempt_number == 0 || tuple.attempt_number > MAX_ATTEMPT_NUMBER {
        return Err(ProtocolError::InvalidNumber(
            "attempt_number must be a positive u53".to_owned(),
        ));
    }
    validate_identity("worker_owner_id", &tuple.worker_owner_id)?;
    validate_digest("worker_profile_digest", &tuple.worker_profile_digest)?;
    validate_uuid("run_id", &tuple.run_id)?;
    validate_uuid("episode_id", &tuple.episode_id)?;
    validate_uuid("trajectory_id", &tuple.trajectory_id)?;
    validate_digest("payload_digest", &tuple.payload_digest)?;
    if tuple.payload_digest != EMPTY_PARAMETERS_DIGEST {
        return Err(ProtocolError::InvalidDigest(
            "payload_digest must bind the empty runtime_v3_episode parameters".to_owned(),
        ));
    }
    if tuple.run_id == tuple.episode_id
        || tuple.run_id == tuple.trajectory_id
        || tuple.run_id == tuple.handoff_id
        || tuple.episode_id == tuple.trajectory_id
        || tuple.episode_id == tuple.handoff_id
        || tuple.trajectory_id == tuple.handoff_id
    {
        return Err(ProtocolError::InvalidIdentity(
            "run, episode, trajectory, and handoff IDs must be distinct".to_owned(),
        ));
    }
    Ok(())
}

fn validate_control_scope(scope: &ControlScope) -> Result<(), ProtocolError> {
    validate_identity("deployment_id", &scope.deployment_id)?;
    validate_identity("worker_owner_id", &scope.worker_owner_id)?;
    validate_digest("worker_profile_digest", &scope.worker_profile_digest)?;
    validate_mode_sequence(scope.mode_sequence)
}

fn validate_mode_sequence(value: u64) -> Result<(), ProtocolError> {
    if value == 0 || value > MAX_ATTEMPT_NUMBER {
        return Err(ProtocolError::InvalidNumber(
            "mode_sequence must be a positive u53".to_owned(),
        ));
    }
    Ok(())
}

fn validate_dispatch_terminal(
    status: DispatchStatus,
    terminal: Option<&TerminalReceipt>,
    tuple: &HandoffTuple,
) -> Result<(), ProtocolError> {
    match status {
        DispatchStatus::Terminal | DispatchStatus::AlreadyCompleted => validate_receipt(
            terminal.ok_or_else(|| {
                ProtocolError::InvalidTerminal("terminal dispatch requires a receipt".to_owned())
            })?,
            tuple,
        ),
        DispatchStatus::Accepted | DispatchStatus::Busy | DispatchStatus::Rejected => {
            if terminal.is_some() {
                return Err(ProtocolError::InvalidTerminal(
                    "nonterminal dispatch cannot carry a receipt".to_owned(),
                ));
            }
            Ok(())
        }
    }
}

fn validate_receipt(receipt: &TerminalReceipt, tuple: &HandoffTuple) -> Result<(), ProtocolError> {
    if receipt.tuple() != *tuple {
        return Err(ProtocolError::InvalidTerminal(
            "terminal receipt tuple does not match frame tuple".to_owned(),
        ));
    }
    validate_uuid("terminal.handoff_id", &receipt.handoff_id)?;
    validate_reference("terminal_ref", &receipt.terminal_ref)?;
    if receipt.checkpoint_sequence > MAX_ATTEMPT_NUMBER {
        return Err(ProtocolError::InvalidNumber(
            "checkpoint_sequence must fit u53".to_owned(),
        ));
    }
    validate_digest("result_digest", &receipt.result_digest)?;
    let bytes = serde_json::to_vec(receipt)
        .map_err(|error| ProtocolError::InvalidTerminal(error.to_string()))?;
    if bytes.len() > MAX_TERMINAL_BYTES {
        return Err(ProtocolError::InvalidTerminal(
            "terminal receipt exceeds 16 KiB".to_owned(),
        ));
    }
    Ok(())
}

fn validate_uuid(label: &str, value: &str) -> Result<(), ProtocolError> {
    let uuid = Uuid::parse_str(value)
        .map_err(|_| ProtocolError::InvalidIdentity(format!("{label} must be UUIDv4")))?;
    if uuid.get_version() != Some(Version::Random) || uuid.is_nil() || uuid.to_string() != value {
        return Err(ProtocolError::InvalidIdentity(format!(
            "{label} must be canonical lowercase UUIDv4"
        )));
    }
    Ok(())
}

fn validate_identity(label: &str, value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > MAX_IDENTITY_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ProtocolError::InvalidIdentity(format!(
            "{label} is not a bounded identifier"
        )));
    }
    Ok(())
}

fn validate_existing_id(label: &str, value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > MAX_IDENTITY_BYTES
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(ProtocolError::InvalidIdentity(format!(
            "{label} is not a bounded durable ID"
        )));
    }
    Ok(())
}

fn validate_digest(label: &str, value: &str) -> Result<(), ProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ProtocolError::InvalidDigest(format!(
            "{label} must be a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

fn validate_reference(label: &str, value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > MAX_REFERENCE_BYTES
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(ProtocolError::InvalidTerminal(format!(
            "{label} is not a bounded reference"
        )));
    }
    Ok(())
}
