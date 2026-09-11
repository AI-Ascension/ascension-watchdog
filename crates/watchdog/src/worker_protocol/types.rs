use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    FrameTooLarge,
    InvalidJson(String),
    InvalidSchema(String),
    InvalidIdentity(String),
    InvalidDigest(String),
    InvalidNumber(String),
    InvalidScope(String),
    InvalidTerminal(String),
    InvalidControl(String),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FrameTooLarge => write!(formatter, "worker handoff frame exceeds 64 KiB"),
            Self::InvalidJson(message) => {
                write!(formatter, "invalid worker handoff JSON: {message}")
            }
            Self::InvalidSchema(message) => {
                write!(formatter, "invalid worker handoff schema: {message}")
            }
            Self::InvalidIdentity(message) => {
                write!(formatter, "invalid worker handoff identity: {message}")
            }
            Self::InvalidDigest(message) => {
                write!(formatter, "invalid worker handoff digest: {message}")
            }
            Self::InvalidNumber(message) => {
                write!(formatter, "invalid worker handoff number: {message}")
            }
            Self::InvalidScope(message) => {
                write!(formatter, "invalid worker handoff scope: {message}")
            }
            Self::InvalidTerminal(message) => write!(
                formatter,
                "invalid worker handoff terminal receipt: {message}"
            ),
            Self::InvalidControl(message) => {
                write!(formatter, "invalid worker handoff control: {message}")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Request,
    Response,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Command {
    Probe,
    Dispatch,
    Lookup,
    Acknowledge,
    SetControlMode,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Probe,
    Dispatch,
    Lookup,
    Acknowledge,
    Control,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerMode {
    Running,
    Paused,
    Draining,
    Stopped,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalStatus {
    Completed,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchStatus {
    Accepted,
    AlreadyCompleted,
    Terminal,
    Busy,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupStatus {
    Running,
    Terminal,
    Unknown,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcknowledgeStatus {
    Acknowledged,
    AlreadyAcknowledged,
    Conflict,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlStatus {
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub contract: String,
    pub schema_digest: String,
    pub direction: Direction,
    pub command: Command,
    pub scope: Scope,
    pub request_id: String,
    pub timeout_ms: u64,
    pub watchdog_boot_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_boot_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffTuple {
    pub handoff_id: String,
    pub deployment_id: String,
    pub job_id: String,
    pub attempt_id: String,
    pub attempt_number: u64,
    pub worker_owner_id: String,
    pub worker_profile_digest: String,
    pub run_id: String,
    pub episode_id: String,
    pub trajectory_id: String,
    pub payload_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalReceipt {
    pub handoff_id: String,
    pub deployment_id: String,
    pub job_id: String,
    pub attempt_id: String,
    pub attempt_number: u64,
    pub worker_owner_id: String,
    pub worker_profile_digest: String,
    pub run_id: String,
    pub episode_id: String,
    pub trajectory_id: String,
    pub payload_digest: String,
    pub status: TerminalStatus,
    pub checkpoint_sequence: u64,
    pub terminal_ref: String,
    pub result_digest: String,
}

impl TerminalReceipt {
    pub fn tuple(&self) -> HandoffTuple {
        HandoffTuple {
            handoff_id: self.handoff_id.clone(),
            deployment_id: self.deployment_id.clone(),
            job_id: self.job_id.clone(),
            attempt_id: self.attempt_id.clone(),
            attempt_number: self.attempt_number,
            worker_owner_id: self.worker_owner_id.clone(),
            worker_profile_digest: self.worker_profile_digest.clone(),
            run_id: self.run_id.clone(),
            episode_id: self.episode_id.clone(),
            trajectory_id: self.trajectory_id.clone(),
            payload_digest: self.payload_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRequest {
    #[serde(flatten)]
    pub header: Header,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeResponse {
    #[serde(flatten)]
    pub header: Header,
    pub deployment_id: String,
    pub worker_owner_id: String,
    pub worker_profile_digest: String,
    pub release_digest: String,
    pub config_digest: String,
    pub ready: bool,
    pub admitting: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchRequest {
    #[serde(flatten)]
    pub header: Header,
    #[serde(flatten)]
    pub tuple: HandoffTuple,
    pub mode_sequence: u64,
    pub operation: String,
    pub parameters: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchResponse {
    #[serde(flatten)]
    pub header: Header,
    #[serde(flatten)]
    pub tuple: HandoffTuple,
    pub status: DispatchStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal: Option<TerminalReceipt>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LookupRequest {
    #[serde(flatten)]
    pub header: Header,
    #[serde(flatten)]
    pub tuple: HandoffTuple,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LookupResponse {
    #[serde(flatten)]
    pub header: Header,
    #[serde(flatten)]
    pub tuple: HandoffTuple,
    pub status: LookupStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal: Option<TerminalReceipt>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgeRequest {
    #[serde(flatten)]
    pub header: Header,
    #[serde(flatten)]
    pub tuple: HandoffTuple,
    pub terminal_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgeResponse {
    #[serde(flatten)]
    pub header: Header,
    #[serde(flatten)]
    pub tuple: HandoffTuple,
    pub status: AcknowledgeStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlScope {
    pub deployment_id: String,
    pub worker_owner_id: String,
    pub worker_profile_digest: String,
    pub mode: WorkerMode,
    pub mode_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetControlModeRequest {
    #[serde(flatten)]
    pub header: Header,
    #[serde(flatten)]
    pub scope: ControlScope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetControlModeResponse {
    #[serde(flatten)]
    pub header: Header,
    #[serde(flatten)]
    pub scope: ControlScope,
    pub status: ControlStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Frame {
    ProbeRequest(ProbeRequest),
    ProbeResponse(ProbeResponse),
    DispatchRequest(DispatchRequest),
    DispatchResponse(DispatchResponse),
    LookupRequest(LookupRequest),
    LookupResponse(LookupResponse),
    AcknowledgeRequest(AcknowledgeRequest),
    AcknowledgeResponse(AcknowledgeResponse),
    SetControlModeRequest(SetControlModeRequest),
    SetControlModeResponse(SetControlModeResponse),
}

impl Frame {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        super::validation::validate_frame(self)
    }

    pub fn is_request(&self) -> bool {
        matches!(
            self,
            Self::ProbeRequest(_)
                | Self::DispatchRequest(_)
                | Self::LookupRequest(_)
                | Self::AcknowledgeRequest(_)
                | Self::SetControlModeRequest(_)
        )
    }

    pub fn is_response(&self) -> bool {
        !self.is_request()
    }
}
