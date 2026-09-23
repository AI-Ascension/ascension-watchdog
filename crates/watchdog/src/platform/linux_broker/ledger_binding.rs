//! Systemd job object bindings retained by the broker ledger.
//!
//! Extracted verbatim from `ledger.rs`: the `JobBinding` identity and the
//! bounded object-path parser keep their exact fields, encodings and
//! effective visibility so the durable launch identity is unchanged.

#[allow(clippy::wildcard_imports)]
use super::super::*;

const MAX_JOB_PATH_BYTES: usize = 128;
pub(super) const SYSTEMD_JOB_PATH_PREFIX: &str = "/org/freedesktop/systemd1/job/";

/// The immutable identity returned by `StartTransientUnit` for one queued
/// manager job.  This is deliberately separate from the generated unit name:
/// a unit can have more than one queued job over its lifetime, and a job ID
/// must never be reconstructed from a unit pathname.  All fields are bounded
/// and non-secret so a pending record can retain this value durably.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobBinding {
    pub(super) unit: String,
    pub(super) job_id: u32,
    pub(super) job_path: String,
}

impl JobBinding {
    /// Construct a binding from the object path returned by PID 1.
    pub fn from_object_path(unit: &str, job_path: &str) -> BrokerResult<Self> {
        let job_id = parse_job_path(job_path)?;
        let binding = Self {
            unit: unit.to_owned(),
            job_id,
            job_path: job_path.to_owned(),
        };
        binding.validate_syntax_for_backend()?;
        Ok(binding)
    }

    /// Validate the binding against the complete durable launch identity.
    pub(in crate::platform::linux_broker) fn validate_for_request(
        &self,
        request: &BrokerRequest,
    ) -> BrokerResult<()> {
        request.validate()?;
        self.validate_syntax_for_backend()?;
        if self.unit != unit_name(request) {
            return Err(BrokerError::Conflict(
                "systemd job binding does not match the generated unit".to_owned(),
            ));
        }
        Ok(())
    }

    pub(in crate::platform::linux_broker) fn unit(&self) -> &str {
        &self.unit
    }

    pub(in crate::platform::linux_broker) fn job_id(&self) -> u32 {
        self.job_id
    }

    pub(in crate::platform::linux_broker) fn job_path(&self) -> &str {
        &self.job_path
    }

    pub(in crate::platform::linux_broker) fn validate_syntax_for_backend(
        &self,
    ) -> BrokerResult<()> {
        if self.unit.is_empty() || self.unit.len() > MAX_IDENTITY_BYTES {
            return Err(BrokerError::Invalid(
                "systemd job unit binding is out of bounds".to_owned(),
            ));
        }
        let parsed = parse_job_path(&self.job_path)?;
        if parsed != self.job_id {
            return Err(BrokerError::Conflict(
                "systemd job ID does not match its object path".to_owned(),
            ));
        }
        Ok(())
    }
}

fn parse_job_path(job_path: &str) -> BrokerResult<u32> {
    if job_path.len() > MAX_JOB_PATH_BYTES || job_path.contains('\0') {
        return Err(BrokerError::Invalid(
            "systemd job object path exceeds its bound".to_owned(),
        ));
    }
    let Some(id_text) = job_path.strip_prefix(SYSTEMD_JOB_PATH_PREFIX) else {
        return Err(BrokerError::Invalid(
            "systemd job object path is not canonical".to_owned(),
        ));
    };
    if id_text.is_empty()
        || id_text.len() > 10
        || id_text == "0"
        || id_text.starts_with('0')
        || id_text.bytes().any(|byte| !byte.is_ascii_digit())
    {
        return Err(BrokerError::Invalid(
            "systemd job object path has an invalid ID".to_owned(),
        ));
    }
    id_text
        .parse::<u32>()
        .map_err(|_| BrokerError::Invalid("systemd job object path ID is out of bounds".to_owned()))
}
