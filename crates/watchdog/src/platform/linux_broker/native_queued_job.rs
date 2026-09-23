//! Queued systemd job protocol: bounded, identity-checked job objects.
//!
//! PID 1 returns a job object from `StartTransientUnit` that the broker must
//! retain until it is bound into the durable ledger. This module owns the
//! safe, bounded representation of job identity and the `JobRemoved` signal,
//! the [`QueuedJobBackend`] trait used by the coordinator, and the native
//! resolution/cancellation calls that never resolve a replacement job from a
//! unit name.

#[allow(clippy::wildcard_imports)]
use super::*;

const MAX_JOB_RESULT_BYTES: usize = 64;

/// Whether PID 1 still has the exact job object returned by
/// `StartTransientUnit`.  `Gone` is deliberately not a success witness: the
/// caller must reconcile the exact unit and, when available, its
/// `JobRemoved` event before deciding whether the effect happened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueuedJobResolution {
    Queued,
    Gone,
}

/// Result of asking PID 1 to cancel one exact queued job.  A raced removal is
/// reported separately from a submitted cancellation and never interpreted as
/// proof that the unit was not started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueuedJobCancellation {
    Submitted,
    AlreadyGone,
}

/// Safe, bounded representation of the systemd `JobRemoved` signal payload.
/// The object path and unit are checked against the immutable job binding
/// before its result can influence reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobRemovedEvent {
    binding: ledger::JobBinding,
    result: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobRemovalOutcome {
    Done,
    Canceled,
    Failed,
}

impl JobRemovedEvent {
    pub fn new(binding: ledger::JobBinding, result: impl Into<String>) -> BrokerResult<Self> {
        binding.validate_syntax_for_backend()?;
        let result = result.into();
        if result.is_empty()
            || result.len() > MAX_JOB_RESULT_BYTES
            || result
                .bytes()
                .any(|byte| !(byte.is_ascii_lowercase() || matches!(byte, b'-')))
        {
            return Err(BrokerError::Invalid(
                "systemd job removal result is out of bounds".to_owned(),
            ));
        }
        Ok(Self { binding, result })
    }

    pub fn binding(&self) -> &ledger::JobBinding {
        &self.binding
    }

    pub fn result(&self) -> &str {
        &self.result
    }

    pub(super) fn outcome(&self) -> JobRemovalOutcome {
        match self.result() {
            "done" => JobRemovalOutcome::Done,
            "canceled" => JobRemovalOutcome::Canceled,
            _ => JobRemovalOutcome::Failed,
        }
    }
}

/// Optional queued-job control contract for a backend.  Existing fake and
/// delegated backends may retain their old lifecycle behavior and receive
/// conservative `Unavailable` defaults; the native systemd backend overrides
/// each method with exact object-path validation.  This keeps cancellation an
/// explicit opt-in rather than making a unit pathname a fallback identity.
pub trait QueuedJobBackend {
    fn queued_job_binding(&self, _unit: &str) -> Option<&ledger::JobBinding> {
        None
    }

    fn take_queued_job_binding(
        &mut self,
        _unit: &str,
        _deadline: Instant,
    ) -> BrokerResult<ledger::JobBinding> {
        Err(BrokerError::Unavailable(
            "backend does not retain a systemd job object identity".to_owned(),
        ))
    }

    fn resolve_queued_job(
        &mut self,
        _binding: &ledger::JobBinding,
        _deadline: Instant,
    ) -> BrokerResult<QueuedJobResolution> {
        Err(BrokerError::Unavailable(
            "backend does not support exact queued-job resolution".to_owned(),
        ))
    }

    fn cancel_queued_job(
        &mut self,
        _binding: &ledger::JobBinding,
        _deadline: Instant,
    ) -> BrokerResult<QueuedJobCancellation> {
        Err(BrokerError::Unavailable(
            "backend does not support exact queued-job cancellation".to_owned(),
        ))
    }

    fn observe_job_removed(
        &mut self,
        binding: &ledger::JobBinding,
        event: JobRemovedEvent,
        deadline: Instant,
    ) -> BrokerResult<JobRemovalOutcome> {
        remaining(deadline)?;
        if event.binding() != binding {
            return Err(BrokerError::Conflict(
                "systemd JobRemoved event does not match the retained job".to_owned(),
            ));
        }
        Ok(event.outcome())
    }
}

pub(crate) fn unit_is_missing(error: &zbus::Error) -> bool {
    matches!(error, zbus::Error::MethodError(name, _, _)
        if name.as_str() == "org.freedesktop.systemd1.NoSuchUnit")
}

pub(super) fn job_is_missing(error: &zbus::Error) -> bool {
    matches!(error, zbus::Error::MethodError(name, _, _)
        if name.as_str() == "org.freedesktop.systemd1.NoSuchJob")
}

#[cfg(target_os = "linux")]
impl NativeSystemdBackend {
    pub(super) fn remember_queued_job(&mut self, binding: ledger::JobBinding) -> BrokerResult<()> {
        let unit = binding.unit().to_owned();
        if let Some(previous) = self.queued_jobs.get(&unit) {
            if previous == &binding {
                return Ok(());
            }
            return Err(BrokerError::Conflict(
                "systemd unit has a different retained job object".to_owned(),
            ));
        }
        if self.queued_jobs.len() >= MAX_ACTIVE_PROCESSES {
            return Err(BrokerError::Unavailable(
                "queued systemd job capacity is exhausted".to_owned(),
            ));
        }
        self.queued_jobs.insert(unit, binding);
        Ok(())
    }

    /// Resolve one retained manager job without looking up a replacement job
    /// from a unit name.  The returned object path, numeric ID, and Job.Unit
    /// property must all agree with the durable binding.
    pub(super) fn resolve_queued_job_native(
        binding: &ledger::JobBinding,
        deadline: Instant,
    ) -> BrokerResult<QueuedJobResolution> {
        remaining(deadline)?;
        binding.validate_syntax_for_backend()?;
        let connection = Self::connection(deadline)?;
        let manager = Self::manager(&connection)?;
        let path: zbus::zvariant::OwnedObjectPath =
            match manager.call("GetJob", &(binding.job_id(),)) {
                Ok(path) => path,
                Err(error) if job_is_missing(&error) => return Ok(QueuedJobResolution::Gone),
                Err(error) => {
                    return Err(BrokerError::Unavailable(format!(
                        "systemd queued job lookup failed: {error}"
                    )));
                }
            };
        if path.as_str() != binding.job_path() {
            return Err(BrokerError::Conflict(
                "systemd queued job object path differs from its durable binding".to_owned(),
            ));
        }
        let job_id: u32 = Self::property(
            path.as_str(),
            "org.freedesktop.systemd1.Job",
            "Id",
            deadline,
        )?;
        if job_id != binding.job_id() {
            return Err(BrokerError::Conflict(
                "systemd queued job ID differs from its durable binding".to_owned(),
            ));
        }
        let job_unit: zbus::zvariant::OwnedObjectPath = Self::property(
            path.as_str(),
            "org.freedesktop.systemd1.Job",
            "Unit",
            deadline,
        )?;
        let expected_unit: zbus::zvariant::OwnedObjectPath =
            match manager.call("GetUnit", &(binding.unit(),)) {
                Ok(path) => path,
                Err(error) if unit_is_missing(&error) => {
                    return Err(BrokerError::Conflict(
                        "systemd queued job unit is missing during exact resolution".to_owned(),
                    ));
                }
                Err(error) => {
                    return Err(BrokerError::Unavailable(format!(
                        "systemd queued job unit lookup failed: {error}"
                    )));
                }
            };
        if job_unit != expected_unit {
            return Err(BrokerError::Conflict(
                "systemd queued job belongs to a different unit".to_owned(),
            ));
        }
        Ok(QueuedJobResolution::Queued)
    }

    pub(super) fn cancel_queued_job_native(
        binding: &ledger::JobBinding,
        deadline: Instant,
    ) -> BrokerResult<QueuedJobCancellation> {
        match Self::resolve_queued_job_native(binding, deadline)? {
            QueuedJobResolution::Gone => return Ok(QueuedJobCancellation::AlreadyGone),
            QueuedJobResolution::Queued => {}
        }
        remaining(deadline)?;
        let connection = Self::connection(deadline)?;
        let manager = Self::manager(&connection)?;
        let result: BrokerResult<()> =
            manager
                .call("CancelJob", &(binding.job_id(),))
                .map_err(|error| {
                    if job_is_missing(&error) {
                        BrokerError::Conflict(
                            "systemd queued job disappeared during exact cancellation".to_owned(),
                        )
                    } else {
                        BrokerError::Unavailable(format!(
                            "systemd queued job cancellation failed: {error}"
                        ))
                    }
                });
        match result {
            Ok(()) => Ok(QueuedJobCancellation::Submitted),
            Err(BrokerError::Conflict(message))
                if message == "systemd queued job disappeared during exact cancellation" =>
            {
                Ok(QueuedJobCancellation::AlreadyGone)
            }
            Err(error) => Err(error),
        }
    }
}

impl QueuedJobBackend for NativeSystemdBackend {
    fn queued_job_binding(&self, unit: &str) -> Option<&ledger::JobBinding> {
        self.queued_jobs.get(unit)
    }

    fn take_queued_job_binding(
        &mut self,
        unit: &str,
        deadline: Instant,
    ) -> BrokerResult<ledger::JobBinding> {
        remaining(deadline)?;
        let binding = self.queued_jobs.get(unit).cloned().ok_or_else(|| {
            BrokerError::Conflict(
                "queued systemd job binding is unavailable for the generated unit".to_owned(),
            )
        })?;
        if binding.unit() != unit {
            return Err(BrokerError::Conflict(
                "queued systemd job binding unit does not match its map key".to_owned(),
            ));
        }
        binding.validate_syntax_for_backend()?;
        self.queued_jobs.remove(unit);
        Ok(binding)
    }

    fn resolve_queued_job(
        &mut self,
        binding: &ledger::JobBinding,
        deadline: Instant,
    ) -> BrokerResult<QueuedJobResolution> {
        Self::resolve_queued_job_native(binding, deadline)
    }

    fn cancel_queued_job(
        &mut self,
        binding: &ledger::JobBinding,
        deadline: Instant,
    ) -> BrokerResult<QueuedJobCancellation> {
        Self::cancel_queued_job_native(binding, deadline)
    }

    fn observe_job_removed(
        &mut self,
        binding: &ledger::JobBinding,
        event: JobRemovedEvent,
        deadline: Instant,
    ) -> BrokerResult<JobRemovalOutcome> {
        let outcome = validate_job_removed(binding, &event, deadline)?;
        // A matching JobRemoved signal proves that this manager job no longer
        // occupies a queue slot. It does not prove that its unit was stopped;
        // callers still reconcile the exact unit/containment separately.
        if self.queued_jobs.get(binding.unit()) == Some(binding) {
            self.queued_jobs.remove(binding.unit());
        }
        Ok(outcome)
    }
}

fn validate_job_removed(
    binding: &ledger::JobBinding,
    event: &JobRemovedEvent,
    deadline: Instant,
) -> BrokerResult<JobRemovalOutcome> {
    remaining(deadline)?;
    if event.binding() != binding {
        return Err(BrokerError::Conflict(
            "systemd JobRemoved event does not match the retained job".to_owned(),
        ));
    }
    Ok(event.outcome())
}

/// Decode a manager `JobRemoved` signal without treating arbitrary signals as
/// lifecycle evidence. The caller must still pass the result through
/// `QueuedJobBackend::observe_job_removed` with the durable binding.
pub fn decode_job_removed(message: &zbus::Message) -> BrokerResult<JobRemovedEvent> {
    let header = message.header();
    if message.message_type() != zbus::message::Type::Signal
        || header.path().map(zbus::zvariant::ObjectPath::as_str)
            != Some("/org/freedesktop/systemd1")
        || header.interface().map(zbus::names::InterfaceName::as_str)
            != Some("org.freedesktop.systemd1.Manager")
        || header.member().map(zbus::names::MemberName::as_str) != Some("JobRemoved")
    {
        return Err(BrokerError::Invalid(
            "systemd message is not a Manager.JobRemoved signal".to_owned(),
        ));
    }
    let (job_id, job_path, unit, result): (u32, zbus::zvariant::OwnedObjectPath, String, String) =
        message.body().deserialize().map_err(|_| {
            BrokerError::Invalid("systemd JobRemoved payload is invalid".to_owned())
        })?;
    let binding = ledger::JobBinding::from_object_path(&unit, job_path.as_str())?;
    if binding.job_id() != job_id {
        return Err(BrokerError::Conflict(
            "systemd JobRemoved ID does not match its object path".to_owned(),
        ));
    }
    JobRemovedEvent::new(binding, result)
}
