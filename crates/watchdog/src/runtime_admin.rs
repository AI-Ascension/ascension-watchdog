//! Operator commands execute only on the owning reconciliation thread.

use super::Supervisor;
use crate::admin::{
    AcceptedView, AdminCommand, AdminDispatchError, AdminDispatcher, AdminMode, AdminResult,
    Capability, DispatchContext, MainLoopHealth, StatusView, command_fingerprint,
};
use crate::config::DesiredMode;
use crate::storage::{
    OperatorCapability, OperatorCommand, OperatorCommandContext, OperatorCommandOutcome,
    now_unix_ms,
};

pub(crate) struct Dispatcher<'a> {
    pub supervisor: &'a mut Supervisor,
    pub health: &'a MainLoopHealth,
}

impl AdminDispatcher for Dispatcher<'_> {
    fn dispatch(
        &mut self,
        context: &DispatchContext,
        command: &AdminCommand,
    ) -> Result<AdminResult, AdminDispatchError> {
        context
            .validate()
            .map_err(|_| AdminDispatchError::Invalid)?;
        command
            .validate()
            .map_err(|_| AdminDispatchError::Invalid)?;
        if context.command_fingerprint() != command_fingerprint(context.capability(), command) {
            return Err(AdminDispatchError::Conflict);
        }
        let operation = match command {
            AdminCommand::Status(_) => OperatorCommand::Status,
            AdminCommand::Start(_) => OperatorCommand::Start,
            AdminCommand::Pause(_) => OperatorCommand::Pause,
            AdminCommand::Resume(_) => OperatorCommand::Resume,
            AdminCommand::Drain(_) => OperatorCommand::Drain,
            AdminCommand::Stop(_) => OperatorCommand::Stop,
            AdminCommand::Jobs(_) => OperatorCommand::Jobs,
            AdminCommand::JobSubmit(_) => OperatorCommand::JobSubmit,
            AdminCommand::Attempt(_) => OperatorCommand::Attempt,
            _ => return Err(AdminDispatchError::Unsupported),
        };
        let durable_context = OperatorCommandContext::new(
            context.request_id().to_string(),
            context.idempotency_key(),
            format!("{:?}", context.principal()),
            match context.capability() {
                Capability::Read => OperatorCapability::Read,
                Capability::Admin => OperatorCapability::Admin,
            },
            context.command_fingerprint(),
        )
        .map_err(|error| AdminDispatchError::from(&error))?;
        if matches!(operation, OperatorCommand::Jobs | OperatorCommand::Attempt) {
            self.supervisor
                .store
                .admit_operator_read(&durable_context, operation)
                .map_err(|error| AdminDispatchError::from(&error))?;
            return self.inspect_work(command);
        }
        if operation == OperatorCommand::Status {
            self.supervisor
                .store
                .admit_operator_read(&durable_context, operation)
                .map_err(|error| AdminDispatchError::from(&error))?;
            let status = self
                .supervisor
                .status()
                .map_err(|error| AdminDispatchError::from(&error))?;
            return Ok(AdminResult::Status(StatusView {
                desired_mode: match status.desired_mode {
                    DesiredMode::Stopped => AdminMode::Stopped,
                    DesiredMode::Running => AdminMode::Running,
                    DesiredMode::Paused => AdminMode::Paused,
                    DesiredMode::Draining => AdminMode::Draining,
                },
                health: self.health.snapshot(),
                jobs_queued: status.jobs_queued,
                jobs_running: status.jobs_running,
                jobs_completed: status.jobs_completed,
                jobs_quarantined: status.jobs_quarantined,
                restart_generation: status
                    .restart_generation
                    .try_into()
                    .map_err(|_| AdminDispatchError::Internal)?,
                config_digest: status.config_digest,
                approved_release_digest: status.approved_release_digest,
            }));
        }
        if let AdminCommand::JobSubmit(request) = command {
            let owner = self
                .supervisor
                .lock
                .as_ref()
                .ok_or(AdminDispatchError::Unauthorized)?;
            let receipt = self
                .supervisor
                .store
                .admit_operator_job_submission(
                    owner,
                    &durable_context,
                    &request.kind,
                    &request.payload,
                    now_unix_ms(),
                )
                .map_err(|error| AdminDispatchError::from(&error))?;
            return match receipt {
                OperatorCommandOutcome::Accepted(receipt)
                | OperatorCommandOutcome::Replayed(receipt) => {
                    serde_json::from_value(receipt.response)
                        .map_err(|_| AdminDispatchError::PersistenceUnavailable)
                }
                OperatorCommandOutcome::ReadOnly => Err(AdminDispatchError::Internal),
            };
        }
        let result = AdminResult::Accepted(AcceptedView {
            command: command.name(),
            queued: true,
        });
        let response = serde_json::to_value(&result).map_err(|_| AdminDispatchError::Internal)?;
        let owner = self
            .supervisor
            .lock
            .as_ref()
            .ok_or(AdminDispatchError::Unauthorized)?;
        let receipt = self
            .supervisor
            .store
            .admit_operator_command(owner, &durable_context, operation, &response, now_unix_ms())
            .map_err(|error| AdminDispatchError::from(&error))?;
        match receipt {
            OperatorCommandOutcome::Accepted(receipt)
            | OperatorCommandOutcome::Replayed(receipt) => serde_json::from_value(receipt.response)
                .map_err(|_| AdminDispatchError::PersistenceUnavailable),
            OperatorCommandOutcome::ReadOnly => Err(AdminDispatchError::Internal),
        }
    }
}

impl Dispatcher<'_> {
    fn inspect_work(&self, command: &AdminCommand) -> Result<AdminResult, AdminDispatchError> {
        match command {
            AdminCommand::Jobs(request) => {
                use crate::admin::JobFilter;
                use crate::storage::JobStatus;
                let filter = match request.filter {
                    JobFilter::All => None,
                    JobFilter::Queued => Some(JobStatus::Queued),
                    JobFilter::Running => Some(JobStatus::Running),
                    JobFilter::Completed => Some(JobStatus::Completed),
                    JobFilter::Failed => Some(JobStatus::Failed),
                    JobFilter::Quarantined => Some(JobStatus::Quarantined),
                };
                let summary = self
                    .supervisor
                    .store
                    .job_summaries(filter, request.limit)
                    .map_err(|error| AdminDispatchError::from(&error))?;
                // Only the deliberately redacted storage projection crosses this boundary.
                let value =
                    serde_json::to_value(summary).map_err(|_| AdminDispatchError::Internal)?;
                Ok(AdminResult::Jobs(
                    serde_json::from_value(value)
                        .map_err(|_| AdminDispatchError::PersistenceUnavailable)?,
                ))
            }
            AdminCommand::Attempt(request) => {
                let summary = self
                    .supervisor
                    .store
                    .attempt_summary(&request.attempt_id)
                    .map_err(|error| AdminDispatchError::from(&error))?
                    .ok_or(AdminDispatchError::NotFound)?;
                let value =
                    serde_json::to_value(summary).map_err(|_| AdminDispatchError::Internal)?;
                Ok(AdminResult::Attempt(
                    serde_json::from_value(value)
                        .map_err(|_| AdminDispatchError::PersistenceUnavailable)?,
                ))
            }
            _ => Err(AdminDispatchError::Unsupported),
        }
    }
}

impl Supervisor {
    pub(crate) fn admin_configuration(&self) -> Option<crate::config::AdminConfig> {
        self.config.admin.clone()
    }
}
