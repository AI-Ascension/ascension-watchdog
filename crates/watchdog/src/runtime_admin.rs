//! Operator commands execute only on the owning reconciliation thread.

use super::Supervisor;
use crate::admin::{
    AcceptedView, AdminCommand, AdminDispatchError, AdminDispatcher, AdminMode, AdminResult,
    Capability, DispatchContext, MainLoopHealth, StatusView,
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
        let operation = match command {
            AdminCommand::Status(_) => OperatorCommand::Status,
            AdminCommand::Start(_) => OperatorCommand::Start,
            AdminCommand::Pause(_) => OperatorCommand::Pause,
            AdminCommand::Resume(_) => OperatorCommand::Resume,
            AdminCommand::Drain(_) => OperatorCommand::Drain,
            AdminCommand::Stop(_) => OperatorCommand::Stop,
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

impl Supervisor {
    pub(crate) fn admin_configuration(&self) -> Option<crate::config::AdminConfig> {
        self.config.admin.clone()
    }
}
