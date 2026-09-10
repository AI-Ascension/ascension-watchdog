//! Operator commands execute only on the owning reconciliation thread.

use super::Supervisor;
use crate::admin::{
    AcceptedView, AdminCommand, AdminDispatchError, AdminDispatcher, AdminMode, AdminResult,
    BackupView, Capability, CommandName, DispatchContext, MainLoopHealth, ReconcileRequest,
    ReconcileTarget, RetryPolicy, StatusView, command_fingerprint,
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
            AdminCommand::Quarantine(_) => OperatorCommand::Quarantine,
            AdminCommand::Retry(_) => OperatorCommand::Retry,
            AdminCommand::Reconcile(request) => {
                self.validate_reconcile_target(request)?;
                OperatorCommand::Reconcile
            }
            AdminCommand::ReleaseInspect(_) => OperatorCommand::ReleaseInspect,
            AdminCommand::Backup(_) => OperatorCommand::Backup,
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
        if matches!(
            operation,
            OperatorCommand::Jobs | OperatorCommand::Attempt | OperatorCommand::ReleaseInspect
        ) {
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
        if let AdminCommand::Quarantine(request) = command {
            let owner = self
                .supervisor
                .lock
                .as_ref()
                .ok_or(AdminDispatchError::Unauthorized)?;
            let result = AdminResult::Accepted(AcceptedView {
                command: CommandName::Quarantine,
                queued: true,
            });
            let response =
                serde_json::to_value(&result).map_err(|_| AdminDispatchError::Internal)?;
            let receipt = self
                .supervisor
                .store
                .admit_operator_quarantine(
                    owner,
                    &durable_context,
                    &request.attempt_id,
                    &request.reason,
                    &response,
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
        if let AdminCommand::Retry(request) = command {
            let owner = self
                .supervisor
                .lock
                .as_ref()
                .ok_or(AdminDispatchError::Unauthorized)?;
            let result = AdminResult::Accepted(AcceptedView {
                command: CommandName::Retry,
                queued: true,
            });
            let response =
                serde_json::to_value(&result).map_err(|_| AdminDispatchError::Internal)?;
            let receipt = self
                .supervisor
                .store
                .admit_operator_retry(
                    owner,
                    &durable_context,
                    &request.attempt_id,
                    matches!(request.policy, RetryPolicy::Reconstruction),
                    &response,
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
        if let AdminCommand::Backup(request) = command {
            let owner = self
                .supervisor
                .lock
                .as_ref()
                .ok_or(AdminDispatchError::Unauthorized)?;
            let pending = AdminResult::Backup(BackupView {
                backup_id: request.backup_id.clone(),
                durable: false,
            });
            let pending_response =
                serde_json::to_value(&pending).map_err(|_| AdminDispatchError::Internal)?;
            let durable = self
                .supervisor
                .store
                .perform_operator_backup(
                    owner,
                    &durable_context,
                    &request.backup_id,
                    &pending_response,
                    now_unix_ms(),
                )
                .map_err(|error| AdminDispatchError::from(&error))?;
            return Ok(AdminResult::Backup(BackupView {
                backup_id: request.backup_id.clone(),
                durable,
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

impl Dispatcher<'_> {
    /// Validate a scoped reconciliation request against the current durable
    /// watchdog inventory before recording its idempotent admission.  The
    /// reconciliation loop remains the only component that performs process
    /// effects; this check prevents a successful receipt for an object that
    /// cannot be addressed and keeps the target semantics explicit.
    fn validate_reconcile_target(
        &self,
        request: &ReconcileRequest,
    ) -> Result<(), AdminDispatchError> {
        match request.target {
            ReconcileTarget::Deployment => Ok(()),
            ReconcileTarget::Component => {
                let id = request.id.as_deref().ok_or(AdminDispatchError::Invalid)?;
                if self
                    .supervisor
                    .config
                    .components
                    .iter()
                    .any(|component| component.id == id)
                {
                    Ok(())
                } else {
                    Err(AdminDispatchError::NotFound)
                }
            }
            ReconcileTarget::Job => {
                let id = request.id.as_deref().ok_or(AdminDispatchError::Invalid)?;
                if self
                    .supervisor
                    .store
                    .job_exists(id)
                    .map_err(|error| AdminDispatchError::from(&error))?
                {
                    Ok(())
                } else {
                    Err(AdminDispatchError::NotFound)
                }
            }
            ReconcileTarget::Attempt => {
                let id = request.id.as_deref().ok_or(AdminDispatchError::Invalid)?;
                if self
                    .supervisor
                    .store
                    .attempt_summary(id)
                    .map_err(|error| AdminDispatchError::from(&error))?
                    .is_some()
                {
                    Ok(())
                } else {
                    Err(AdminDispatchError::NotFound)
                }
            }
        }
    }

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
            AdminCommand::ReleaseInspect(request) => {
                let inspection = self.supervisor.inspect_release(&request.release_id)?;
                let status = self
                    .supervisor
                    .store
                    .status()
                    .map_err(|error| AdminDispatchError::from(&error))?;
                Ok(AdminResult::ReleaseInspection(
                    crate::admin::ReleaseInspection {
                        release_id: inspection.release_id,
                        release_digest: inspection.manifest_digest.clone(),
                        compatible: inspection.compatible,
                        active: status.approved_release_digest.as_deref()
                            == Some(inspection.manifest_digest.as_str()),
                    },
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

    fn inspect_release(
        &self,
        release_id: &str,
    ) -> Result<crate::release_staged::ProtectedReleaseInspection, AdminDispatchError> {
        let catalog = self
            .config
            .release_catalog
            .as_ref()
            .ok_or(AdminDispatchError::Unsupported)?;
        let owner_policy =
            crate::release_staged::CatalogOwnerPolicy::approved_unix_uid(catalog.owner_uid);
        let catalog = crate::release_staged::ProtectedReleaseCatalog::new_with_owner_policy(
            &catalog.root,
            owner_policy,
        )
        .map_err(|_| AdminDispatchError::Conflict)?;
        catalog
            .inspect(release_id, &self.config)
            .map_err(|_| AdminDispatchError::Conflict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::{AdminRequest, AuthenticatedPrincipalClass, ContractVersion};
    use crate::config::WatchdogConfig;

    fn supervisor() -> crate::Result<(tempfile::TempDir, Supervisor)> {
        let directory = tempfile::tempdir()?;
        let config = WatchdogConfig {
            database: directory.path().join("watchdog.sqlite3"),
            ..WatchdogConfig::default()
        };
        let supervisor = Supervisor::initialize(config)?;
        Ok((directory, supervisor))
    }

    fn context(command: AdminCommand) -> crate::Result<(DispatchContext, AdminCommand)> {
        let request = AdminRequest {
            contract: ContractVersion::V1,
            request_id: uuid::Uuid::new_v4().to_string(),
            idempotency_key: "reconcile-test-key".to_owned(),
            capability: Capability::Admin,
            token: "test-token".to_owned(),
            deadline_ms: 1_000,
            command,
        };
        let context = request
            .dispatch_context(AuthenticatedPrincipalClass::AdminToken)
            .map_err(crate::WatchdogError::InvalidInput)?;
        Ok((context, request.command))
    }

    #[test]
    fn deployment_reconcile_is_durably_admitted_and_idempotent() -> crate::Result<()> {
        let (_directory, mut supervisor) = supervisor()?;
        let health = MainLoopHealth::new();
        let command = AdminCommand::Reconcile(ReconcileRequest {
            target: ReconcileTarget::Deployment,
            id: None,
        });
        let (context, command) = context(command)?;
        let mut dispatcher = Dispatcher {
            supervisor: &mut supervisor,
            health: &health,
        };
        let first = dispatcher
            .dispatch(&context, &command)
            .map_err(|_| crate::WatchdogError::Conflict("reconcile admission failed".to_owned()))?;
        assert_eq!(
            first,
            AdminResult::Accepted(AcceptedView {
                command: CommandName::Reconcile,
                queued: true,
            })
        );
        assert_eq!(dispatcher.supervisor.store.operator_command_count()?, 1);

        let replay = dispatcher
            .dispatch(&context, &command)
            .map_err(|_| crate::WatchdogError::Conflict("reconcile replay failed".to_owned()))?;
        assert_eq!(replay, first);
        assert_eq!(dispatcher.supervisor.store.operator_command_count()?, 1);
        Ok(())
    }

    #[test]
    fn scoped_reconcile_rejects_unknown_job_before_receipt() -> crate::Result<()> {
        let (_directory, mut supervisor) = supervisor()?;
        let health = MainLoopHealth::new();
        let command = AdminCommand::Reconcile(ReconcileRequest {
            target: ReconcileTarget::Job,
            id: Some("missing-job".to_owned()),
        });
        let (context, command) = context(command)?;
        let mut dispatcher = Dispatcher {
            supervisor: &mut supervisor,
            health: &health,
        };
        assert_eq!(
            dispatcher.dispatch(&context, &command),
            Err(AdminDispatchError::NotFound)
        );
        assert_eq!(dispatcher.supervisor.store.operator_command_count()?, 0);
        Ok(())
    }

    #[test]
    fn scoped_reconcile_requires_exact_existing_attempt() -> crate::Result<()> {
        let (_directory, mut supervisor) = supervisor()?;
        let health = MainLoopHealth::new();
        let command = AdminCommand::Reconcile(ReconcileRequest {
            target: ReconcileTarget::Attempt,
            id: Some("missing-attempt".to_owned()),
        });
        let (context, command) = context(command)?;
        let mut dispatcher = Dispatcher {
            supervisor: &mut supervisor,
            health: &health,
        };
        assert_eq!(
            dispatcher.dispatch(&context, &command),
            Err(AdminDispatchError::NotFound)
        );
        assert_eq!(dispatcher.supervisor.store.operator_command_count()?, 0);
        Ok(())
    }
}
