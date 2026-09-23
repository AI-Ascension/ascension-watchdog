//! Service installation, binding, and runtime.
//!
//! Owns the fixed `ascension-watchdog` SCM boundary: the idempotent install
//! plan and its least-privilege account policy, the opaque bound-service
//! binding and stopped witness used by the uninstall path, the bounded SCM
//! health checker, and the service runtime/dispatcher with its trusted
//! readiness gate.
//!
//! Extracted verbatim from `native.rs`; the fixed service name, the refusal
//! of the legacy `LocalSystem` installer, the canonical command-line/config
//! revalidation before stop and delete, and the readiness-gated `Running`
//! publication are unchanged.  The public service types are re-exported from
//! `native` under their original names.

use super::{
    Arc, AtomicU32, Duration, ERROR_SERVICE_EXISTS, ERROR_SERVICE_NOT_ACTIVE, ERROR_SUCCESS, Mutex,
    OnceLock, Ordering, Path, PathBuf, PlatformError, SERVICE_NAME, Service, ServiceAccess,
    ServiceAction, ServiceActionType, ServiceControl, ServiceControlHandlerResult,
    ServiceErrorControl, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo,
    ServiceManager, ServiceManagerAccess, ServiceStartType, ServiceState, ServiceStatus,
    ServiceStatusHandle, ServiceType, canonicalize_executable, normalize_path,
    service_control_handler, service_dispatcher,
};

const SERVICE_CONFIG_ARGUMENT: &str = "--config";
const SERVICE_SWITCH_ARGUMENT: &str = "--service";
const DEFAULT_SERVICE_CONFIG: &str = r"C:\ProgramData\Ascension\Watchdog\watchdog.json";
const HEALTH_STALE_AFTER: Duration = Duration::from_secs(90);
const SERVICE_READY_TIMEOUT: Duration = Duration::from_mins(2);
const SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(30);

type ReconcileCallback =
    dyn Fn(Arc<Mutex<bool>>) -> Result<(), PlatformError> + Send + Sync + 'static;
type ReadinessCallback = dyn Fn() -> Result<(), PlatformError> + Send + Sync + 'static;

static SERVICE_RECONCILE: OnceLock<Arc<ReconcileCallback>> = OnceLock::new();
static SERVICE_READINESS: OnceLock<Arc<ReadinessCallback>> = OnceLock::new();

/// Idempotent SCM installation plan.  The caller must separately authorize
/// and perform this mutation; this method only uses SCM APIs, never a shell.
pub struct ServiceInstallPlan {
    pub service_name: String,
    pub executable: PathBuf,
}

impl ServiceInstallPlan {
    /// Refuse the legacy installer rather than silently registering as
    /// `LocalSystem`.  A service account is an authorization decision and
    /// must be supplied explicitly by the deployment owner.
    pub fn install(&self) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(
            "Windows service installation requires an explicit least-privilege service account"
                .to_owned(),
        ))
    }

    /// Install an automatic own-process service under an explicit account.
    /// `account_password` is passed only to SCM and is never included in an
    /// error or diagnostic value.  Virtual service accounts may use `None`.
    pub fn install_as(
        &self,
        account_name: &str,
        account_password: Option<&str>,
    ) -> Result<(), PlatformError> {
        self.install_as_with_config(
            account_name,
            account_password,
            Path::new(DEFAULT_SERVICE_CONFIG),
        )
    }

    /// Install with an explicit, non-secret configuration path. The service
    /// command line remains closed and bounded; credentials are never accepted
    /// as launch arguments.
    pub fn install_as_with_config(
        &self,
        account_name: &str,
        account_password: Option<&str>,
        config_path: &Path,
    ) -> Result<(), PlatformError> {
        if self.service_name != SERVICE_NAME {
            return Err(PlatformError::Invalid(
                "service name is not the fixed ascension-watchdog name".to_owned(),
            ));
        }
        validate_service_account(account_name)?;
        let config_path = canonicalize_service_config_path(config_path)?;
        let executable = canonicalize_executable(&self.executable)?;
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .map_err(service_error("OpenSCManager"))?;
        let info = ServiceInfo {
            name: self.service_name.clone().into(),
            display_name: "AI-Ascension deterministic deployment watchdog".into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: windows_service::service::ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: executable,
            launch_arguments: vec![
                "daemon".into(),
                SERVICE_SWITCH_ARGUMENT.into(),
                SERVICE_CONFIG_ARGUMENT.into(),
                config_path.as_os_str().to_owned(),
            ],
            dependencies: Vec::new(),
            account_name: Some(account_name.into()),
            account_password: account_password.map(Into::into),
        };
        let service_access = ServiceAccess::QUERY_STATUS
            | ServiceAccess::START
            | ServiceAccess::STOP
            | ServiceAccess::CHANGE_CONFIG
            | ServiceAccess::DELETE;
        let (service, created) = match manager.create_service(&info, service_access) {
            Ok(service) => (service, true),
            Err(error) if service_exists(&error) => manager
                .open_service(&self.service_name, service_access)
                .map(|service| (service, false))
                .map_err(service_error("OpenService(existing)"))?,
            Err(error) => return Err(service_error("CreateService")(error)),
        };
        let result = (|| {
            service
                .change_config(&info)
                .map_err(service_error("ChangeServiceConfig"))?;
            service
                .update_failure_actions(ServiceFailureActions {
                    reset_period: ServiceFailureResetPeriod::After(Duration::from_hours(24)),
                    reboot_msg: None,
                    command: None,
                    actions: Some(vec![
                        ServiceAction {
                            action_type: ServiceActionType::Restart,
                            delay: Duration::from_secs(5),
                        },
                        ServiceAction {
                            action_type: ServiceActionType::Restart,
                            delay: Duration::from_secs(30),
                        },
                        ServiceAction {
                            action_type: ServiceActionType::None,
                            delay: Duration::default(),
                        },
                    ]),
                })
                .map_err(service_error("ChangeServiceConfig2(failure actions)"))?;
            service
                .set_failure_actions_on_non_crash_failures(true)
                .map_err(service_error("ChangeServiceConfig2(failure actions flag)"))?;
            Ok::<(), PlatformError>(())
        })();
        if let Err(error) = result {
            if created {
                service
                    .delete()
                    .map_err(service_error("DeleteService(rollback)"))?;
            }
            return Err(error);
        }
        Ok(())
    }

    /// Refuse the legacy unbound removal path. The platform boundary cannot
    /// authenticate an owner-local deployment from a bare service name, so
    /// callers must bind SCM, stop that concrete binding, verify the owner
    /// store, and then use the bound deletion operation.
    pub fn uninstall(&self) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(
            "Windows service uninstall requires a durable owner-local Stopped intent".to_owned(),
        ))
    }

    /// Bind the fixed service's SCM command line before opening the owner
    /// store or writing a stop intent. A missing service is an idempotent
    /// no-op; an existing service returns an opaque concrete binding for the
    /// bounded stop operation, whose native witness is then consumed by
    /// deletion.
    pub fn bind_installed_service(
        &self,
        config_path: &Path,
    ) -> Result<Option<ServiceBinding>, PlatformError> {
        if self.service_name != SERVICE_NAME {
            return Err(PlatformError::Invalid(
                "service name is not the fixed ascension-watchdog name".to_owned(),
            ));
        }
        validate_service_config_path(config_path)?;
        let expected_executable = canonicalize_executable(&self.executable)?;
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(service_error("OpenSCManager(verify uninstall)"))?;
        let service = match manager.open_service(&self.service_name, ServiceAccess::QUERY_CONFIG) {
            Ok(service) => service,
            Err(error) if service_missing(&error) => return Ok(None),
            Err(error) => return Err(service_error("OpenService(verify uninstall)")(error)),
        };
        let expected_config = canonicalize_service_config_path(config_path)?;
        let service_config = service
            .query_config()
            .map_err(service_error("QueryServiceConfig(verify uninstall)"))?;
        validate_installed_service_config(&service_config, &expected_executable, &expected_config)?;
        Ok(Some(ServiceBinding {
            executable: expected_executable,
            config: expected_config,
        }))
    }

    /// Stop a previously bound service and wait for SCM's stopped state.
    ///
    /// The returned opaque witness proves only the native SCM state for this
    /// exact binding. It does not prove the watchdog owner store has durable
    /// `Stopped` intent; the owner boundary must establish that separately
    /// before consuming the witness for deletion.
    pub fn stop_bound_service(
        &self,
        binding: &ServiceBinding,
    ) -> Result<StoppedServiceWitness, PlatformError> {
        if self.service_name != SERVICE_NAME {
            return Err(PlatformError::Invalid(
                "service name is not the fixed ascension-watchdog name".to_owned(),
            ));
        }
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(service_error("OpenSCManager(stop uninstall)"))?;
        let service = match manager.open_service(
            &self.service_name,
            ServiceAccess::QUERY_CONFIG
                | ServiceAccess::QUERY_STATUS
                | ServiceAccess::STOP
                | ServiceAccess::DELETE,
        ) {
            Ok(service) => service,
            Err(error) if service_missing(&error) => {
                return Err(PlatformError::IdentityMismatch(
                    "bound watchdog service disappeared before stop".to_owned(),
                ));
            }
            Err(error) => return Err(service_error("OpenService(stop uninstall)")(error)),
        };
        // Re-query immediately before the SCM stop. The initial bind occurs
        // before the owner store is opened; this closes the gap where another
        // deployment could rewrite the fixed service while state is settling.
        let service_config = service
            .query_config()
            .map_err(service_error("QueryServiceConfig(stop uninstall)"))?;
        validate_installed_service_config(&service_config, &binding.executable, &binding.config)?;
        let status = service
            .query_status()
            .map_err(service_error("QueryServiceStatus(stop uninstall)"))?;
        if status.current_state != ServiceState::Stopped
            && status.current_state != ServiceState::StopPending
            && let Err(error) = service.stop()
        {
            if !service_not_active(&error) {
                return Err(service_error("ControlService(stop uninstall)")(error));
            }
            // The service may have reached Stopped between the query and
            // ControlService. Re-query the authoritative SCM state before
            // deciding whether deletion is safe.
            let refreshed = service
                .query_status()
                .map_err(service_error("QueryServiceStatus(stop race)"))?;
            if refreshed.current_state != ServiceState::Stopped
                && refreshed.current_state != ServiceState::StopPending
            {
                return Err(PlatformError::Unavailable(
                    "SCM reported service-not-active but the service was not stopped".to_owned(),
                ));
            }
        }
        if status.current_state != ServiceState::Stopped {
            wait_for_service_state(&service, ServiceState::Stopped, SERVICE_STOP_TIMEOUT)?;
        }
        // The service can be reconfigured while it is stopping. Re-bind before
        // returning the stop witness so deletion cannot use stale authority.
        let service_config = service
            .query_config()
            .map_err(service_error("QueryServiceConfig(after stop)"))?;
        validate_installed_service_config(&service_config, &binding.executable, &binding.config)?;
        let status = service
            .query_status()
            .map_err(service_error("QueryServiceStatus(after stop)"))?;
        if status.current_state != ServiceState::Stopped {
            return Err(PlatformError::Unavailable(
                "SCM service was not stopped after bounded stop".to_owned(),
            ));
        }
        Ok(StoppedServiceWitness {
            binding: binding.clone(),
            service,
        })
    }

    /// Delete a concrete bound service only after consuming the opaque native
    /// stop witness. The installed command line and SCM state are re-queried
    /// immediately before deletion on the same held SCM handle used for stop.
    /// Never reopen by name: a replacement service must not inherit an older
    /// service object's stop witness.
    pub fn delete_bound_stopped_service(
        &self,
        stopped: StoppedServiceWitness,
    ) -> Result<(), PlatformError> {
        if self.service_name != SERVICE_NAME {
            return Err(PlatformError::Invalid(
                "service name is not the fixed ascension-watchdog name".to_owned(),
            ));
        }
        let StoppedServiceWitness { binding, service } = stopped;
        let service_config = service
            .query_config()
            .map_err(service_error("QueryServiceConfig(delete uninstall)"))?;
        validate_installed_service_config(&service_config, &binding.executable, &binding.config)?;
        let status = service
            .query_status()
            .map_err(service_error("QueryServiceStatus(delete uninstall)"))?;
        if status.current_state != ServiceState::Stopped {
            return Err(PlatformError::Unavailable(
                "SCM service was not stopped before deletion".to_owned(),
            ));
        }
        let service_config = service
            .query_config()
            .map_err(service_error("QueryServiceConfig(before delete)"))?;
        validate_installed_service_config(&service_config, &binding.executable, &binding.config)?;
        service
            .delete()
            .map_err(service_error("DeleteService(uninstall)"))
    }
}

/// A concrete SCM binding captured by querying the fixed service's installed
/// command line. Its fields remain private so callers cannot substitute a
/// different executable or owner config between stop and delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceBinding {
    executable: PathBuf,
    config: PathBuf,
}

impl ServiceBinding {
    /// Return the canonical owner-local config path captured from SCM. The
    /// caller must use this path for the post-stop store verification rather
    /// than resolving its original operator input again.
    #[must_use]
    pub fn config_path(&self) -> &Path {
        &self.config
    }
}

/// Opaque native SCM stop witness.
///
/// This type has no public constructor or mutable fields. It proves only that
/// [`ServiceInstallPlan::stop_bound_service`] revalidated this exact binding
/// and observed SCM `Stopped`. It retains that service object's handle until
/// deletion or drop; it is not a proof of durable owner-store intent or
/// reconciliation. Concurrent reconfiguration still requires the repeated
/// binding and stopped-state checks performed before deletion.
pub struct StoppedServiceWitness {
    binding: ServiceBinding,
    service: Service,
}

impl std::fmt::Debug for StoppedServiceWitness {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoppedServiceWitness")
            .field("binding", &self.binding)
            .field("service_handle_held", &true)
            .finish_non_exhaustive()
    }
}

impl StoppedServiceWitness {
    /// Return the exact binding captured when SCM stop completed. This is
    /// useful for an owner boundary to compare its durable-store witness
    /// before consuming this token for deletion.
    #[must_use]
    pub fn binding(&self) -> &ServiceBinding {
        &self.binding
    }
}

fn validate_service_config_path(path: &Path) -> Result<(), PlatformError> {
    let text = path.to_string_lossy();
    if !path.is_absolute()
        || text.is_empty()
        || text.len() > 512
        || text.contains('\0')
        || text.contains('"')
        || text.chars().any(char::is_control)
    {
        return Err(PlatformError::Invalid(
            "Windows service config must be an absolute bounded path".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn canonicalize_service_config_path(path: &Path) -> Result<PathBuf, PlatformError> {
    validate_service_config_path(path)?;
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| PlatformError::Io(format!("service config path: {error}")))?;
    if !canonical.is_file() {
        return Err(PlatformError::Invalid(
            "Windows service config is not a regular file".to_owned(),
        ));
    }
    Ok(canonical)
}

pub(crate) fn validate_installed_service_config(
    service_config: &windows_service::service::ServiceConfig,
    expected_executable: &Path,
    expected_config: &Path,
) -> Result<(), PlatformError> {
    if service_config.service_type != ServiceType::OWN_PROCESS {
        return Err(PlatformError::IdentityMismatch(
            "SCM service type is not the fixed watchdog own-process deployment".to_owned(),
        ));
    }
    let removal_start_mode = match service_config.start_type {
        ServiceStartType::AutoStart => crate::service_command::RemovalStartMode::AutoStart,
        ServiceStartType::OnDemand => crate::service_command::RemovalStartMode::OnDemand,
        ServiceStartType::Disabled => crate::service_command::RemovalStartMode::Disabled,
        ServiceStartType::SystemStart | ServiceStartType::BootStart => {
            crate::service_command::RemovalStartMode::Unsupported
        }
    };
    crate::service_command::validate_removal_start_mode(removal_start_mode).map_err(|error| {
        PlatformError::IdentityMismatch(format!("invalid SCM removal start mode: {error}"))
    })?;
    let command_line = crate::service_command::parse_service_command_line(
        &service_config.executable_path.to_string_lossy(),
    )
    .map_err(|error| {
        PlatformError::IdentityMismatch(format!("invalid SCM service command line: {error}"))
    })?;
    let actual_executable = PathBuf::from(command_line.executable);
    let actual_config = PathBuf::from(command_line.config);
    let canonical_executable = canonicalize_executable(&actual_executable)?;
    let canonical_config = canonicalize_service_config_path(&actual_config)?;
    if normalize_path(&actual_executable) != normalize_path(&canonical_executable)
        || normalize_path(&canonical_executable) != normalize_path(expected_executable)
    {
        return Err(PlatformError::IdentityMismatch(
            "SCM service executable is not the approved canonical watchdog executable".to_owned(),
        ));
    }
    if normalize_path(&actual_config) != normalize_path(&canonical_config)
        || normalize_path(&canonical_config) != normalize_path(expected_config)
    {
        return Err(PlatformError::IdentityMismatch(
            "SCM service config is not the approved canonical owner-local config".to_owned(),
        ));
    }
    Ok(())
}

fn validate_service_account(account_name: &str) -> Result<(), PlatformError> {
    let normalized = account_name.to_ascii_lowercase();
    if account_name.is_empty()
        || account_name.len() > 256
        || account_name.contains('\0')
        || account_name.chars().any(char::is_control)
        || matches!(
            normalized.as_str(),
            "localsystem"
                | ".\\localsystem"
                | "localservice"
                | ".\\localservice"
                | "networkservice"
                | ".\\networkservice"
                | "nt authority\\system"
                | "nt authority\\localsystem"
        )
    {
        return Err(PlatformError::Invalid(
            "Windows service account must be an explicit least-privilege identity".to_owned(),
        ));
    }
    Ok(())
}

/// Minimal trusted health checker.  It can request SCM stop/recovery only
/// when an owner-local heartbeat file is stale; it never launches components.
pub struct ScmHealthChecker {
    pub service_name: String,
    pub heartbeat_file: PathBuf,
    pub stale_after: Duration,
}

impl ScmHealthChecker {
    /// Request SCM recovery when the bounded heartbeat age proves a hang.
    pub fn request_recovery_if_stale(
        &self,
        now: std::time::SystemTime,
    ) -> Result<bool, PlatformError> {
        if self.service_name != SERVICE_NAME {
            return Err(PlatformError::Invalid(
                "health checker service name is not fixed".to_owned(),
            ));
        }
        let metadata = std::fs::metadata(&self.heartbeat_file)
            .map_err(|error| PlatformError::Io(format!("heartbeat metadata: {error}")))?;
        let modified = metadata
            .modified()
            .map_err(|error| PlatformError::Io(format!("heartbeat timestamp: {error}")))?;
        let age = now.duration_since(modified).unwrap_or_default();
        if age <= self.stale_after.min(HEALTH_STALE_AFTER) {
            return Ok(false);
        }
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(service_error("OpenSCManager(health checker)"))?;
        let service = manager
            .open_service(
                &self.service_name,
                ServiceAccess::START | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
            )
            .map_err(service_error("OpenService(health checker)"))?;
        let status = service
            .query_status()
            .map_err(service_error("QueryServiceStatus(health checker)"))?;
        if status.current_state != ServiceState::Running {
            // Do not turn a deliberate stop or a pending transition into an
            // implicit start merely because an old heartbeat remains on disk.
            return Ok(false);
        }
        service
            .stop()
            .map_err(service_error("ControlService(stop)"))?;
        wait_for_service_state(&service, ServiceState::Stopped, HEALTH_STALE_AFTER)?;
        service
            .start::<&std::ffi::OsStr>(&[])
            .map_err(service_error("StartService(recovery)"))?;
        wait_for_service_state(&service, ServiceState::Running, HEALTH_STALE_AFTER)?;
        Ok(true)
    }
}

fn wait_for_service_state(
    service: &Service,
    expected: ServiceState,
    timeout: Duration,
) -> Result<(), PlatformError> {
    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(std::time::Instant::now);
    loop {
        let status = service
            .query_status()
            .map_err(service_error("QueryServiceStatus(recovery)"))?;
        if status.current_state == expected {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(PlatformError::Timeout(format!(
                "SCM service did not reach {expected:?} before the bounded recovery deadline"
            )));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Service runtime callback.  The callback must call its real reconciliation
/// loop and return when the SCM stop flag is observed.
pub struct ServiceRuntime;

impl ServiceRuntime {
    /// Enter the SCM dispatcher for the fixed service name.
    ///
    /// This compatibility entrypoint deliberately refuses to claim `Running`
    /// because it has no trusted readiness witness.  Call
    /// [`Self::run_with_readiness`] from the production daemon.
    pub fn run<F>(reconcile: F) -> Result<(), PlatformError>
    where
        F: Fn(Arc<Mutex<bool>>) -> Result<(), PlatformError> + Send + Sync + 'static,
    {
        Self::run_with_readiness(reconcile, || {
            Err(PlatformError::Unavailable(
                "service readiness witness was not supplied".to_owned(),
            ))
        })
    }

    /// Enter the SCM dispatcher and publish `Running` only after the caller's
    /// bounded, real readiness witness succeeds.  The witness should perform
    /// the same configuration, storage, IPC, and control-loop checks used by
    /// the daemon; a static boolean or process-alive probe is not sufficient.
    pub fn run_with_readiness<F, R>(reconcile: F, readiness: R) -> Result<(), PlatformError>
    where
        F: Fn(Arc<Mutex<bool>>) -> Result<(), PlatformError> + Send + Sync + 'static,
        R: Fn() -> Result<(), PlatformError> + Send + Sync + 'static,
    {
        SERVICE_RECONCILE.set(Arc::new(reconcile)).map_err(|_| {
            PlatformError::Unavailable("service runtime was already initialized".to_owned())
        })?;
        SERVICE_READINESS.set(Arc::new(readiness)).map_err(|_| {
            PlatformError::Unavailable("service readiness was already initialized".to_owned())
        })?;
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .map_err(service_error("service dispatcher"))
    }
}

windows_service::define_windows_service!(ffi_service_main, dispatch_service_main);

fn dispatch_service_main(arguments: Vec<std::ffi::OsString>) {
    if let (Some(reconcile), Some(readiness)) = (SERVICE_RECONCILE.get(), SERVICE_READINESS.get()) {
        if let Err(error) = service_entry(arguments, reconcile, readiness) {
            // The SCM callback cannot return a Rust error.  Do not silently
            // discard startup/status failures: this is the last diagnostic
            // path before SCM applies configured failure actions.
            eprintln!("ascension-watchdog service entry failed: {error}");
        }
    } else {
        eprintln!("ascension-watchdog service entry callbacks were not initialized");
    }
}

fn service_entry(
    _arguments: Vec<std::ffi::OsString>,
    reconcile: &Arc<ReconcileCallback>,
    readiness: &Arc<ReadinessCallback>,
) -> Result<(), PlatformError> {
    let stopping = Arc::new(Mutex::new(false));
    let stop_flag = Arc::clone(&stopping);
    let status_slot = Arc::new(Mutex::new(None::<ServiceStatusHandle>));
    let handler_status_slot = Arc::clone(&status_slot);
    let stop_checkpoint = Arc::new(AtomicU32::new(1));
    let handler_checkpoint = Arc::clone(&stop_checkpoint);
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            if let Ok(mut value) = stop_flag.lock() {
                *value = true;
            }
            let checkpoint = handler_checkpoint.fetch_add(1, Ordering::AcqRel);
            if let Ok(slot) = handler_status_slot.lock()
                && let Some(status) = *slot
                && let Err(error) = status.set_service_status(ServiceStatus {
                    service_type: ServiceType::OWN_PROCESS,
                    current_state: ServiceState::StopPending,
                    controls_accepted: windows_service::service::ServiceControlAccept::empty(),
                    exit_code: windows_service::service::ServiceExitCode::Win32(ERROR_SUCCESS),
                    checkpoint,
                    wait_hint: SERVICE_STOP_TIMEOUT,
                    process_id: None,
                })
            {
                eprintln!("ascension-watchdog failed to publish STOP_PENDING: {error}");
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(SERVICE_NAME, handler)
        .map_err(service_error("RegisterServiceCtrlHandler"))?;
    if let Ok(mut slot) = status_slot.lock() {
        *slot = Some(status);
    } else {
        return Err(PlatformError::Unavailable(
            "service status slot was poisoned before startup".to_owned(),
        ));
    }
    status
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StartPending,
            controls_accepted: windows_service::service::ServiceControlAccept::STOP
                | windows_service::service::ServiceControlAccept::PRESHUTDOWN,
            exit_code: windows_service::service::ServiceExitCode::Win32(ERROR_SUCCESS),
            checkpoint: 1,
            wait_hint: SERVICE_READY_TIMEOUT,
            process_id: None,
        })
        .map_err(service_error("SetServiceStatus(StartPending)"))?;
    if let Err(error) = readiness() {
        status
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Stopped,
                controls_accepted: windows_service::service::ServiceControlAccept::empty(),
                exit_code: windows_service::service::ServiceExitCode::ServiceSpecific(1),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .map_err(service_error(
                "SetServiceStatus(Stopped after readiness failure)",
            ))?;
        return Err(error);
    }
    status
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: windows_service::service::ServiceControlAccept::STOP
                | windows_service::service::ServiceControlAccept::PRESHUTDOWN,
            exit_code: windows_service::service::ServiceExitCode::Win32(ERROR_SUCCESS),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .map_err(service_error("SetServiceStatus(Running)"))?;
    let reconcile_error = reconcile(stopping).err();
    status
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: windows_service::service::ServiceControlAccept::empty(),
            // A failed/uncertain reconciliation is explicitly not a clean
            // stop. SCM receives a service-specific failure status, while the
            // durable stop intent prevents child relaunch on any recovery.
            exit_code: if reconcile_error.is_some() {
                windows_service::service::ServiceExitCode::ServiceSpecific(1)
            } else {
                windows_service::service::ServiceExitCode::Win32(ERROR_SUCCESS)
            },
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .map_err(service_error("SetServiceStatus(Stopped)"))?;
    if let Some(error) = reconcile_error {
        return Err(error);
    }
    Ok(())
}

fn service_exists(error: &windows_service::Error) -> bool {
    matches!(
        error,
        windows_service::Error::Winapi(error)
            if error.raw_os_error() == Some(ERROR_SERVICE_EXISTS.cast_signed())
    )
}

pub(crate) fn service_missing(error: &windows_service::Error) -> bool {
    matches!(
        error,
        windows_service::Error::Winapi(error)
            if error.raw_os_error() == Some(
                windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST.cast_signed(),
            )
    )
}

pub(crate) fn service_not_active(error: &windows_service::Error) -> bool {
    matches!(
        error,
        windows_service::Error::Winapi(error)
            if error.raw_os_error() == Some(ERROR_SERVICE_NOT_ACTIVE.cast_signed())
    )
}

fn service_error(operation: &'static str) -> impl Fn(windows_service::Error) -> PlatformError {
    move |error| PlatformError::Io(format!("{operation}: {error}"))
}
