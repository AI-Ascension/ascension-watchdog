//! Windows SCM entrypoint and bounded service-management commands.
//!
//! The native platform crate owns SCM status and dispatch. This module only
//! binds that runner to the watchdog's real durable reconciliation loop. The
//! SCM command line is intentionally closed: the service accepts `daemon
//! --service --config` and one canonical absolute config path. No credentials or
//! arbitrary child arguments are carried in the service command line.

#![cfg(windows)]

use crate::config::{DesiredMode, WatchdogConfig};
use crate::error::{Result, WatchdogError};
use crate::runtime::Supervisor;
use crate::service::ServiceLoop;
use crate::storage::now_unix_ms;
use ascension_platform_windows::{
    PlatformError, ServiceBinding, ServiceInstallPlan, ServiceRuntime, StoppedServiceWitness,
};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const SERVICE_NAME: &str = "ascension-watchdog";
pub const DEFAULT_SERVICE_CONFIG: &str = r"C:\ProgramData\Ascension\Watchdog\watchdog.json";
pub const DEFAULT_SERVICE_ACCOUNT: &str = r"NT SERVICE\ascension-watchdog";

const SERVICE_COMMAND: &str = "daemon";
const SERVICE_SWITCH: &str = "--service";
const CONFIG_SWITCH: &str = "--config";
const MAX_SERVICE_CONFIG_BYTES: usize = 512;
// Leave a small margin below the native SCM stop wait hint so a failed
// reconciliation can report a failure status before SCM's outer deadline.
const SERVICE_STOP_RETRY_TIMEOUT: Duration = Duration::from_secs(25);

/// Dispatch the native SCM entrypoint when the fixed service marker is
/// present. `None` means this is an ordinary foreground/CLI invocation.
pub fn run_if_service(args: &[String]) -> Result<Option<i32>> {
    let Some(config_path) = parse_service_args(args)? else {
        return Ok(None);
    };
    run_service(&config_path).map(|()| Some(0))
}

/// Handle `watchdog service install|uninstall` without exposing a secret
/// password argument. Installation uses the Windows virtual service account
/// by default; a deployment may select another explicitly authorized account,
/// but credentials must be provisioned through SCM/OS policy rather than this
/// command line.
pub fn service_command(args: &mut Vec<String>, global_config: &Path) -> Result<Option<String>> {
    let command = args.first().cloned().ok_or_else(|| {
        WatchdogError::InvalidInput("service requires install or uninstall".to_owned())
    })?;
    args.remove(0);
    match command.as_str() {
        "install" => {
            let executable = take_option(args, "--executable")
                .map(PathBuf::from)
                .unwrap_or(std::env::current_exe()?);
            let account = take_option(args, "--account")
                .unwrap_or_else(|| DEFAULT_SERVICE_ACCOUNT.to_owned());
            if !args.is_empty() {
                return Err(WatchdogError::InvalidInput(format!(
                    "unexpected service install argument {}",
                    args[0]
                )));
            }
            let config_path = canonical_service_config_path(&service_config_path(global_config)?)?;
            // Validate the closed config before mutating SCM. This reads only
            // the config document and never initializes the owner database.
            WatchdogConfig::from_file(&config_path)?;
            let plan = ServiceInstallPlan {
                service_name: SERVICE_NAME.to_owned(),
                executable,
            };
            plan.install_as_with_config(&account, None, &config_path)
                .map_err(|error| platform_error(&error))?;
            Ok(Some(
                json!({
                    "installed": true,
                    "service": SERVICE_NAME,
                    "config": config_path,
                    "account": account,
                    "started": false,
                    "data_preserved": true,
                })
                .to_string(),
            ))
        }
        "uninstall" => {
            if !args.is_empty() {
                return Err(WatchdogError::InvalidInput(format!(
                    "unexpected service uninstall argument {}",
                    args[0]
                )));
            }
            let plan = ServiceInstallPlan {
                service_name: SERVICE_NAME.to_owned(),
                executable: std::env::current_exe()?,
            };
            let config_input = service_config_path(global_config)?;
            // Bind the operator's config to the fixed SCM service before
            // opening its store or writing owner state. A missing service is
            // idempotent and must not cause an alternate store to be opened.
            let Some(binding) = plan
                .bind_installed_service(&config_input)
                .map_err(|error| platform_error(&error))?
            else {
                return Ok(Some(
                    json!({
                        "uninstalled": true,
                        "service": SERVICE_NAME,
                        "data_preserved": true,
                        "already_absent": true,
                    })
                    .to_string(),
                ));
            };
            // The owner boundary below uses the canonical config path captured
            // from SCM. Re-resolving the operator's input could follow a
            // changed symlink to an alternate owner store after binding.
            // A running service receives the authenticated SCM stop first. Its
            // reconciliation thread persists Stopped and drains owned work;
            // this command does not race its singleton store. The returned
            // witness proves only native SCM state; the owner-store witness
            // below remains a separate required capability.
            let native_stop = plan
                .stop_bound_service(&binding)
                .map_err(|error| platform_error(&error))?;
            // Once SCM is stopped, reopen the exact bound store and mint the
            // private durable owner witness only after Stopped intent and a
            // clean persistent reconciliation are observed. Deletion consumes
            // both this witness and the native SCM witness.
            delete_durably_stopped_service(
                &plan,
                native_stop,
                mint_durably_stopped_deployment(&binding),
            )?;
            Ok(Some(
                json!({
                    "uninstalled": true,
                    "service": SERVICE_NAME,
                    "data_preserved": true,
                })
                .to_string(),
            ))
        }
        other => Err(WatchdogError::InvalidInput(format!(
            "unknown service command {other}"
        ))),
    }
}

/// Private owner-store capability issued only after the binding's config has
/// opened the matching watchdog store, durable `Stopped` intent has been
/// persisted, and a clean reconciliation has completed. The platform-native
/// SCM witness is intentionally separate because this crate owns the store
/// semantics while the platform crate owns SCM.
#[derive(Debug)]
struct DurablyStoppedDeployment {
    binding: ServiceBinding,
}

fn mint_durably_stopped_deployment(binding: &ServiceBinding) -> Result<DurablyStoppedDeployment> {
    let config_path = binding.config_path().to_owned();
    let config = WatchdogConfig::from_file(&config_path)?;
    let mut supervisor = Supervisor::open(config)?;
    if supervisor.status()?.desired_mode != DesiredMode::Stopped {
        supervisor.request_stop(now_unix_ms())?;
    }
    let report = supervisor.reconcile_once(now_unix_ms())?;
    if report.desired_mode != DesiredMode::Stopped
        || !report.errors.is_empty()
        || !report.quarantined.is_empty()
    {
        return Err(WatchdogError::Conflict(
            "bound watchdog store did not reach a clean Stopped reconciliation".to_owned(),
        ));
    }
    let persisted = supervisor.status()?;
    if persisted.desired_mode != DesiredMode::Stopped {
        return Err(WatchdogError::Conflict(
            "bound watchdog store did not persist Stopped intent".to_owned(),
        ));
    }
    Ok(DurablyStoppedDeployment {
        binding: binding.clone(),
    })
}

/// Keep the owner witness check ahead of the native deletion seam. This
/// generic helper is deliberately small so a failed owner proof can be tested
/// without installing or deleting an SCM service.
fn with_durably_stopped_deployment<F>(
    owner_stop: Result<DurablyStoppedDeployment>,
    delete: F,
) -> Result<()>
where
    F: FnOnce(DurablyStoppedDeployment) -> Result<()>,
{
    delete(owner_stop?)
}

fn delete_durably_stopped_service(
    plan: &ServiceInstallPlan,
    native_stop: StoppedServiceWitness,
    owner_stop: Result<DurablyStoppedDeployment>,
) -> Result<()> {
    with_durably_stopped_deployment(owner_stop, |owner_stop| {
        if native_stop.binding() != &owner_stop.binding {
            return Err(WatchdogError::Conflict(
                "native SCM stop witness does not match durable owner deployment".to_owned(),
            ));
        }
        plan.delete_bound_stopped_service(native_stop)
            .map_err(|error| platform_error(&error))
    })
}

fn run_service(config_path: &Path) -> Result<()> {
    let state = Arc::new(Mutex::new(None::<ServiceLoop>));

    let readiness_state = Arc::clone(&state);
    let readiness_path = config_path.to_owned();
    let readiness = move || {
        let config =
            WatchdogConfig::from_file(&readiness_path).map_err(|error| watchdog_error(&error))?;
        let interval = Duration::from_millis(config.probe_interval_ms);
        let supervisor = Supervisor::open(config).map_err(|error| watchdog_error(&error))?;
        let mut service =
            ServiceLoop::new(supervisor, interval).map_err(|error| watchdog_error(&error))?;
        // SCM Running is not published until this real reconciliation has
        // completed and durable progress/health has been recorded.
        service
            .reconcile(now_unix_ms())
            .map_err(|error| watchdog_error(&error))?;
        let mut slot = readiness_state.lock().map_err(|_| {
            PlatformError::Unavailable("Windows service state lock was poisoned".to_owned())
        })?;
        if slot.is_some() {
            return Err(PlatformError::Unavailable(
                "Windows service readiness was initialized twice".to_owned(),
            ));
        }
        *slot = Some(service);
        Ok(())
    };

    let reconcile_state = Arc::clone(&state);
    let reconcile = move |stop| -> std::result::Result<(), PlatformError> {
        let service = reconcile_state.lock().ok().and_then(|mut slot| slot.take());
        let Some(mut service) = service else {
            return Err(PlatformError::Unavailable(
                "ascension-watchdog service loop was unavailable after readiness".to_owned(),
            ));
        };
        let mut stop_deadline = None;
        loop {
            match service.run_until_stopped_with_scm_stop(&stop) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    let stopping = stop.lock().map(|value| *value).unwrap_or(true);
                    if !stopping {
                        // Before an SCM stop, keep the same owner alive and
                        // retry ordinary transient reconciliation failures.
                        eprintln!("ascension-watchdog service loop failed: {error}");
                        std::thread::sleep(Duration::from_millis(250));
                        continue;
                    }
                    let deadline = *stop_deadline
                        .get_or_insert_with(|| Instant::now() + SERVICE_STOP_RETRY_TIMEOUT);
                    if Instant::now() >= deadline {
                        return Err(PlatformError::Timeout(format!(
                            "SCM stop reconciliation remained uncertain after {SERVICE_STOP_RETRY_TIMEOUT:?}: {error}"
                        )));
                    }
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    eprintln!("ascension-watchdog stop reconciliation failed: {error}");
                    std::thread::sleep(remaining.min(Duration::from_millis(250)));
                }
            }
        }
    };

    ServiceRuntime::run_with_readiness(reconcile, readiness).map_err(|error| platform_error(&error))
}

fn parse_service_args(args: &[String]) -> Result<Option<PathBuf>> {
    let values = args.iter().skip(1).map(String::as_str).collect::<Vec<_>>();
    match values.as_slice() {
        [SERVICE_COMMAND, SERVICE_SWITCH, CONFIG_SWITCH, path] => {
            let path = PathBuf::from(path);
            Ok(Some(canonical_service_config_path(&path)?))
        }
        [SERVICE_COMMAND, SERVICE_SWITCH, ..] => Err(WatchdogError::InvalidInput(
            "Windows service accepts only `daemon --service --config ABSOLUTE_PATH`".to_owned(),
        )),
        _ => Ok(None),
    }
}

fn service_config_path(global_config: &Path) -> Result<PathBuf> {
    let path = if global_config == Path::new("config/watchdog.json") {
        default_config_path()
    } else {
        global_config.to_owned()
    };
    validate_service_config_path(&path)?;
    Ok(path)
}

fn default_config_path() -> PathBuf {
    PathBuf::from(DEFAULT_SERVICE_CONFIG)
}

fn validate_service_config_path(path: &Path) -> Result<()> {
    let text = path.to_string_lossy();
    if !path.is_absolute()
        || text.is_empty()
        || text.len() > MAX_SERVICE_CONFIG_BYTES
        || text.contains('\0')
        || text.contains('"')
        || text.chars().any(char::is_control)
    {
        return Err(WatchdogError::InvalidInput(
            "Windows service config must be an absolute bounded path".to_owned(),
        ));
    }
    Ok(())
}

fn canonical_service_config_path(path: &Path) -> Result<PathBuf> {
    validate_service_config_path(path)?;
    let canonical = std::fs::canonicalize(path)?;
    if !canonical.is_file() {
        return Err(WatchdogError::InvalidInput(
            "Windows service config is not a regular file".to_owned(),
        ));
    }
    Ok(canonical)
}

fn take_option(args: &mut Vec<String>, option: &str) -> Option<String> {
    let index = args.iter().position(|value| value == option)?;
    if index + 1 >= args.len() {
        return Some(String::new());
    }
    let value = args.remove(index + 1);
    args.remove(index);
    Some(value)
}

fn platform_error(error: &PlatformError) -> WatchdogError {
    WatchdogError::Unsupported(error.to_string())
}

fn watchdog_error(error: &WatchdogError) -> PlatformError {
    PlatformError::Unavailable(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        std::iter::once("watchdog.exe")
            .chain(values.iter().copied())
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn only_the_fixed_service_invocation_is_claimed() {
        assert!(parse_service_args(&args(&["daemon"])).unwrap().is_none());
        assert!(parse_service_args(&args(&["daemon", "--service"])).is_err());
    }

    #[test]
    fn service_arguments_reject_unbounded_or_unknown_values() {
        assert!(parse_service_args(&args(&["daemon", "--service", "--unknown"])).is_err());
        assert!(
            parse_service_args(&args(
                &["daemon", "--service", "--config", "relative.json",]
            ))
            .is_err()
        );
    }

    #[test]
    fn service_argument_path_is_canonical_and_must_be_a_file() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let configured = directory.path().join("watchdog.json");
        std::fs::write(&configured, b"{}")?;
        let parsed = parse_service_args(&args(&[
            "daemon",
            "--service",
            "--config",
            configured
                .to_str()
                .ok_or_else(|| WatchdogError::InvalidInput("test path was not UTF-8".to_owned()))?,
        ]))?
        .ok_or_else(|| {
            WatchdogError::InvalidInput("service invocation was not claimed".to_owned())
        })?;
        assert_eq!(parsed, std::fs::canonicalize(configured)?);
        Ok(())
    }

    #[test]
    fn failed_owner_witness_does_not_call_native_delete_seam() {
        let mut called = false;
        let result = with_durably_stopped_deployment(
            Err(WatchdogError::Conflict(
                "owner reconciliation was not durable".to_owned(),
            )),
            |_owner| {
                called = true;
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!called);
    }
}
