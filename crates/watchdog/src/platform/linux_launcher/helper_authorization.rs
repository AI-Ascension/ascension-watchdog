//! Hidden-helper authorization and authorized target execution.

use super::MAX_TIMEOUT;
use super::O_CLOEXEC;
use super::O_NONBLOCK;
use super::cgroup::verify_current_cgroup;
use super::executable_snapshot::hash_file;
use super::executable_snapshot::open_verified_executable;
use super::framed_protocol::read_frame_bounded;
use super::framed_protocol::read_gateway_health_frame;
use super::framed_protocol::read_go_bounded;
use super::framed_protocol::remaining_timeout;
use super::framed_protocol::set_worker_reader_blocking;
use super::parent_launcher::HelperReadyChannel;
use super::protected_bootstrap::LinuxHelperBootstrap;
use super::protected_bootstrap::helper_invocation_requested;
use super::protected_bootstrap::parse_helper_bootstrap;
use crate::platform::contract::AdapterError;
use crate::platform::contract::ComponentKind;
use crate::platform::contract::LaunchSpec;
use crate::platform::contract::SessionSelector;
use crate::platform::gateway_health::GatewayHealthBootstrap;
use crate::platform::gateway_health::GatewayHealthFrameBinding;
use rustix::pipe::PipeFlags;
use rustix::pipe::pipe_with;
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::time::Instant;

/// The request supplied to the root-owned durable-intent authorizer.
///
/// A caller must authorize the complete specification and exact cgroup path;
/// authorizing only the launch nonce or executable path is insufficient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxHelperRequest {
    pub specification: LaunchSpec,
    pub cgroup_path: PathBuf,
}

/// Authorization returned by the root-owned durable-intent lookup.
///
/// The helper compares the request to this value, canonicalizes the approved
/// role path, and hashes the executable again immediately before launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxHelperAuthorization {
    pub specification: LaunchSpec,
    pub cgroup_path: PathBuf,
    pub allowlisted_executables: BTreeMap<ComponentKind, PathBuf>,
}

impl LinuxHelperAuthorization {
    /// Validate the closed helper authorization surface.
    ///
    /// # Errors
    ///
    /// Returns an explicit error when the durable authorization is malformed,
    /// has no role allowlist entry, or names an untrusted cgroup path.
    pub fn validate(&self) -> Result<(), AdapterError> {
        self.specification.validate()?;
        if !self.cgroup_path.is_absolute() {
            return Err(AdapterError::Invalid(
                "Linux helper cgroup path must be absolute".to_owned(),
            ));
        }
        let Some(approved) = self
            .allowlisted_executables
            .get(&self.specification.component)
        else {
            return Err(AdapterError::Unsupported(
                "Linux helper role is not allowlisted".to_owned(),
            ));
        };
        if !approved.is_absolute() {
            return Err(AdapterError::Invalid(
                "Linux helper allowlist path must be absolute".to_owned(),
            ));
        }
        if self.specification.executable_sha256.len() != 64
            || !self
                .specification
                .executable_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(AdapterError::Invalid(
                "Linux helper executable digest is not SHA-256".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Run the hidden helper after root code has authorized its frame.
///
/// The authorizer is deliberately called after the frame is decoded and must
/// resolve the launch nonce against durable intent.  It must not authorize a
/// request solely because the executable or role is familiar.
///
/// # Errors
///
/// Returns an explicit error for malformed input, authorization mismatch,
/// cgroup mismatch, GO timeout/nonce mismatch, or target launch failure.
pub fn run_hidden_helper_with_authorizer<F>(authorizer: F) -> Result<i32, AdapterError>
where
    F: FnOnce(&LinuxHelperRequest) -> Result<LinuxHelperAuthorization, AdapterError>,
{
    if !helper_invocation_requested() {
        return Err(AdapterError::Unsupported(
            "Linux helper entrypoint was not requested".to_owned(),
        ));
    }
    if parse_helper_bootstrap()?.is_some() {
        return Err(AdapterError::Invalid(
            "Linux helper protected bootstrap requires the bootstrap authorizer API".to_owned(),
        ));
    }
    run_hidden_helper_core(None, None, None, |request, _| authorizer(request))
}

/// Run the hidden helper with the separately supplied protected-config
/// context.  The authorizer receives both the decoded frame and this context,
/// allowing it to perform a read-only launch-intent lookup against the exact
/// root-configured store rather than trusting a path from the frame.
pub fn run_hidden_helper_with_bootstrap_authorizer<F>(authorizer: F) -> Result<i32, AdapterError>
where
    F: FnOnce(
        &LinuxHelperRequest,
        &LinuxHelperBootstrap,
    ) -> Result<LinuxHelperAuthorization, AdapterError>,
{
    if !helper_invocation_requested() {
        return Err(AdapterError::Unsupported(
            "Linux helper entrypoint was not requested".to_owned(),
        ));
    }
    let (bootstrap, ready) = parse_helper_bootstrap()?.ok_or_else(|| {
        AdapterError::Invalid(
            "Linux helper requires a separately supplied protected config bootstrap".to_owned(),
        )
    })?;
    let worker_reader = bootstrap.worker_pipe_file()?;
    let gateway_health_reader = bootstrap.gateway_health_pipe_file()?;
    run_hidden_helper_core(
        Some(ready),
        worker_reader,
        gateway_health_reader,
        |request, gateway_health| {
            if gateway_health.is_some() && request.specification.component == ComponentKind::Gateway
            {
                return Err(AdapterError::Invalid(
                    "Gateway health bootstrap requires the Gateway health authorizer API"
                        .to_owned(),
                ));
            }
            authorizer(request, &bootstrap)
        },
    )
}

/// Run a protected helper with optional health binding and a held admission guard.
///
/// The real watchdog dispatcher uses the optional-binding variant below to
/// admit both ordinary worker helpers and explicitly configured health helpers.
pub fn run_hidden_helper_if_requested_with_health_authorizer<F, G>(
    authorizer: F,
) -> Result<Option<i32>, AdapterError>
where
    F: FnOnce(
        &LinuxHelperRequest,
        &LinuxHelperBootstrap,
        Option<&GatewayHealthFrameBinding>,
    ) -> Result<(LinuxHelperAuthorization, G), AdapterError>,
{
    if !helper_invocation_requested() {
        return Ok(None);
    }
    let (bootstrap, ready) = parse_helper_bootstrap()?.ok_or_else(|| {
        AdapterError::Invalid("Linux helper requires protected config bootstrap".to_owned())
    })?;
    let worker_reader = bootstrap.worker_pipe_file()?;
    let gateway_health_reader = bootstrap.gateway_health_pipe_file()?;
    let mut admission_guard = None;
    let result = run_hidden_helper_core(
        Some(ready),
        worker_reader,
        gateway_health_reader,
        |request, observed| {
            let (authorization, guard) = authorizer(request, &bootstrap, observed)?;
            admission_guard = Some(guard);
            Ok(authorization)
        },
    );
    // Successful exec replaces this process while the guard still exists.
    // Its native descriptors must be CLOEXEC. Errors release it here, after
    // the core can no longer execute the target. No launch follows Drop.
    drop(admission_guard);
    result.map(Some)
}

/// Run the hidden helper with a required dedicated Gateway health binding.
///
/// The callback receives only the non-secret binding derived from the fixed
/// frame after GO.  It must independently load the expected launch nonce and
/// frame digest from the owner-local durable launch-intent store and compare
/// them before returning [`LinuxHelperAuthorization`].  The transport frame
/// is never an authorization source by itself, and this entrypoint rejects a
/// helper invocation that did not carry the dedicated health pipe.
pub fn run_hidden_helper_with_bootstrap_and_gateway_health_authorizer<F>(
    authorizer: F,
) -> Result<i32, AdapterError>
where
    F: FnOnce(
        &LinuxHelperRequest,
        &LinuxHelperBootstrap,
        &GatewayHealthFrameBinding,
    ) -> Result<LinuxHelperAuthorization, AdapterError>,
{
    if !helper_invocation_requested() {
        return Err(AdapterError::Unsupported(
            "Linux helper entrypoint was not requested".to_owned(),
        ));
    }
    let (bootstrap, ready) = parse_helper_bootstrap()?.ok_or_else(|| {
        AdapterError::Invalid(
            "Linux helper requires a separately supplied protected config bootstrap".to_owned(),
        )
    })?;
    let worker_reader = bootstrap.worker_pipe_file()?;
    let gateway_health_reader = bootstrap.gateway_health_pipe_file()?;
    run_hidden_helper_core(
        Some(ready),
        worker_reader,
        gateway_health_reader,
        |request, gateway_health| {
            let gateway_health = gateway_health.ok_or_else(|| {
                AdapterError::Invalid(
                    "Linux Gateway health authorizer requires the dedicated health pipe".to_owned(),
                )
            })?;
            authorizer(request, &bootstrap, gateway_health)
        },
    )
}

pub(super) fn run_hidden_helper_core<F>(
    mut ready: Option<HelperReadyChannel>,
    worker_reader: Option<File>,
    mut gateway_health_reader: Option<File>,
    authorizer: F,
) -> Result<i32, AdapterError>
where
    F: FnOnce(
        &LinuxHelperRequest,
        Option<&GatewayHealthFrameBinding>,
    ) -> Result<LinuxHelperAuthorization, AdapterError>,
{
    let started = Instant::now();
    let mut control_stdin = open_helper_control_stdin()?;
    let request = read_frame_bounded(&mut control_stdin, remaining_timeout(started, MAX_TIMEOUT))?;
    if worker_reader.is_some() && request.specification.component != ComponentKind::Harness {
        drop(worker_reader);
        drop(gateway_health_reader);
        return Err(AdapterError::Unsupported(
            "Linux worker bootstrap pipe requires the Harness role".to_owned(),
        ));
    }
    if gateway_health_reader.is_some() && request.specification.component != ComponentKind::Gateway
    {
        drop(worker_reader);
        drop(gateway_health_reader);
        return Err(AdapterError::Unsupported(
            "Linux Gateway health bootstrap pipe requires the Gateway role".to_owned(),
        ));
    }
    if worker_reader.is_some() && gateway_health_reader.is_some() {
        drop(worker_reader);
        drop(gateway_health_reader);
        return Err(AdapterError::Invalid(
            "Linux worker and Gateway health pipes cannot be combined".to_owned(),
        ));
    }
    if let Some(channel) = ready.as_mut() {
        channel.send(&request.specification.launch_nonce)?;
    }
    let (authorization, gateway_health) = authorize_after_release_with_health(
        &request,
        &mut control_stdin,
        started,
        gateway_health_reader.as_mut(),
        authorizer,
    )?;
    verify_current_cgroup(&authorization.cgroup_path)?;
    spawn_authorized_target(&authorization, worker_reader, gateway_health.as_ref()).map(|()| 0)
}

#[cfg(test)]
pub(super) fn authorize_after_release<F>(
    request: &LinuxHelperRequest,
    control_stdin: &mut impl Read,
    started: Instant,
    authorizer: F,
) -> Result<LinuxHelperAuthorization, AdapterError>
where
    F: FnOnce(&LinuxHelperRequest) -> Result<LinuxHelperAuthorization, AdapterError>,
{
    authorize_after_release_with_health(request, control_stdin, started, None, |request, _| {
        authorizer(request)
    })
    .map(|(authorization, _)| authorization)
}

pub(super) fn authorize_after_release_with_health<F>(
    request: &LinuxHelperRequest,
    control_stdin: &mut impl Read,
    started: Instant,
    gateway_health_reader: Option<&mut File>,
    authorizer: F,
) -> Result<(LinuxHelperAuthorization, Option<GatewayHealthBootstrap>), AdapterError>
where
    F: FnOnce(
        &LinuxHelperRequest,
        Option<&GatewayHealthFrameBinding>,
    ) -> Result<LinuxHelperAuthorization, AdapterError>,
{
    // The request frame can arrive before the parent has assigned this helper
    // to the cgroup. GO is sent only after that assignment and its verification.
    // Checking membership before GO races the parent's legitimate handoff.
    // Query durable authorization after the barrier too: stop may have been
    // committed while this helper was waiting, invalidating earlier approval.
    let go = read_go_bounded(control_stdin, remaining_timeout(started, MAX_TIMEOUT))?;
    if go != request.specification.launch_nonce {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper GO nonce does not match the authorized launch".to_owned(),
        ));
    }
    let gateway_health = gateway_health_reader
        .map(|reader| {
            read_gateway_health_frame(reader, request, remaining_timeout(started, MAX_TIMEOUT))
        })
        .transpose()?;
    let gateway_health_binding = gateway_health
        .as_ref()
        .map(GatewayHealthFrameBinding::from_bootstrap);
    let authorization = authorizer(request, gateway_health_binding.as_ref())?;
    authorize_request(request, &authorization)?;
    Ok((authorization, gateway_health))
}

/// Run the hidden helper if the current process was invoked in helper mode.
///
/// This convenience function is intended for the real watchdog `main`: when
/// it returns `Ok(false)`, normal CLI parsing may continue.  The authorizer
/// remains root-owned so this module cannot invent durable intent.
///
/// # Errors
///
/// Returns the same bounded helper errors as
/// [`run_hidden_helper_with_authorizer`].
pub fn run_hidden_helper_if_requested<F>(authorizer: F) -> Result<Option<i32>, AdapterError>
where
    F: FnOnce(&LinuxHelperRequest) -> Result<LinuxHelperAuthorization, AdapterError>,
{
    if !helper_invocation_requested() {
        return Ok(None);
    }
    run_hidden_helper_with_authorizer(authorizer).map(Some)
}

/// Run the hidden helper with protected bootstrap context when requested.
pub fn run_hidden_helper_if_requested_with_bootstrap_authorizer<F>(
    authorizer: F,
) -> Result<Option<i32>, AdapterError>
where
    F: FnOnce(
        &LinuxHelperRequest,
        &LinuxHelperBootstrap,
    ) -> Result<LinuxHelperAuthorization, AdapterError>,
{
    if !helper_invocation_requested() {
        return Ok(None);
    }
    run_hidden_helper_with_bootstrap_authorizer(authorizer).map(Some)
}

/// Run the required-health helper path when the current process was invoked
/// in helper mode.
pub fn run_hidden_helper_if_requested_with_bootstrap_and_gateway_health_authorizer<F>(
    authorizer: F,
) -> Result<Option<i32>, AdapterError>
where
    F: FnOnce(
        &LinuxHelperRequest,
        &LinuxHelperBootstrap,
        &GatewayHealthFrameBinding,
    ) -> Result<LinuxHelperAuthorization, AdapterError>,
{
    if !helper_invocation_requested() {
        return Ok(None);
    }
    run_hidden_helper_with_bootstrap_and_gateway_health_authorizer(authorizer).map(Some)
}

pub(super) fn open_helper_control_stdin() -> Result<File, AdapterError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK | O_CLOEXEC)
        .open("/proc/self/fd/0")
        .map_err(|error| {
            AdapterError::Unavailable(format!(
                "Linux helper control stdin cannot be opened for bounded I/O: {error}"
            ))
        })
}

pub(super) fn authorize_request(
    request: &LinuxHelperRequest,
    authorization: &LinuxHelperAuthorization,
) -> Result<(), AdapterError> {
    authorization.validate()?;
    if request.specification != authorization.specification
        || request.cgroup_path != authorization.cgroup_path
    {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper request differs from durable authorization".to_owned(),
        ));
    }
    let approved = fs::canonicalize(
        authorization
            .allowlisted_executables
            .get(&request.specification.component)
            .ok_or_else(|| {
                AdapterError::Unsupported("Linux helper role is not allowlisted".to_owned())
            })?,
    )
    .map_err(|error| {
        AdapterError::Unavailable(format!("Linux helper allowlist unavailable: {error}"))
    })?;
    let requested = fs::canonicalize(&request.specification.executable).map_err(|error| {
        AdapterError::Invalid(format!(
            "Linux helper executable cannot be resolved: {error}"
        ))
    })?;
    if approved != requested {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper executable is outside the role allowlist".to_owned(),
        ));
    }
    let digest = hash_file(&requested)?;
    if digest != request.specification.executable_sha256 {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper executable digest changed".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn spawn_authorized_target(
    authorization: &LinuxHelperAuthorization,
    worker_reader: Option<File>,
    gateway_health: Option<&GatewayHealthBootstrap>,
) -> Result<(), AdapterError> {
    let specification = &authorization.specification;
    if specification.component == ComponentKind::HostBroker {
        return Err(AdapterError::Unsupported(
            "Linux helper does not launch graphical HostBroker sessions".to_owned(),
        ));
    }
    if let SessionSelector::Explicit(session) = specification.session
        && session != 0
    {
        return Err(AdapterError::Unsupported(
            "Linux helper does not select Windows user sessions".to_owned(),
        ));
    }
    let approved = fs::canonicalize(
        authorization
            .allowlisted_executables
            .get(&specification.component)
            .ok_or_else(|| {
                AdapterError::Unsupported("Linux helper role is not allowlisted".to_owned())
            })?,
    )
    .map_err(|error| {
        AdapterError::Unavailable(format!(
            "Linux helper target allowlist is unavailable: {error}"
        ))
    })?;
    let requested = fs::canonicalize(&specification.executable).map_err(|error| {
        AdapterError::Invalid(format!("Linux helper target cannot be resolved: {error}"))
    })?;
    if approved != requested {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper target differs from the authorized role path".to_owned(),
        ));
    }
    let (executable_file, executable_fd_path) =
        open_verified_executable(&approved, &specification.executable_sha256)?;
    if let Some(reader) = worker_reader.as_ref() {
        set_worker_reader_blocking(reader)?;
    }
    if worker_reader.is_some() && gateway_health.is_some() {
        return Err(AdapterError::Invalid(
            "Linux worker and Gateway health stdin cannot be combined".to_owned(),
        ));
    }
    let gateway_health_reader = gateway_health.map(gateway_health_stdin).transpose()?;
    let mut command = Command::new(&executable_fd_path);
    command.arg0(&specification.executable);
    command.args(&specification.arguments).env_clear().envs(
        specification
            .environment
            .iter()
            .map(|(name, value)| (name, value)),
    );
    // A worker or Gateway health launch receives its exclusive one-shot
    // bootstrap stream.  Ordinary targets must never inherit the helper's
    // request/GO control stdin; explicitly disconnect it at the exec boundary.
    if let Some(reader) = worker_reader {
        command.stdin(Stdio::from(reader));
    } else if let Some(reader) = gateway_health_reader {
        command.stdin(Stdio::from(reader));
    } else {
        command.stdin(Stdio::null());
    }
    if let Some(path) = specification.working_directory.as_deref() {
        let canonical = fs::canonicalize(path).map_err(|error| {
            AdapterError::Invalid(format!(
                "Linux helper working directory is invalid: {error}"
            ))
        })?;
        command.current_dir(canonical);
    }
    let error = command.exec();
    drop(executable_file);
    Err(AdapterError::Io(format!(
        "Linux target exec failed: {error}"
    )))
}

pub(super) fn gateway_health_stdin(
    bootstrap: &GatewayHealthBootstrap,
) -> Result<File, AdapterError> {
    let (reader, writer) = pipe_with(PipeFlags::CLOEXEC).map_err(|error| {
        AdapterError::Unavailable(format!(
            "Linux Gateway health target stdin pipe cannot be created: {error}"
        ))
    })?;
    let reader = File::from(reader);
    let mut writer = File::from(writer);
    let frame = bootstrap.encoded_frame();
    writer.write_all(frame.as_ref()).map_err(|error| {
        AdapterError::Io(format!(
            "Linux Gateway health target stdin handoff failed: {error}"
        ))
    })?;
    drop(writer);
    Ok(reader)
}
