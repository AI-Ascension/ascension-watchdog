//! Native Windows runtime coverage for the worker bootstrap handoff.
//!
//! The fixture is an ignored libtest entrypoint so the component executable
//! is the same test image as the supervisor.  The parent test still launches
//! it through the real Windows Job Object and worker-pipe path; no synthetic
//! child mode or platform test hook is involved.

#![cfg(windows)]

use super::{ReconcileReport, Supervisor};
use crate::config::{ComponentConfig, DesiredMode, WatchdogConfig, WorkerConfig, hex_digest};
use crate::policy::ComponentState;
use crate::storage::{LaunchIntentState, WorkerBootstrapBinding};
use crate::worker_bootstrap::{
    ExpectedPeer, FRAME_PREFIX_BYTES, MAGIC, MAX_PAYLOAD_BYTES, WorkerBootstrap, decode_frame,
};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

const COMPONENT_ID: &str = "harness";
const FRAME_MARKER: &str = "worker-bootstrap-frame.bin";
const TEMP_FRAME_MARKER: &str = "worker-bootstrap-frame.tmp";

/// Child-side libtest fixture for the native worker startup channel.
///
/// The native launcher writes one complete frame to stdin while this process
/// is suspended.  Read the fixed prefix first, enforce the protocol payload
/// bound before allocating, decode through the watchdog-owned codec, and only
/// then publish a marker in the configured working directory.  The finite
/// sleep gives the parent a live process to stop through its exact Job handle.
#[test]
#[ignore = "native Windows worker bootstrap child fixture"]
fn worker_child_fixture() {
    let mut stdin = std::io::stdin().lock();
    let mut prefix = [0_u8; FRAME_PREFIX_BYTES];
    stdin
        .read_exact(&mut prefix)
        .expect("worker bootstrap prefix must be delivered");
    assert_eq!(&prefix[..MAGIC.len()], MAGIC);

    let payload_length = u32::from_be_bytes([
        prefix[MAGIC.len()],
        prefix[MAGIC.len() + 1],
        prefix[MAGIC.len() + 2],
        prefix[MAGIC.len() + 3],
    ]) as usize;
    assert!(
        (1..=MAX_PAYLOAD_BYTES).contains(&payload_length),
        "worker bootstrap payload must stay within its fixed bound"
    );

    let frame_length = FRAME_PREFIX_BYTES + payload_length;
    let mut frame = vec![0_u8; frame_length];
    frame[..FRAME_PREFIX_BYTES].copy_from_slice(&prefix);
    stdin
        .read_exact(&mut frame[FRAME_PREFIX_BYTES..])
        .expect("worker bootstrap payload must be complete");
    let bootstrap = decode_frame(&frame).expect("worker bootstrap must decode exactly once");
    assert_eq!(bootstrap.component_id, COMPONENT_ID);

    let working_directory = std::env::current_dir().expect("worker fixture working directory");
    let temporary_marker = working_directory.join(TEMP_FRAME_MARKER);
    let marker = working_directory.join(FRAME_MARKER);
    fs::write(&temporary_marker, &frame).expect("worker fixture marker write");
    fs::rename(&temporary_marker, &marker).expect("worker fixture marker publish");

    // Keep the child alive long enough for the parent to observe the marker,
    // inspect the identity binding, and issue an exact owned stop.
    thread::sleep(Duration::from_secs(30));
}

fn runtime_config(directory: &Path, executable: &Path, executable_digest: &str) -> WatchdogConfig {
    WatchdogConfig {
        database: directory.join("watchdog.sqlite3"),
        deployment_id: "windows-worker-runtime-test".to_owned(),
        desired_mode: DesiredMode::Running,
        allow_synthetic_children: false,
        components: vec![ComponentConfig {
            id: COMPONENT_ID.to_owned(),
            executable: executable.to_owned(),
            args: vec![
                "--exact".to_owned(),
                "runtime::runtime_worker_windows_tests::worker_child_fixture".to_owned(),
                "--ignored".to_owned(),
                "--nocapture".to_owned(),
            ],
            cwd: Some(directory.to_owned()),
            environment: BTreeMap::from([(
                "STS2_WORKER_ENDPOINT_NAMESPACE".to_owned(),
                crate::worker_endpoint::WINDOWS_NAMESPACE.to_owned(),
            )]),
            executable_sha256: Some(executable_digest.to_owned()),
            restart: true,
        }],
        worker: Some(WorkerConfig {
            component_id: COMPONENT_ID.to_owned(),
            endpoint_namespace: PathBuf::from(crate::worker_endpoint::WINDOWS_NAMESPACE),
            credential_path: directory.join("worker-credential"),
            allowed_peer_sid: None,
            worker_profile_digest: "b".repeat(64),
            release_digest: "c".repeat(64),
            worker_config_digest: "d".repeat(64),
            schema_digest: crate::worker_protocol::SCHEMA_DIGEST.to_owned(),
            timeout_ms: 5_000,
        }),
        ..WatchdogConfig::default()
    }
}

fn protect_config(path: &Path) -> Result<(), Box<dyn Error>> {
    let status = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            r"
$ErrorActionPreference = 'Stop'
$securityModule = Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1'
Import-Module -Name $securityModule -Force -ErrorAction Stop
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [System.Security.AccessControl.FileSecurity]::new()
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $env:ASCENSION_TEST_CONFIG_PATH -AclObject $acl
            ",
        ])
        .env("ASCENSION_TEST_CONFIG_PATH", path)
        .status()?;
    if !status.success() {
        return Err("PowerShell failed to apply the owner-only config ACL".into());
    }
    Ok(())
}

fn wait_for_frame(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match fs::read(path) {
            Ok(frame) => {
                if decode_frame(&frame).is_ok() {
                    return Ok(frame);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            return Err("worker child did not publish a valid bootstrap frame".into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn assert_controller_binding(
    supervisor: &Supervisor,
    frame: &[u8],
    child_identity: &crate::process::ProcessIdentity,
    binding: &WorkerBootstrapBinding,
) -> Result<(), Box<dyn Error>> {
    let bootstrap: WorkerBootstrap = decode_frame(frame)?;
    assert_eq!(bootstrap.component_id, COMPONENT_ID);
    assert_eq!(
        bootstrap.launch_nonce.to_string(),
        child_identity.launch_nonce
    );
    assert_eq!(
        bootstrap.watchdog_boot_id.to_string(),
        supervisor.worker_boot_id()
    );

    let controller = supervisor
        .windows_controller_identity
        .as_ref()
        .ok_or("supervisor did not retain the controller image identity")?;
    assert_eq!(
        controller.session_id, 0,
        "native worker fixture requires an explicitly authorized session-0 controller"
    );
    let ExpectedPeer::Windows(peer) = &bootstrap.expected_peer else {
        return Err("worker bootstrap did not carry a Windows expected peer".into());
    };
    assert_eq!(peer.pid, controller.pid);
    assert_eq!(
        peer.creation_token,
        controller.creation_time_100ns.to_string()
    );
    assert_eq!(peer.executable, controller.executable.to_string_lossy());
    assert_eq!(peer.executable_sha256, controller.sha256);
    assert_eq!(peer.session_id, controller.session_id);
    assert_eq!(peer.sid, controller.user_sid);
    assert_eq!(child_identity.executable_digest, controller.sha256);
    assert_eq!(binding.watchdog_boot_id, supervisor.worker_boot_id());
    assert_eq!(binding.frame_sha256, hex_digest(frame));
    Ok(())
}

#[test]
#[ignore = "requires an explicitly authorized session-0 controller"]
fn native_worker_runtime_delivers_controller_bound_bootstrap_and_stops_exact_child()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let executable = std::env::current_exe()?;
    let executable_digest = hex_digest(&fs::read(&executable)?);
    let config_path = directory.path().join("watchdog.json");
    let config = runtime_config(directory.path(), &executable, &executable_digest);
    config.to_file(&config_path)?;
    protect_config(&config_path)?;

    // Loading from the protected source is part of the native pre-resume
    // contract.  In particular, this prevents the test from accidentally
    // exercising the source_path-less configuration fallback.
    let config = WatchdogConfig::from_file(&config_path)?;
    assert_eq!(config.source_path.as_deref(), Some(config_path.as_path()));
    assert!(!config.allow_synthetic_children);
    let component = config
        .components
        .first()
        .cloned()
        .ok_or("runtime test configuration has no harness component")?;

    let mut supervisor = Supervisor::initialize(config)?;
    let mut start_report = ReconcileReport::default();
    supervisor.start_component(&component, 1_000, &mut start_report)?;
    assert_eq!(start_report.started, [COMPONENT_ID.to_owned()]);
    assert!(
        start_report.errors.is_empty(),
        "native start reported errors"
    );

    let child_identity = supervisor
        .child_identity(COMPONENT_ID)
        .cloned()
        .ok_or("supervisor did not retain the native child identity")?;
    let binding = supervisor
        .children
        .get(COMPONENT_ID)
        .and_then(|child| child.worker_bootstrap_binding())
        .cloned()
        .ok_or("native worker child has no bootstrap binding")?;
    let frame = wait_for_frame(&directory.path().join(FRAME_MARKER))?;
    assert_controller_binding(&supervisor, &frame, &child_identity, &binding)?;
    let intents = supervisor.store.unsettled_launch_intents()?;
    assert_eq!(intents.len(), 1);
    let durable_binding = supervisor
        .store
        .worker_bootstrap_binding(&intents[0].id)?
        .ok_or("prepared worker bootstrap binding is missing")?;
    assert_eq!(durable_binding, binding);

    // Persist stop intent, then use the exact in-memory RuntimeChild handle;
    // no PID lookup or process-name cleanup is permitted by this assertion.
    supervisor.request_stop(2_000)?;
    let mut stop_report = ReconcileReport::default();
    supervisor.stop_component(&component, 2_001, &mut stop_report)?;
    assert_eq!(stop_report.stopped, [COMPONENT_ID.to_owned()]);
    assert!(stop_report.quarantined.is_empty());
    assert!(supervisor.children.is_empty());
    assert!(supervisor.child_identity(COMPONENT_ID).is_none());
    assert!(supervisor.store.unsettled_launch_intents()?.is_empty());
    let record = supervisor
        .store
        .component(COMPONENT_ID)?
        .ok_or("stopped component record is missing")?;
    assert_eq!(record.state, ComponentState::Stopped);
    assert!(record.pid.is_none());
    assert!(record.launch_nonce.is_none());

    // Drop the SQLite/lock owner before TempDir removes the test directory.
    drop(supervisor);
    drop(directory);
    Ok(())
}

#[test]
#[ignore = "requires an explicitly authorized session-0 controller"]
fn native_worker_launch_rejects_durable_stop_before_resume_and_cleans_exact_job()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let executable = std::env::current_exe()?;
    let executable_digest = hex_digest(&fs::read(&executable)?);
    let config_path = directory.path().join("watchdog.json");
    let config = runtime_config(directory.path(), &executable, &executable_digest);
    config.to_file(&config_path)?;
    protect_config(&config_path)?;
    let config = WatchdogConfig::from_file(&config_path)?;
    let component = config
        .components
        .first()
        .cloned()
        .ok_or("runtime test configuration has no harness component")?;

    let mut supervisor = Supervisor::initialize(config)?;
    let native_config = supervisor.config.clone();
    let status = supervisor.store.status()?;
    let incarnation = super::runtime_incarnation(status.restart_generation)?;
    let launch_nonce = uuid::Uuid::new_v4().to_string();
    let worker = supervisor
        .prepare_worker_bootstrap(&component, &launch_nonce)?
        .ok_or("native worker bootstrap was not prepared")?;
    let specification = super::launch_spec_for(
        &native_config,
        &component,
        launch_nonce.clone(),
        incarnation,
    )?;
    supervisor.process_manager.ensure_ready(&native_config)?;
    let planned_containment = supervisor
        .process_manager
        .planned_containment(&native_config, &specification)?;
    assert_eq!(planned_containment, format!("windows-job:{launch_nonce}"));
    let launch_spec_digest =
        super::launch_spec_binding_digest(&specification, &planned_containment)?;
    let intent = supervisor.store.prepare_launch_intent(
        COMPONENT_ID,
        &launch_nonce,
        &specification.incarnation,
        &launch_spec_digest,
        Some(&planned_containment),
        1_001,
    )?;
    supervisor.bind_prepared_worker_bootstrap(&component, &intent, &worker, 1_002)?;

    // Revoke the durable running authority after the exact intent/frame are
    // prepared but before the native launcher is allowed to resume the child.
    supervisor.request_stop(1_003)?;
    let launch = supervisor.process_manager.launch(
        &native_config,
        &component,
        &specification,
        &planned_containment,
        &intent.id,
        1_004,
        Some(&worker),
    );
    let launch_error = match launch {
        Err(super::runtime_process::RuntimeLaunchError::Ordinary(error)) => error,
        Err(super::runtime_process::RuntimeLaunchError::CleanupUncertain(error)) => {
            return Err(format!("durable stop launch cleanup was uncertain: {error}").into());
        }
        Ok(mut child) => {
            let cleanup = supervisor.process_manager.stop(&mut child);
            return Err(format!(
                "native worker resumed after durable stop; exact cleanup={cleanup:?}"
            )
            .into());
        }
    };
    assert!(
        matches!(
            launch_error,
            crate::error::WatchdogError::IdentityMismatch(_)
        ),
        "native worker launch was not rejected by the pre-resume barrier: {launch_error}"
    );
    assert!(
        launch_error
            .to_string()
            .contains("durable running intent was revoked")
            || launch_error
                .to_string()
                .contains("pre-resume admission rejected"),
        "unexpected durable-stop rejection: {launch_error}"
    );

    let marker = directory.path().join(FRAME_MARKER);
    assert!(
        !marker.exists(),
        "stopped worker must never publish a frame"
    );
    assert!(!directory.path().join(TEMP_FRAME_MARKER).exists());
    assert_eq!(
        supervisor
            .process_manager
            .cleanup_planned_containment(&native_config, &planned_containment)?,
        super::runtime_process::RuntimeStopOutcome::AlreadyExited
    );

    // The direct process-manager call intentionally leaves durable intent
    // cleanup to its caller, just as start_component does after an ordinary
    // launch error. Verify the exact prepared row, then settle it explicitly.
    let intents = supervisor.store.unsettled_launch_intents()?;
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].id, intent.id);
    assert_eq!(intents[0].state, LaunchIntentState::Prepared);
    supervisor.store.clean_launch_intent(&intent.id, 1_005)?;
    assert!(supervisor.store.unsettled_launch_intents()?.is_empty());
    assert!(supervisor.children.is_empty());
    drop(supervisor);
    drop(directory);
    Ok(())
}

/// A workstation controller must not reinterpret the service selector as its
/// desktop session.  This stays enabled on desktop Windows so the production
/// service-session guard has a native, no-effects regression check; an
/// authorized session-0 runner has nothing to reject and is skipped.
#[test]
fn native_worker_runtime_rejects_service_session_from_desktop_without_effects()
-> Result<(), Box<dyn Error>> {
    let controller = ascension_platform_windows::capture_current_controller(
        Instant::now() + Duration::from_secs(5),
    )?;
    if controller.session_id == 0 {
        return Ok(());
    }

    let directory = tempfile::tempdir()?;
    let executable = std::env::current_exe()?;
    let executable_digest = hex_digest(&fs::read(&executable)?);
    let config_path = directory.path().join("watchdog.json");
    let config = runtime_config(directory.path(), &executable, &executable_digest);
    config.to_file(&config_path)?;
    protect_config(&config_path)?;
    let config = WatchdogConfig::from_file(&config_path)?;
    let component = config
        .components
        .first()
        .cloned()
        .ok_or("runtime test configuration has no harness component")?;

    let mut supervisor = Supervisor::initialize(config)?;
    let mut report = ReconcileReport::default();
    supervisor.start_component(&component, 1_000, &mut report)?;
    assert!(report.started.is_empty());
    assert_eq!(report.errors.len(), 1);
    assert!(
        report.errors[0].contains("explicit service session 0 requires a session-0 controller")
    );
    assert!(supervisor.children.is_empty());
    assert!(supervisor.store.unsettled_launch_intents()?.is_empty());
    let record = supervisor
        .store
        .component(COMPONENT_ID)?
        .ok_or("rejected component record is missing")?;
    assert_eq!(record.state, ComponentState::Stopped);
    assert!(record.pid.is_none());
    assert!(record.launch_nonce.is_none());
    assert!(!directory.path().join(FRAME_MARKER).exists());
    assert!(!directory.path().join(TEMP_FRAME_MARKER).exists());
    drop(supervisor);
    drop(directory);
    Ok(())
}
