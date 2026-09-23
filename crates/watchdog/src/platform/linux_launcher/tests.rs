//! Inline unit tests for the Linux launcher module tree.

use super::DELEGATED_CGROUP_ROOT_ARGUMENT;
use super::GATEWAY_HEALTH_PIPE_ARGUMENT;
use super::GO_MAGIC;
use super::HELPER_ARGUMENT;
use super::PARENT_BOOTSTRAP_PID_ARGUMENT;
use super::PROTECTED_CONFIG_ARGUMENT;
use super::executable_snapshot::hash_file;
use super::executable_snapshot::open_verified_executable;
use super::framed_protocol::decode_frame;
use super::framed_protocol::encode_frame;
use super::framed_protocol::open_parent_worker_descriptor;
use super::framed_protocol::put_string_io;
use super::framed_protocol::read_gateway_health_frame;
use super::framed_protocol::read_go_bounded;
use super::framed_protocol::set_nonblocking;
use super::framed_protocol::validate_worker_boot_metadata;
use super::framed_protocol::validate_worker_pipe_handle;
use super::framed_protocol::write_bounded;
use super::framed_protocol::write_gateway_health_frame;
use super::framed_protocol::write_worker_frame;
use super::helper_authorization::LinuxHelperAuthorization;
use super::helper_authorization::LinuxHelperRequest;
use super::helper_authorization::authorize_after_release;
use super::helper_authorization::authorize_request;
use super::helper_authorization::gateway_health_stdin;
use super::parent_launcher::ParentBootstrap;
use super::parent_launcher::PendingLaunch;
use super::parent_launcher::TrustedLinuxLauncher;
use super::protected_bootstrap::LinuxHelperBootstrap;
use super::protected_bootstrap::parse_helper_bootstrap_arguments;
use crate::platform::contract::AdapterError;
use crate::platform::contract::ComponentKind;
use crate::platform::contract::LaunchSpec;
use crate::platform::contract::SessionSelector;
use crate::platform::gateway_health::GatewayHealthBootstrap;
use crate::worker_bootstrap::WorkerBootstrapLaunch;
use rustix::fs::MemfdFlags;
use rustix::fs::OFlags;
use rustix::fs::fcntl_getfl;
use rustix::fs::memfd_create;
use rustix::pipe::PipeFlags;
use rustix::pipe::pipe_with;
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;
use tempfile::tempdir;
use uuid::Uuid;

fn specification() -> LaunchSpec {
    LaunchSpec {
        deployment_id: "deployment".to_owned(),
        instance_id: "instance".to_owned(),
        component: ComponentKind::Synthetic,
        incarnation: "incarnation".to_owned(),
        launch_nonce: "nonce-1".to_owned(),
        executable: PathBuf::from("/bin/true"),
        executable_sha256: "a".repeat(64),
        arguments: vec!["--fixture".to_owned()],
        working_directory: None,
        environment: vec![("PATH".to_owned(), "/usr/bin".to_owned())],
        session: SessionSelector::Explicit(0),
        graceful_timeout: Duration::from_secs(1),
        force_timeout: Duration::from_secs(2),
    }
}

#[test]
fn frame_round_trip_preserves_exact_spec_and_cgroup() -> Result<(), Box<dyn std::error::Error>> {
    let specification = specification();
    let path = PathBuf::from("/sys/fs/cgroup/ascension-test");
    let frame = encode_frame(&specification, &path)?;
    let payload_length = u32::from_le_bytes(frame[..4].try_into()?);
    assert_eq!(usize::try_from(payload_length)?, frame.len() - 4);
    let request = decode_frame(&frame[4..])?;
    assert_eq!(request.specification, specification);
    assert_eq!(request.cgroup_path, path);
    Ok(())
}

#[test]
fn wrong_nonce_go_is_rejected_before_target_spawn() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(GO_MAGIC);
    assert!(put_string_io(&mut bytes, "wrong").is_ok());
    let mut cursor = Cursor::new(bytes);
    let result = read_go_bounded(&mut cursor, Duration::from_secs(1));
    assert_eq!(result.as_deref(), Ok("wrong"));
    assert_ne!(result.as_deref(), Ok("nonce-1"));
}

#[test]
fn eof_before_go_is_a_hard_failure() {
    let mut cursor = Cursor::new(Vec::<u8>::new());
    assert!(matches!(
        read_go_bounded(&mut cursor, Duration::from_secs(1)),
        Err(AdapterError::Unavailable(_))
    ));
}

#[test]
fn unsupported_component_cannot_be_authorized() {
    let mut specification = specification();
    specification.component = ComponentKind::HostBroker;
    let authorization = LinuxHelperAuthorization {
        specification,
        cgroup_path: PathBuf::from("/sys/fs/cgroup/ascension-test"),
        allowlisted_executables: BTreeMap::new(),
    };
    assert!(matches!(
        authorization.validate(),
        Err(AdapterError::Unsupported(_))
    ));
}

#[test]
fn durable_authorization_mismatch_is_rejected_before_hashing() {
    let specification = specification();
    let request = LinuxHelperRequest {
        specification: specification.clone(),
        cgroup_path: PathBuf::from("/sys/fs/cgroup/ascension-test"),
    };
    let mut authorized = specification;
    authorized.launch_nonce = "different-nonce".to_owned();
    let mut allowlist = BTreeMap::new();
    allowlist.insert(ComponentKind::Synthetic, PathBuf::from("/bin/true"));
    let authorization = LinuxHelperAuthorization {
        specification: authorized,
        cgroup_path: request.cgroup_path.clone(),
        allowlisted_executables: allowlist,
    };
    assert!(matches!(
        authorize_request(&request, &authorization),
        Err(AdapterError::IdentityMismatch(_))
    ));
}

#[test]
fn timeout_is_bounded() {
    let result = TrustedLinuxLauncher::new("/bin/true")
        .and_then(|launcher| launcher.with_timeout(Duration::from_secs(16)));
    assert!(result.is_err());
}

#[test]
fn bootstrap_reads_the_opened_config_inode_after_path_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir()?;
    let path = directory.path().join("watchdog.json");
    fs::write(&path, b"trusted-config")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let bootstrap = LinuxHelperBootstrap::new(&path)?;

    fs::rename(&path, directory.path().join("watchdog.json.original"))?;
    fs::write(&path, b"attacker-config")?;

    let mut bytes = String::new();
    bootstrap
        .protected_config_file()?
        .read_to_string(&mut bytes)?;
    assert_eq!(bytes, "trusted-config");
    Ok(())
}

#[test]
fn bootstrap_rejects_group_readable_or_foreign_shape_config()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir()?;
    let path = directory.path().join("watchdog.json");
    fs::write(&path, b"config")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
    assert!(matches!(
        LinuxHelperBootstrap::new(&path),
        Err(AdapterError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn parent_bootstrap_handles_remain_cloexec_and_invisible_to_target()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir()?;
    let config_path = directory.path().join("watchdog.json");
    fs::write(&config_path, b"trusted-config")?;
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))?;
    let root_path = directory.path().join("cgroup");
    fs::create_dir(&root_path)?;
    fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700))?;
    for control in ["cgroup.procs", "cgroup.events", "cgroup.kill"] {
        fs::write(root_path.join(control), b"")?;
    }

    let bootstrap =
        LinuxHelperBootstrap::new(&config_path)?.with_delegated_cgroup_root(&root_path)?;
    let parent = bootstrap.parent_descriptors(None, None)?;
    assert!(rustix::io::fcntl_getfd(&parent.config)?.contains(rustix::io::FdFlags::CLOEXEC));
    assert!(rustix::io::fcntl_getfd(&parent.root)?.contains(rustix::io::FdFlags::CLOEXEC));
    assert!(rustix::io::fcntl_getfd(&parent.ready)?.contains(rustix::io::FdFlags::CLOEXEC));

    let status = Command::new("/bin/sh")
        .args([
            "-c",
            "test ! -e /proc/self/fd/$1 && test ! -e /proc/self/fd/$2 && test ! -e /proc/self/fd/$3",
            "fd-check",
            &parent.config_fd.to_string(),
            &parent.root_fd.to_string(),
            &parent.ready_fd.to_string(),
        ])
        .status()?;
    assert!(status.success(), "target observed a parent bootstrap fd");
    Ok(())
}

#[test]
fn parent_bootstrap_drop_closes_keepalive_descriptors() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir()?;
    let config_path = directory.path().join("watchdog.json");
    fs::write(&config_path, b"trusted-config")?;
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))?;
    let root_path = directory.path().join("cgroup");
    fs::create_dir(&root_path)?;
    fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700))?;
    for control in ["cgroup.procs", "cgroup.events", "cgroup.kill"] {
        fs::write(root_path.join(control), b"")?;
    }

    let bootstrap =
        LinuxHelperBootstrap::new(&config_path)?.with_delegated_cgroup_root(&root_path)?;
    let identities = {
        let parent = bootstrap.parent_descriptors(None, None)?;
        let mut identities = Vec::new();
        for (file, fd) in [
            (&parent.config, parent.config_fd),
            (&parent.root, parent.root_fd),
            (&parent.ready, parent.ready_fd),
        ] {
            let metadata = file.metadata()?;
            identities.push((fd, metadata.dev(), metadata.ino()));
        }
        identities
    };
    for (fd, device, inode) in identities {
        // Parallel tests may immediately reuse a released descriptor number.
        // Only retaining the original unique resource indicates a leaked handle.
        match fs::metadata(format!("/proc/self/fd/{fd}")) {
            Ok(replacement) => assert_ne!(
                (replacement.dev(), replacement.ino()),
                (device, inode),
                "original bootstrap resource remains open at descriptor {fd}"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[test]
fn delayed_helper_ready_ack_keeps_parent_descriptor_alive() -> Result<(), Box<dyn std::error::Error>>
{
    let ready = File::from(memfd_create("ascension-ready-test", MemfdFlags::CLOEXEC)?);
    let ready_fd = ready.as_raw_fd();
    let mut parent = ParentBootstrap {
        config: File::open("/dev/null")?,
        config_fd: 0,
        root: File::open("/dev/null")?,
        root_fd: 1,
        ready,
        ready_fd,
        worker_reader: None,
        worker_reader_fd: None,
        worker_writer: None,
        gateway_health_reader: None,
        gateway_health_reader_fd: None,
        gateway_health_writer: None,
    };
    let mut delayed_helper = Command::new("/bin/sh")
        .args([
            "-c",
            "sleep 0.05; printf 'ASC-RDY1\\001\\000x' > /proc/$PPID/fd/$1",
            "delayed-helper",
            &ready_fd.to_string(),
        ])
        .spawn()?;
    let started = Instant::now();
    parent.wait_for_ready("x", Duration::from_secs(1))?;
    assert!(started.elapsed() >= Duration::from_millis(30));
    assert!(delayed_helper.wait()?.success());
    Ok(())
}

#[test]
fn readiness_ack_rejects_trailing_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let mut ready = File::from(memfd_create("ascension-ready-extra", MemfdFlags::CLOEXEC)?);
    ready.write_all(b"ASC-RDY1\x01\x00xextra")?;
    let mut parent = ParentBootstrap {
        config: File::open("/dev/null")?,
        config_fd: 0,
        root: File::open("/dev/null")?,
        root_fd: 1,
        ready_fd: ready.as_raw_fd(),
        ready,
        worker_reader: None,
        worker_reader_fd: None,
        worker_writer: None,
        gateway_health_reader: None,
        gateway_health_reader_fd: None,
        gateway_health_writer: None,
    };
    assert!(matches!(
        parent.wait_for_ready("x", Duration::from_millis(10)),
        Err(AdapterError::IdentityMismatch(_))
    ));
    Ok(())
}

#[test]
fn descriptor_bound_exec_is_not_redirected_by_path_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("approved-target");
    fs::copy("/bin/true", &path)?;
    let digest = hash_file(&path)?;
    let (file, fd_path) = open_verified_executable(&path, &digest)?;

    let moved = directory.path().join("approved-target.original");
    fs::rename(&path, &moved)?;
    fs::copy("/bin/false", &path)?;
    let status = Command::new(&fd_path).status()?;

    assert!(
        status.success(),
        "descriptor exec followed the replaced path"
    );
    drop(file);
    Ok(())
}

#[test]
fn sealed_snapshot_is_not_changed_by_in_place_mutation() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("approved-target");
    fs::copy("/bin/true", &path)?;
    let digest = hash_file(&path)?;
    let (file, fd_path) = open_verified_executable(&path, &digest)?;

    let replacement = fs::read("/bin/false")?;
    fs::write(&path, replacement)?;
    let status = Command::new(&fd_path).status()?;

    assert!(
        status.success(),
        "sealed snapshot followed in-place mutation"
    );
    drop(file);
    Ok(())
}

#[test]
fn special_file_is_rejected_before_reading() {
    let result = open_verified_executable(Path::new("/dev/null"), &"0".repeat(64));
    assert!(matches!(result, Err(AdapterError::Invalid(_))));
}

#[test]
fn descriptor_bound_exec_rejects_changed_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("approved-target");
    fs::copy("/bin/true", &path)?;
    let result = open_verified_executable(&path, &"0".repeat(64));
    assert!(matches!(result, Err(AdapterError::IdentityMismatch(_))));
    Ok(())
}

#[test]
fn release_barrier_precedes_durable_authorization() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let request = LinuxHelperRequest {
        specification: specification(),
        cgroup_path: PathBuf::from("/sys/fs/cgroup/ascension-test"),
    };
    let stopped = Arc::new(AtomicBool::new(false));
    let nonce = request.specification.launch_nonce.clone();
    // Models durable stop becoming visible before the parent's GO.
    stopped.store(true, Ordering::Release);
    let mut go = Vec::new();
    go.extend_from_slice(GO_MAGIC);
    put_string_io(&mut go, &nonce).unwrap();
    let mut cursor = Cursor::new(go);
    let result = authorize_after_release(&request, &mut cursor, Instant::now(), |_| {
        assert!(stopped.load(Ordering::Acquire));
        Err(AdapterError::Unavailable(
            "durable stop denies launch".to_owned(),
        ))
    });
    assert!(
        matches!(result, Err(AdapterError::Unavailable(message)) if message == "durable stop denies launch")
    );
}

#[test]
fn wrong_release_nonce_never_queries_authority() {
    let request = LinuxHelperRequest {
        specification: specification(),
        cgroup_path: PathBuf::from("/sys/fs/cgroup/ascension-test"),
    };
    let mut go = Vec::new();
    go.extend_from_slice(GO_MAGIC);
    put_string_io(&mut go, "stale-nonce").unwrap();
    let mut cursor = Cursor::new(go);
    let mut queried = false;
    let result = authorize_after_release(&request, &mut cursor, Instant::now(), |_| {
        queried = true;
        Err(AdapterError::Unavailable(
            "must not reach authority".to_owned(),
        ))
    });
    assert!(matches!(result, Err(AdapterError::IdentityMismatch(_))));
    assert!(!queried);
}

#[test]
fn worker_bootstrap_launch_keeps_exact_frame_and_digest() {
    let peer = crate::worker_bootstrap::LinuxPeer::new(1, "1", "/bin/true", "a".repeat(64), 0, 0)
        .expect("valid Linux peer");
    let bootstrap = crate::worker_bootstrap::WorkerBootstrap::linux(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "harness",
        peer,
    )
    .expect("valid worker bootstrap");
    let launch = WorkerBootstrapLaunch::new(bootstrap).expect("encodable worker bootstrap");
    assert_eq!(
        launch.frame_sha256(),
        crate::config::hex_digest(launch.frame())
    );
    assert_eq!(launch.bootstrap().component_id, "harness");
}

#[test]
fn worker_bootstrap_identity_mismatch_is_rejected_before_spawn()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = Uuid::new_v4();
    let peer = crate::worker_bootstrap::LinuxPeer::new(1, "1", "/bin/true", "a".repeat(64), 0, 0)?;
    let frame =
        crate::worker_bootstrap::WorkerBootstrap::linux(nonce, Uuid::new_v4(), "harness", peer)?;
    let worker = WorkerBootstrapLaunch::new(frame)?;
    let launcher = TrustedLinuxLauncher::new("/bin/true")?;
    let mut spec = specification();
    spec.component = ComponentKind::Harness;
    spec.instance_id = "harness".to_owned();
    spec.launch_nonce = Uuid::new_v4().to_string();
    assert!(matches!(
        launcher.prepare_with_worker_bootstrap(&spec, Path::new("/unused"), &worker),
        Err(AdapterError::IdentityMismatch(_))
    ));
    spec.launch_nonce = nonce.to_string();
    spec.instance_id = "different".to_owned();
    assert!(matches!(
        launcher.prepare_with_worker_bootstrap(&spec, Path::new("/unused"), &worker),
        Err(AdapterError::IdentityMismatch(_))
    ));
    spec.instance_id = "harness".to_owned();
    assert!(matches!(
        launcher.prepare_with_worker_bootstrap(&spec, Path::new("/unused"), &worker),
        Err(AdapterError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn worker_pipe_is_nonblocking_cloexec_and_writes_exact_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let (reader_fd, writer_fd) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)?;
    let mut reader = File::from(reader_fd);
    let mut writer = File::from(writer_fd);
    assert!(rustix::io::fcntl_getfd(&reader)?.contains(rustix::io::FdFlags::CLOEXEC));
    assert!(rustix::io::fcntl_getfd(&writer)?.contains(rustix::io::FdFlags::CLOEXEC));
    assert!(fcntl_getfl(&writer)?.contains(OFlags::NONBLOCK));
    let frame = b"ASC-WB01-worker-frame";
    write_worker_frame(&mut writer, frame, Duration::from_secs(1))?;
    drop(writer);
    let mut received = Vec::new();
    reader.read_to_end(&mut received)?;
    assert_eq!(received, frame);
    Ok(())
}

#[test]
fn helper_request_write_is_bounded_when_child_does_not_read()
-> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new("/bin/sleep")
        .arg("30")
        .stdin(Stdio::piped())
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("sleep child did not expose stdin"))?;
    set_nonblocking(&stdin, "test helper stdin")?;
    let started = Instant::now();
    let result = write_bounded(
        &mut stdin,
        &vec![0_u8; 4 * 1024 * 1024],
        Duration::from_millis(30),
        "test helper request",
    );
    let _ = child.kill();
    let _ = child.wait();
    assert!(matches!(result, Err(AdapterError::Timeout(_))));
    assert!(started.elapsed() < Duration::from_millis(500));
    Ok(())
}

#[test]
fn worker_pipe_rejects_regular_descriptors_and_bad_metadata() {
    assert!(matches!(
        validate_worker_pipe_handle(&File::open("/dev/null").expect("/dev/null")),
        Err(AdapterError::Invalid(_))
    ));
    let boot_id = Uuid::new_v4().to_string();
    assert!(validate_worker_boot_metadata(&boot_id, &"a".repeat(64)).is_ok());
    assert!(validate_worker_boot_metadata(&boot_id.to_uppercase(), &"a".repeat(64)).is_err());
    assert!(validate_worker_boot_metadata(&boot_id, &"A".repeat(64)).is_err());
    assert!(
        validate_worker_boot_metadata("12345678-1234-4234-7234-123456789abc", &"a".repeat(64))
            .is_err()
    );
}

fn gateway_specification(nonce: Uuid) -> LaunchSpec {
    let mut specification = specification();
    specification.component = ComponentKind::Gateway;
    specification.launch_nonce = nonce.to_string();
    specification
}

#[test]
fn gateway_health_pipe_is_nonblocking_cloexec_and_exact() -> Result<(), Box<dyn std::error::Error>>
{
    let nonce = Uuid::new_v4();
    let bootstrap =
        GatewayHealthBootstrap::new(nonce, [0x5a_u8; 32]).expect("valid Gateway health bootstrap");
    let expected = bootstrap.encoded_frame();
    let (reader, writer) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)?;
    let mut reader = File::from(reader);
    let mut writer = File::from(writer);
    assert!(rustix::io::fcntl_getfd(&reader)?.contains(rustix::io::FdFlags::CLOEXEC));
    assert!(rustix::io::fcntl_getfd(&writer)?.contains(rustix::io::FdFlags::CLOEXEC));
    assert!(fcntl_getfl(&reader)?.contains(OFlags::NONBLOCK));
    assert!(fcntl_getfl(&writer)?.contains(OFlags::NONBLOCK));
    write_gateway_health_frame(&mut writer, expected.as_ref(), Duration::from_secs(1))?;
    drop(writer);
    let request = LinuxHelperRequest {
        specification: gateway_specification(nonce),
        cgroup_path: PathBuf::from("/sys/fs/cgroup/ascension-test"),
    };
    let decoded = read_gateway_health_frame(&mut reader, &request, Duration::from_secs(1))?;
    assert!(decoded == bootstrap);
    assert_eq!(decoded.encoded_frame().as_ref(), expected.as_ref());
    Ok(())
}

#[test]
fn gateway_health_pipe_rejects_trailing_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let nonce = Uuid::new_v4();
    let bootstrap =
        GatewayHealthBootstrap::new(nonce, [0x5a_u8; 32]).expect("valid Gateway health bootstrap");
    let (reader, writer) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)?;
    let mut reader = File::from(reader);
    let mut writer = File::from(writer);
    let frame = bootstrap.encoded_frame();
    writer.write_all(frame.as_ref())?;
    writer.write_all(b"extra")?;
    drop(writer);
    let request = LinuxHelperRequest {
        specification: gateway_specification(nonce),
        cgroup_path: PathBuf::from("/sys/fs/cgroup/ascension-test"),
    };
    assert!(matches!(
        read_gateway_health_frame(&mut reader, &request, Duration::from_secs(1)),
        Err(AdapterError::Invalid(message))
            if message.contains("trailing bytes")
    ));
    Ok(())
}

#[test]
fn gateway_health_frame_reaches_exclusive_target_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let bootstrap = GatewayHealthBootstrap::new(Uuid::new_v4(), [0x2a_u8; 32])
        .expect("valid Gateway health bootstrap");
    let expected = bootstrap.encoded_frame();
    let reader = gateway_health_stdin(&bootstrap)?;
    assert!(rustix::io::fcntl_getfd(&reader)?.contains(rustix::io::FdFlags::CLOEXEC));
    let output = Command::new("/bin/cat")
        .stdin(Stdio::from(reader))
        .output()?;
    assert!(output.status.success());
    assert_eq!(output.stdout, expected.as_ref());
    Ok(())
}

#[test]
fn health_helper_argument_grammar_rejects_trailing_values() {
    let result = parse_helper_bootstrap_arguments(
        [
            "watchdog".to_owned(),
            HELPER_ARGUMENT.to_owned(),
            PARENT_BOOTSTRAP_PID_ARGUMENT.to_owned(),
            "1".to_owned(),
            PROTECTED_CONFIG_ARGUMENT.to_owned(),
            "3".to_owned(),
            DELEGATED_CGROUP_ROOT_ARGUMENT.to_owned(),
            "4".to_owned(),
            "5".to_owned(),
            GATEWAY_HEALTH_PIPE_ARGUMENT.to_owned(),
            "6".to_owned(),
            "unexpected".to_owned(),
        ]
        .into_iter(),
    );
    assert!(matches!(
        result,
        Err(AdapterError::Invalid(message))
            if message == "Linux helper invocation has unexpected arguments"
    ));
}

#[test]
fn pre_admission_control_failure_retains_child_for_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir()?;
    let marker = directory.path().join("stdin-closed");
    let marker = marker.to_string_lossy().replace('\'', "'\\''");
    let helper = directory.path().join("helper.sh");
    fs::write(
        &helper,
        format!("#!/bin/sh\nexec 0<&-\nprintf ready > '{marker}'\nexec sleep 30\n"),
    )?;
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700))?;
    // Snapshot the native interpreter, not a shebang script: the sealed
    // executable descriptor deliberately closes at exec, so an interpreter
    // cannot reopen a script through that descriptor afterward.
    let mut launcher =
        TrustedLinuxLauncher::new("/bin/sh")?.with_timeout(Duration::from_secs(1))?;
    launcher.helper_argument = helper.to_string_lossy().into_owned();
    let mut pending = launcher.prepare(&specification(), Path::new("/sys/fs/cgroup/test"))?;

    let deadline = Instant::now() + Duration::from_secs(1);
    while !directory.path().join("stdin-closed").exists() {
        assert!(
            Instant::now() < deadline,
            "helper did not close stdin in time"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(pending.child_mut().is_some());
    let started = Instant::now();
    let result = pending.release_gate();
    assert!(matches!(result, Err(AdapterError::Io(_))));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(pending.child_mut().is_some());
    Ok(())
}

#[test]
fn into_child_missing_handle_is_fallible_without_panicking() {
    let mut pending = PendingLaunch {
        child: None,
        request_frame: None,
        stdin: None,
        parent_bootstrap: None,
        worker_writer: None,
        worker_launch: None,
        gateway_health_writer: None,
        gateway_health_frame: None,
        launch_nonce: "nonce".to_owned(),
        timeout: Duration::from_secs(1),
        released: true,
    };
    assert!(matches!(
        pending.take_child(),
        Err(AdapterError::Unavailable(message))
            if message == "Linux helper child handle was lost"
    ));
}

#[test]
fn expired_worker_write_cannot_emit_even_immediately_available_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let (reader, writer) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)?;
    let mut reader = File::from(reader);
    let mut writer = File::from(writer);
    assert!(matches!(
        write_worker_frame(&mut writer, b"frame", Duration::ZERO),
        Err(AdapterError::Timeout(_))
    ));
    let mut byte = [0_u8; 1];
    assert_eq!(
        reader
            .read(&mut byte)
            .expect_err("no bytes admitted")
            .kind(),
        io::ErrorKind::WouldBlock
    );
    Ok(())
}

#[test]
fn stalled_worker_reader_cannot_extend_write_deadline() -> Result<(), Box<dyn std::error::Error>> {
    let (reader, writer) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)?;
    let _reader = File::from(reader);
    let mut writer = File::from(writer);
    let mut saturated = false;
    for _ in 0..1024 {
        match writer.write(&[0_u8; 4096]) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                saturated = true;
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    assert!(saturated, "test pipe must reach backpressure");
    let start = Instant::now();
    assert!(matches!(
        write_worker_frame(&mut writer, b"frame", Duration::from_millis(20)),
        Err(AdapterError::Timeout(_))
    ));
    assert!(start.elapsed() < Duration::from_secs(2));
    Ok(())
}

#[test]
fn helper_reader_duplicate_is_anonymous_cloexec_and_independently_owned()
-> Result<(), Box<dyn std::error::Error>> {
    const ISOLATED: &str = "ASCENSION_TEST_ISOLATED_READER_OWNERSHIP";
    if std::env::var_os(ISOLATED).is_none() {
        // CLOEXEC closes descriptors at exec, not at fork. Other tests spawn
        // processes concurrently, which can briefly retain this test's read
        // end and invalidate an immediate EPIPE assertion. Run the ownership
        // assertions in a process with no concurrent tests or child launches.
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "platform::linux_launcher::tests::helper_reader_duplicate_is_anonymous_cloexec_and_independently_owned",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(ISOLATED, "1")
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait()? {
                assert!(status.success(), "isolated ownership test failed: {status}");
                return Ok(());
            }
            if Instant::now() >= deadline {
                child.kill()?;
                child.wait()?;
                return Err("isolated ownership test exceeded deadline".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let (reader, writer) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)?;
    let reader = File::from(reader);
    let mut writer = File::from(writer);
    let mut duplicate = open_parent_worker_descriptor(std::process::id(), reader.as_raw_fd())?;
    assert!(rustix::io::fcntl_getfd(&duplicate)?.contains(rustix::io::FdFlags::CLOEXEC));
    drop(reader);
    write_worker_frame(&mut writer, b"frame", Duration::from_secs(1))?;
    let mut bytes = [0_u8; 5];
    duplicate.read_exact(&mut bytes)?;
    assert_eq!(&bytes, b"frame");
    drop(duplicate);
    assert_eq!(
        writer
            .write(b"frame")
            .expect_err("all readers closed")
            .kind(),
        io::ErrorKind::BrokenPipe
    );
    Ok(())
}

#[test]
fn malformed_bare_helper_invocation_requires_parent_bootstrap() {
    let result = parse_helper_bootstrap_arguments(
        ["watchdog".to_owned(), HELPER_ARGUMENT.to_owned()].into_iter(),
    );
    assert!(matches!(
        result,
        Err(AdapterError::Invalid(message))
            if message == "Linux helper parent bootstrap process identifier is missing"
    ));
}

#[test]
fn unprotected_helper_mode_still_requires_exact_parent_prefix() {
    let result = parse_helper_bootstrap_arguments(
        [
            "watchdog".to_owned(),
            HELPER_ARGUMENT.to_owned(),
            PARENT_BOOTSTRAP_PID_ARGUMENT.to_owned(),
            "1".to_owned(),
        ]
        .into_iter(),
    );
    assert!(matches!(result, Ok(None)));
}
