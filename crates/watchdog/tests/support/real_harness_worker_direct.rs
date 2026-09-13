// SPDX-License-Identifier: MIT

//! Real authenticated peer exercise; only the downstream gateway/MCP are fixtures.

use super::real_harness_worker_fixture::{Fixture, copy_immutable_image, hash_regular_file};
use ascension_watchdog::config::WatchdogConfig;
use ascension_watchdog::storage::{
    Store, WORKER_HANDOFF_OPERATION, WorkerBinding, WorkerClaimWitness, WorkerHandoffState,
};
use ascension_watchdog::worker_bootstrap::{LinuxPeer, WorkerBootstrap, encode_frame};
use ascension_watchdog::worker_client::{WorkerClient, WorkerClientConfig, WorkerPeerIdentity};
use ascension_watchdog::worker_endpoint::{EndpointPlatform, resolve};
use ascension_watchdog::worker_protocol::{ControlScope, WorkerMode};
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid};
use std::fs;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn timed_out_owned_group_is_stopped_before_reap() -> TestResult {
    let mut command = Command::new("/bin/sleep");
    command
        .arg("30")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = ChildGuard {
        child: Some(command.spawn()?),
        group: true,
    };
    assert!(child.wait(Duration::from_millis(10)).is_err());
    assert!(!child.finish()?.success());
    assert!(child.child.is_none());
    Ok(())
}

fn require_gate(name: &str) -> TestResult {
    if std::env::var(name).as_deref() != Ok("1") {
        return Err(io::Error::other(format!("{name}=1 is required")).into());
    }
    Ok(())
}

/// Hold the child unreaped until its owned group is cleaned; never signal a
/// recycled PID/group. The outer controller group also contains runtime children.
struct ChildGuard {
    child: Option<Child>,
    group: bool,
}

impl ChildGuard {
    fn child(&mut self) -> TestResult<&mut Child> {
        self.child
            .as_mut()
            .ok_or_else(|| io::Error::other("child already reaped").into())
    }

    fn finish(&mut self) -> TestResult<ExitStatus> {
        let child = self.child()?;
        let pid = Pid::from_child(child);
        if self.group {
            kill_process_group(pid, Signal::KILL).or_else(|error| {
                if error == rustix::io::Errno::SRCH {
                    Ok(())
                } else {
                    Err(error)
                }
            })?;
        } else {
            // This remains our unreaped direct child, including on failure.
            self.child()?.kill()?;
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        )?
        .is_none()
        {
            if Instant::now() >= deadline {
                return Err(io::Error::other("child cleanup deadline expired").into());
            }
            thread::sleep(Duration::from_millis(20));
        }
        if self.group {
            verify_group_stopped(pid.as_raw_nonzero().get())?;
        }
        // waitid observed exit without reaping, so wait cannot await execution.
        let status = self.child()?.wait()?;
        self.child = None;
        Ok(status)
    }

    fn wait(&mut self, timeout: Duration) -> TestResult<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            let exited = waitid(
                WaitId::Pid(Pid::from_child(self.child()?)),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            )?
            .is_some();
            if exited {
                return self.finish();
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other("direct worker test deadline expired").into());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

fn verify_group_stopped(group: i32) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut live = false;
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
                continue;
            }
            let stat = match fs::read_to_string(entry.path().join("stat")) {
                Ok(stat) => stat,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            let close = stat
                .rfind(')')
                .ok_or_else(|| io::Error::other("invalid process stat"))?;
            let fields: Vec<_> = stat[close + 2..].split_whitespace().collect();
            if fields.get(2).and_then(|value| value.parse::<i32>().ok()) == Some(group)
                && !matches!(fields.first(), Some(&"Z" | &"X"))
            {
                live = true;
            }
        }
        if !live {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other("owned group still has live processes").into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.finish();
        }
    }
}

pub(super) fn run_controller_reexec(
    gate: &str,
    controller_gate: &str,
    binary_env: &str,
    digest_env: &str,
) -> TestResult {
    require_gate(gate)?;
    let directory = tempfile::tempdir()?;
    let controller = directory.path().join("controller");
    let source = std::env::current_exe()?;
    copy_immutable_image(&source, &controller, &hash_regular_file(&source)?.0)?;
    let mut command = Command::new(&controller);
    command
        .args([
            "--ignored",
            "--exact",
            "real_watchdog_direct_controller",
            "--nocapture",
        ])
        .env_clear()
        .env(gate, "1")
        .env(controller_gate, "1")
        .env(
            binary_env,
            std::env::var_os(binary_env)
                .ok_or_else(|| io::Error::other("pinned harness path required"))?,
        )
        .env(
            digest_env,
            std::env::var_os(digest_env)
                .ok_or_else(|| io::Error::other("pinned harness digest required"))?,
        )
        .stdin(Stdio::null())
        .process_group(0);
    if let Some(temp) = std::env::var_os("TMPDIR") {
        command.env("TMPDIR", temp);
    }
    let mut controller = ChildGuard {
        child: Some(command.spawn()?),
        group: true,
    };
    let status = controller.wait(Duration::from_secs(90))?;
    if !status.success() {
        return Err(io::Error::other("immutable direct controller failed").into());
    }
    Ok(())
}

fn start_token(pid: u32) -> TestResult<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let close = stat
        .rfind(')')
        .ok_or_else(|| io::Error::other("invalid process stat"))?;
    stat[close + 2..]
        .split_whitespace()
        .nth(19)
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("missing process creation token").into())
}

pub(super) fn run_controller(
    gate: &str,
    controller_gate: &str,
    _binary_env: &str,
    _digest_env: &str,
) -> TestResult {
    require_gate(gate)?;
    require_gate(controller_gate)?;
    if rustix::process::getpgrp().as_raw_nonzero().get() != i32::try_from(std::process::id())? {
        return Err(io::Error::other("controller must lead its test-owned process group").into());
    }
    let mut fixture = Fixture::from_environment()?;
    let config = WatchdogConfig::from_file(fixture.config_path())?;
    let component = config
        .components
        .first()
        .ok_or_else(|| io::Error::other("missing component"))?;
    let worker = config
        .worker
        .as_ref()
        .ok_or_else(|| io::Error::other("missing worker"))?;
    let nonce = Uuid::new_v4();
    let watchdog_boot = Uuid::new_v4();
    let image = fs::canonicalize(std::env::current_exe()?)?;
    let bootstrap = WorkerBootstrap::linux(
        nonce,
        watchdog_boot,
        &component.id,
        LinuxPeer::new(
            std::process::id(),
            start_token(std::process::id())?,
            image
                .to_str()
                .ok_or_else(|| io::Error::other("controller path not UTF-8"))?,
            hash_regular_file(&image)?.0,
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        )?,
    )?;
    let endpoint = PathBuf::from(resolve(
        EndpointPlatform::Linux,
        worker
            .endpoint_namespace
            .to_str()
            .ok_or_else(|| io::Error::other("namespace not UTF-8"))?,
        &nonce.to_string(),
    )?);
    let mut command = Command::new(&component.executable);
    command
        .args(&component.args)
        .env_clear()
        .envs(&component.environment)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(cwd) = &component.cwd {
        command.current_dir(cwd);
    }
    let mut child = ChildGuard {
        child: Some(command.spawn()?),
        group: false,
    };
    let mut stdin = child
        .child()?
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("bootstrap pipe absent"))?;
    stdin.write_all(&encode_frame(&bootstrap)?)?;
    drop(stdin);
    let pid = child.child()?.id();
    let peer = WorkerPeerIdentity::new(
        &component.executable,
        &worker.release_digest,
        pid,
        start_token(pid)?,
    )?
    .with_peer_credentials(
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    )?;
    let binding = WorkerBinding {
        deployment_id: config.deployment_id.clone(),
        worker_owner_id: component.id.clone(),
        worker_profile_digest: worker.worker_profile_digest.clone(),
        release_digest: worker.release_digest.clone(),
        config_digest: worker.worker_config_digest.clone(),
        schema_digest: worker.schema_digest.clone(),
    };
    let client = WorkerClient::new(
        WorkerClientConfig::new(&endpoint, &worker.credential_path, binding.clone(), peer)?,
        watchdog_boot.to_string(),
    )?;
    exercise_protocol(&client, &config, &binding, &mut child)?;
    // The failed child has been reaped. Outer group cleanup also owns any
    // remaining descendants; fixture removal is not native service evidence.
    fixture.mark_cleanup_verified();
    println!(
        "Real peer authenticated and dispatched once; failed peer cannot acknowledge or redispatch."
    );
    Ok(())
}

fn exercise_protocol(
    client: &WorkerClient,
    config: &WatchdogConfig,
    binding: &WorkerBinding,
    child: &mut ChildGuard,
) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(15);
    let probe = loop {
        match client.probe() {
            Ok(probe) => break probe,
            Err(error) if Instant::now() >= deadline => return Err(error.into()),
            Err(_) => thread::sleep(Duration::from_millis(25)),
        }
    };
    let worker_boot = probe
        .header
        .worker_boot_id
        .ok_or_else(|| io::Error::other("worker boot absent"))?;
    let mut store = Store::initialize(&config.database, config)?;
    store.configure_worker_binding_at(binding, 1)?;
    let scope = |mode, mode_sequence| ControlScope {
        deployment_id: binding.deployment_id.clone(),
        worker_owner_id: binding.worker_owner_id.clone(),
        worker_profile_digest: binding.worker_profile_digest.clone(),
        mode,
        mode_sequence,
    };
    let control = client.set_control_mode_and_persist(
        &mut store,
        &worker_boot,
        scope(WorkerMode::Running, 1),
        2,
    )?;
    // A read-only probe never grants admission; `ready` reflects the durable
    // authenticated control state, while the wire `admitting` flag stays false.
    let running_probe = client.probe()?;
    assert!(running_probe.ready);
    assert!(!running_probe.admitting);
    let job = store.submit_job_at(WORKER_HANDOFF_OPERATION, &serde_json::json!({}), 3)?;
    let witness = WorkerClaimWitness {
        deployment_id: binding.deployment_id.clone(),
        worker_owner_id: binding.worker_owner_id.clone(),
        worker_profile_digest: binding.worker_profile_digest.clone(),
        release_digest: binding.release_digest.clone(),
        config_digest: binding.config_digest.clone(),
        schema_digest: binding.schema_digest.clone(),
        watchdog_boot_id: control.watchdog_boot_id.clone(),
        worker_boot_id: worker_boot.clone(),
        mode_sequence: 1,
    };
    let dispatched = client
        .claim_and_dispatch(&mut store, &witness, 4)
        .map_err(|error| io::Error::other(format!("direct dispatch: {error}")))?
        .ok_or_else(|| io::Error::other("job not dispatched"))?;
    assert_eq!(dispatched.handoff.job_id, job.id);
    assert_eq!(dispatched.handoff.state, WorkerHandoffState::Admitted);
    let tuple = dispatched.handoff.tuple();
    // Close and reopen the owner-local store before historical reconciliation.
    drop(store);
    let mut store = Store::open(&config.database, config)?;
    // The synthetic MCP exits without launching an episode. The real worker
    // deliberately fails closed; this is not successful gameplay evidence.
    assert!(!child.wait(Duration::from_secs(35))?.success());
    let retained = store
        .worker_handoff(&tuple.handoff_id)?
        .ok_or_else(|| io::Error::other("handoff lost"))?;
    assert_ne!(retained.state, WorkerHandoffState::Acknowledged);
    assert!(
        client
            .reconcile_handoff(&mut store, &tuple, &control, 5)
            .is_err()
    );
    assert!(client.claim_and_dispatch(&mut store, &witness, 6).is_err());
    drop(store);
    let store = Store::open_read_only(&config.database, config)?;
    assert_eq!(
        store
            .worker_handoff(&tuple.handoff_id)?
            .ok_or_else(|| io::Error::other("receipt lost"))?,
        retained
    );
    drop(store);
    Ok(())
}
