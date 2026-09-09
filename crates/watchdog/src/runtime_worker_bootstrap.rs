//! Supervisor-owned bootstrap preparation before durable launch intent.

use crate::config::ComponentConfig;
use crate::error::{Result, WatchdogError};
use crate::worker_bootstrap::WorkerBootstrapLaunch;

#[cfg(target_os = "linux")]
pub(super) fn verify_binding(
    binding: Option<&crate::storage::WorkerBootstrapBinding>,
    worker_required: bool,
    boot: Option<&str>,
    digest: Option<&str>,
) -> Result<()> {
    match (worker_required, binding, boot, digest) {
        (false, None, None, None) => Ok(()),
        (true, Some(binding), Some(boot), Some(digest))
            if binding.watchdog_boot_id == boot && binding.frame_sha256 == digest =>
        {
            Ok(())
        }
        _ => Err(WatchdogError::IdentityMismatch(
            "worker helper bootstrap differs from durable launch binding".to_owned(),
        )),
    }
}

impl super::Supervisor {
    pub(crate) fn bind_prepared_worker_bootstrap(
        &mut self,
        component: &ComponentConfig,
        intent: &crate::storage::LaunchIntent,
        worker: &WorkerBootstrapLaunch,
        now_ms: u64,
    ) -> Result<()> {
        if let Err(error) = self
            .store
            .bind_worker_bootstrap(&intent.id, worker.bootstrap(), now_ms)
        {
            // No process creation has occurred. Revoke this prepared authority
            // now rather than leaving it for a later orphan-recovery pass.
            if let Err(cleanup) = self.store.clean_launch_intent(&intent.id, now_ms) {
                self.quarantine_component(
                    component,
                    Some(intent.launch_nonce.clone()),
                    None,
                    None,
                    None,
                    "worker bootstrap binding and prepared-intent cleanup failed".to_owned(),
                    now_ms,
                )?;
                return Err(WatchdogError::Conflict(format!(
                    "worker bootstrap binding failed ({error}); intent cleanup failed ({cleanup})"
                )));
            }
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn retire_recovered_worker(
        &mut self,
        component: &ComponentConfig,
        intent: &crate::storage::LaunchIntent,
        child: super::runtime_process::RuntimeChild,
        now_ms: u64,
    ) -> Result<()> {
        let reason = match self.store.worker_bootstrap_binding(&intent.id) {
            Ok(Some(binding)) if binding.watchdog_boot_id == self.worker_boot_id => {
                "persisted worker has no current in-memory bootstrap handoff proof"
            }
            Ok(Some(_)) => "persisted worker belongs to a previous watchdog bootstrap",
            Ok(None) => "persisted worker has no bootstrap binding",
            Err(_) => "persisted worker bootstrap binding is unavailable",
        };
        // A reopened handle is cleanup authority only, never a transferable
        // worker bootstrap. Retain it before durable writes or stop attempts.
        self.retain_quarantined_child(component, &intent.id, child, reason.to_owned(), now_ms)?;
        self.stop_component(component, now_ms, &mut super::ReconcileReport::default())
    }

    pub(crate) fn prepare_worker_bootstrap(
        &self,
        component: &ComponentConfig,
        launch_nonce: &str,
    ) -> Result<Option<WorkerBootstrapLaunch>> {
        if self.config.allow_synthetic_children
            || self
                .config
                .worker
                .as_ref()
                .is_none_or(|worker| worker.component_id != component.id)
        {
            return Ok(None);
        }
        native_bootstrap(component, launch_nonce, &self.worker_boot_id).map(Some)
    }
}

pub(super) fn current_binding(
    held: Option<&crate::storage::WorkerBootstrapBinding>,
    stored: Option<&crate::storage::WorkerBootstrapBinding>,
    watchdog_boot_id: &str,
) -> bool {
    held.is_some_and(|held| held.watchdog_boot_id == watchdog_boot_id && stored == Some(held))
}

#[cfg(target_os = "linux")]
fn native_bootstrap(
    component: &ComponentConfig,
    launch_nonce: &str,
    watchdog_boot_id: &str,
) -> Result<WorkerBootstrapLaunch> {
    use crate::worker_bootstrap::{ExpectedPeer, WorkerBootstrap};
    use std::time::{Duration, Instant};
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(5))
        .ok_or_else(|| {
            WatchdogError::InvalidInput("worker bootstrap deadline overflow".to_owned())
        })?;
    let peer = crate::worker_client::capture_linux_controller(deadline)?;
    let nonce = uuid::Uuid::parse_str(launch_nonce)
        .map_err(|_| WatchdogError::InvalidInput("invalid worker launch nonce".to_owned()))?;
    let boot = uuid::Uuid::parse_str(watchdog_boot_id)
        .map_err(|_| WatchdogError::InvalidInput("invalid watchdog boot identity".to_owned()))?;
    WorkerBootstrap::new(nonce, boot, component.id.clone(), ExpectedPeer::Linux(peer))
        .and_then(WorkerBootstrapLaunch::new)
        .map_err(|_| WatchdogError::InvalidInput("invalid worker bootstrap policy".to_owned()))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn held_controller_capture_rejects_an_expired_deadline() {
        assert!(crate::worker_client::capture_linux_controller(std::time::Instant::now()).is_err());
    }

    #[test]
    #[ignore = "test-owned immutable subprocess entrypoint"]
    fn capture_self_fixture() -> Result<()> {
        // Debug test images include large symbol sections. This exercises the
        // identity/hash result. Release builds exercise the production budget.
        let seconds = if cfg!(debug_assertions) { 90 } else { 5 };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
        let peer = crate::worker_client::capture_linux_controller(deadline)?;
        assert_eq!(peer.pid, std::process::id());
        assert_eq!(peer.uid, rustix::process::geteuid().as_raw());
        assert_eq!(peer.gid, rustix::process::getegid().as_raw());
        assert_eq!(
            std::path::Path::new(&peer.executable),
            std::env::current_exe()?
        );
        assert_eq!(
            peer.executable_sha256,
            crate::config::hex_digest(&std::fs::read(&peer.executable)?)
        );
        assert!(
            peer.creation_token
                .parse::<u64>()
                .is_ok_and(|value| value > 0)
        );
        Ok(())
    }

    #[test]
    fn controller_capture_uses_a_real_immutable_owned_image() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, Instant};
        let root = tempfile::tempdir()?;
        let image = root.path().join("controller");
        std::fs::copy(std::env::current_exe()?, &image)?;
        std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o500))?;
        let component = ComponentConfig {
            id: "harness".to_owned(),
            executable: image,
            args: vec![
                "--exact".to_owned(),
                "runtime::runtime_worker_bootstrap::tests::capture_self_fixture".to_owned(),
                "--ignored".to_owned(),
            ],
            cwd: None,
            environment: std::collections::BTreeMap::new(),
            executable_sha256: None,
            restart: false,
        };
        let mut child = crate::process::OwnedChild::spawn(&component, 1)?;
        let deadline = Instant::now() + Duration::from_secs(105);
        loop {
            if let Some(status) = child.try_wait()? {
                assert!(
                    status.success(),
                    "controller capture fixture failed: {:?}",
                    child.output()
                );
                return Ok(());
            }
            if Instant::now() >= deadline {
                let _ = child.terminate(Duration::from_secs(1));
                return Err(WatchdogError::Timeout(
                    "controller capture fixture timed out".to_owned(),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn helper_metadata_requires_exact_persisted_boot_and_frame() {
        let binding = crate::storage::WorkerBootstrapBinding {
            watchdog_boot_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            frame_sha256: "b".repeat(64),
        };
        let boot = Some(binding.watchdog_boot_id.as_str());
        let digest = Some(binding.frame_sha256.as_str());
        assert!(verify_binding(Some(&binding), true, boot, digest).is_ok());
        assert!(verify_binding(None, false, None, None).is_ok());
        for (stored, required, supplied_boot, supplied_digest) in [
            (None, true, boot, digest),
            (Some(&binding), true, None, digest),
            (Some(&binding), true, boot, None),
            (Some(&binding), true, Some("different-boot"), digest),
            (Some(&binding), true, boot, Some("different-frame")),
            (None, false, boot, digest),
            (Some(&binding), false, boot, digest),
        ] {
            assert!(verify_binding(stored, required, supplied_boot, supplied_digest).is_err());
        }
    }

    #[test]
    fn persisted_binding_cannot_replace_live_current_bootstrap_proof() {
        let binding = crate::storage::WorkerBootstrapBinding {
            watchdog_boot_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            frame_sha256: "b".repeat(64),
        };
        assert!(current_binding(
            Some(&binding),
            Some(&binding),
            &binding.watchdog_boot_id
        ));
        assert!(!current_binding(
            None,
            Some(&binding),
            &binding.watchdog_boot_id
        ));
        assert!(!current_binding(
            Some(&binding),
            None,
            &binding.watchdog_boot_id
        ));
        assert!(!current_binding(
            Some(&binding),
            Some(&binding),
            "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        ));
        let mut changed = binding.clone();
        changed.frame_sha256 = "d".repeat(64);
        assert!(!current_binding(
            Some(&binding),
            Some(&changed),
            &binding.watchdog_boot_id
        ));
    }

    fn sleeper() -> ComponentConfig {
        ComponentConfig {
            id: "harness".to_owned(),
            executable: "/usr/bin/sleep".into(),
            args: vec!["30".to_owned()],
            cwd: None,
            environment: std::collections::BTreeMap::new(),
            executable_sha256: None,
            restart: true,
        }
    }

    #[test]
    fn reopened_owner_retires_missing_and_old_worker_bindings_using_exact_child() -> Result<()> {
        for old_binding in [false, true] {
            let root = tempfile::tempdir()?;
            let component = sleeper();
            let config = crate::WatchdogConfig {
                database: root.path().join("state.sqlite"),
                desired_mode: crate::DesiredMode::Running,
                allow_synthetic_children: true,
                components: vec![component.clone()],
                ..crate::WatchdogConfig::default()
            };
            let mut original = super::super::Supervisor::initialize(config.clone())?;
            original.reconcile_once(1000)?;
            let intent = original.store.unsettled_launch_intents()?.remove(0);
            let old_boot = original.worker_boot_id.clone();
            if old_binding {
                // Synthetic recovery fixture: construct the historical native
                // binding shape without claiming a native launch took place.
                let raw = rusqlite::Connection::open(&config.database)?;
                raw.execute("INSERT INTO worker_bootstrap_bindings(intent_id,version,watchdog_boot_id,frame_sha256) VALUES (?,1,?,?)",
                    rusqlite::params![intent.id, old_boot, "b".repeat(64)])?;
            }
            let child = original
                .children
                .remove("harness")
                .ok_or_else(|| WatchdogError::Conflict("missing test-owned child".to_owned()))?;
            drop(original);
            let mut replacement = super::super::Supervisor::open(config)?;
            replacement.acquire_lock()?;
            assert_ne!(replacement.worker_boot_id, old_boot);
            replacement.retire_recovered_worker(&component, &intent, child, 2000)?;
            assert!(replacement.children.is_empty());
            assert!(replacement.store.unsettled_launch_intents()?.is_empty());
            assert_eq!(
                replacement
                    .store
                    .component("harness")?
                    .map(|record| record.state),
                Some(crate::policy::ComponentState::Stopped)
            );
            assert!(replacement.store.current_worker_control()?.is_none());
            assert!(replacement.store.current_worker_claim_witness()?.is_none());
        }
        Ok(())
    }

    #[test]
    fn worker_retirement_keeps_uncertain_cleanup_owned_and_quarantined() -> Result<()> {
        let root = tempfile::tempdir()?;
        let component = sleeper();
        let config = crate::WatchdogConfig {
            database: root.path().join("state.sqlite"),
            desired_mode: crate::DesiredMode::Running,
            allow_synthetic_children: true,
            components: vec![component.clone()],
            ..crate::WatchdogConfig::default()
        };
        let mut supervisor = super::super::Supervisor::initialize(config)?;
        supervisor.reconcile_once(1000)?;
        let intent = supervisor.store.unsettled_launch_intents()?.remove(0);
        let child = supervisor
            .children
            .remove("harness")
            .ok_or_else(|| WatchdogError::Conflict("missing test-owned child".to_owned()))?;
        supervisor.process_manager.inject_stop_result(Ok(
            super::super::runtime_process::RuntimeStopOutcome::TimedOut,
        ));
        supervisor.retire_recovered_worker(&component, &intent, child, 2000)?;
        assert!(supervisor.children.contains_key("harness"));
        assert_eq!(supervisor.store.unsettled_launch_intents()?.len(), 1);
        assert_eq!(
            supervisor
                .store
                .component("harness")?
                .map(|record| record.state),
            Some(crate::policy::ComponentState::Quarantined)
        );
        assert!(!current_binding(
            supervisor.children["harness"].worker_bootstrap_binding(),
            None,
            &supervisor.worker_boot_id
        ));
        supervisor.stop_component(
            &component,
            3000,
            &mut super::super::ReconcileReport::default(),
        )?;
        assert!(supervisor.children.is_empty());
        assert!(supervisor.store.unsettled_launch_intents()?.is_empty());
        Ok(())
    }

    #[test]
    fn rejected_bootstrap_binding_revokes_prepared_intent_or_quarantines() -> Result<()> {
        use crate::worker_bootstrap::{ExpectedPeer, LinuxPeer, WorkerBootstrap};
        for reject_cleanup in [false, true] {
            let root = tempfile::tempdir()?;
            let component = sleeper();
            let config = crate::WatchdogConfig {
                database: root.path().join("state.sqlite"),
                desired_mode: crate::DesiredMode::Running,
                allow_synthetic_children: true,
                components: vec![component.clone()],
                ..crate::WatchdogConfig::default()
            };
            let mut supervisor = super::super::Supervisor::initialize(config.clone())?;
            supervisor.acquire_lock()?;
            let nonce = uuid::Uuid::new_v4();
            let intent = supervisor.store.prepare_launch_intent(
                "harness",
                &nonce.to_string(),
                "watchdog-generation-1",
                &"a".repeat(64),
                Some("synthetic:test"),
                1000,
            )?;
            let frame = WorkerBootstrap::new(
                nonce,
                uuid::Uuid::new_v4(),
                "harness",
                ExpectedPeer::Linux(LinuxPeer {
                    pid: 1,
                    creation_token: "1".to_owned(),
                    executable: "/synthetic/controller".to_owned(),
                    executable_sha256: "a".repeat(64),
                    uid: 0,
                    gid: 0,
                }),
            )
            .map_err(|error| WatchdogError::InvalidInput(error.to_string()))?;
            let launch = WorkerBootstrapLaunch::new(frame)
                .map_err(|error| WatchdogError::InvalidInput(error.to_string()))?;
            let raw = rusqlite::Connection::open(&config.database)?;
            raw.execute_batch("CREATE TRIGGER reject_binding BEFORE INSERT ON worker_bootstrap_bindings BEGIN SELECT RAISE(ABORT,'injected binding failure'); END;")?;
            if reject_cleanup {
                raw.execute_batch("CREATE TRIGGER reject_intent_cleanup BEFORE UPDATE ON launch_intents WHEN NEW.state='cleaned' BEGIN SELECT RAISE(ABORT,'injected cleanup failure'); END;")?;
            }
            assert!(
                supervisor
                    .bind_prepared_worker_bootstrap(&component, &intent, &launch, 2000)
                    .is_err()
            );
            assert!(supervisor.children.is_empty());
            assert!(
                supervisor
                    .store
                    .worker_bootstrap_binding(&intent.id)?
                    .is_none()
            );
            if reject_cleanup {
                assert_eq!(supervisor.store.unsettled_launch_intents()?.len(), 1);
                assert_eq!(
                    supervisor
                        .store
                        .component("harness")?
                        .map(|record| record.state),
                    Some(crate::policy::ComponentState::Quarantined)
                );
            } else {
                assert!(supervisor.store.unsettled_launch_intents()?.is_empty());
            }
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
fn native_bootstrap(
    _component: &ComponentConfig,
    _launch_nonce: &str,
    _watchdog_boot_id: &str,
) -> Result<WorkerBootstrapLaunch> {
    Err(WatchdogError::InvalidInput(
        "native worker bootstrap producer is unavailable on this platform".to_owned(),
    ))
}
