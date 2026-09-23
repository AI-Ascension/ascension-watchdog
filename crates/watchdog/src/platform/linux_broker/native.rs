//! Native Linux systemd broker backend.
//!
//! This coordinator keeps the [`NativeSystemdBackend`] state and the
//! `SystemdBackend` lifecycle that produces retained-containment effects,
//! including inherited-containment recovery. The cohesive seams are extracted
//! into flat sibling modules: [`native_transport`] (bus/proxy access and unit
//! inspection), [`native_queued_job`] (the bounded queued-job protocol) and
//! [`native_process_identity`] (exact process/executable proofs). The public
//! entrypoint and every re-export keep their original names so callers in
//! `linux_broker.rs` and the existing `#[test]` modules are unchanged.

#[allow(clippy::wildcard_imports)]
use super::*;
use rustix::process::{Signal, pidfd_send_signal};

#[path = "native_cgroup.rs"]
mod native_cgroup;
use native_cgroup::HeldCgroup;

#[path = "native_descriptor_store.rs"]
mod native_descriptor_store;
use native_descriptor_store::NativeDescriptorStore;

#[path = "native_activation.rs"]
mod native_activation;

#[path = "native_bootstrap.rs"]
mod native_bootstrap;

#[path = "native_transport.rs"]
mod native_transport;

#[path = "native_queued_job.rs"]
mod native_queued_job;
pub use native_queued_job::{
    JobRemovalOutcome, JobRemovedEvent, QueuedJobBackend, QueuedJobCancellation,
    QueuedJobResolution, decode_job_removed,
};

#[path = "native_process_identity.rs"]
mod native_process_identity;
#[path = "native_systemd_backend.rs"]
mod native_systemd_backend;
#[cfg(target_os = "linux")]
pub(crate) use native_process_identity::process_start_token;
#[cfg(all(target_os = "linux", test))]
pub(crate) use native_process_identity::require_no_supplementary_groups;
#[cfg(all(target_os = "linux", test))]
pub(crate) use native_process_identity::verify_process_executable;

struct NativeSystemdBackend {
    retained: BTreeMap<String, RetainedContainment>,
    descriptor_store: Option<NativeDescriptorStore>,
    unavailable: native_activation::CapturedDescriptors,
    /// Job object paths returned by PID 1 are retained by generated unit
    /// until the broker binds them into its durable ledger.  The map is
    /// bounded by the same active-process limit as launch admission.
    queued_jobs: BTreeMap<String, ledger::JobBinding>,
}

struct RetainedContainment {
    observation: UnitObservation,
    controls: HeldCgroup,
    empty_verified: bool,
    manager_stored: bool,
}

#[cfg(target_os = "linux")]
impl NativeSystemdBackend {
    fn recover_inherited(
        &mut self,
        mut descriptors: native_activation::CapturedDescriptors,
        ledger: &BrokerLedger,
        policy: &BrokerPolicy,
        deadline: Instant,
    ) -> BrokerResult<()> {
        self.descriptor_store.as_ref().ok_or_else(|| {
            BrokerError::Unavailable("authenticated descriptor store is unavailable".to_owned())
        })?;
        NativeDescriptorStore::verify_inherited(&descriptors, deadline)?;
        for receipt in ledger.recoverable_receipts(policy)? {
            let name = descriptor_store::DescriptorName::for_receipt(&receipt)?;
            let Some(directory) = descriptors.remove(&name) else {
                continue;
            };
            let launch_policy = policy.component(receipt.request.component)?;
            let observation = UnitObservation {
                unit: receipt.unit.clone(),
                pid: receipt.pid,
                creation_token: receipt.creation_token.clone(),
                executable: receipt.executable.clone(),
                executable_sha256: receipt.executable_sha256.clone(),
                uid: receipt.uid,
                gid: receipt.gid,
                capability_bounding_set: receipt.capability_bounding_set,
                ambient_capabilities: receipt.ambient_capabilities,
                no_new_privileges: launch_policy.capabilities.no_new_privileges,
                control_group: receipt.control_group.clone(),
            };
            observation.verify(&unit_name(&receipt.request), launch_policy)?;
            match HeldCgroup::from_directory(&directory, deadline) {
                Ok(controls) => {
                    self.retained.insert(
                        receipt.unit,
                        RetainedContainment {
                            observation,
                            controls,
                            empty_verified: false,
                            manager_stored: true,
                        },
                    );
                }
                Err(_) => {
                    // A deleted/offline control is not positive retirement.
                    // Keep its original directory bounded and diagnosable; do
                    // not substitute a fresh unit path or discard its evidence.
                    self.unavailable.insert(name, directory);
                }
            }
            remaining(deadline)?;
        }
        self.unavailable.extend(descriptors);
        Ok(())
    }
}

#[cfg(test)]
#[path = "native_queued_job_tests.rs"]
mod queued_job_tests;

#[cfg(test)]
#[path = "native_identity_tests.rs"]
mod identity_tests;

#[cfg(target_os = "linux")]
pub fn run_native_broker(
    socket: &Path,
    policy_path: &Path,
    ledger_path: &Path,
) -> BrokerResult<()> {
    // This must remain the first operation: before protected-file loading,
    // socket binding, D-Bus connections, or background thread creation.
    let inherited = native_activation::capture()?;
    let policy = BrokerPolicy::from_file(policy_path)?;
    let peer_gid = policy.peer.gid;
    let ledger = BrokerLedger::open(ledger_path)?;
    let mut backend = NativeSystemdBackend::connect();
    let deadline = Instant::now()
        .checked_add(MAX_IO_TIMEOUT)
        .unwrap_or_else(Instant::now);
    backend.descriptor_store = Some(NativeDescriptorStore::connect(deadline)?);
    backend.recover_inherited(inherited, &ledger, &policy, deadline)?;
    let listener = bind_root_owned_socket(socket, peer_gid)?;
    serve(
        &listener,
        LinuxSystemdBroker::new_with_ledger(policy, backend, ledger),
    )
}
