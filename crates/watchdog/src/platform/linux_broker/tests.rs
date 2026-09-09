use super::*;
use tempfile::tempdir_in;

struct FakeBackend {
    starts: usize,
    inspects: usize,
    stops: usize,
    units: BTreeMap<String, UnitObservation>,
}

impl FakeBackend {
    fn new() -> Self {
        Self {
            starts: 0,
            inspects: 0,
            stops: 0,
            units: BTreeMap::new(),
        }
    }
}

impl SystemdBackend for FakeBackend {
    fn start(
        &mut self,
        unit: &str,
        _request: &BrokerRequest,
        policy: &LaunchPolicy,
        _deadline: Instant,
    ) -> BrokerResult<UnitObservation> {
        self.starts += 1;
        let observation = UnitObservation {
            unit: unit.to_owned(),
            pid: 42,
            creation_token: "start-token".to_owned(),
            executable: policy.executable.clone(),
            executable_sha256: policy.executable_sha256.clone(),
            uid: policy.target_uid,
            gid: policy.target_gid,
            capability_bounding_set: policy.capabilities.bounding_set,
            ambient_capabilities: policy.capabilities.ambient_set,
            no_new_privileges: true,
            control_group: format!("/system.slice/{unit}"),
        };
        self.units.insert(unit.to_owned(), observation.clone());
        Ok(observation)
    }

    fn inspect(
        &mut self,
        unit: &str,
        _policy: &LaunchPolicy,
        _deadline: Instant,
    ) -> BrokerResult<Option<UnitObservation>> {
        self.inspects += 1;
        Ok(self.units.get(unit).cloned())
    }

    fn stop(&mut self, unit: &str, _deadline: Instant) -> BrokerResult<()> {
        self.stops += 1;
        self.units.remove(unit);
        Ok(())
    }
}

fn digest(path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(fs::read(path).expect("fixture executable must be readable"));
    hex_digest(&hasher.finalize())
}

fn policy() -> BrokerPolicy {
    let executable = fs::canonicalize("/usr/bin/true").expect("fixture executable path");
    let peer_executable = fs::canonicalize("/usr/bin/sleep").expect("peer fixture executable path");
    let launch = LaunchPolicy {
        executable: executable.clone(),
        executable_sha256: digest(&executable),
        arguments: Vec::new(),
        working_directory: PathBuf::from("/"),
        environment: Vec::new(),
        // Keep the synthetic launch identity separate from the invoking test
        // peer on hosted runners, where the runner itself may be UID/GID
        // 1001.  This is a fixture-only identity; the fake backend never
        // attempts an account lookup or privilege transition.
        target_uid: if rustix::process::getuid().as_raw() == 65_534 {
            65_533
        } else {
            65_534
        },
        target_gid: if rustix::process::getgid().as_raw() == 65_534 {
            65_533
        } else {
            65_534
        },
        capabilities: CapabilityPolicy {
            bounding_set: 0,
            ambient_set: 0,
            no_new_privileges: true,
        },
        cgroup: CgroupPolicy {
            tasks_max: 16,
            memory_max_bytes: 64 * 1024 * 1024,
        },
        timeout: Duration::from_secs(2),
    };
    let peer = PeerPolicy {
        uid: rustix::process::getuid().as_raw(),
        gid: rustix::process::getgid().as_raw(),
        executable: peer_executable.clone(),
        executable_sha256: digest(&peer_executable),
    };
    BrokerPolicy::new(peer, BTreeMap::from([(BrokerComponent::Synthetic, launch)]))
        .expect("valid fixture policy")
}

fn credentials(policy: &BrokerPolicy) -> (PeerCredentials, std::process::Child) {
    let child = std::process::Command::new("/usr/bin/sleep")
        .arg("30")
        .spawn()
        .expect("peer fixture process");
    (
        PeerCredentials {
            pid: child.id(),
            uid: policy.peer.uid,
            gid: policy.peer.gid,
        },
        child,
    )
}

fn request(nonce: &str) -> BrokerRequest {
    BrokerRequest {
        component: BrokerComponent::Synthetic,
        instance: "instance".to_owned(),
        incarnation: "incarnation".to_owned(),
        nonce: nonce.to_owned(),
    }
}

fn observation(policy: &LaunchPolicy, unit: &str) -> UnitObservation {
    UnitObservation {
        unit: unit.to_owned(),
        pid: 42,
        creation_token: "start-token".to_owned(),
        executable: policy.executable.clone(),
        executable_sha256: policy.executable_sha256.clone(),
        uid: policy.target_uid,
        gid: policy.target_gid,
        capability_bounding_set: policy.capabilities.bounding_set,
        ambient_capabilities: policy.capabilities.ambient_set,
        no_new_privileges: true,
        control_group: format!("/system.slice/{unit}"),
    }
}

fn protected_tempdir() -> tempfile::TempDir {
    let runtime_directory =
        PathBuf::from(format!("/run/user/{}", rustix::process::getuid().as_raw()));
    tempdir_in(runtime_directory).expect("protected test directory")
}

#[test]
fn fixed_policy_has_distinct_target_identity_and_no_capabilities() {
    let policy = policy();
    let launch = policy
        .component(BrokerComponent::Synthetic)
        .expect("policy entry");
    assert_ne!(launch.target_uid, policy.peer.uid);
    assert_eq!(launch.capabilities.bounding_set, 0);
    assert_eq!(launch.capabilities.ambient_set, 0);
}

#[test]
fn policy_rejects_uid_reuse_and_nonzero_capability_sets() {
    let original = policy();
    let launch = original
        .component(BrokerComponent::Synthetic)
        .expect("policy entry")
        .clone();
    let mut reused_uid = launch.clone();
    reused_uid.target_uid = original.peer.uid;
    assert!(
        BrokerPolicy::new(
            original.peer.clone(),
            BTreeMap::from([(BrokerComponent::Synthetic, reused_uid)])
        )
        .is_err()
    );

    let mut capabilities = launch;
    capabilities.capabilities.bounding_set = 1;
    assert!(
        BrokerPolicy::new(
            original.peer,
            BTreeMap::from([(BrokerComponent::Synthetic, capabilities)])
        )
        .is_err()
    );
}

#[test]
fn duplicate_nonce_does_not_start_a_second_unit() {
    let policy = policy();
    let mut broker = LinuxSystemdBroker::new(policy.clone(), FakeBackend::new());
    let (peer, mut child) = credentials(&policy);
    let first = broker.handle(peer, request("nonce")).expect("first launch");
    let second = broker
        .handle(peer, request("nonce"))
        .expect("duplicate launch");
    let _ = child.kill();
    let _ = child.wait();
    assert!(!first.duplicate);
    assert!(second.duplicate);
    assert_eq!(broker.backend.starts, 1);
}

#[test]
fn committed_duplicate_must_match_the_persisted_process_binding() {
    let policy = policy();
    let request = request("replacement");
    let mut broker = LinuxSystemdBroker::new(policy.clone(), FakeBackend::new());
    let (peer, mut child) = credentials(&policy);
    let first = broker.handle(peer, request.clone()).expect("first launch");
    let unit = first.unit.clone();
    let replacement = broker.backend.units.get_mut(&unit).expect("launched unit");
    replacement.pid = 43;
    replacement.creation_token = "replacement-start-token".to_owned();
    broker.active_units.remove(&unit);

    let error = broker
        .handle(peer, request.clone())
        .expect_err("replacement process must not satisfy an old nonce");
    let _ = child.kill();
    let _ = child.wait();
    assert!(matches!(error, BrokerError::Conflict(_)));
    assert!(!broker.active_units.contains(&unit));
    assert_eq!(broker.receipts.get(&request), Some(&first));
    assert_eq!(broker.backend.starts, 1);
}

#[test]
fn partial_ledger_append_poisons_state_and_blocks_effects() {
    let policy = policy();
    let directory = protected_tempdir();
    let path = directory.path().join("broker-ledger");
    let mut ledger = BrokerLedger::init(&path).expect("initialize ledger");
    ledger.inject_partial_write_failure();
    let partial_request = request("partial");
    let launch_policy = policy
        .component(BrokerComponent::Synthetic)
        .expect("launch policy");

    let error = ledger
        .reserve(
            &partial_request,
            &unit_name(&partial_request),
            launch_policy,
        )
        .expect_err("injected partial write must fail");
    assert!(matches!(error, BrokerError::Io(_)));
    assert!(ledger.is_poisoned());
    assert!(!ledger.contains(&partial_request));
    assert!(BrokerLedger::open(&path).is_err());
    assert!(
        ledger
            .reserve(
                &request("second"),
                &unit_name(&request("second")),
                launch_policy
            )
            .is_err()
    );

    let mut broker =
        LinuxSystemdBroker::new_with_ledger(policy.clone(), FakeBackend::new(), ledger);
    let (peer, mut child) = credentials(&policy);
    let error = broker
        .handle(peer, request("effect-blocked"))
        .expect_err("poisoned ledger must block backend effects");
    let _ = child.kill();
    let _ = child.wait();
    assert!(matches!(error, BrokerError::Unavailable(_)));
    assert_eq!(broker.backend.starts, 0);
    assert_eq!(broker.backend.inspects, 0);
    assert_eq!(broker.backend.stops, 0);
}

#[test]
fn sync_failure_poisons_ledger_without_inserting_uncommitted_state() {
    let policy = policy();
    let directory = protected_tempdir();
    let path = directory.path().join("broker-ledger");
    let mut ledger = BrokerLedger::init(&path).expect("initialize ledger");
    let sync_request = request("sync");
    let unit = unit_name(&sync_request);
    let launch_policy = policy
        .component(BrokerComponent::Synthetic)
        .expect("launch policy");
    ledger.inject_sync_failure();

    let error = ledger
        .reserve(&sync_request, &unit, launch_policy)
        .expect_err("injected sync failure must fail");
    assert!(matches!(error, BrokerError::Io(_)));
    assert!(ledger.is_poisoned());
    assert!(!ledger.contains(&sync_request));

    let mut reopened = BrokerLedger::open(&path).expect("fresh owner may inspect synced record");
    assert!(!reopened.is_poisoned());
    assert!(reopened.contains(&sync_request));
    assert!(
        reopened
            .reserve(
                &request("new-after-reopen"),
                &unit_name(&request("new-after-reopen")),
                launch_policy,
            )
            .is_ok()
    );
}

#[test]
fn committed_duplicate_survives_owner_reopen_with_exact_observation() {
    let policy = policy();
    let directory = protected_tempdir();
    let path = directory.path().join("broker-ledger");
    let ledger = BrokerLedger::init(&path).expect("initialize ledger");
    let request = request("reopen");
    let (peer, mut child) = credentials(&policy);
    let mut first_broker =
        LinuxSystemdBroker::new_with_ledger(policy.clone(), FakeBackend::new(), ledger);
    let first = first_broker
        .handle(peer, request.clone())
        .expect("first launch");
    let exact_observation = first_broker
        .backend
        .units
        .get(&first.unit)
        .cloned()
        .expect("exact launched observation");
    drop(first_broker);

    let reopened = BrokerLedger::open(&path).expect("reopen durable ledger");
    let mut backend = FakeBackend::new();
    backend.units.insert(first.unit.clone(), exact_observation);
    let mut replacement = LinuxSystemdBroker::new_with_ledger(policy.clone(), backend, reopened);
    let duplicate = replacement
        .handle(peer, request)
        .expect("exact duplicate after reopen");
    let _ = child.kill();
    let _ = child.wait();
    assert!(duplicate.duplicate);
    assert_eq!(replacement.backend.starts, 0);
    assert_eq!(replacement.backend.inspects, 1);
}

#[test]
fn unit_name_binds_all_request_identity_fields() {
    assert_ne!(unit_name(&request("a")), unit_name(&request("b")));
    assert!(unit_name(&request("a")).ends_with(".service"));
}

#[test]
fn unknown_request_field_is_rejected() {
    let result = parse_json::<BrokerRequest>(
        br#"{"component":"synthetic","instance":"i","incarnation":"c","nonce":"n","executable":"/bin/sh"}"#,
        "request",
    );
    assert!(result.is_err());
}

#[test]
fn duplicate_json_members_are_rejected_before_schema_admission() {
    let result = parse_json::<BrokerRequest>(
        br#"{"component":"synthetic","instance":"i","instance":"j","incarnation":"c","nonce":"n"}"#,
        "request",
    );
    assert!(result.is_err());
}

#[test]
fn durable_pending_record_never_relaunches_an_inactive_unit() {
    let policy = policy();
    let mut ledger = BrokerLedger::memory();
    let request = request("pending");
    let unit = unit_name(&request);
    let launch_policy = policy
        .component(BrokerComponent::Synthetic)
        .expect("launch policy");
    assert!(
        ledger
            .reserve(&request, &unit, launch_policy)
            .expect("reserve pending")
    );
    let mut broker =
        LinuxSystemdBroker::new_with_ledger(policy.clone(), FakeBackend::new(), ledger);
    let (peer, mut child) = credentials(&policy);
    let error = broker
        .handle(peer, request)
        .expect_err("inactive durable record must remain uncertain");
    let _ = child.kill();
    let _ = child.wait();
    assert!(matches!(error, BrokerError::Conflict(_)));
    assert_eq!(broker.backend.starts, 0);
}

#[test]
fn active_unit_without_durable_history_is_not_adopted() {
    let policy = policy();
    let request = request("orphan");
    let unit = unit_name(&request);
    let launch_policy = policy
        .component(BrokerComponent::Synthetic)
        .expect("launch policy");
    let mut backend = FakeBackend::new();
    backend
        .units
        .insert(unit.clone(), observation(launch_policy, &unit));
    let mut broker = LinuxSystemdBroker::new(policy.clone(), backend);
    let (peer, mut child) = credentials(&policy);
    let error = broker
        .handle(peer, request.clone())
        .expect_err("orphan unit must not be adopted");
    let _ = child.kill();
    let _ = child.wait();
    assert!(matches!(error, BrokerError::Conflict(_)));
    assert!(!broker.ledger.contains(&request));
    assert_eq!(broker.backend.starts, 0);
}

#[test]
fn missing_persistent_ledger_is_not_treated_as_empty() {
    let path = PathBuf::from(format!(
        "/var/lib/ascension-watchdog-p28-missing-{}",
        std::process::id()
    ));
    let error = BrokerLedger::open(&path).expect_err("missing ledger must fail closed");
    assert!(matches!(error, BrokerError::Unavailable(_)));
}

#[test]
fn executable_path_and_digest_are_required_in_postcondition() {
    let policy = policy();
    let launch_policy = policy
        .component(BrokerComponent::Synthetic)
        .expect("launch policy");
    let unit = unit_name(&request("postcondition"));
    let mut wrong_path = observation(launch_policy, &unit);
    wrong_path.executable = PathBuf::from("/usr/bin/sleep");
    assert!(wrong_path.verify(&unit, launch_policy).is_err());

    let mut wrong_digest = observation(launch_policy, &unit);
    wrong_digest.executable_sha256 = "0".repeat(64);
    assert!(wrong_digest.verify(&unit, launch_policy).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn proc_executable_proof_rejects_wrong_path_and_digest() {
    let policy = policy();
    let launch_policy = policy
        .component(BrokerComponent::Synthetic)
        .expect("launch policy");
    let mut child = std::process::Command::new("/usr/bin/sleep")
        .arg("30")
        .spawn()
        .expect("fixture process");
    assert!(verify_process_executable(child.id(), launch_policy).is_err());

    let sleep = fs::canonicalize("/usr/bin/sleep").expect("sleep fixture path");
    let mut wrong_digest = launch_policy.clone();
    wrong_digest.executable = sleep;
    wrong_digest.executable_sha256 = "0".repeat(64);
    assert!(verify_process_executable(child.id(), &wrong_digest).is_err());
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn active_capacity_applies_to_existing_durable_records() {
    let policy = policy();
    let request = request("existing-at-cap");
    let unit = unit_name(&request);
    let launch_policy = policy
        .component(BrokerComponent::Synthetic)
        .expect("launch policy");
    let mut ledger = BrokerLedger::memory();
    assert!(
        ledger
            .reserve(&request, &unit, launch_policy)
            .expect("reserve durable record")
    );
    let mut broker =
        LinuxSystemdBroker::new_with_ledger(policy.clone(), FakeBackend::new(), ledger);
    for index in 0..MAX_ACTIVE_PROCESSES {
        broker.active_units.insert(format!("active-{index}"));
    }
    let (peer, mut child) = credentials(&policy);
    let error = broker
        .handle(peer, request)
        .expect_err("existing ledger records must not bypass active cap");
    let _ = child.kill();
    let _ = child.wait();
    assert!(matches!(error, BrokerError::Unavailable(_)));
    assert_eq!(broker.backend.starts, 0);
}

#[test]
fn peer_credentials_are_kernel_bound() {
    let policy = policy();
    let (peer, mut child) = credentials(&policy);
    let error = authenticate_peer(
        PeerCredentials {
            pid: peer.pid,
            uid: policy.peer.uid.saturating_add(1),
            gid: policy.peer.gid,
        },
        &policy.peer,
    )
    .expect_err("forged uid must fail");
    let _ = child.kill();
    let _ = child.wait();
    assert!(matches!(error, BrokerError::Unauthorized(_)));
}

#[cfg(target_os = "linux")]
#[test]
fn process_start_token_is_not_pid_only() {
    let token = process_start_token(std::process::id()).expect("current process stat");
    assert!(!token.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn supplementary_groups_postcheck_requires_an_empty_groups_field() {
    let base = "Uid:\t1001\t1001\t1001\t1001\nGid:\t1001\t1001\t1001\t1001\n";
    require_no_supplementary_groups(&format!("{base}Groups:\t"))
        .expect("empty supplementary groups are approved");
    let error = require_no_supplementary_groups(&format!("{base}Groups:\t1001"))
        .expect_err("supplementary groups must be rejected");
    assert!(matches!(error, BrokerError::Conflict(_)));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires an approved disposable host, installed broker policy/service, and cleanup helper"]
fn native_systemd_broker_is_explicitly_gated() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("ASCENSION_NATIVE_BROKER_TEST")
        .ok()
        .as_deref()
        != Some("1")
    {
        return Ok(());
    }
    let socket = std::env::var("ASCENSION_NATIVE_BROKER_SOCKET")?;
    let cleanup_helper = std::env::var("ASCENSION_NATIVE_BROKER_CLEANUP_HELPER")?;
    let client = BrokerClient::new(socket, Duration::from_secs(20))?;
    let request = BrokerRequest {
        component: BrokerComponent::Synthetic,
        instance: "native-test".to_owned(),
        incarnation: "native-test".to_owned(),
        nonce: format!("native-{}", std::process::id()),
    };
    let receipt = client.launch(&request)?;
    let token = process_start_token(receipt.pid)?;
    assert_eq!(token, receipt.creation_token);
    assert!(fs::metadata(format!("/proc/{}/status", receipt.pid)).is_ok());

    let cleanup_status = std::process::Command::new(cleanup_helper)
        .arg("--unit")
        .arg(&receipt.unit)
        .status()?;
    assert!(cleanup_status.success());
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if fs::metadata(format!("/proc/{}/status", receipt.pid)).is_err() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("native broker cleanup did not remove the synthetic process".into())
}
