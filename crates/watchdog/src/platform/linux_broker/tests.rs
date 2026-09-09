use super::*;
use tempfile::tempdir_in;

#[path = "retirement_tests.rs"]
mod retirement;

#[path = "failed_launch_cleanup_tests.rs"]
mod failed_launch_cleanup;

#[path = "orphan_cleanup_tests.rs"]
mod orphan_cleanup;

struct FakeBackend {
    starts: usize,
    inspects: usize,
    stops: usize,
    units: BTreeMap<String, UnitObservation>,
    stop_error: Option<BrokerError>,
    retain_on_stop: bool,
    start_override: Option<UnitObservation>,
    retained: BTreeMap<String, UnitObservation>,
    emptied: BTreeMap<String, UnitObservation>,
    containment_error: Option<BrokerError>,
    store_error_after_capture: Option<BrokerError>,
    withhold_empty_proof: bool,
    releases: usize,
    release_error: Option<BrokerError>,
    orphan_stops: usize,
    retirement_error: Option<BrokerError>,
    inspect_error: Option<BrokerError>,
}

impl FakeBackend {
    fn new() -> Self {
        Self {
            starts: 0,
            inspects: 0,
            stops: 0,
            units: BTreeMap::new(),
            stop_error: None,
            retain_on_stop: false,
            start_override: None,
            retained: BTreeMap::new(),
            emptied: BTreeMap::new(),
            containment_error: None,
            store_error_after_capture: None,
            withhold_empty_proof: false,
            releases: 0,
            release_error: None,
            orphan_stops: 0,
            retirement_error: None,
            inspect_error: None,
        }
    }
}

impl SystemdBackend for FakeBackend {
    fn release_retired(
        &mut self,
        _receipt: &LaunchReceipt,
        _deadline: Instant,
    ) -> BrokerResult<()> {
        self.releases += 1;
        if let Some(error) = &self.release_error {
            return Err(error.clone());
        }
        Ok(())
    }
    fn start(
        &mut self,
        unit: &str,
        _request: &BrokerRequest,
        policy: &LaunchPolicy,
        _deadline: Instant,
    ) -> BrokerResult<UnitObservation> {
        self.starts += 1;
        let observation = self
            .start_override
            .clone()
            .unwrap_or_else(|| UnitObservation {
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
            });
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
        if let Some(error) = &self.inspect_error {
            return Err(error.clone());
        }
        Ok(self.units.get(unit).cloned())
    }

    fn stop(
        &mut self,
        unit: &str,
        expected: &UnitObservation,
        _deadline: Instant,
    ) -> BrokerResult<()> {
        self.stops += 1;
        if let Some(error) = self.stop_error.clone() {
            return Err(error);
        }
        if expected.unit != unit || self.units.get(unit) != Some(expected) {
            return Err(BrokerError::Conflict(
                "fake exact stop binding changed".to_owned(),
            ));
        }
        if !self.retain_on_stop {
            self.units.remove(unit);
            if !self.withhold_empty_proof {
                self.emptied.insert(unit.to_owned(), expected.clone());
            }
        }
        Ok(())
    }

    fn retain_containment(
        &mut self,
        _request: &BrokerRequest,
        expected: &UnitObservation,
        policy: &LaunchPolicy,
        _deadline: Instant,
    ) -> BrokerResult<()> {
        if let Some(error) = self.containment_error.clone() {
            return Err(error);
        }
        expected.verify(&expected.unit, policy)?;
        if let Some(previous) = self.retained.get(&expected.unit) {
            if previous != expected {
                return Err(BrokerError::Conflict(
                    "retained identity changed".to_owned(),
                ));
            }
        } else {
            self.retained
                .insert(expected.unit.clone(), expected.clone());
        }
        if let Some(error) = &self.store_error_after_capture {
            return Err(error.clone());
        }
        Ok(())
    }

    fn verify_retirement(
        &mut self,
        expected: &LaunchReceipt,
        _deadline: Instant,
    ) -> BrokerResult<bool> {
        if let Some(error) = &self.retirement_error {
            return Err(error.clone());
        }
        let Some(original) = self.emptied.get(&expected.unit) else {
            return Ok(false);
        };
        if self.retained.get(&expected.unit) != Some(original)
            || !ledger::same_process_binding(
                &receipt_from(&expected.request, original, false),
                expected,
            )
        {
            return Err(BrokerError::Conflict(
                "foreign population witness".to_owned(),
            ));
        }
        Ok(true)
    }

    fn require_retained_containment(
        &mut self,
        receipt: &LaunchReceipt,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<()> {
        remaining(deadline)?;
        verify_receipt_identity(
            receipt,
            &receipt.request,
            &unit_name(&receipt.request),
            policy,
        )?;
        let original = self.retained.get(&receipt.unit).ok_or_else(|| {
            BrokerError::Conflict("original containment is unavailable".to_owned())
        })?;
        original.verify(&receipt.unit, policy)?;
        if !ledger::same_process_binding(&receipt_from(&receipt.request, original, false), receipt)
        {
            return Err(BrokerError::Conflict(
                "original receipt binding differs".to_owned(),
            ));
        }
        Ok(())
    }

    fn stop_retained_containment(
        &mut self,
        receipt: &LaunchReceipt,
        _deadline: Instant,
    ) -> BrokerResult<()> {
        let original = self.retained.get(&receipt.unit).ok_or_else(|| {
            BrokerError::Conflict("original containment is unavailable".to_owned())
        })?;
        if !ledger::same_process_binding(&receipt_from(&receipt.request, original, false), receipt)
        {
            return Err(BrokerError::Conflict(
                "original receipt binding differs".to_owned(),
            ));
        }
        self.orphan_stops += 1;
        if let Some(error) = &self.stop_error {
            return Err(error.clone());
        }
        if !self.withhold_empty_proof {
            self.emptied.insert(receipt.unit.clone(), original.clone());
        }
        Ok(())
    }

    fn require_containment(
        &mut self,
        expected: &UnitObservation,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<()> {
        self.require_local_containment(expected, policy, deadline)?;
        if let Some(error) = &self.store_error_after_capture {
            return Err(error.clone());
        }
        Ok(())
    }

    fn require_local_containment(
        &mut self,
        expected: &UnitObservation,
        policy: &LaunchPolicy,
        _deadline: Instant,
    ) -> BrokerResult<()> {
        expected.verify(&expected.unit, policy)?;
        if self.retained.get(&expected.unit) != Some(expected) {
            return Err(BrokerError::Conflict(
                "original containment is unavailable".to_owned(),
            ));
        }
        Ok(())
    }
}

fn digest(path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(fs::read(path).expect("fixture executable must be readable"));
    hex_digest(&hasher.finalize())
}

fn wait_for_peer_executable(pid: u32) -> PathBuf {
    let expected = fs::canonicalize("/usr/bin/sleep").expect("peer fixture executable path");
    let proc_executable = format!("/proc/{pid}/exe");
    for _ in 0..1_000 {
        if let Ok(executable) = fs::read_link(&proc_executable) {
            if executable == expected {
                return executable;
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("peer fixture process did not reach its executable");
}

fn peer_fixture() -> (PathBuf, String) {
    let mut child = std::process::Command::new("/usr/bin/sleep")
        .arg("30")
        .spawn()
        .expect("peer fixture process");
    let executable = wait_for_peer_executable(child.id());
    let executable_sha256 = digest(&executable);
    let _ = child.kill();
    let _ = child.wait();
    (executable, executable_sha256)
}

fn policy() -> BrokerPolicy {
    let executable = fs::canonicalize("/usr/bin/true").expect("fixture executable path");
    let (peer_executable, peer_executable_sha256) = peer_fixture();
    let peer_user_id = rustix::process::getuid().as_raw();
    let peer_group_id = rustix::process::getgid().as_raw();
    let distinct_nonzero = |value: u32| {
        let candidate = value.saturating_add(1);
        if candidate != 0 && candidate != value {
            candidate
        } else {
            1
        }
    };
    let launch = LaunchPolicy {
        executable: executable.clone(),
        executable_sha256: digest(&executable),
        arguments: Vec::new(),
        working_directory: PathBuf::from("/"),
        environment: Vec::new(),
        target_uid: distinct_nonzero(peer_user_id),
        target_gid: distinct_nonzero(peer_group_id),
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
        uid: peer_user_id,
        gid: peer_group_id,
        executable: peer_executable.clone(),
        executable_sha256: peer_executable_sha256,
    };
    BrokerPolicy::new(peer, BTreeMap::from([(BrokerComponent::Synthetic, launch)]))
        .expect("valid fixture policy")
}

fn transport_policy() -> BrokerPolicy {
    let base = policy();
    let executable = fs::canonicalize("/proc/self/exe").expect("test executable path");
    let peer = PeerPolicy {
        uid: base.peer.uid,
        gid: base.peer.gid,
        executable_sha256: digest(&executable),
        executable,
    };
    // The real peer here is the large, unoptimized test image rather than the
    // tiny sleep fixture. Its authenticated digest must fit the same bounded
    // request window used by the real transport.
    let mut components = base.components.clone();
    for launch in components.values_mut() {
        launch.timeout = MAX_IO_TIMEOUT;
    }
    BrokerPolicy::new(peer, components).expect("transport fixture policy")
}

fn credentials(policy: &BrokerPolicy) -> (PeerCredentials, std::process::Child) {
    let child = std::process::Command::new("/usr/bin/sleep")
        .arg("30")
        .spawn()
        .expect("peer fixture process");
    assert_eq!(wait_for_peer_executable(child.id()), policy.peer.executable);
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
fn failed_launch_postcondition_cannot_authorize_cleanup_of_observed_cgroup() {
    for wrong_cgroup in [false, true] {
        let policy = policy();
        let request = request("unverified-start");
        let unit = unit_name(&request);
        let launch_policy = policy.component(request.component).expect("launch policy");
        let mut backend = FakeBackend::new();
        let mut observation = backend
            .start(
                &unit,
                &request,
                launch_policy,
                Instant::now() + Duration::from_secs(2),
            )
            .expect("construct fixture observation");
        backend.units.clear();
        backend.starts = 0;
        if wrong_cgroup {
            observation.control_group = "/system.slice/unrelated.service".to_owned();
        } else {
            observation.executable = PathBuf::from("/unapproved/image");
        }
        backend.start_override = Some(observation);
        let directory = protected_tempdir();
        let path = directory.path().join("ledger");
        let ledger = BrokerLedger::init(&path).expect("initialize ledger");
        let mut broker = LinuxSystemdBroker::new_with_ledger(policy.clone(), backend, ledger);
        let (peer, mut child) = credentials(&policy);
        let result = broker.handle(peer, request.clone());
        let _ = child.kill();
        let _ = child.wait();
        assert!(matches!(result, Err(BrokerError::Conflict(_))));
        assert_eq!(broker.backend.starts, 1);
        assert_eq!(
            broker.backend.stops, 0,
            "unverified observation is not cleanup authority"
        );
        assert!(broker.receipts.is_empty());
        drop(broker);
        let reopened = BrokerLedger::open(&path).expect("reopen preserved reservation");
        assert_eq!(reopened.state(&request), Some(ledger::LedgerState::Pending));
    }
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
fn committed_duplicate_cannot_replace_original_containment_after_owner_reopen() {
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
    assert!(replacement.handle(peer, request.clone()).is_err());
    let _ = child.kill();
    let _ = child.wait();
    assert!(replacement.backend.retained.is_empty());
    assert!(replacement.receipts.is_empty());
    assert_eq!(
        replacement.ledger.state(&request),
        Some(ledger::LedgerState::Committed)
    );
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
fn lifecycle_wire_schema_is_versioned_and_closed() {
    let valid = format!(
        "{{\"version\":1,\"operation\":\"inspect\",\"request\":{}}}",
        serde_json::to_string(&request("wire")).expect("request JSON")
    );
    let parsed = parse_json::<BrokerLifecycleRequest>(valid.as_bytes(), "lifecycle request")
        .expect("versioned lifecycle request");
    assert_eq!(parsed.version, BROKER_PROTOCOL_VERSION);
    assert_eq!(parsed.operation, BrokerLifecycleOperation::Inspect);

    let extra = format!(
        "{{\"version\":1,\"operation\":\"inspect\",\"request\":{},\"unit\":\"bad\"}}",
        serde_json::to_string(&request("wire-extra")).expect("request JSON")
    );
    assert!(parse_json::<BrokerLifecycleRequest>(extra.as_bytes(), "lifecycle request").is_err());
    assert!(parse_json::<BrokerLifecycleRequest>(
        br#"{"version":2,"operation":"inspect","request":{"component":"synthetic","instance":"i","incarnation":"c","nonce":"n"}}"#,
        "lifecycle request"
    )
    .expect("schema parses before version validation")
    .validate()
    .is_err());
}

#[test]
fn legacy_launch_request_remains_a_four_field_schema() {
    let request = parse_json::<BrokerRequest>(
        br#"{"component":"synthetic","instance":"i","incarnation":"c","nonce":"n"}"#,
        "legacy request",
    )
    .expect("legacy request parses");
    assert_eq!(request.component, BrokerComponent::Synthetic);
    assert!(parse_json::<BrokerRequest>(
        br#"{"component":"synthetic","instance":"i","incarnation":"c","nonce":"n","version":1}"#,
        "legacy request",
    )
    .is_err());
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
fn inspect_requires_the_same_live_process_binding_and_does_not_change_ledger() {
    let policy = policy();
    let request = request("inspect-binding");
    let mut broker = LinuxSystemdBroker::new(policy.clone(), FakeBackend::new());
    let (peer, mut child) = credentials(&policy);
    let receipt = broker
        .handle(peer, request.clone())
        .expect("launch for inspect");
    let before = broker.ledger.state(&request).expect("committed record");
    broker
        .backend
        .units
        .get_mut(&receipt.unit)
        .expect("live fake unit")
        .creation_token = "reused-start-token".to_owned();

    let error = broker
        .inspect(peer, request.clone())
        .expect_err("changed live identity must fail closed");
    let after = broker
        .ledger
        .state(&request)
        .expect("committed record remains");
    let _ = child.kill();
    let _ = child.wait();
    assert!(matches!(error, BrokerError::Conflict(_)));
    assert_eq!(before, after);
    assert_eq!(broker.backend.stops, 0);
}

#[test]
fn stop_is_durable_and_terminal_duplicates_do_not_touch_backend() {
    let policy = policy();
    let request = request("terminal-stop");
    let mut broker = LinuxSystemdBroker::new(policy.clone(), FakeBackend::new());
    let (peer, mut child) = credentials(&policy);
    broker
        .handle(peer, request.clone())
        .expect("launch for stop");

    let stopped = broker.stop(peer, request.clone()).expect("stop exact unit");
    let duplicate = broker
        .stop(peer, request.clone())
        .expect("terminal stop duplicate");
    let inspected = broker
        .inspect(peer, request.clone())
        .expect("terminal inspect");
    let _ = child.kill();
    let _ = child.wait();

    assert_eq!(stopped.state, BrokerLifecycleState::Stopped);
    assert!(!stopped.duplicate);
    assert_eq!(duplicate.state, BrokerLifecycleState::Stopped);
    assert!(duplicate.duplicate);
    assert_eq!(inspected.state, BrokerLifecycleState::Stopped);
    assert!(!inspected.duplicate);
    assert_eq!(broker.backend.stops, 1);
    assert!(broker.active_units.is_empty());
    assert_eq!(
        broker.ledger.state(&request).expect("terminal record"),
        ledger::LedgerState::Stopped
    );
}

#[test]
fn stop_backend_error_retains_active_ownership_for_retry() {
    let policy = policy();
    let request = request("stop-error");
    let mut backend = FakeBackend::new();
    backend.stop_error = Some(BrokerError::Unavailable("injected stop failure".to_owned()));
    let mut broker = LinuxSystemdBroker::new(policy.clone(), backend);
    let (peer, mut child) = credentials(&policy);
    let receipt = broker
        .handle(peer, request.clone())
        .expect("launch for stop error");

    let error = broker
        .stop(peer, request.clone())
        .expect_err("stop error must be returned");
    let _ = child.kill();
    let _ = child.wait();
    assert!(matches!(error, BrokerError::Unavailable(_)));
    assert!(broker.active_units.contains(&receipt.unit));
    assert_eq!(
        broker
            .ledger
            .state(&request)
            .expect("stop-pending record retained"),
        ledger::LedgerState::StopPending
    );
    assert_eq!(broker.backend.stops, 1);
}

#[test]
fn stop_confirmation_timeout_retains_active_ownership() {
    let mut policy = policy();
    let mut launch = policy
        .component(BrokerComponent::Synthetic)
        .expect("launch policy")
        .clone();
    launch.timeout = Duration::from_millis(30);
    policy = BrokerPolicy::new(
        policy.peer.clone(),
        BTreeMap::from([(BrokerComponent::Synthetic, launch)]),
    )
    .expect("short test policy");
    let request = request("stop-timeout");
    let mut backend = FakeBackend::new();
    backend.retain_on_stop = true;
    let mut broker = LinuxSystemdBroker::new(policy.clone(), backend);
    let (peer, mut child) = credentials(&policy);
    let receipt = broker
        .handle(peer, request.clone())
        .expect("launch for stop timeout");
    let error = broker
        .stop(peer, request)
        .expect_err("persistent unit must not be reported stopped");
    let _ = child.kill();
    let _ = child.wait();
    assert!(matches!(error, BrokerError::Unavailable(_)));
    assert!(broker.active_units.contains(&receipt.unit));
    assert_eq!(broker.backend.stops, 1);
}

#[test]
fn versioned_lifecycle_round_trip_uses_real_unix_stream_transport() {
    let policy = transport_policy();
    let request = request("transport-inspect");
    let peer = PeerCredentials {
        pid: std::process::id(),
        uid: policy.peer.uid,
        gid: policy.peer.gid,
    };
    let mut broker = LinuxSystemdBroker::new(policy.clone(), FakeBackend::new());
    broker
        .handle(peer, request.clone())
        .expect("seed exact committed unit");
    let (mut client, mut server) = UnixStream::pair().expect("unix stream pair");
    let join = thread::spawn(move || {
        handle_connection(&mut server, &mut broker, Instant::now() + MAX_IO_TIMEOUT)
    });
    let envelope = BrokerLifecycleRequest {
        version: BROKER_PROTOCOL_VERSION,
        operation: BrokerLifecycleOperation::Inspect,
        request,
    };
    let bytes = serde_json::to_vec(&envelope).expect("lifecycle request JSON");
    client.write_all(&bytes).expect("write lifecycle request");
    client
        .shutdown(std::net::Shutdown::Write)
        .expect("finish lifecycle request");
    let response =
        read_frame(&mut client, Instant::now() + MAX_IO_TIMEOUT).expect("read lifecycle response");
    join.join()
        .expect("transport server thread")
        .expect("transport request");
    let response: LifecycleWireResponseOwned =
        parse_json(&response, "lifecycle response").expect("closed lifecycle response");
    assert!(response.accepted);
    assert_eq!(response.version, BROKER_PROTOCOL_VERSION);
    assert_eq!(response.operation, BrokerLifecycleOperation::Inspect);
    assert_eq!(response.state, Some(BrokerLifecycleState::Active));
    assert!(response.receipt.is_some());
}

#[test]
fn stopped_record_survives_ledger_reopen() {
    let policy = policy();
    let directory = protected_tempdir();
    let path = directory.path().join("broker-ledger");
    let ledger = BrokerLedger::init(&path).expect("initialize ledger");
    let request = request("stop-reopen");
    let (peer, mut child) = credentials(&policy);
    let mut broker =
        LinuxSystemdBroker::new_with_ledger(policy.clone(), FakeBackend::new(), ledger);
    broker
        .handle(peer, request.clone())
        .expect("launch before reopen");
    broker.stop(peer, request.clone()).expect("durable stop");
    drop(broker);

    let reopened = BrokerLedger::open(&path).expect("open terminal ledger");
    let mut replacement =
        LinuxSystemdBroker::new_with_ledger(policy.clone(), FakeBackend::new(), reopened);
    let duplicate = replacement
        .stop(peer, request)
        .expect("duplicate after ledger reopen");
    let _ = child.kill();
    let _ = child.wait();
    assert!(duplicate.duplicate);
    assert_eq!(replacement.backend.stops, 0);
    assert_eq!(replacement.backend.inspects, 1);
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
        Instant::now() + Duration::from_secs(2),
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
