use super::*;

#[test]
fn rejected_commit_after_retention_retires_and_releases_without_acknowledging_launch() {
    let policy = policy();
    let request = request("rejected-commit-cleanup");
    let directory = protected_tempdir();
    let path = directory.path().join("ledger");
    let ledger = BrokerLedger::init(&path).expect("initialize");
    let mut broker =
        LinuxSystemdBroker::new_with_ledger(policy.clone(), FakeBackend::new(), ledger);
    let (peer, mut child) = credentials(&policy);
    broker.ledger.inject_commit_rejection();
    assert!(broker.handle(peer, request.clone()).is_err());
    assert_eq!(
        (
            broker.backend.starts,
            broker.backend.stops,
            broker.backend.releases
        ),
        (1, 1, 1)
    );
    assert_eq!(
        broker.ledger.state(&request),
        Some(ledger::LedgerState::Stopped)
    );
    assert!(broker.handle(peer, request.clone()).is_err());
    assert_eq!(broker.backend.starts, 1, "failed nonce is never reused");
    drop(broker);
    let reopened = BrokerLedger::open(path).expect("pending to cleanup to terminal is durable");
    assert_eq!(reopened.state(&request), Some(ledger::LedgerState::Stopped));
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn failed_descriptor_storage_keeps_local_cleanup_authority_but_never_launch_ack() {
    let policy = policy();
    let request = request("failed-store-cleanup");
    let mut backend = FakeBackend::new();
    backend.store_error_after_capture = Some(BrokerError::Unavailable(
        "store verification failed".to_owned(),
    ));
    let mut broker = LinuxSystemdBroker::new(policy.clone(), backend);
    let (peer, mut child) = credentials(&policy);
    assert!(broker.handle(peer, request.clone()).is_err());
    assert_eq!(
        broker.ledger.state(&request),
        Some(ledger::LedgerState::Stopped)
    );
    assert_eq!(
        (
            broker.backend.starts,
            broker.backend.stops,
            broker.backend.releases
        ),
        (1, 1, 1)
    );
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn interrupted_failed_launch_cleanup_keeps_exact_receipt_and_can_retry_without_ack() {
    let policy = policy();
    let request = request("failed-store-interrupted-cleanup");
    let directory = protected_tempdir();
    let path = directory.path().join("ledger");
    let ledger = BrokerLedger::init(&path).expect("initialize");
    let mut backend = FakeBackend::new();
    backend.store_error_after_capture = Some(BrokerError::Unavailable(
        "store verification failed".to_owned(),
    ));
    backend.stop_error = Some(BrokerError::Unavailable("stop not yet complete".to_owned()));
    let mut broker = LinuxSystemdBroker::new_with_ledger(policy.clone(), backend, ledger);
    let (peer, mut child) = credentials(&policy);
    assert!(broker.handle(peer, request.clone()).is_err());
    assert_eq!(
        broker.ledger.state(&request),
        Some(ledger::LedgerState::StopPending)
    );
    assert_eq!(broker.backend.releases, 0);
    let recovery = broker
        .ledger
        .recoverable_receipts(&policy)
        .expect("retained recovery binding");
    assert_eq!(recovery.len(), 1);
    assert_eq!(recovery[0].request, request);
    assert!(
        broker.handle(peer, request.clone()).is_err(),
        "cleanup intent cannot turn into launch ack"
    );
    assert_eq!(broker.backend.starts, 1);
    let reopened = BrokerLedger::open(&path).expect("reopen interrupted cleanup");
    assert_eq!(
        reopened
            .recoverable_receipts(&policy)
            .expect("reopened binding"),
        recovery
    );
    broker.backend.stop_error = None;
    broker
        .stop(peer, request.clone())
        .expect("local original permits stop despite failed store admission");
    assert_eq!(
        broker.ledger.state(&request),
        Some(ledger::LedgerState::Stopped)
    );
    assert_eq!(broker.backend.releases, 1);
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn failed_cleanup_intent_persistence_prevents_termination_and_descriptor_removal() {
    let policy = policy();
    let request = request("cleanup-intent-sync-failure");
    let launch = policy
        .component(BrokerComponent::Synthetic)
        .expect("launch policy")
        .clone();
    let directory = protected_tempdir();
    let ledger = BrokerLedger::init(directory.path().join("ledger")).expect("initialize");
    let mut broker = LinuxSystemdBroker::new_with_ledger(policy, FakeBackend::new(), ledger);
    let unit = unit_name(&request);
    broker
        .ledger
        .reserve(&request, &unit, &launch)
        .expect("durable reservation");
    let deadline = Instant::now() + Duration::from_secs(2);
    let observed = broker
        .backend
        .start(&unit, &request, &launch, None, deadline)
        .expect("synthetic launch");
    broker
        .backend
        .retain_containment(&request, &observed, &launch, deadline)
        .expect("capture original");
    broker.ledger.inject_sync_failure();
    assert!(broker.cleanup_failed_launch(&request, &observed).is_err());
    assert!(broker.ledger.is_poisoned());
    assert_eq!(
        broker.ledger.state(&request),
        Some(ledger::LedgerState::Pending)
    );
    assert_eq!((broker.backend.stops, broker.backend.releases), (0, 0));
    assert!(broker.backend.retained.contains_key(&unit));
}

#[test]
fn failed_cleanup_binding_rejects_changed_policy_or_receipt_before_append() {
    let policy = policy();
    let launch = policy
        .component(BrokerComponent::Synthetic)
        .expect("launch policy");
    let request = request("cleanup-binding-conflict");
    let unit = unit_name(&request);
    let mut ledger = BrokerLedger::memory();
    ledger.reserve(&request, &unit, launch).expect("reserve");
    let receipt = receipt_from(&request, &observation(launch, &unit), false);
    let mut foreign = receipt.clone();
    foreign.uid ^= 1;
    assert!(
        ledger
            .begin_failed_launch_cleanup(&request, &foreign, launch)
            .is_err()
    );
    let mut changed_policy = launch.clone();
    changed_policy.arguments.push("changed".to_owned());
    assert!(
        ledger
            .begin_failed_launch_cleanup(&request, &receipt, &changed_policy)
            .is_err()
    );
    assert_eq!(ledger.state(&request), Some(ledger::LedgerState::Pending));
}
