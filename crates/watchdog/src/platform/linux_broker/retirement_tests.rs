use super::*;

#[test]
fn descriptor_cleanup_failure_is_terminal_durable_and_retryable_without_another_stop() {
    let policy = policy();
    let request = request("descriptor-cleanup-retry");
    let directory = protected_tempdir();
    let path = directory.path().join("ledger");
    let ledger = BrokerLedger::init(&path).expect("initialize ledger");
    let mut broker =
        LinuxSystemdBroker::new_with_ledger(policy.clone(), FakeBackend::new(), ledger);
    let (peer, mut child) = credentials(&policy);
    broker.handle(peer, request.clone()).expect("launch");
    broker.backend.release_error = Some(BrokerError::Unavailable(
        "manager temporarily unavailable".to_owned(),
    ));
    assert!(broker.stop(peer, request.clone()).is_err());
    assert_eq!(
        broker.ledger.state(&request),
        Some(ledger::LedgerState::Stopped)
    );
    assert_eq!(broker.backend.stops, 1);
    assert_eq!(broker.backend.releases, 1);
    assert!(broker.inspect(peer, request.clone()).is_ok());
    assert_eq!(
        broker.backend.releases, 1,
        "read-only inspect does not remove descriptors"
    );
    drop(broker);
    let mut replacement = LinuxSystemdBroker::new_with_ledger(
        policy,
        FakeBackend::new(),
        BrokerLedger::open(path).expect("reopen terminal state"),
    );
    let receipt = replacement
        .stop(peer, request.clone())
        .expect("retry only descriptor removal");
    assert!(receipt.duplicate);
    assert_eq!(replacement.backend.stops, 0);
    assert_eq!(replacement.backend.releases, 1);
    assert!(
        replacement.handle(peer, request).is_err(),
        "terminal nonce cannot relaunch"
    );
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn unresolved_retirement_never_releases_the_original_descriptor() {
    let policy = policy();
    let request = request("keep-unresolved-descriptor");
    let mut broker = LinuxSystemdBroker::new(policy.clone(), FakeBackend::new());
    let (peer, mut child) = credentials(&policy);
    broker.handle(peer, request.clone()).expect("launch");
    broker.backend.withhold_empty_proof = true;
    assert!(broker.stop(peer, request.clone()).is_err());
    assert!(broker.stop(peer, request).is_err());
    assert_eq!(broker.backend.releases, 0);
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn only_policy_matching_committed_or_stop_pending_receipts_can_bind_inherited_capabilities() {
    let policy = policy();
    let launch = policy
        .component(BrokerComponent::Synthetic)
        .expect("launch policy");
    let mut ledger = BrokerLedger::memory();
    for stage in 0..4 {
        let request = request(&format!("recovery-stage-{stage}"));
        let unit = unit_name(&request);
        ledger.reserve(&request, &unit, launch).expect("reserve");
        let receipt = receipt_from(&request, &observation(launch, &unit), false);
        if stage > 0 {
            ledger.commit(&request, &receipt).expect("commit");
        }
        if stage > 1 {
            ledger.begin_stop(&request, &receipt).expect("stop intent");
        }
        if stage > 2 {
            ledger
                .mark_stopped(&request, &receipt)
                .expect("verified retirement");
        }
    }
    let receipts = ledger
        .recoverable_receipts(&policy)
        .expect("bounded recovery bindings");
    assert_eq!(receipts.len(), 2);
    assert!(receipts.iter().all(|receipt| matches!(
        receipt.request.nonce.as_str(),
        "recovery-stage-1" | "recovery-stage-2"
    )));
    let mut changed = policy.clone();
    changed
        .components
        .get_mut(&BrokerComponent::Synthetic)
        .expect("synthetic policy")
        .arguments
        .push("changed".to_owned());
    assert!(ledger.recoverable_receipts(&changed).is_err());
}

#[test]
fn live_unit_after_owner_reopen_cannot_replace_the_original_stop_capability() {
    for stop_pending in [false, true] {
        let policy = policy();
        let request = request("live-lost-original");
        let directory = protected_tempdir();
        let path = directory.path().join("ledger");
        let ledger = BrokerLedger::init(&path).expect("initialize ledger");
        let mut broker =
            LinuxSystemdBroker::new_with_ledger(policy.clone(), FakeBackend::new(), ledger);
        let (peer, mut child) = credentials(&policy);
        let receipt = broker.handle(peer, request.clone()).expect("launch");
        if stop_pending {
            broker
                .ledger
                .begin_stop(&request, &receipt)
                .expect("persist interrupted stop");
        }
        let before = broker.ledger.state(&request);
        let original = broker
            .backend
            .units
            .remove(&receipt.unit)
            .expect("surviving process");
        drop(broker);
        let reopened = BrokerLedger::open(path).expect("reopen owner state");
        let mut backend = FakeBackend::new();
        backend.units.insert(receipt.unit.clone(), original);
        let mut replacement = LinuxSystemdBroker::new_with_ledger(policy, backend, reopened);
        assert!(replacement.stop(peer, request.clone()).is_err());
        assert_eq!(replacement.ledger.state(&request), before);
        assert_eq!(replacement.backend.stops, 0);
        assert!(replacement.backend.units.contains_key(&receipt.unit));
        assert!(replacement.backend.retained.is_empty());
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[test]
fn unresolved_capacity_survives_owner_reopen_and_counts_all_nonterminal_states() {
    let policy = policy();
    let launch = policy
        .component(BrokerComponent::Synthetic)
        .expect("launch policy");
    let directory = protected_tempdir();
    let path = directory.path().join("ledger");
    let mut ledger = BrokerLedger::init(&path).expect("initialize ledger");
    for index in 0..MAX_ACTIVE_PROCESSES {
        let request = request(&format!("capacity-{index}"));
        let unit = unit_name(&request);
        ledger
            .reserve(&request, &unit, launch)
            .expect("reserve bounded process");
        if index % 3 != 0 {
            let receipt = receipt_from(&request, &observation(launch, &unit), false);
            ledger
                .commit(&request, &receipt)
                .expect("commit bounded process");
            if index % 3 == 2 {
                ledger
                    .begin_stop(&request, &receipt)
                    .expect("interrupt bounded stop");
            }
        }
    }
    drop(ledger);
    let mut reopened = BrokerLedger::open(path).expect("reopen outstanding reservations");
    let next = request("capacity-overflow");
    let next_unit = unit_name(&next);
    assert!(reopened.reserve(&next, &next_unit, launch).is_err());
    assert!(!reopened.contains(&next));
    let first = request("capacity-1");
    let unit = unit_name(&first);
    let receipt = receipt_from(&first, &observation(launch, &unit), false);
    reopened
        .begin_stop(&first, &receipt)
        .expect("start exact retirement");
    reopened
        .mark_stopped(&first, &receipt)
        .expect("record verified retirement");
    assert!(
        reopened
            .reserve(&next, &next_unit, launch)
            .expect("retirement frees one slot")
    );
    assert!(
        reopened.reserve(&first, &unit, launch).is_err(),
        "terminal nonce is never reusable"
    );
}

#[test]
fn exact_duplicate_at_capacity_does_not_need_another_process_slot() {
    let policy = policy();
    let request = request("duplicate-at-capacity");
    let mut broker = LinuxSystemdBroker::new(policy.clone(), FakeBackend::new());
    let (peer, mut child) = credentials(&policy);
    broker.handle(peer, request.clone()).expect("first launch");
    for index in 1..MAX_ACTIVE_PROCESSES {
        broker.active_units.insert(format!("other-unit-{index}"));
    }
    let duplicate = broker
        .handle(peer, request)
        .expect("same process needs no extra slot");
    assert!(duplicate.duplicate);
    assert_eq!(broker.backend.starts, 1);
    assert_eq!(broker.active_units.len(), MAX_ACTIVE_PROCESSES);
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn natural_exit_retires_only_with_the_original_empty_witness() {
    let policy = policy();
    let request = request("natural-empty");
    let directory = protected_tempdir();
    let path = directory.path().join("ledger");
    let ledger = BrokerLedger::init(&path).expect("initialize ledger");
    let mut broker =
        LinuxSystemdBroker::new_with_ledger(policy.clone(), FakeBackend::new(), ledger);
    let (peer, mut child) = credentials(&policy);
    let receipt = broker.handle(peer, request.clone()).expect("launch");
    let original = broker
        .backend
        .units
        .remove(&receipt.unit)
        .expect("original unit");
    broker
        .backend
        .emptied
        .insert(receipt.unit.clone(), original);

    assert!(broker.inspect(peer, request.clone()).is_err());
    assert_eq!(
        broker.ledger.state(&request),
        Some(ledger::LedgerState::Committed)
    );
    let stopped = broker
        .stop(peer, request.clone())
        .expect("prove natural exit");
    assert_eq!(stopped.state, BrokerLifecycleState::Stopped);
    assert_eq!(
        broker.backend.stops, 0,
        "natural retirement performs no kill"
    );
    assert!(broker.active_units.is_empty());
    drop(broker);
    let reopened = BrokerLedger::open(path).expect("reopen natural retirement");
    assert_eq!(reopened.state(&request), Some(ledger::LedgerState::Stopped));
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn missing_unit_without_empty_witness_never_becomes_stopped() {
    for stop_pending in [false, true] {
        let policy = policy();
        let request = request("missing-unproven");
        let mut broker = LinuxSystemdBroker::new(policy.clone(), FakeBackend::new());
        let (peer, mut child) = credentials(&policy);
        let receipt = broker.handle(peer, request.clone()).expect("launch");
        if stop_pending {
            broker
                .ledger
                .begin_stop(&request, &receipt)
                .expect("persist interrupted stop");
        }
        let before = broker.ledger.state(&request);
        broker.backend.units.remove(&receipt.unit);
        broker.backend.retained.clear();
        assert!(broker.stop(peer, request.clone()).is_err());
        assert_eq!(broker.ledger.state(&request), before);
        assert!(broker.active_units.contains(&receipt.unit));
        assert_eq!(broker.backend.stops, 0);
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[test]
fn stop_success_without_empty_proof_retains_intent_until_proven() {
    let policy = policy();
    let request = request("stop-empty-witness");
    let mut backend = FakeBackend::new();
    backend.withhold_empty_proof = true;
    let mut broker = LinuxSystemdBroker::new(policy.clone(), backend);
    let (peer, mut child) = credentials(&policy);
    let receipt = broker.handle(peer, request.clone()).expect("launch");
    assert!(broker.stop(peer, request.clone()).is_err());
    assert_eq!(
        broker.ledger.state(&request),
        Some(ledger::LedgerState::StopPending)
    );
    assert!(broker.active_units.contains(&receipt.unit));
    assert!(broker.backend.units.is_empty());
    assert_eq!(broker.backend.stops, 1);
    let original = broker
        .backend
        .retained
        .get(&receipt.unit)
        .expect("retained original")
        .clone();
    broker.backend.emptied.insert(receipt.unit, original);
    let stopped = broker
        .stop(peer, request.clone())
        .expect("reconcile exact empty witness");
    assert_eq!(stopped.state, BrokerLifecycleState::Stopped);
    assert_eq!(
        broker.backend.stops, 1,
        "reconciliation does not repeat termination"
    );
    assert_eq!(
        broker.ledger.state(&request),
        Some(ledger::LedgerState::Stopped)
    );
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn replacement_owner_cannot_invent_retirement_from_a_missing_unit() {
    let policy = policy();
    let request = request("lost-original-handles");
    let directory = protected_tempdir();
    let path = directory.path().join("ledger");
    let ledger = BrokerLedger::init(&path).expect("initialize ledger");
    let mut broker =
        LinuxSystemdBroker::new_with_ledger(policy.clone(), FakeBackend::new(), ledger);
    let (peer, mut child) = credentials(&policy);
    let receipt = broker.handle(peer, request.clone()).expect("launch");
    broker
        .ledger
        .begin_stop(&request, &receipt)
        .expect("stop intent before owner loss");
    drop(broker);
    let reopened = BrokerLedger::open(path).expect("reopen pending stop");
    let mut replacement = LinuxSystemdBroker::new_with_ledger(policy, FakeBackend::new(), reopened);
    assert!(replacement.stop(peer, request.clone()).is_err());
    assert_eq!(
        replacement.ledger.state(&request),
        Some(ledger::LedgerState::StopPending)
    );
    assert_eq!(replacement.backend.stops, 0);
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn containment_acquisition_failure_cannot_acknowledge_launch() {
    let policy = policy();
    let request = request("capture-failure");
    let mut backend = FakeBackend::new();
    backend.containment_error = Some(BrokerError::Unavailable(
        "injected capture failure".to_owned(),
    ));
    let mut broker = LinuxSystemdBroker::new(policy.clone(), backend);
    let (peer, mut child) = credentials(&policy);
    assert!(broker.handle(peer, request.clone()).is_err());
    assert_eq!(
        broker.ledger.state(&request),
        Some(ledger::LedgerState::Pending)
    );
    assert_eq!(broker.backend.starts, 1);
    assert_eq!(broker.backend.stops, 0);
    assert!(broker.receipts.is_empty());
    assert!(broker.backend.retained.is_empty());
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn empty_witness_for_another_process_cannot_retire_original() {
    let policy = policy();
    let request = request("foreign-empty");
    let mut broker = LinuxSystemdBroker::new(policy.clone(), FakeBackend::new());
    let (peer, mut child) = credentials(&policy);
    let receipt = broker.handle(peer, request.clone()).expect("launch");
    let mut foreign = broker
        .backend
        .units
        .remove(&receipt.unit)
        .expect("original unit");
    foreign.creation_token = "different-process".to_owned();
    broker.backend.emptied.insert(receipt.unit.clone(), foreign);
    assert!(broker.stop(peer, request.clone()).is_err());
    assert_eq!(
        broker.ledger.state(&request),
        Some(ledger::LedgerState::Committed)
    );
    assert!(broker.active_units.contains(&receipt.unit));
    assert_eq!(broker.backend.stops, 0);
    let _ = child.kill();
    let _ = child.wait();
}
