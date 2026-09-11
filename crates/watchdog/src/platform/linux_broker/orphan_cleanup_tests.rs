use super::*;

#[test]
fn inspect_errors_and_changed_live_identity_never_enter_orphan_cleanup() {
    for inspect_error in [false, true] {
        let policy = policy();
        let request = request("orphan-no-error-fallback");
        let mut broker = LinuxSystemdBroker::new(policy.clone(), FakeBackend::new());
        let (peer, mut child) = credentials(&policy);
        let receipt = broker.handle(peer, request.clone()).expect("launch");
        if inspect_error {
            broker.backend.inspect_error = Some(BrokerError::Unavailable(
                "NoSuchUnit in generic error text".to_owned(),
            ));
        } else {
            broker
                .backend
                .units
                .get_mut(&receipt.unit)
                .expect("unit")
                .creation_token = "replacement".to_owned();
        }
        assert!(broker.stop(peer, request.clone()).is_err());
        assert_eq!(
            broker.ledger.state(&request),
            Some(ledger::LedgerState::Committed)
        );
        assert_eq!(
            (
                broker.backend.stops,
                broker.backend.orphan_stops,
                broker.backend.releases
            ),
            (0, 0, 0)
        );
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[test]
fn orphan_stop_uses_original_containment_and_preserves_terminal_deduplication() {
    let policy = policy();
    let request = request("orphan-cleanup");
    let directory = protected_tempdir();
    let path = directory.path().join("ledger");
    let mut broker = LinuxSystemdBroker::new_with_ledger(
        policy.clone(),
        FakeBackend::new(),
        BrokerLedger::init(&path).expect("initialize"),
    );
    let (peer, mut child) = credentials(&policy);
    let receipt = broker.handle(peer, request.clone()).expect("launch");
    broker.backend.units.remove(&receipt.unit);
    assert!(broker.inspect(peer, request.clone()).is_err());
    assert_eq!(
        broker.ledger.state(&request),
        Some(ledger::LedgerState::Committed)
    );
    assert_eq!(
        (
            broker.backend.stops,
            broker.backend.orphan_stops,
            broker.backend.releases
        ),
        (0, 0, 0)
    );
    let result = broker
        .stop(peer, request.clone())
        .expect("original orphan cleanup");
    assert_eq!(result.state, BrokerLifecycleState::Stopped);
    assert_eq!(
        (
            broker.backend.stops,
            broker.backend.orphan_stops,
            broker.backend.releases
        ),
        (0, 1, 1)
    );
    assert!(broker.active_units.is_empty());
    assert!(
        broker
            .stop(peer, request.clone())
            .expect("terminal retry")
            .duplicate
    );
    assert_eq!(broker.backend.orphan_stops, 1);
    assert!(broker.handle(peer, request.clone()).is_err());
    drop(broker);
    assert_eq!(
        BrokerLedger::open(path).expect("reopen").state(&request),
        Some(ledger::LedgerState::Stopped)
    );
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn orphan_cleanup_persistence_or_population_errors_prevent_effects() {
    for population_error in [false, true] {
        let policy = policy();
        let request = request("orphan-pre-effect-failure");
        let directory = protected_tempdir();
        let mut broker = LinuxSystemdBroker::new_with_ledger(
            policy.clone(),
            FakeBackend::new(),
            BrokerLedger::init(directory.path().join("ledger")).expect("initialize"),
        );
        let (peer, mut child) = credentials(&policy);
        let receipt = broker.handle(peer, request.clone()).expect("launch");
        broker.backend.units.remove(&receipt.unit);
        if population_error {
            broker.backend.retirement_error =
                Some(BrokerError::Io("unreadable population".to_owned()));
        } else {
            broker.ledger.inject_sync_failure();
        }
        assert!(broker.stop(peer, request.clone()).is_err());
        assert_eq!(
            broker.ledger.state(&request),
            Some(ledger::LedgerState::Committed)
        );
        assert_eq!(
            (
                broker.backend.stops,
                broker.backend.orphan_stops,
                broker.backend.releases
            ),
            (0, 0, 0)
        );
        assert!(broker.backend.retained.contains_key(&receipt.unit));
        assert!(broker.active_units.contains(&receipt.unit));
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[test]
fn orphan_cleanup_unknown_keeps_durable_stop_intent_and_recovered_original() {
    let policy = policy();
    let request = request("orphan-unknown");
    let directory = protected_tempdir();
    let path = directory.path().join("ledger");
    let mut broker = LinuxSystemdBroker::new_with_ledger(
        policy.clone(),
        FakeBackend::new(),
        BrokerLedger::init(&path).expect("initialize"),
    );
    let (peer, mut child) = credentials(&policy);
    let receipt = broker.handle(peer, request.clone()).expect("launch");
    broker.backend.units.remove(&receipt.unit);
    broker.backend.withhold_empty_proof = true;
    assert!(broker.stop(peer, request.clone()).is_err());
    assert_eq!(
        broker.ledger.state(&request),
        Some(ledger::LedgerState::StopPending)
    );
    assert_eq!(broker.backend.releases, 0);
    assert!(broker.handle(peer, request.clone()).is_err());
    let mut recovered = FakeBackend::new();
    // Synthetic stand-in for authenticated descriptor-store recovery, not
    // evidence that a native service or kernel was restarted.
    recovered.retained = std::mem::take(&mut broker.backend.retained);
    drop(broker);
    let mut replacement = LinuxSystemdBroker::new_with_ledger(
        policy,
        recovered,
        BrokerLedger::open(path).expect("reopen stop intent"),
    );
    replacement
        .stop(peer, request.clone())
        .expect("retry using original capability");
    assert_eq!(
        replacement.ledger.state(&request),
        Some(ledger::LedgerState::Stopped)
    );
    assert_eq!(
        (
            replacement.backend.starts,
            replacement.backend.stops,
            replacement.backend.orphan_stops
        ),
        (0, 0, 1)
    );
    let _ = child.kill();
    let _ = child.wait();
}
