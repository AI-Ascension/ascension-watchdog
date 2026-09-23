//! Process-group lifetime and bounded-cleanup regression tests.
//!
//! These tests stay at `process::tests` so existing test discovery and names
//! are unchanged; they exercise the child/observation modules together.

use super::child::{abort_spawned_child, cleanup_spawned_child};
use super::*;
use crate::config::ComponentConfig;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn immediate_component() -> ComponentConfig {
    ComponentConfig {
        id: "process-group-lifetime".to_owned(),
        executable: PathBuf::from("/bin/sh"),
        args: vec!["-c".to_owned(), "exit 0".to_owned()],
        cwd: None,
        environment: BTreeMap::new(),
        executable_sha256: None,
        restart: false,
    }
}

#[test]
fn repeated_cleanup_after_reap_never_reuses_numeric_group_authority() {
    let mut child = OwnedChild::spawn(&immediate_component(), 1_000).expect("spawn");
    let signal_count = Arc::clone(&child.process_group.signal_count);
    child.wait().expect("wait and clean exact group");
    let after_reap = signal_count.load(std::sync::atomic::Ordering::SeqCst);
    assert!(after_reap > 0, "cleanup must signal the original group");

    let repeated = child.terminate(Duration::from_millis(100));
    assert!(
        repeated.is_ok(),
        "already cleaned child must return its retained exit status"
    );
    drop(child);
    assert_eq!(
        signal_count.load(std::sync::atomic::Ordering::SeqCst),
        after_reap,
        "terminate/Drop must not signal a recycled numeric PGID"
    );
}

#[test]
fn injected_cleanup_proof_failure_returns_without_unbounded_reap() {
    let mut child = OwnedChild::spawn(&immediate_component(), 1_000).expect("spawn");
    child.process_group.force_cleanup_failure = true;
    let started = Instant::now();
    let result = abort_spawned_child(
        &mut child.child,
        &mut child.process_group,
        Instant::now() + Duration::from_secs(1),
    );
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "injected cleanup failure must not block in Child::wait"
    );
    assert!(result.is_err(), "injected cleanup failure must be reported");

    child.process_group.force_cleanup_failure = false;
    cleanup_spawned_child(
        &mut child.child,
        &mut child.process_group,
        Instant::now() + Duration::from_secs(1),
    )
    .expect("clear injected failure and reap through exact authority");
}
