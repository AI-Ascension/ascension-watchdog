// SPDX-License-Identifier: MIT

//! Pure contract checks for the real-harness systemd scope proof.
//!
//! These tests deliberately do not invoke systemd or inspect a live unit. The
//! native process test remains explicitly ignored and is the only test that
//! requires a built harness image and a delegated user cgroup.

#![cfg(target_os = "linux")]

#[path = "support/real_harness_worker_scope.rs"]
#[allow(dead_code)]
mod real_harness_worker_scope;

use real_harness_worker_scope::{
    ScopeProof, parse_properties, validate_scope_proof, validate_scope_properties,
    validate_stopped_scope_identity,
};
use std::collections::BTreeMap;

fn valid_properties() -> String {
    [
        "Id=ascension-watchdog-real-0123456789abcdef0123456789abcdef.scope",
        "LoadState=loaded",
        "ActiveState=active",
        "ControlGroup=/user.slice/user-1000.slice/user@1000.service/app.slice/ascension-watchdog-real-0123456789abcdef0123456789abcdef.scope",
        "Description=ascension-watchdog-real-harness-0123456789abcdef0123456789abcdef",
        "Delegate=yes",
        "KillMode=control-group",
        "SendSIGKILL=yes",
        "RuntimeMaxUSec=2min",
        "TimeoutStopUSec=5s",
        "CollectMode=inactive-or-failed",
    ]
    .join("\n")
}

#[test]
fn scope_property_contract_rejects_unbounded_runtime() {
    let output = valid_properties().replace("RuntimeMaxUSec=2min", "RuntimeMaxUSec=infinity");
    let properties = parse_properties(&output).expect("well-formed property output");
    let error = validate_scope_properties(
        &properties,
        "ascension-watchdog-real-0123456789abcdef0123456789abcdef.scope",
        "ascension-watchdog-real-harness-0123456789abcdef0123456789abcdef",
    )
    .expect_err("infinite runtime must not establish ownership");
    assert!(error.contains("RuntimeMaxUSec"));
}

#[test]
fn scope_property_parser_rejects_duplicates_and_malformed_lines() {
    assert!(parse_properties("Id=a\nId=b").is_err());
    assert!(parse_properties("Id=a\nnot-a-property").is_err());
    assert!(parse_properties("").is_err());
}

#[test]
fn scope_proof_rejects_active_state_without_cgroup() {
    let mut proof = ScopeProof {
        schema_version: 1,
        state: "active".to_owned(),
        unit: "worker.scope".to_owned(),
        description: "worker description".to_owned(),
        config_path: "/tmp/config.json".to_owned(),
        config_digest: "b".repeat(64),
        daemon_image: "/tmp/daemon".to_owned(),
        daemon_sha256: "a".repeat(64),
        control_group: None,
        daemon_pid: Some(10),
        worker_pid: None,
        expected: BTreeMap::from([
            ("Delegate".to_owned(), "yes".to_owned()),
            ("KillMode".to_owned(), "control-group".to_owned()),
            ("SendSIGKILL".to_owned(), "yes".to_owned()),
            ("RuntimeMaxUSec".to_owned(), "<=120s".to_owned()),
            ("TimeoutStopUSec".to_owned(), "<=5s".to_owned()),
            ("CollectMode".to_owned(), "inactive-or-failed".to_owned()),
        ]),
        actual: BTreeMap::from([(String::from("Delegate"), String::from("yes"))]),
        detail: String::from("test"),
    };
    assert!(
        validate_scope_proof(&proof)
            .expect_err("active proof without cgroup must be rejected")
            .contains("cgroup")
    );
    proof.config_digest = "A".repeat(64);
    assert!(
        validate_scope_proof(&proof)
            .expect_err("scope proof must bind a lowercase stable config digest")
            .contains("config digest")
    );
}

#[test]
fn stopped_scope_rejects_recreated_or_mismatched_cgroup() {
    let properties = parse_properties(
        "Id=worker.scope\nLoadState=loaded\nActiveState=inactive\nControlGroup=/new.scope\nDescription=worker description",
    )
    .expect("well-formed stopped properties");
    let error = validate_stopped_scope_identity(
        &properties,
        "worker.scope",
        "worker description",
        Some("/original.scope"),
    )
    .expect_err("a recreated cgroup path must not prove the original stopped");
    assert!(error.contains("does not match"));
}

#[test]
fn stopped_scope_rejects_missing_original_cgroup_handle() {
    let properties = parse_properties(
        "Id=worker.scope\nLoadState=loaded\nActiveState=inactive\nControlGroup=\nDescription=worker description",
    )
    .expect("well-formed stopped properties");
    let error =
        validate_stopped_scope_identity(&properties, "worker.scope", "worker description", None)
            .expect_err("an absent admission cgroup cannot prove stop");
    assert!(error.contains("no retained original cgroup"));
}
