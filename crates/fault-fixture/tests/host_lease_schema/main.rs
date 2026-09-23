//! Executable conformance checks for the additive host lease-control artifact.
//!
//! The workspace intentionally has no JSON-Schema runtime dependency. These
//! tests therefore check the published schema metadata and the bounded closed
//! shapes used by this artifact, then exercise the semantic rules that JSON
//! Schema cannot express (digest and identity binding, time ordering, and
//! duplicate acknowledgment lineage).
//!
//! The test functions stay at the root of this test target so their discovered
//! names and count are unchanged; the shared fixtures, bounded accessors,
//! validators and the reference host moved into the cohesive child modules
//! below. Every scenario still drives the extracted code through the same
//! entrypoints, so the modules keep cross-module integration coverage.

mod frame;
mod reference_host;
mod strict;
mod support;
mod time;
mod validators;

use std::collections::BTreeSet;

use serde_json::Value;

use crate::frame::{validate_frame, validate_request_semantics};
use crate::reference_host::{ReferenceHost, ReferenceStatus, set_grant_digest};
use crate::strict::parse_unique_json;
use crate::support::{
    CONTRACT, MAX_FRAME_BYTES, MAX_SAFE_INTEGER, SCHEMA_DIGEST, exact_object, object, read_bytes,
    read_json, sha256_hex,
};
use crate::time::{derive_deadline, monotonic_seconds, timestamp, timestamp_key};

#[allow(clippy::too_many_lines)]
#[test]
fn protected_persistence_and_reference_lifecycle_are_stateful()
-> Result<(), Box<dyn std::error::Error>> {
    let install = read_json("fixtures/valid/lease-install-request.json")?;
    let renew = read_json("fixtures/valid/lease-renew-request.json")?;
    let revoke = read_json("fixtures/valid/lease-revoke-request.json")?;
    let installation_id = install["payload"]["installation_id"]
        .as_str()
        .ok_or("installation id missing")?;

    let mut host = ReferenceHost::default();
    assert_eq!(
        host.install(&install, "2026-09-07T00:00:02Z", monotonic_seconds(100),),
        ReferenceStatus::Installed
    );
    assert_eq!(
        host.install(&install, "2026-09-07T00:00:04Z", monotonic_seconds(102),),
        ReferenceStatus::Duplicate
    );
    assert!(
        host.installations[installation_id]
            .current_persisted_grant
            .pointer("/lease/fence_token")
            .is_none()
    );
    assert!(
        host.installations[installation_id]
            .current_persisted_grant
            .pointer("/lease/fence_token_digest")
            .is_some()
    );
    assert_eq!(
        host.renew(&renew, "2026-09-07T00:00:10Z", monotonic_seconds(110),),
        ReferenceStatus::Renewed
    );
    assert_eq!(
        host.renew(&renew, "2026-09-07T00:00:11Z", monotonic_seconds(111),),
        ReferenceStatus::RenewDuplicate
    );

    let mut renewed_revoke = revoke.clone();
    renewed_revoke["payload"]["grant"] = renew["payload"]["grant"].clone();
    set_grant_digest(&mut renewed_revoke)?;
    assert_eq!(host.revoke(&renewed_revoke), ReferenceStatus::Revoked);
    assert_eq!(
        host.revoke(&renewed_revoke),
        ReferenceStatus::RevokeDuplicate
    );
    assert_eq!(
        host.install(&install, "2026-09-07T00:00:31Z", monotonic_seconds(131),),
        ReferenceStatus::Duplicate
    );
    assert!(!host.installations[installation_id].active);
    assert!(host.deadline(installation_id).is_none());

    let mut conflicting_reason = renewed_revoke.clone();
    conflicting_reason["payload"]["reason"] = Value::String("operator".to_owned());
    assert_eq!(host.revoke(&conflicting_reason), ReferenceStatus::Conflict);

    let mut changed_installation = install.clone();
    changed_installation["payload"]["installation_id"] =
        Value::String("00000000-0000-4000-8000-00000000000a".to_owned());
    assert_eq!(
        host.install(
            &changed_installation,
            "2026-09-07T00:00:02Z",
            monotonic_seconds(100),
        ),
        ReferenceStatus::Conflict
    );

    let mut changed_grant = install.clone();
    changed_grant["payload"]["grant"]["lease"]["expires_at"] =
        Value::String("2026-09-07T00:00:31Z".to_owned());
    set_grant_digest(&mut changed_grant)?;
    assert_eq!(
        host.install(
            &changed_grant,
            "2026-09-07T00:00:02Z",
            monotonic_seconds(100),
        ),
        ReferenceStatus::Conflict
    );

    let mut same_lease = ReferenceHost::default();
    assert_eq!(
        same_lease.install(&install, "2026-09-07T00:00:02Z", monotonic_seconds(100),),
        ReferenceStatus::Installed
    );
    assert_eq!(
        same_lease.install(
            &changed_installation,
            "2026-09-07T00:00:02Z",
            monotonic_seconds(100),
        ),
        ReferenceStatus::Conflict
    );
    assert_eq!(
        same_lease.install(
            &changed_installation,
            "2026-09-07T00:00:31Z",
            monotonic_seconds(131),
        ),
        ReferenceStatus::Conflict
    );

    let mut missing_host = ReferenceHost::default();
    assert_eq!(
        missing_host.renew(&renew, "2026-09-07T00:00:10Z", monotonic_seconds(110),),
        ReferenceStatus::Missing
    );

    let mut nonadvancing = ReferenceHost::default();
    assert_eq!(
        nonadvancing.install(&install, "2026-09-07T00:00:02Z", monotonic_seconds(100),),
        ReferenceStatus::Installed
    );
    assert_eq!(
        nonadvancing.renew(&renew, "2026-09-07T00:00:10Z", monotonic_seconds(110),),
        ReferenceStatus::Renewed
    );
    let mut sequence_conflict = renew.clone();
    sequence_conflict["payload"]["grant"]["lease"]["expires_at"] =
        Value::String("2026-09-07T00:02:00Z".to_owned());
    set_grant_digest(&mut sequence_conflict)?;
    assert_eq!(
        nonadvancing.renew(
            &sequence_conflict,
            "2026-09-07T00:00:10Z",
            monotonic_seconds(110),
        ),
        ReferenceStatus::Conflict
    );

    let mut restarted = ReferenceHost::default();
    assert_eq!(
        restarted.install(&install, "2026-09-07T00:00:02Z", monotonic_seconds(100),),
        ReferenceStatus::Installed
    );
    assert_eq!(
        restarted.renew(&renew, "2026-09-07T00:00:10Z", monotonic_seconds(110),),
        ReferenceStatus::Renewed
    );
    assert!(restarted.deadline(installation_id).is_some());
    restarted.restart();
    assert!(restarted.deadline(installation_id).is_none());
    assert_eq!(
        restarted.renew(&renew, "2026-09-07T00:00:10Z", monotonic_seconds(110),),
        ReferenceStatus::Conflict
    );
    assert!(!restarted.installations[installation_id].active);
    assert!(restarted.deadline(installation_id).is_none());
    assert_eq!(
        restarted.install(&install, "2026-09-07T00:00:02Z", monotonic_seconds(100),),
        ReferenceStatus::Conflict
    );

    let mut expired = install.clone();
    let mut deadline_host = ReferenceHost::default();
    assert_eq!(
        deadline_host.install(&expired, "2026-09-07T00:00:30Z", monotonic_seconds(130),),
        ReferenceStatus::Expired
    );
    expired["payload"]["grant"]["lease"]["expires_at"] =
        Value::String("2026-09-07T00:00:31Z".to_owned());
    set_grant_digest(&mut expired)?;
    assert_eq!(
        deadline_host.install(&expired, "2026-09-07T00:00:30Z", monotonic_seconds(130),),
        ReferenceStatus::Installed
    );

    let mut late_install = ReferenceHost::default();
    assert_eq!(
        late_install.install(&install, "2026-09-07T00:00:02Z", monotonic_seconds(100),),
        ReferenceStatus::Installed
    );
    assert_eq!(
        late_install.install(&install, "2026-09-07T00:01:30Z", monotonic_seconds(190),),
        ReferenceStatus::Duplicate
    );

    let mut late_renew = ReferenceHost::default();
    assert_eq!(
        late_renew.install(&install, "2026-09-07T00:00:02Z", monotonic_seconds(100),),
        ReferenceStatus::Installed
    );
    assert_eq!(
        late_renew.renew(&renew, "2026-09-07T00:00:10Z", monotonic_seconds(110),),
        ReferenceStatus::Renewed
    );
    assert_eq!(
        late_renew.renew(&renew, "2026-09-07T02:00:00Z", monotonic_seconds(7_300),),
        ReferenceStatus::RenewDuplicate
    );
    Ok(())
}

#[test]
fn received_wall_checks_clamp_monotonic_deadlines() -> Result<(), Box<dyn std::error::Error>> {
    let received = timestamp_key("2026-09-07T00:00:10Z", "received")?;
    let short_expiry = timestamp_key("2026-09-07T00:00:15Z", "expiry")?;
    assert_eq!(
        derive_deadline(received, short_expiry, 30, monotonic_seconds(100))?,
        monotonic_seconds(105)
    );

    let long_expiry = timestamp_key("2026-09-07T00:01:15Z", "expiry")?;
    assert_eq!(
        derive_deadline(received, long_expiry, 30, monotonic_seconds(100))?,
        monotonic_seconds(130)
    );
    assert!(derive_deadline(received, received, 30, monotonic_seconds(100)).is_err());
    assert!(
        derive_deadline(
            received,
            timestamp_key("2026-09-07T00:00:09Z", "expiry")?,
            30,
            monotonic_seconds(100)
        )
        .is_err()
    );
    let fractional_received = timestamp_key("2026-09-07T00:00:10.900Z", "received")?;
    let fractional_expiry = timestamp_key("2026-09-07T00:00:15.100Z", "expiry")?;
    assert_eq!(
        derive_deadline(
            fractional_received,
            fractional_expiry,
            30,
            monotonic_seconds(100)
        )?,
        monotonic_seconds(104) + 200_000_000
    );
    let fractional_clamped = timestamp_key("2026-09-07T00:01:15.100Z", "expiry")?;
    assert_eq!(
        derive_deadline(
            fractional_received,
            fractional_clamped,
            30,
            monotonic_seconds(100)
        )?,
        monotonic_seconds(130)
    );
    Ok(())
}

#[test]
fn timestamp_and_semantic_identity_checks_are_strict() -> Result<(), Box<dyn std::error::Error>> {
    assert!(timestamp("2026-09-07T00:00:00.1Z", "fraction").is_ok());
    assert!(timestamp("2026-09-07T00:00:.00Z", "malformed").is_err());
    assert!(timestamp("2026-02-30T00:00:00Z", "calendar").is_err());

    let install = read_json("fixtures/valid/lease-install-request.json")?;
    let mut wrong_principal = install.clone();
    wrong_principal["payload"]["grant"]["gateway"]["principal_id"] =
        Value::String("00000000-0000-4000-8000-000000000009".to_owned());
    set_grant_digest(&mut wrong_principal)?;
    assert!(validate_request_semantics(&wrong_principal, "lease_install_request").is_err());

    let mut wrong_role = install.clone();
    wrong_role["actor"]["role"] = Value::String("host".to_owned());
    assert!(validate_frame(&wrong_role, "lease_install_request").is_err());

    let mut wrong_capability = install.clone();
    wrong_capability["auth"]["capability"] = Value::String("lease_revoke".to_owned());
    assert!(validate_frame(&wrong_capability, "lease_install_request").is_err());

    let mut wrong_u53 = install.clone();
    wrong_u53["payload"]["grant"]["boot"]["authority_generation"] =
        Value::Number((MAX_SAFE_INTEGER + 1).into());
    set_grant_digest(&mut wrong_u53)?;
    assert!(validate_request_semantics(&wrong_u53, "lease_install_request").is_err());

    let mut wrong_sequence = read_json("fixtures/valid/lease-renew-request.json")?;
    wrong_sequence["payload"]["renew_sequence"] = Value::Number((MAX_SAFE_INTEGER + 1).into());
    assert!(validate_frame(&wrong_sequence, "lease_renew_request").is_err());

    let mut zero_renew_ack = read_json("fixtures/valid/lease-renew-response.json")?;
    zero_renew_ack["payload"]["ack"]["renew_sequence"] = Value::Number(0.into());
    assert!(validate_frame(&zero_renew_ack, "lease_renew_response").is_err());
    let mut oversized_renew_ack = read_json("fixtures/valid/lease-renew-response.json")?;
    oversized_renew_ack["payload"]["ack"]["renew_sequence"] =
        Value::Number((MAX_SAFE_INTEGER + 1).into());
    assert!(validate_frame(&oversized_renew_ack, "lease_renew_response").is_err());

    let mut duplicate_status = read_json("fixtures/valid/lease-install-response.json")?;
    duplicate_status["payload"]["ack"]["result"]["status"] = Value::String("RENEWED".to_owned());
    assert!(validate_frame(&duplicate_status, "lease_install_response").is_err());
    Ok(())
}

#[test]
fn duplicate_json_members_are_rejected_before_semantic_validation()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = read_bytes("fixtures/valid/lease-install-request.json")?;
    assert!(parse_unique_json(&valid).is_ok());
    assert!(parse_unique_json(br#"{"contract":"a","contract":"b"}"#).is_err());
    assert!(parse_unique_json(br#"{"nested":{"id":1,"id":2}}"#).is_err());
    Ok(())
}

#[test]
fn manifest_pins_the_exact_closed_schema_without_self_reference()
-> Result<(), Box<dyn std::error::Error>> {
    let schema_bytes = read_bytes("frame.schema.json")?;
    assert_eq!(sha256_hex(&schema_bytes), SCHEMA_DIGEST);
    let manifest = read_json("manifest.json")?;
    let manifest_object = exact_object(
        &manifest,
        &[
            "$schema",
            "$id",
            "contract",
            "version",
            "schema_file",
            "schema_digest",
            "canonicalization",
            "digest_algorithm",
            "limits",
            "compatibility",
            "publication",
        ],
        "manifest",
    )?;
    assert_eq!(manifest_object["contract"], CONTRACT);
    assert_eq!(manifest_object["schema_digest"], SCHEMA_DIGEST);
    assert_eq!(manifest_object["schema_file"], "frame.schema.json");
    assert_ne!(manifest_object["schema_digest"], manifest_object["$id"]);
    let schema = parse_unique_json(&schema_bytes)?;
    let alternatives = schema["oneOf"].as_array().ok_or("schema oneOf missing")?;
    assert_eq!(alternatives.len(), 6);
    for definition in [
        "install_request_frame",
        "install_response_frame",
        "renew_request_frame",
        "renew_response_frame",
        "revoke_request_frame",
        "revoke_response_frame",
    ] {
        assert!(
            schema["$defs"][definition].is_object(),
            "missing {definition}"
        );
    }
    assert_eq!(
        schema["$defs"]["common_frame"]["additionalProperties"],
        false
    );
    assert_eq!(schema["$defs"]["grant"]["additionalProperties"], false);
    assert_eq!(schema["$defs"]["ack"]["additionalProperties"], false);
    Ok(())
}

#[test]
fn valid_lifecycle_fixtures_are_closed_bound_and_semantically_coherent()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = [
        ("lease-install-request.json", "lease_install_request"),
        ("lease-install-response.json", "lease_install_response"),
        (
            "lease-install-duplicate-response.json",
            "lease_install_response",
        ),
        ("lease-renew-request.json", "lease_renew_request"),
        ("lease-renew-response.json", "lease_renew_response"),
        (
            "lease-renew-duplicate-response.json",
            "lease_renew_response",
        ),
        ("lease-revoke-request.json", "lease_revoke_request"),
        ("lease-revoke-response.json", "lease_revoke_response"),
        (
            "lease-revoke-duplicate-response.json",
            "lease_revoke_response",
        ),
    ];
    for (file, kind) in valid {
        let bytes = read_bytes(&format!("fixtures/valid/{file}"))?;
        assert!(bytes.len() <= MAX_FRAME_BYTES, "{file} exceeds frame bound");
        let value = parse_unique_json(&bytes)?;
        validate_frame(&value, kind).map_err(|error| format!("{file}: {error}"))?;
        if kind.ends_with("_request") {
            validate_request_semantics(&value, kind).map_err(|error| format!("{file}: {error}"))?;
        }
    }
    let install = read_json("fixtures/valid/lease-install-request.json")?;
    let renew = read_json("fixtures/valid/lease-renew-request.json")?;
    let renewed_expiry = renew["payload"]["grant"]["lease"]["expires_at"]
        .as_str()
        .ok_or("renew expiry missing")?;
    let initial_expiry = install["payload"]["grant"]["lease"]["expires_at"]
        .as_str()
        .ok_or("initial expiry missing")?;
    assert!(renewed_expiry > initial_expiry);
    let install_ack = read_json("fixtures/valid/lease-install-response.json")?;
    let duplicate_ack = read_json("fixtures/valid/lease-install-duplicate-response.json")?;
    for field in [
        "installation_id",
        "grant_digest",
        "boot_id",
        "instance_incarnation",
        "host_fence_id",
        "fence_generation",
        "lease_id",
        "lease_epoch",
        "host_install_generation",
        "recorded_at",
        "expires_at",
    ] {
        assert_eq!(
            install_ack["payload"]["ack"][field], duplicate_ack["payload"]["ack"][field],
            "duplicate changed {field}"
        );
    }
    let renew_ack = read_json("fixtures/valid/lease-renew-response.json")?;
    let renew_duplicate_ack = read_json("fixtures/valid/lease-renew-duplicate-response.json")?;
    let revoke_ack = read_json("fixtures/valid/lease-revoke-response.json")?;
    let revoke_duplicate_ack = read_json("fixtures/valid/lease-revoke-duplicate-response.json")?;
    for (label, original, duplicate) in [
        ("renew", &renew_ack, &renew_duplicate_ack),
        ("revoke", &revoke_ack, &revoke_duplicate_ack),
    ] {
        for field in [
            "installation_id",
            "grant_digest",
            "boot_id",
            "instance_incarnation",
            "host_fence_id",
            "fence_generation",
            "lease_id",
            "lease_epoch",
            "host_install_generation",
            "recorded_at",
            "renew_sequence",
            "expires_at",
        ] {
            assert_eq!(
                original["payload"]["ack"][field], duplicate["payload"]["ack"][field],
                "{label} duplicate changed {field}"
            );
        }
    }
    Ok(())
}

#[test]
fn invalid_fixtures_cover_shape_digest_context_and_expiry_failures()
-> Result<(), Box<dyn std::error::Error>> {
    let unknown = read_json("fixtures/invalid/unknown-field.json")?;
    assert!(validate_frame(&unknown, "lease_install_request").is_err());
    let mismatch = read_json("fixtures/semantic-invalid/grant-context-mismatch.json")?;
    assert!(validate_request_semantics(&mismatch, "lease_install_request").is_err());
    let bad_digest = read_json("fixtures/semantic-invalid/grant-digest-mismatch.json")?;
    assert!(validate_request_semantics(&bad_digest, "lease_install_request").is_err());
    let expired = read_json("fixtures/semantic-invalid/expired-renewal.json")?;
    assert!(validate_request_semantics(&expired, "lease_renew_request").is_err());
    Ok(())
}

#[test]
fn schema_and_fixture_field_sets_are_explicitly_closed() -> Result<(), Box<dyn std::error::Error>> {
    let schema = read_json("frame.schema.json")?;
    let definitions = schema["$defs"]
        .as_object()
        .ok_or("schema definitions missing")?;
    let object_definitions: BTreeSet<&str> = [
        "actor",
        "auth",
        "release_set",
        "boot_context",
        "host_fence",
        "lease_context",
        "gateway_identity",
        "grant",
        "result",
        "ack",
        "common_frame",
        "install_request",
        "install_response",
        "renew_request",
        "renew_response",
        "revoke_request",
        "revoke_response",
    ]
    .into_iter()
    .collect();
    for definition in object_definitions {
        assert_eq!(
            definitions[definition]["additionalProperties"], false,
            "{definition} is open"
        );
    }
    let install = read_json("fixtures/valid/lease-install-request.json")?;
    let payload = object(&install["payload"], "payload")?;
    assert_eq!(payload.keys().collect::<Vec<_>>().len(), 3);
    assert!(payload.contains_key("installation_id"));
    assert!(payload.contains_key("grant"));
    assert!(payload.contains_key("grant_digest"));
    Ok(())
}
