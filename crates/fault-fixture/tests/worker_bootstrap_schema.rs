//! Structural bootstrap conformance, separate from byte-codec authentication checks.

use serde_json::{Value, json};

#[test]
fn bootstrap_schema_validates_owner_fixtures_and_rejects_structural_mutations()
-> Result<(), Box<dyn std::error::Error>> {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/worker-bootstrap-v1/schema.json"
    ))?;
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(&schema)?;
    for fixture in [
        include_str!("../../../schemas/worker-bootstrap-v1/valid/linux.json"),
        include_str!("../../../schemas/worker-bootstrap-v1/valid/windows.json"),
    ] {
        let valid: Value = serde_json::from_str(fixture)?;
        assert!(validator.is_valid(&valid));
        for field in [
            "version",
            "launch_nonce",
            "watchdog_boot_id",
            "component_id",
            "expected_peer",
        ] {
            let mut missing = valid.clone();
            missing
                .as_object_mut()
                .ok_or("fixture object")?
                .remove(field);
            assert!(!validator.is_valid(&missing), "missing {field}");
        }
        for (pointer, replacement) in [
            ("/version", json!(2)),
            (
                "/launch_nonce",
                json!("aaaaaaaa-aaaa-4aaa-0aaa-aaaaaaaaaaaa"),
            ),
            ("/component_id", json!("..")),
            ("/expected_peer/pid", json!(0)),
            ("/expected_peer/pid", json!(4294967296_u64)),
            ("/expected_peer/executable", json!("relative.exe")),
            ("/expected_peer/creation_token", json!("01")),
            ("/expected_peer/executable_sha256", json!("A".repeat(64))),
        ] {
            let mut invalid = valid.clone();
            *invalid.pointer_mut(pointer).ok_or("fixture field")? = replacement;
            assert!(!validator.is_valid(&invalid), "invalid {pointer}");
        }
        for pointer in ["", "/expected_peer"] {
            let mut extra = valid.clone();
            extra
                .pointer_mut(pointer)
                .and_then(Value::as_object_mut)
                .ok_or("fixture object")?
                .insert("unapproved".into(), json!(true));
            assert!(!validator.is_valid(&extra));
        }
    }
    Ok(())
}
