// SPDX-License-Identifier: MIT

use std::{fs, path::Path};

use jsonschema::Draft;
use serde_json::Value;

#[test]
fn published_host_lease_schema_validates_every_fixture_class()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/host-lease-control-v1");
    let schema: Value = serde_json::from_slice(&fs::read(root.join("frame.schema.json"))?)?;
    let validator = jsonschema::options()
        .with_draft(Draft::Draft202012)
        .build(&schema)?;

    for (directory, accepted, expected_count) in [
        ("valid", true, 9),
        ("invalid", false, 1),
        // These require the separate semantic validator: valid JSON Schema
        // shape must not be confused with a valid cryptographic grant.
        ("semantic-invalid", true, 3),
    ] {
        let mut count = 0;
        for entry in fs::read_dir(root.join("fixtures").join(directory))? {
            let path = entry?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                let value: Value = serde_json::from_slice(&fs::read(&path)?)?;
                assert_eq!(
                    validator.is_valid(&value),
                    accepted,
                    "schema classification mismatch: {}",
                    path.display()
                );
                count += 1;
            }
        }
        assert_eq!(
            count, expected_count,
            "fixture inventory drift: {directory}"
        );
    }

    let original: Value = serde_json::from_slice(&fs::read(
        root.join("fixtures/valid/lease-renew-response.json"),
    )?)?;
    for sequence in [0_u64, 9_007_199_254_740_992] {
        let mut response = original.clone();
        response["payload"]["ack"]["renew_sequence"] = sequence.into();
        assert!(!validator.is_valid(&response), "invalid renewal sequence");
    }
    Ok(())
}
