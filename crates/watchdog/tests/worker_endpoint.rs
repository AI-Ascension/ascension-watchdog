use ascension_watchdog::worker_endpoint::{EndpointPlatform, WINDOWS_NAMESPACE, resolve};

const NONCE: &str = "12345678-1234-4234-8234-123456789abc";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Conformance {
    contract: String,
    owner: String,
    license: String,
    cases: Vec<EndpointCase>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointCase {
    id: String,
    platform: String,
    namespace: String,
    nonce: String,
    expected: Option<String>,
}

#[test]
fn published_machine_vectors_match_the_owner_resolver() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = include_bytes!("../../../schemas/worker-endpoint-v1/conformance.json");
    assert_eq!(
        ascension_watchdog::config::hex_digest(bytes),
        "2f7d9758a681ed77d633e3ed576de1a415734b7ef96255f099e0cb6c9b658f41"
    );
    let vectors: Conformance = serde_json::from_slice(bytes)?;
    assert_eq!(vectors.contract, "ascension-worker-endpoint-v1");
    assert_eq!(vectors.owner, "AI-Ascension/ascension-watchdog");
    assert_eq!(vectors.license, "MIT");
    assert_eq!(vectors.cases.len(), 27);
    for case in vectors.cases {
        let platform = match case.platform.as_str() {
            "linux" => EndpointPlatform::Linux,
            "windows" => EndpointPlatform::Windows,
            _ => return Err("unknown conformance platform".into()),
        };
        let actual = resolve(platform, &case.namespace, &case.nonce);
        match case.expected {
            Some(expected) => assert_eq!(actual?, expected, "{}", case.id),
            None => assert!(actual.is_err(), "{}", case.id),
        }
    }
    Ok(())
}

#[test]
fn endpoint_is_launch_specific_and_platform_exact() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        resolve(EndpointPlatform::Linux, "/run/worker", NONCE)?,
        "/run/worker/ascension-worker-12345678-1234-4234-8234-123456789abc.sock"
    );
    assert_eq!(
        resolve(EndpointPlatform::Windows, WINDOWS_NAMESPACE, NONCE)?,
        r"\\.\pipe\ascension-worker-12345678-1234-4234-8234-123456789abc"
    );
    assert_ne!(
        resolve(EndpointPlatform::Linux, "/run/worker", NONCE)?,
        resolve(
            EndpointPlatform::Linux,
            "/run/worker",
            &uuid::Uuid::new_v4().to_string()
        )?
    );
    Ok(())
}

#[test]
fn malformed_namespaces_and_nonces_fail_without_io() {
    for namespace in [
        "",
        "/",
        "relative",
        "//run",
        "/run/",
        "/run//ipc",
        "/run/./ipc",
        "/run/../ipc",
        "/run\\ipc",
        "/run\nipc",
    ] {
        assert!(resolve(EndpointPlatform::Linux, namespace, NONCE).is_err());
    }
    assert!(
        resolve(
            EndpointPlatform::Linux,
            &format!("/{}", "x".repeat(100)),
            NONCE
        )
        .is_err()
    );
    for nonce in [
        "",
        "12345678-1234-3234-8234-123456789abc",
        "12345678-1234-4234-7234-123456789abc",
        "12345678-1234-4234-8234-123456789ABC",
        "../escape",
    ] {
        assert!(resolve(EndpointPlatform::Linux, "/run/worker", nonce).is_err());
        assert!(resolve(EndpointPlatform::Windows, WINDOWS_NAMESPACE, nonce).is_err());
    }
    assert!(
        resolve(
            EndpointPlatform::Windows,
            &format!("{WINDOWS_NAMESPACE}{NONCE}"),
            NONCE
        )
        .is_err()
    );
}
