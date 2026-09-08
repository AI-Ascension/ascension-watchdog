use ascension_watchdog::worker_endpoint::{EndpointPlatform, WINDOWS_NAMESPACE, resolve};

const NONCE: &str = "12345678-1234-4234-8234-123456789abc";

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
