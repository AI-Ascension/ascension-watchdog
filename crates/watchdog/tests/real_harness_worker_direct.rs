// SPDX-License-Identifier: MIT

//! Opt-in direct-process coverage for the authenticated watchdog worker client.
//!
//! This test deliberately does not start `Supervisor`, the native process
//! launcher, systemd, or a cgroup. The outer test re-executes an immutable
//! copy of this test binary as the controller, and that controller launches
//! one independently built harness runtime image as a direct child. The
//! harness's downstream gateway/MCP inputs remain synthetic fixtures.

#![cfg(target_os = "linux")]

#[path = "support/real_harness_worker_direct.rs"]
mod real_harness_worker_direct;
#[allow(dead_code)] // Reuse native fixture staging without its service launcher.
#[path = "support/real_harness_worker_fixture.rs"]
mod real_harness_worker_fixture;
#[path = "support/real_harness_worker_gateway.rs"]
mod real_harness_worker_gateway;

const DIRECT_GATE_ENV: &str = "ASCENSION_WATCHDOG_REAL_HARNESS_DIRECT";
const CONTROLLER_ENV: &str = "ASCENSION_WATCHDOG_REAL_HARNESS_DIRECT_CONTROLLER";
const HARNESS_BINARY_ENV: &str = "STS2_HARNESS_RUNTIME_BINARY";
const HARNESS_SHA256_ENV: &str = "STS2_HARNESS_RUNTIME_SHA256";

#[test]
#[ignore = "requires explicit direct-process gate and independently built pinned harness"]
fn real_watchdog_direct_process_harness_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    real_harness_worker_direct::run_controller_reexec(
        DIRECT_GATE_ENV,
        CONTROLLER_ENV,
        HARNESS_BINARY_ENV,
        HARNESS_SHA256_ENV,
    )
}

#[test]
#[ignore = "controller entrypoint for real_watchdog_direct_process_harness_roundtrip"]
fn real_watchdog_direct_controller() -> Result<(), Box<dyn std::error::Error>> {
    real_harness_worker_direct::run_controller(
        DIRECT_GATE_ENV,
        CONTROLLER_ENV,
        HARNESS_BINARY_ENV,
        HARNESS_SHA256_ENV,
    )
}
