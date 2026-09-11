#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;

#[test]
fn packaging_preflight_runs_without_scm_mutation() {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|error| panic!("repository root must be available: {error}"));
    let script = repository.join("deploy/windows/test-install-uninstall.ps1");
    let output = Command::new("pwsh")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            script.to_string_lossy().as_ref(),
            "-RepositoryPath",
            repository.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap_or_else(|error| panic!("pwsh packaging preflight could not start: {error}"));
    assert!(
        output.status.success(),
        "packaging preflight failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
