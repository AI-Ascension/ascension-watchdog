#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;

#[test]
fn linux_install_and_uninstall_are_idempotent_and_require_stopped_owner() {
    let unshare = match Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--pid",
            "--fork",
            "true",
        ])
        .status()
    {
        Ok(status) if status.success() => "unshare",
        Ok(status) => {
            eprintln!("skipping namespace installer test: unshare exited {status}");
            return;
        }
        Err(error) => {
            eprintln!("skipping namespace installer test: unshare unavailable: {error}");
            return;
        }
    };

    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("crate manifest has a repository parent")
        .to_path_buf();
    let harness = repository.join("deploy/linux/test-install-uninstall.sh");
    let status = Command::new(unshare)
        .args(["--user", "--map-root-user", "--mount", "--pid", "--fork"])
        .arg("sh")
        .arg(&harness)
        .arg(&repository)
        .status()
        .expect("run namespace installer harness");
    if status.code() == Some(77) {
        eprintln!("skipping namespace installer test: mount unavailable");
        return;
    }
    assert!(
        status.success(),
        "namespace installer harness failed: {status}"
    );
}
