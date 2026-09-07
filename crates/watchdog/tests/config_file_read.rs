// SPDX-License-Identifier: MIT

#![cfg(target_os = "linux")]

use std::error::Error;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Probe(Child);

impl Drop for Probe {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(Some(_))) {
            return;
        }
        let _ = self.0.kill();
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if matches!(self.0.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        eprintln!("configuration probe cleanup could not confirm direct child exit");
    }
}

#[test]
fn config_fifo_is_rejected_without_waiting_for_a_writer() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("watchdog.json");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &path,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )?;
    // This command has no child-launch path, and both streams are discarded.
    // The parent bounds and reaps the exact child even against the old reader.
    let mut child = Probe(
        Command::new(env!("CARGO_BIN_EXE_watchdog"))
            .args(["config", "validate"])
            .arg(&path)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child.0.try_wait()? {
            assert!(!status.success(), "FIFO configuration was accepted");
            return Ok(());
        }
        if Instant::now() >= deadline {
            child.0.kill()?;
            let reap_deadline = Instant::now() + Duration::from_secs(1);
            while child.0.try_wait()?.is_none() {
                if Instant::now() >= reap_deadline {
                    return Err("configuration child did not reap after kill".into());
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            return Err("configuration reader blocked on FIFO".into());
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn configuration_rejects_leaf_and_ancestor_links() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir()?;
    let real = directory.path().join("real");
    std::fs::create_dir(&real)?;
    let path = real.join("watchdog.json");
    ascension_watchdog::WatchdogConfig::default().to_file(&path)?;
    let leaf_link = directory.path().join("leaf.json");
    let ancestor_link = directory.path().join("linked");
    symlink(&path, &leaf_link)?;
    symlink(&real, &ancestor_link)?;
    assert!(ascension_watchdog::WatchdogConfig::from_file(&leaf_link).is_err());
    assert!(
        ascension_watchdog::WatchdogConfig::from_file(ancestor_link.join("watchdog.json")).is_err()
    );
    assert!(ascension_watchdog::WatchdogConfig::from_file(&path).is_ok());
    Ok(())
}

#[test]
fn configuration_bounds_regular_files_and_normalizes_its_source() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("watchdog.json");
    ascension_watchdog::WatchdogConfig::default().to_file(&path)?;
    let loaded = ascension_watchdog::WatchdogConfig::from_file(&path)?;
    assert_eq!(loaded.source_path.as_ref(), Some(&path));
    assert!(ascension_watchdog::WatchdogConfig::from_file(directory.path()).is_err());
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)?
        .set_len(65_537)?;
    assert!(ascension_watchdog::WatchdogConfig::from_file(&path).is_err());
    assert!(
        ascension_watchdog::WatchdogConfig::from_file(directory.path().join("../watchdog.json"))
            .is_err()
    );
    Ok(())
}
