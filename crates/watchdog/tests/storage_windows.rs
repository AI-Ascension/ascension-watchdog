//! Windows-only storage handle contract checks.

#![cfg(windows)]

use ascension_watchdog::storage::SingletonLock;
use std::fs;

#[test]
fn owner_lock_prevents_lock_file_replacement_until_release() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database = temp.path().join("watchdog.sqlite3");
    let owner = SingletonLock::acquire(&database).expect("owner lock");
    let lock_path = owner.path().to_path_buf();
    let replacement = temp.path().join("replacement.lock");

    // The lock handle is opened without delete sharing, so an attacker cannot
    // unlink or rename the authoritative file while its owner is alive.
    assert!(fs::remove_file(&lock_path).is_err());
    assert!(fs::rename(&lock_path, &replacement).is_err());
    assert!(lock_path.is_file());

    drop(owner);
    fs::remove_file(lock_path).expect("released lock file can be removed");
}
