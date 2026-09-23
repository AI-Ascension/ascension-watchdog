//! Lock file shape and on-disk byte validation.

use crate::Result;
use crate::bundle::append_bundle_record;
use crate::digest::sha256_hex;
use crate::identifiers::{
    unique, valid_commit, valid_hex_digest, valid_prefixed_digest, valid_profile_id,
    valid_relative_path, valid_repository,
};
use crate::model::{LockFile, Profile};
use crate::paths::{collect_files, require_regular_file, safe_join};
use std::fs;
use std::path::Path;

pub(crate) fn validate_lock_shape(lock: &LockFile, profile: &Profile) -> Result<()> {
    if !valid_hex_digest(&lock.profile_sha256) {
        return Err("invalid profile configuration digest".to_owned());
    }
    if lock.lock_version != 1 {
        return Err("lock_version must be 1".to_owned());
    }
    if !valid_repository(&lock.repository) || lock.repository != profile.repository {
        return Err("lock repository does not match profile".to_owned());
    }
    if !valid_profile_id(&lock.profile_id) || lock.profile_id != profile.profile_id {
        return Err("lock profile_id does not match profile".to_owned());
    }
    if lock.source.repository != "AI-Ascension/.github" {
        return Err("lock source.repository must be AI-Ascension/.github".to_owned());
    }
    if !valid_commit(&lock.source.commit) || lock.source.commit != profile.source_commit {
        return Err("lock source.commit does not match profile source_commit".to_owned());
    }
    if !valid_prefixed_digest(&lock.source.bundle_digest)
        || lock.source.bundle_digest != profile.source_digest
    {
        return Err("lock bundle_digest does not match profile source_digest".to_owned());
    }
    if lock.source.distribution != "local" {
        return Err("lock source.distribution must be local".to_owned());
    }
    if lock.source.published {
        return Err(
            "local source must keep published=false until remote publication is verified"
                .to_owned(),
        );
    }
    if lock.generated_by != "standards-sync/1" {
        return Err("lock generated_by must be standards-sync/1".to_owned());
    }
    if lock.files.is_empty() {
        return Err("lock files must contain at least one entry".to_owned());
    }
    if lock.protected_paths.is_empty() || !unique(&lock.protected_paths) {
        return Err("protected_paths must be non-empty and unique".to_owned());
    }
    for path in &lock.protected_paths {
        if !path.starts_with("standards/") || !valid_relative_path(path) {
            return Err(format!("unsafe protected path '{path}'"));
        }
    }
    let mut previous: Option<&str> = None;
    for entry in &lock.files {
        if !entry.path.starts_with("standards/")
            || !valid_relative_path(&entry.path)
            || !valid_hex_digest(&entry.sha256)
        {
            return Err(format!("invalid lock entry '{}'", entry.path));
        }
        if previous.is_some_and(|old| old >= entry.path.as_str()) {
            return Err("lock files must be sorted and unique".to_owned());
        }
        previous = Some(&entry.path);
    }
    Ok(())
}

pub(crate) fn validate_lock_bytes(root: &Path, lock: &LockFile) -> Result<()> {
    let mut bundle_input = Vec::new();
    for entry in &lock.files {
        let full = safe_join(root, &entry.path)?;
        require_regular_file(&full)?;
        let bytes =
            fs::read(&full).map_err(|error| format!("cannot read {}: {error}", full.display()))?;
        let actual = sha256_hex(&bytes);
        if actual != entry.sha256 {
            return Err(format!(
                "digest mismatch for {}: expected {}, got {actual}",
                entry.path, entry.sha256
            ));
        }
        append_bundle_record(&mut bundle_input, &entry.path, &bytes);
    }
    let actual_bundle = format!("sha256:{}", sha256_hex(&bundle_input));
    if actual_bundle != lock.source.bundle_digest {
        return Err(format!(
            "bundle digest mismatch: expected {}, got {actual_bundle}",
            lock.source.bundle_digest
        ));
    }

    let standards = root.join("standards");
    let mut actual_files = Vec::new();
    collect_files(&standards, &standards, &mut actual_files)?;
    actual_files.sort();
    let locked: Vec<String> = lock.files.iter().map(|entry| entry.path.clone()).collect();
    if actual_files != locked {
        return Err(format!(
            "lock inventory differs from local standards files: lock has {} entries, local tree has {}",
            locked.len(),
            actual_files.len()
        ));
    }
    Ok(())
}
