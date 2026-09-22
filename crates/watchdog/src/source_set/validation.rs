//! Manifest schema parsing plus the shared identity and digest primitives.
//!
//! These helpers are the unauthenticated admission layer: they only ever
//! inspect already-parsed values and never touch the filesystem or Git.

use super::SourceSetManifest;

pub(super) fn validate_manifest(manifest: &SourceSetManifest) -> Result<(), String> {
    if manifest.schema_version != 1 {
        return Err(format!(
            "unsupported source-set manifest schema version {}",
            manifest.schema_version
        ));
    }
    if manifest.classification.trim().is_empty() {
        return Err("source-set manifest classification is empty".to_owned());
    }
    if manifest.repositories.is_empty() {
        return Err("source-set manifest has no repositories".to_owned());
    }
    for (name, pin) in &manifest.repositories {
        if name.is_empty() || name.contains('/') || name.contains('\\') {
            return Err(format!("invalid source repository name {name:?}"));
        }
        if !valid_revision(&pin.revision) {
            return Err(format!(
                "source repository {name} does not use a full commit pin"
            ));
        }
        if let Some(source_revision) = &pin.source_revision {
            if !valid_revision(source_revision) {
                return Err(format!(
                    "source repository {name} has an invalid source revision pin"
                ));
            }
        }
        if let Some(source_tree) = &pin.source_tree {
            if !valid_revision(source_tree) {
                return Err(format!(
                    "source repository {name} has an invalid source tree pin"
                ));
            }
        }
        if pin.source_revision.is_some() != pin.source_tree.is_some() {
            return Err(format!(
                "source repository {name} must pin source_revision and source_tree together"
            ));
        }
        if pin.reference.trim().is_empty() {
            return Err(format!("source repository {name} has an empty ref"));
        }
        if normalize_remote(&pin.remote).is_none() {
            return Err(format!(
                "source repository {name} has an unsupported remote"
            ));
        }
    }
    Ok(())
}

pub(super) fn normalize_remote(remote: &str) -> Option<String> {
    let remote = remote.trim().trim_end_matches('/').trim_end_matches(".git");
    let repository = if let Some(repository) = remote.strip_prefix("git@github.com:") {
        repository
    } else if let Some(repository) = remote.strip_prefix("https://github.com/") {
        repository
    } else if let Some(repository) = remote.strip_prefix("ssh://git@github.com/") {
        repository
    } else if !remote.contains("://") && !remote.contains(':') {
        remote
    } else {
        return None;
    };
    let repository = repository.trim_matches('/');
    (repository.split('/').count() == 2 && !repository.contains(char::is_whitespace))
        .then(|| repository.to_owned())
}

fn valid_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn digest_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(DIGITS[usize::from(byte >> 4)]),
                char::from(DIGITS[usize::from(byte & 15)]),
            ]
        })
        .collect()
}
