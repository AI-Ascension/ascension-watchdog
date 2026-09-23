//! Fail-closed validation of one approved component launch specification.
//!
//! Every bound here is a pre-spawn rejection: identifier shape, owner-local
//! executable and cwd, argument/environment limits and the optional approved
//! digest. Nothing in this module starts a process.

use crate::config::ComponentConfig;
use crate::error::{Result, WatchdogError};

pub(super) fn validate_component(spec: &ComponentConfig) -> Result<()> {
    if spec.id.is_empty() || spec.id.len() > 128 || spec.id.as_bytes().contains(&0) {
        return Err(WatchdogError::InvalidInput(
            "component id is invalid".to_string(),
        ));
    }
    if !spec.executable.is_absolute() || spec.executable.as_os_str().is_empty() {
        return Err(WatchdogError::InvalidInput(format!(
            "component {} executable must be absolute",
            spec.id
        )));
    }
    let executable_text = spec
        .executable
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if executable_text.starts_with("/mnt/")
        || executable_text.starts_with("//wsl")
        || executable_text.contains("/proc/")
    {
        return Err(WatchdogError::InvalidInput(format!(
            "component {} executable must be owner-local",
            spec.id
        )));
    }
    if spec.args.len() > 64
        || spec
            .args
            .iter()
            .any(|arg| arg.as_bytes().len() > 8 * 1024 || arg.as_bytes().contains(&0))
    {
        return Err(WatchdogError::InvalidInput(format!(
            "component {} arguments are outside bounds",
            spec.id
        )));
    }
    if let Some(cwd) = &spec.cwd {
        if !cwd.is_absolute() {
            return Err(WatchdogError::InvalidInput(format!(
                "component {} cwd must be absolute",
                spec.id
            )));
        }
        let cwd_text = cwd
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        if cwd_text.starts_with("/mnt/") || cwd_text.starts_with("//wsl") {
            return Err(WatchdogError::InvalidInput(format!(
                "component {} cwd must be owner-local",
                spec.id
            )));
        }
    }
    if spec.environment.len() > 64
        || spec.environment.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > 128
                || key.contains('=')
                || key.as_bytes().contains(&0)
                || value.as_bytes().len() > 8 * 1024
                || value.as_bytes().contains(&0)
        })
    {
        return Err(WatchdogError::InvalidInput(format!(
            "component {} environment is outside bounds",
            spec.id
        )));
    }
    let launch_bytes = spec
        .args
        .iter()
        .map(String::len)
        .chain(
            spec.environment
                .iter()
                .map(|(key, value)| key.len().saturating_add(value.len())),
        )
        .fold(0_usize, usize::saturating_add);
    if launch_bytes > 32 * 1024 {
        return Err(WatchdogError::InvalidInput(
            "component launch data exceeds aggregate byte limit".to_owned(),
        ));
    }
    if let Some(digest) = &spec.executable_sha256 {
        crate::config::validate_digest(digest).map_err(|message| {
            WatchdogError::InvalidInput(format!("component {}: {message}", spec.id))
        })?;
    }
    Ok(())
}
