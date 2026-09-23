//! Cgroup discovery and membership verification.

use crate::platform::contract::AdapterError;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

pub(super) fn verify_current_cgroup(expected: &Path) -> Result<(), AdapterError> {
    let expected = fs::canonicalize(expected).map_err(|error| {
        AdapterError::Unavailable(format!("Linux helper cgroup cannot be resolved: {error}"))
    })?;
    let current = discover_current_cgroup()?;
    if current != expected {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper is not in the authorized cgroup".to_owned(),
        ));
    }
    let pid = std::process::id();
    let pids = fs::read_to_string(expected.join("cgroup.procs")).map_err(|error| {
        AdapterError::Unavailable(format!(
            "Linux helper cgroup membership is unreadable: {error}"
        ))
    })?;
    if !pids
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .any(|member| member == pid)
    {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper PID is not present in the authorized cgroup".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn discover_current_cgroup() -> Result<PathBuf, AdapterError> {
    let mountpoint = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| {
            AdapterError::Unavailable(format!("cgroup mountinfo unavailable: {error}"))
        })?
        .lines()
        .find_map(parse_cgroup2_mountpoint)
        .ok_or_else(|| AdapterError::Unavailable("no cgroup v2 mount is available".to_owned()))?;
    let relative = fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| AdapterError::Unavailable(format!("process cgroup unavailable: {error}")))?
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
        .ok_or_else(|| AdapterError::Unavailable("process has no cgroup v2 path".to_owned()))?;
    let relative = relative.trim_start_matches('/');
    if relative
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(AdapterError::Unavailable(
            "process cgroup path is malformed".to_owned(),
        ));
    }
    let path = if relative.is_empty() {
        mountpoint
    } else {
        mountpoint.join(relative)
    };
    fs::canonicalize(path).map_err(|error| {
        AdapterError::Unavailable(format!("current cgroup cannot be resolved: {error}"))
    })
}

pub(super) fn parse_cgroup2_mountpoint(line: &str) -> Option<PathBuf> {
    let mut sections = line.split(" - ");
    let pre = sections.next()?;
    let post = sections.next()?;
    if post.split_whitespace().next()? != "cgroup2" {
        return None;
    }
    let fields = pre.split_whitespace().collect::<Vec<_>>();
    fields
        .get(4)
        .map(|field| PathBuf::from(unescape_mountinfo(field)))
}

pub(super) fn unescape_mountinfo(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\134", "\\")
}
