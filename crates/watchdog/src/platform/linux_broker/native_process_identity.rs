//! Exact process identity: creation token, executable proof and status checks.
//!
//! Every read is bounded and every comparison is against the caller's exact
//! [`UnitObservation`]/[`LaunchPolicy`]; a mismatch is a conflict, never a
//! successful adoption. These free functions are shared by the transport
//! inspection path and the backend's containment proofs.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn verify_held_process(
    expected: &UnitObservation,
    controls: &mut HeldCgroup,
    deadline: Instant,
) -> BrokerResult<rustix::fd::OwnedFd> {
    if !controls.contains(expected.pid, deadline)? {
        return Err(BrokerError::Conflict(
            "original process is not in held containment".to_owned(),
        ));
    }
    let pid =
        Pid::from_raw(i32::try_from(expected.pid).map_err(|_| {
            BrokerError::Conflict("process PID is outside native bounds".to_owned())
        })?)
        .ok_or_else(|| BrokerError::Conflict("process PID is zero".to_owned()))?;
    let pidfd = pidfd_open(pid, PidfdFlags::empty())
        .map_err(|error| BrokerError::Conflict(format!("exact process is unavailable: {error}")))?;
    let policy = NativeSystemdBackend::observation_policy(expected);
    let process =
        read_process_postcondition(expected.pid, &policy, &expected.control_group, deadline)?;
    if process.creation_token != expected.creation_token
        || process.executable != expected.executable
        || process.executable_sha256 != expected.executable_sha256
        || process.uid != expected.uid
        || process.gid != expected.gid
        || process.capability_bounding_set != expected.capability_bounding_set
        || process.ambient_capabilities != expected.ambient_capabilities
        || process.no_new_privileges != expected.no_new_privileges
        || !controls.contains(expected.pid, deadline)?
    {
        return Err(BrokerError::Conflict(
            "exact process binding changed during containment verification".to_owned(),
        ));
    }
    Ok(pidfd)
}

#[cfg(target_os = "linux")]
pub(super) struct ProcessPostcondition {
    pub(super) creation_token: String,
    pub(super) executable: PathBuf,
    pub(super) executable_sha256: String,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) capability_bounding_set: u64,
    pub(super) ambient_capabilities: u64,
    pub(super) no_new_privileges: bool,
}

#[cfg(target_os = "linux")]
pub(super) fn read_process_postcondition(
    pid: u32,
    policy: &LaunchPolicy,
    control_group: &str,
    deadline: Instant,
) -> BrokerResult<ProcessPostcondition> {
    let executable = process_executable_proof(pid, policy, deadline)?;
    let status = String::from_utf8(read_bounded_file(
        Path::new(&format!("/proc/{pid}/status")),
        MAX_FRAME_BYTES,
        "process status",
    )?)
    .map_err(|_| BrokerError::Conflict("process status is not UTF-8".to_owned()))?;
    let uid = parse_status_quad(&status, "Uid")?;
    let gid = parse_status_quad(&status, "Gid")?;
    if uid.iter().any(|value| *value != policy.target_uid)
        || gid.iter().any(|value| *value != policy.target_gid)
    {
        return Err(BrokerError::Conflict(
            "systemd target UID/GID postcheck failed".to_owned(),
        ));
    }
    require_no_supplementary_groups(&status)?;
    let cap_bounding_set = parse_hex_status(&status, "CapBnd")?;
    let ambient_capabilities = parse_hex_status(&status, "CapAmb")?;
    let no_new_privileges = status
        .lines()
        .find_map(|line| line.strip_prefix("NoNewPrivs:"))
        .map(str::trim)
        .is_some_and(|value| value == "1");
    if !no_new_privileges
        || cap_bounding_set != policy.capabilities.bounding_set
        || ambient_capabilities != policy.capabilities.ambient_set
    {
        return Err(BrokerError::Conflict(
            "systemd capability postcheck failed".to_owned(),
        ));
    }
    let cgroup = String::from_utf8(read_bounded_file(
        Path::new(&format!("/proc/{pid}/cgroup")),
        MAX_FRAME_BYTES,
        "process cgroup",
    )?)
    .map_err(|_| BrokerError::Conflict("process cgroup is not UTF-8".to_owned()))?;
    let actual_cgroup = cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| {
            BrokerError::Conflict("target has no unified cgroup membership".to_owned())
        })?;
    if actual_cgroup != control_group {
        return Err(BrokerError::Conflict(
            "target cgroup does not match exact systemd unit".to_owned(),
        ));
    }
    let final_executable = process_executable_proof(pid, policy, deadline)?;
    if executable.creation_token != final_executable.creation_token
        || executable.executable != final_executable.executable
        || executable.executable_sha256 != final_executable.executable_sha256
    {
        return Err(BrokerError::Conflict(
            "target executable identity changed during postcheck".to_owned(),
        ));
    }
    Ok(ProcessPostcondition {
        creation_token: final_executable.creation_token,
        executable: final_executable.executable,
        executable_sha256: final_executable.executable_sha256,
        uid: policy.target_uid,
        gid: policy.target_gid,
        capability_bounding_set: cap_bounding_set,
        ambient_capabilities,
        no_new_privileges,
    })
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessExecutableProof {
    creation_token: String,
    executable: PathBuf,
    pub(super) executable_sha256: String,
}

/// Pin the PID while checking its current executable.  The start token alone
/// does not bind an execve result, and a path-only check does not bind the
/// inode contents.  Both the exact /proc/PID/exe path and its digest must
/// match the immutable launch policy before a unit is acknowledged.
#[cfg(target_os = "linux")]
fn process_executable_proof(
    pid: u32,
    policy: &LaunchPolicy,
    deadline: Instant,
) -> BrokerResult<ProcessExecutableProof> {
    let process = Pid::from_raw(
        i32::try_from(pid)
            .map_err(|_| BrokerError::Conflict("process PID is out of bounds".to_owned()))?,
    )
    .ok_or_else(|| BrokerError::Conflict("process PID is zero".to_owned()))?;
    let _pidfd = pidfd_open(process, PidfdFlags::empty()).map_err(|error| {
        BrokerError::Conflict(format!("process identity is unavailable: {error}"))
    })?;
    let creation_before = process_start_token(pid)?;
    let proc_executable = PathBuf::from(format!("/proc/{pid}/exe"));
    let executable = fs::read_link(&proc_executable).map_err(io_error)?;
    if executable != policy.executable {
        return Err(BrokerError::Conflict(
            "process executable path does not match fixed policy".to_owned(),
        ));
    }
    let executable_sha256 =
        hash_open_file_until(File::open(&proc_executable).map_err(io_error)?, deadline)?;
    let creation_after = process_start_token(pid)?;
    let executable_after = fs::read_link(&proc_executable).map_err(io_error)?;
    if creation_before != creation_after || executable != executable_after {
        return Err(BrokerError::Conflict(
            "process executable identity changed during proof".to_owned(),
        ));
    }
    if executable_sha256 != policy.executable_sha256 {
        return Err(BrokerError::Conflict(
            "process executable digest does not match fixed policy".to_owned(),
        ));
    }
    Ok(ProcessExecutableProof {
        creation_token: creation_after,
        executable: executable_after,
        executable_sha256,
    })
}

#[cfg(all(target_os = "linux", test))]
pub(crate) fn verify_process_executable(pid: u32, policy: &LaunchPolicy) -> BrokerResult<()> {
    process_executable_proof(pid, policy, Instant::now() + policy.timeout).map(|_| ())
}

#[cfg(target_os = "linux")]
pub(crate) fn require_no_supplementary_groups(status: &str) -> BrokerResult<()> {
    let groups = status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:"))
        .ok_or_else(|| BrokerError::Conflict("process status lacks Groups".to_owned()))?;
    if !groups.trim().is_empty() {
        return Err(BrokerError::Conflict(
            "systemd supplementary-group postcheck failed".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_status_quad(status: &str, field: &str) -> BrokerResult<[u32; 4]> {
    let values = status
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{field}:")))
        .ok_or_else(|| BrokerError::Conflict(format!("process status lacks {field}")))?
        .split_whitespace()
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| BrokerError::Conflict(format!("process status has invalid {field}")))
        })
        .collect::<BrokerResult<Vec<_>>>()?;
    values
        .try_into()
        .map_err(|_| BrokerError::Conflict(format!("process status has incomplete {field}")))
}

#[cfg(target_os = "linux")]
fn parse_hex_status(status: &str, field: &str) -> BrokerResult<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{field}:")))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .ok_or_else(|| BrokerError::Conflict(format!("process status has invalid {field}")))
}

#[cfg(target_os = "linux")]
pub(crate) fn process_start_token(pid: u32) -> BrokerResult<String> {
    let boot_id = String::from_utf8(read_bounded_file(
        Path::new("/proc/sys/kernel/random/boot_id"),
        37,
        "kernel boot identity",
    )?)
    .map_err(|_| BrokerError::Conflict("kernel boot identity is not UTF-8".to_owned()))?;
    let stat = String::from_utf8(read_bounded_file(
        Path::new(&format!("/proc/{pid}/stat")),
        MAX_FRAME_BYTES,
        "process stat",
    )?)
    .map_err(|_| BrokerError::Conflict("process stat is not UTF-8".to_owned()))?;
    boot_scoped_start_token(&boot_id, &stat)
}

pub(crate) fn boot_scoped_start_token(boot_id: &str, stat: &str) -> BrokerResult<String> {
    let boot_id = boot_id.strip_suffix('\n').unwrap_or(boot_id);
    let boot = uuid::Uuid::parse_str(boot_id)
        .map_err(|_| BrokerError::Conflict("kernel boot identity is invalid".to_owned()))?;
    if boot.is_nil() || boot.to_string() != boot_id {
        return Err(BrokerError::Conflict(
            "kernel boot identity is not canonical".to_owned(),
        ));
    }
    let close = stat.rfind(')').ok_or_else(|| {
        BrokerError::Conflict("process stat has no command terminator".to_owned())
    })?;
    let ticks = stat
        .get(close + 2..)
        .and_then(|suffix| suffix.split_whitespace().nth(19))
        .ok_or_else(|| BrokerError::Conflict("process stat has no start token".to_owned()))?;
    let value = ticks
        .parse::<u64>()
        .map_err(|_| BrokerError::Conflict("process start ticks are invalid".to_owned()))?;
    if value.to_string() != ticks {
        return Err(BrokerError::Conflict(
            "process start ticks are not canonical".to_owned(),
        ));
    }
    // A durable receipt must not collide with the same PID/start tick after a
    // reboot. This broker token is separate from decimal worker-IPC birth fields.
    Ok(format!("boot:{boot_id}:{ticks}"))
}
