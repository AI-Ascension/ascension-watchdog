//! identity component of the Linux process adapter.
//!
//! Extracted from `platform::linux_process` into a cohesive module; the
//! coordinator preserves the public `platform::linux_process` paths and
//! delegates to these items.  Bodies are behaviour-preserving moves.

#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Clone, Debug)]
pub(super) struct LiveProcess {
    pub(super) token: String,
    pub(super) executable: PathBuf,
    pub(super) executable_sha256: String,
    pub(super) executable_sealed: bool,
}

pub(super) fn validate_allowlist(
    allowlist: BTreeMap<ComponentKind, PathBuf>,
) -> Result<BTreeMap<ComponentKind, PathBuf>, AdapterError> {
    for path in allowlist.values() {
        if !path.is_absolute() || path.as_os_str().is_empty() {
            return Err(AdapterError::Invalid(
                "Linux executable allowlist paths must be absolute".to_owned(),
            ));
        }
    }
    Ok(allowlist)
}

pub(super) fn canonical_approved_executable(
    approved: Option<&PathBuf>,
    requested: &Path,
    expected_digest: &str,
) -> Result<PathBuf, AdapterError> {
    let Some(approved) = approved else {
        return Err(AdapterError::Unsupported(
            "component role has no Linux executable allowlist entry".to_owned(),
        ));
    };
    let approved = fs::canonicalize(approved).map_err(|error| {
        AdapterError::Unavailable(format!("approved executable is unavailable: {error}"))
    })?;
    let requested = fs::canonicalize(requested).map_err(|error| {
        AdapterError::Invalid(format!("requested executable cannot be resolved: {error}"))
    })?;
    if approved != requested {
        return Err(AdapterError::IdentityMismatch(
            "requested executable is outside the role allowlist".to_owned(),
        ));
    }
    let digest = hash_file(&requested)?;
    if digest != expected_digest {
        return Err(AdapterError::IdentityMismatch(
            "approved executable digest does not match the launch".to_owned(),
        ));
    }
    Ok(requested)
}

pub(super) fn validate_working_directory(path: Option<&Path>) -> Result<(), AdapterError> {
    let Some(path) = path else {
        return Ok(());
    };
    if !path.is_absolute() {
        return Err(AdapterError::Invalid(
            "Linux working directory must be absolute".to_owned(),
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        AdapterError::Invalid(format!("working directory cannot be resolved: {error}"))
    })?;
    if !canonical.is_dir() {
        return Err(AdapterError::Invalid(
            "Linux working directory is not a directory".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_environment(environment: &[(String, String)]) -> Result<(), AdapterError> {
    for (name, value) in environment {
        if name.is_empty()
            || name.contains('=')
            || name.chars().any(char::is_control)
            || value.chars().any(char::is_control)
        {
            return Err(AdapterError::Invalid(
                "Linux environment contains an invalid name or value".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(super) fn wait_for_target_in_cgroup(
    boot_id: &str,
    cgroup: &Cgroup,
    helper_pid: u32,
    executable: &Path,
    digest: &str,
    timeout: Duration,
    child: &mut Child,
) -> Result<(u32, LiveProcess), AdapterError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    loop {
        if let Some(status) = child.try_wait().map_err(|error| {
            AdapterError::Io(format!("Linux helper status check failed: {error}"))
        })? {
            return Err(AdapterError::Io(format!(
                "Linux helper exited before the approved target appeared: {status}"
            )));
        }
        if !cgroup.pids()?.contains(&helper_pid) {
            return Err(AdapterError::IdentityMismatch(
                "Linux helper left its delegated cgroup before target exec".to_owned(),
            ));
        }
        match read_live_process_for_executable(boot_id, helper_pid, executable) {
            Ok(Some(actual)) if actual.executable_sha256 == digest => {
                return Ok((helper_pid, actual));
            }
            Ok(Some(_) | None) => {}
            Err(AdapterError::Unavailable(_)) => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(AdapterError::Timeout(
                "Linux helper did not produce the approved target in time".to_owned(),
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

pub(super) fn read_live_process_for_executable(
    boot_id: &str,
    pid: u32,
    expected_executable: &Path,
) -> Result<Option<LiveProcess>, AdapterError> {
    if pid == 0 {
        return Err(AdapterError::Invalid("cannot inspect pid zero".to_owned()));
    }
    let stat_path = format!("/proc/{pid}/stat");
    let stat = fs::read_to_string(&stat_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AdapterError::Unavailable(format!("process {pid} does not exist"))
        } else {
            AdapterError::Io(format!("cannot read process {pid} birth data: {error}"))
        }
    })?;
    let start_ticks = parse_start_ticks(&stat)
        .ok_or_else(|| AdapterError::Io(format!("process {pid} has malformed /proc stat data")))?;
    let executable = fs::read_link(format!("/proc/{pid}/exe")).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AdapterError::Unavailable(format!("process {pid} executable is gone"))
        } else {
            AdapterError::Io(format!("cannot read process {pid} executable: {error}"))
        }
    })?;
    let executable_sealed = is_sealed_memfd(&executable);
    if executable != expected_executable {
        if !executable_sealed || !executable_fd_is_sealed(pid)? {
            return Ok(None);
        }
    }
    let executable_sha256 = hash_live_executable(pid)?;
    Ok(Some(LiveProcess {
        token: format!("{boot_id}:{start_ticks}"),
        executable: if executable == expected_executable {
            executable
        } else {
            expected_executable.to_owned()
        },
        executable_sha256,
        executable_sealed,
    }))
}

pub(super) fn identities_match(expected: &ProcessIdentity, actual: &LiveProcess) -> bool {
    expected.creation.token == actual.token
        && expected.executable_sha256 == actual.executable_sha256
        && live_process_matches_executable(
            actual,
            &expected.executable,
            &expected.executable_sha256,
        )
}

pub(super) fn live_process_matches_executable(
    actual: &LiveProcess,
    expected_executable: &Path,
    expected_digest: &str,
) -> bool {
    (actual.executable == expected_executable
        || (actual.executable_sealed && is_sealed_memfd(&actual.executable)))
        && actual.executable_sha256 == expected_digest
}

pub(super) fn read_live_process(boot_id: &str, pid: u32) -> Result<LiveProcess, AdapterError> {
    if pid == 0 {
        return Err(AdapterError::Invalid("cannot inspect pid zero".to_owned()));
    }
    let stat_path = format!("/proc/{pid}/stat");
    let stat = fs::read_to_string(&stat_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AdapterError::Unavailable(format!("process {pid} does not exist"))
        } else {
            AdapterError::Io(format!("cannot read process {pid} birth data: {error}"))
        }
    })?;
    let start_ticks = parse_start_ticks(&stat)
        .ok_or_else(|| AdapterError::Io(format!("process {pid} has malformed /proc stat data")))?;
    let executable = fs::read_link(format!("/proc/{pid}/exe")).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AdapterError::Unavailable(format!("process {pid} executable is gone"))
        } else {
            AdapterError::Io(format!("cannot read process {pid} executable: {error}"))
        }
    })?;
    let executable_sha256 = hash_live_executable(pid)?;
    let executable_sealed = is_sealed_memfd(&executable) && executable_fd_is_sealed(pid)?;
    Ok(LiveProcess {
        token: format!("{boot_id}:{start_ticks}"),
        executable,
        executable_sha256,
        executable_sealed,
    })
}

pub(super) fn read_process_creation_status(
    boot_id: &str,
    pid: u32,
    expected_token: &str,
) -> Result<MissingContainmentStatus, AdapterError> {
    if pid == 0 {
        return Err(AdapterError::Invalid("cannot inspect pid zero".to_owned()));
    }
    let expected_boot_prefix = format!("{boot_id}:");
    if expected_token
        .strip_prefix(&expected_boot_prefix)
        .and_then(|ticks| ticks.parse::<u64>().ok())
        .is_none()
    {
        return Err(AdapterError::Invalid(
            "recorded Linux process creation token is malformed".to_owned(),
        ));
    }
    let stat_path = format!("/proc/{pid}/stat");
    let stat = fs::read_to_string(&stat_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AdapterError::Unavailable(format!("process {pid} does not exist"))
        } else {
            AdapterError::Io(format!("cannot read process {pid} birth data: {error}"))
        }
    });
    let stat = match stat {
        Ok(stat) => stat,
        Err(AdapterError::Unavailable(_)) => return Ok(MissingContainmentStatus::Absent),
        Err(error) => return Err(error),
    };
    let start_ticks = parse_start_ticks(&stat)
        .ok_or_else(|| AdapterError::Io(format!("process {pid} has malformed /proc stat data")))?;
    let actual_token = format!("{boot_id}:{start_ticks}");
    if actual_token == expected_token {
        Ok(MissingContainmentStatus::Present)
    } else {
        Ok(MissingContainmentStatus::Reused)
    }
}

pub(super) fn is_sealed_memfd(path: &Path) -> bool {
    path.to_str()
        .is_some_and(|value| value.starts_with("/memfd:"))
}

pub(super) fn executable_fd_is_sealed(pid: u32) -> Result<bool, AdapterError> {
    let path = format!("/proc/{pid}/exe");
    let flags = rustix::fs::OFlags::NONBLOCK
        .bits()
        .try_into()
        .map_err(|_| AdapterError::Invalid("Linux nonblocking flag is out of range".to_owned()))?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|error| {
            AdapterError::Unavailable(format!(
                "cannot open live executable for seal check: {error}"
            ))
        })?;
    let seals = fcntl_get_seals(&file).map_err(|error| {
        AdapterError::Unavailable(format!("cannot inspect live executable seals: {error}"))
    })?;
    Ok(seals.contains(SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL))
}

pub(super) fn hash_live_executable(pid: u32) -> Result<String, AdapterError> {
    hash_file(Path::new(&format!("/proc/{pid}/exe")))
}

pub(super) fn parse_start_ticks(stat: &str) -> Option<u64> {
    let close = stat.rfind(')')?;
    let suffix = stat.get(close + 2..)?;
    suffix.split_whitespace().nth(19)?.parse().ok()
}

pub(super) fn read_boot_id() -> Result<String, AdapterError> {
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|error| {
        AdapterError::Unavailable(format!("Linux boot identity is unavailable: {error}"))
    })?;
    let boot_id = boot_id.trim();
    if boot_id.is_empty()
        || boot_id.len() > MAX_BOOT_ID_BYTES
        || boot_id.contains(['\0', '\n', '\r'])
    {
        return Err(AdapterError::Unavailable(
            "Linux boot identity is malformed".to_owned(),
        ));
    }
    Ok(boot_id.to_owned())
}

pub(super) fn hash_file(path: &Path) -> Result<String, AdapterError> {
    let flags = rustix::fs::OFlags::NONBLOCK
        .bits()
        .try_into()
        .map_err(|_| AdapterError::Invalid("Linux nonblocking flag is out of range".to_owned()))?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|error| {
            AdapterError::Unavailable(format!("cannot open executable bytes: {error}"))
        })?;
    let metadata = file.metadata().map_err(|error| {
        AdapterError::Unavailable(format!("cannot inspect executable bytes: {error}"))
    })?;
    if !metadata.is_file() {
        return Err(AdapterError::Invalid(
            "executable is not a regular file".to_owned(),
        ));
    }
    if metadata.len() > MAX_HASH_BYTES {
        return Err(AdapterError::Invalid(
            "executable exceeds the hash size bound".to_owned(),
        ));
    }
    let mut reader = file;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total_read = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| AdapterError::Io(format!("cannot hash executable: {error}")))?;
        if read == 0 {
            break;
        }
        total_read = total_read
            .checked_add(u64::try_from(read).map_err(|_| {
                AdapterError::Invalid("executable read size exceeds bounds".to_owned())
            })?)
            .ok_or_else(|| {
                AdapterError::Invalid("executable exceeds the hash size bound".to_owned())
            })?;
        if total_read > MAX_HASH_BYTES {
            return Err(AdapterError::Invalid(
                "executable exceeds the hash size bound".to_owned(),
            ));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
