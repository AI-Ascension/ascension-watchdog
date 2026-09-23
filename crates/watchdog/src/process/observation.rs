//! Non-reaping child observation and exact process-group membership proofs.
//!
//! Unix observation uses `waitid(WNOWAIT)` so the direct child's PID and PGID
//! stay reserved until the group cleanup proof completes; membership is read
//! from `/proc` because a group `kill` status alone includes the zombie leader.

use crate::error::{Result, WatchdogError};
use std::process::Child;
#[cfg(not(unix))]
use std::process::ExitStatus;
#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use super::identity::parse_proc_stat_identity;
#[cfg(unix)]
use rustix::process::{
    Pid, Signal, WaitId, WaitIdOptions, kill_process_group, test_kill_process_group, waitid,
};

#[cfg(unix)]
pub(super) fn observe_child_exit(child: &mut Child) -> Result<Option<()>> {
    let status = waitid(
        WaitId::Pid(Pid::from_child(child)),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    )
    .map_err(|error| WatchdogError::Io(std::io::Error::from(error)))?;
    Ok(status.map(|_| ()))
}

#[cfg(unix)]
pub(super) fn signal_process_group(pgid: Pid) -> std::io::Result<()> {
    kill_process_group(pgid, Signal::KILL).map_err(std::io::Error::from)
}

#[cfg(not(unix))]
pub(super) fn observe_child_exit(child: &mut Child) -> Result<Option<ExitStatus>> {
    child.try_wait().map_err(WatchdogError::from)
}

#[cfg(unix)]
pub(super) fn wait_for_child_exit(child: &mut Child, deadline: Instant) -> Result<()> {
    loop {
        if observe_child_exit(child)?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(WatchdogError::Timeout(
                "owned child did not exit before cleanup deadline".to_owned(),
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(unix)]
pub(super) fn group_has_other_members(pgid: Pid, leader_pid: u32) -> Result<bool> {
    match test_kill_process_group(pgid) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::SRCH => return Ok(false),
        Err(error) => return Err(WatchdogError::Io(std::io::Error::from(error))),
    }

    #[cfg(target_os = "linux")]
    {
        let entries = std::fs::read_dir("/proc")?;
        for entry in entries {
            let entry = entry?;
            let Some(member_pid) = entry
                .file_name()
                .to_str()
                .and_then(|value| value.parse::<u32>().ok())
            else {
                continue;
            };
            if member_pid == leader_pid {
                continue;
            }
            let stat_path = entry.path().join("stat");
            let stat = match std::fs::read_to_string(stat_path) {
                Ok(stat) => stat,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(WatchdogError::Io(error)),
            };
            let Some((_, process_group)) = parse_proc_stat_identity(&stat) else {
                return Err(WatchdogError::Conflict(format!(
                    "cannot prove process-group membership for pid {member_pid}"
                )));
            };
            if process_group == pgid.as_raw_pid() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = leader_pid;
        Err(WatchdogError::Unsupported(
            "exact synthetic process-group membership proof is unavailable on this Unix target"
                .to_owned(),
        ))
    }
}
