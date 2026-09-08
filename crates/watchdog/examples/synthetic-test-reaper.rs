// SPDX-License-Identifier: MIT
//! Linux-only test runner for synthetic process suites.
//!
//! Invoke this binary as PID 1 in a fresh user and PID namespace with a
//! private `/proc`, for example through `unshare --user --map-root-user
//! --pid --fork --mount-proc`.  PID 1 owns every orphaned descendant in that
//! namespace, so it can reap them without using a host-wide subreaper.
//!
//! The runner never signals a process.  A workload or drain timeout returns a
//! failure from namespace init; Linux then terminates only the children in
//! this test namespace.  The target status is returned unchanged when the
//! target and all descendants finish within their bounds.

#[cfg(target_os = "linux")]
mod linux {
    use rustix::process::{
        Pid, WaitOptions, WaitStatus, getpid, getppid, set_child_subreaper, wait,
    };
    use std::ffi::OsString;
    use std::fs;
    use std::io as std_io;
    use std::process::Command;
    use std::thread;
    use std::time::{Duration, Instant};

    pub const RUNNER_FAILURE_EXIT: u8 = 125;
    const DEFAULT_WORKLOAD_TIMEOUT: Duration = Duration::from_mins(5);
    const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
    const MAX_WORKLOAD_TIMEOUT: Duration = Duration::from_hours(1);
    const MAX_DRAIN_TIMEOUT: Duration = Duration::from_mins(1);
    const ADOPTION_SETTLE: Duration = Duration::from_millis(50);
    const POLL_INTERVAL: Duration = Duration::from_millis(5);

    struct Options {
        workload_timeout: Duration,
        drain_timeout: Duration,
        command: Vec<OsString>,
    }

    /// Return a bounded timeout parsed from a `--*-timeout-ms=` option.
    fn parse_timeout(value: &str, option: &str, maximum: Duration) -> Result<Duration, String> {
        let milliseconds = value
            .parse::<u64>()
            .map_err(|_| format!("{option} must be an unsigned millisecond count"))?;
        if milliseconds == 0 || u128::from(milliseconds) > maximum.as_millis() {
            return Err(format!(
                "{option} must be within 1..={} milliseconds",
                maximum.as_millis()
            ));
        }
        let seconds = Duration::from_secs(milliseconds / 1_000);
        let remainder = Duration::from_millis(milliseconds % 1_000);
        seconds
            .checked_add(remainder)
            .ok_or_else(|| format!("{option} is too large"))
    }

    fn parse_options(args: impl Iterator<Item = OsString>) -> Result<Options, String> {
        let mut workload_timeout = DEFAULT_WORKLOAD_TIMEOUT;
        let mut drain_timeout = DEFAULT_DRAIN_TIMEOUT;
        let mut command = Vec::new();
        let mut after_separator = false;

        for arg in args {
            if !after_separator && arg == "--" {
                after_separator = true;
                continue;
            }
            if !after_separator && let Some(text) = arg.to_str() {
                if let Some(value) = text.strip_prefix("--workload-timeout-ms=") {
                    workload_timeout =
                        parse_timeout(value, "--workload-timeout-ms", MAX_WORKLOAD_TIMEOUT)?;
                    continue;
                }
                if let Some(value) = text.strip_prefix("--drain-timeout-ms=") {
                    drain_timeout = parse_timeout(value, "--drain-timeout-ms", MAX_DRAIN_TIMEOUT)?;
                    continue;
                }
                if text.starts_with('-') {
                    return Err(format!("unknown runner option: {text}"));
                }
            }
            command.push(arg);
        }

        if command.is_empty() {
            return Err(
                "expected a target executable, optionally after `--` (runner options use `--name=value`)"
                    .to_owned(),
            );
        }
        Ok(Options {
            workload_timeout,
            drain_timeout,
            command,
        })
    }

    fn status_field<'a>(status: &'a str, name: &str) -> Option<&'a str> {
        status.lines().find_map(|line| {
            line.strip_prefix(name)
                .and_then(|value| value.strip_prefix(':'))
                .map(str::trim)
        })
    }

    fn last_namespace_pid(status: &str) -> Option<u32> {
        status_field(status, "NSpid")?
            .split_whitespace()
            .last()?
            .parse()
            .ok()
    }

    fn proc_mount_is_present(mountinfo: &str) -> bool {
        mountinfo.lines().any(|line| {
            let Some((mount_fields, filesystem_fields)) = line.split_once(" - ") else {
                return false;
            };
            let mount_fields = mount_fields.split_whitespace().collect::<Vec<_>>();
            let filesystem = filesystem_fields.split_whitespace().next();
            mount_fields
                .get(4)
                .is_some_and(|mountpoint| *mountpoint == "/proc")
                && filesystem == Some("proc")
        })
    }

    /// The runner must be namespace init before it can wait for every child
    /// process in this namespace.
    /// Matching PID namespace descriptors and a proc mount prevent an
    /// inherited host `/proc` from making host processes appear owned here.
    fn ensure_private_namespace_init() -> std_io::Result<()> {
        if getpid() != Pid::INIT {
            return Err(std_io::Error::other(
                "synthetic test reaper must run as PID 1 in its namespace",
            ));
        }
        if getppid().is_some() {
            return Err(std_io::Error::other(
                "namespace init unexpectedly has a visible parent",
            ));
        }

        let self_namespace = fs::read_link("/proc/self/ns/pid")?;
        let init_namespace = fs::read_link("/proc/1/ns/pid")?;
        if self_namespace != init_namespace {
            return Err(std_io::Error::other(
                "the /proc view does not match the runner PID namespace",
            ));
        }
        if !proc_mount_is_present(&fs::read_to_string("/proc/self/mountinfo")?) {
            return Err(std_io::Error::other(
                "a private proc filesystem mounted at /proc is required",
            ));
        }

        let self_status = fs::read_to_string("/proc/self/status")?;
        let init_status = fs::read_to_string("/proc/1/status")?;
        for (label, status) in [("self", self_status), ("init", init_status)] {
            if status_field(&status, "Pid") != Some("1") || last_namespace_pid(&status) != Some(1) {
                return Err(std_io::Error::other(format!(
                    "/proc/{label} does not describe namespace PID 1",
                )));
            }
        }
        Ok(())
    }

    /// Return whether `/proc` contains a namespace process other than init.
    /// A mismatching `NSpid` field fails closed instead of treating a host
    /// process as a test-owned descendant.
    fn proc_has_non_init_process() -> std_io::Result<bool> {
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            if pid == 1 {
                continue;
            }
            let status_path = entry.path().join("status");
            let status = match fs::read_to_string(&status_path) {
                Ok(status) => status,
                Err(error) if error.kind() == std_io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if last_namespace_pid(&status) != Some(pid) {
                return Err(std_io::Error::other(format!(
                    "private /proc identity mismatch for PID {pid}",
                )));
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn exit_code(status: WaitStatus) -> std_io::Result<u8> {
        if let Some(code) = status.exit_status() {
            return u8::try_from(code)
                .map_err(|_| std_io::Error::other("target exit status is outside u8 range"));
        }
        if let Some(signal) = status.terminating_signal() {
            let code = 128_i32.saturating_add(signal);
            return u8::try_from(code)
                .map_err(|_| std_io::Error::other("target signal status is outside u8 range"));
        }
        Err(std_io::Error::other(
            "target returned no terminal wait status",
        ))
    }

    fn sleep_until_next_poll() {
        thread::sleep(POLL_INTERVAL);
    }

    fn drain_until_quiet(target_code: u8, deadline: Instant) -> std_io::Result<u8> {
        let mut empty_since = None;
        loop {
            if Instant::now() >= deadline {
                return Err(std_io::Error::new(
                    std_io::ErrorKind::TimedOut,
                    "target exited but a namespace descendant did not drain before the deadline",
                ));
            }

            let wait_result = wait(WaitOptions::NOHANG);
            match wait_result {
                Ok(Some((_pid, _status))) => {
                    // The target was already reaped. If a descendant reuses
                    // its numeric PID, it is still only a descendant event;
                    // never treat it as a second target exit.
                    empty_since = None;
                }
                Ok(None) => {
                    if proc_has_non_init_process()? {
                        empty_since = None;
                    } else if empty_since.is_none() {
                        empty_since = Some(Instant::now());
                    }
                }
                Err(error) if error == rustix::io::Errno::INTR => continue,
                Err(error) if error == rustix::io::Errno::CHILD => {
                    // ECHILD alone is not a completion proof: adoption and
                    // proc visibility can settle on different observations.
                    // Require a quiet private-proc interval as well.
                    if proc_has_non_init_process()? {
                        empty_since = None;
                    } else if empty_since.is_none() {
                        empty_since = Some(Instant::now());
                    }
                }
                Err(error) => return Err(error.into()),
            }

            if empty_since.is_some_and(|since| since.elapsed() >= ADOPTION_SETTLE) {
                return Ok(target_code);
            }
            sleep_until_next_poll();
        }
    }

    pub fn run(
        command: &mut Command,
        workload_timeout: Duration,
        drain_timeout: Duration,
    ) -> std_io::Result<u8> {
        ensure_private_namespace_init()?;
        // PID 1 is the kernel's namespace reaper. Retaining the explicit
        // subreaper setting also covers the WSL relay's delayed adoption path
        // without broadening ownership beyond this namespace.
        set_child_subreaper(Some(Pid::INIT))?;
        let child = command.spawn()?;
        let target = Pid::from_child(&child);
        // Do not call Child::wait: rustix wait is the only status/reap
        // authority, and the numeric target PID remains reserved until it is
        // observed and reaped here.
        drop(child);

        let workload_deadline = Instant::now()
            .checked_add(workload_timeout)
            .ok_or_else(|| std_io::Error::other("workload timeout overflowed the clock"))?;
        let target_code = loop {
            if Instant::now() >= workload_deadline {
                return Err(std_io::Error::new(
                    std_io::ErrorKind::TimedOut,
                    "target did not exit before the workload deadline",
                ));
            }
            match wait(WaitOptions::NOHANG) {
                Ok(Some((pid, status))) if pid == target => break exit_code(status)?,
                Ok(Some((_pid, _status))) => {}
                Ok(None) => sleep_until_next_poll(),
                Err(error) if error == rustix::io::Errno::INTR => {}
                Err(error) if error == rustix::io::Errno::CHILD => {
                    return Err(std_io::Error::other(
                        "namespace reported ECHILD before the target exit was observed",
                    ));
                }
                Err(error) => return Err(error.into()),
            }
        };

        let drain_deadline = Instant::now()
            .checked_add(drain_timeout)
            .ok_or_else(|| std_io::Error::other("drain timeout overflowed the clock"))?;
        drain_until_quiet(target_code, drain_deadline)
    }

    pub fn main() -> std_io::Result<u8> {
        let options = parse_options(std::env::args_os().skip(1)).map_err(std_io::Error::other)?;
        let mut command = Command::new(&options.command[0]);
        command.args(&options.command[1..]);
        run(
            &mut command,
            options.workload_timeout,
            options.drain_timeout,
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn options_require_a_target_and_keep_target_arguments() {
            let options = parse_options(
                [
                    OsString::from("--workload-timeout-ms=17"),
                    OsString::from("--drain-timeout-ms=23"),
                    OsString::from("--"),
                    OsString::from("/bin/sh"),
                    OsString::from("-c"),
                    OsString::from("exit 7"),
                ]
                .into_iter(),
            )
            .expect("valid runner arguments");
            assert_eq!(options.workload_timeout, Duration::from_millis(17));
            assert_eq!(options.drain_timeout, Duration::from_millis(23));
            assert_eq!(options.command[0], OsString::from("/bin/sh"));
            assert_eq!(options.command[2], OsString::from("exit 7"));
        }

        #[test]
        fn proc_status_parsing_uses_the_namespace_pid() {
            let status = "Pid:\t1\nPPid:\t0\nNSpid:\t9001\t1\n";
            assert_eq!(status_field(status, "Pid"), Some("1"));
            assert_eq!(last_namespace_pid(status), Some(1));
        }

        #[test]
        fn timeout_limits_reject_unbounded_workload_and_drain() {
            for (option, maximum, accepted, rejected) in [
                (
                    "--workload-timeout-ms",
                    MAX_WORKLOAD_TIMEOUT,
                    "3600000",
                    "3600001",
                ),
                ("--drain-timeout-ms", MAX_DRAIN_TIMEOUT, "60000", "60001"),
            ] {
                assert_eq!(parse_timeout(accepted, option, maximum), Ok(maximum));
                assert_eq!(
                    parse_timeout("1", option, maximum),
                    Ok(Duration::from_millis(1))
                );
                for invalid in ["0", "-1", rejected, "18446744073709551615"] {
                    assert!(parse_timeout(invalid, option, maximum).is_err());
                }
            }
        }

        #[test]
        fn proc_mount_parser_requires_a_proc_filesystem_at_proc() {
            let mountinfo = "36 25 0:32 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw";
            assert!(proc_mount_is_present(mountinfo));
            assert!(!proc_mount_is_present(
                "36 25 0:32 / /tmp rw,relatime - tmpfs tmpfs rw"
            ));
        }
    }
}

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    return match linux::main() {
        Ok(code) => std::process::ExitCode::from(code),
        Err(error) => {
            eprintln!("synthetic test reaper: {error}");
            std::process::ExitCode::from(linux::RUNNER_FAILURE_EXIT)
        }
    };

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("synthetic test reaper requires Linux");
        std::process::ExitCode::from(125)
    }
}
