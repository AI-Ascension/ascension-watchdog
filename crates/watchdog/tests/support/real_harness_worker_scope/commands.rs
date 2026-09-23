//! Bounded systemd helper execution and launcher child ownership.

use super::properties::{ScopeProperties, parse_properties};
use super::{COMMAND_TIMEOUT, MAX_COMMAND_OUTPUT, POLL_INTERVAL, SYSTEMCTL};
use std::io::{self, Read};
use std::os::fd::{AsFd, OwnedFd};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) fn preserve_bus_environment(
    command: &mut Command,
) -> Result<(), Box<dyn std::error::Error>> {
    let bus = std::env::var_os("DBUS_SESSION_BUS_ADDRESS")
        .ok_or_else(|| io::Error::other("DBUS_SESSION_BUS_ADDRESS is required for user systemd"))?;
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| io::Error::other("XDG_RUNTIME_DIR is required for user systemd"))?;
    command
        .env_clear()
        .env("DBUS_SESSION_BUS_ADDRESS", bus)
        .env("XDG_RUNTIME_DIR", runtime);
    Ok(())
}

pub(crate) fn systemd_command(path: &str) -> Result<Command, Box<dyn std::error::Error>> {
    let mut command = Command::new(path);
    preserve_bus_environment(&mut command)?;
    Ok(command)
}

pub(crate) fn run_bounded(
    mut command: Command,
    timeout: Duration,
) -> Result<(bool, String), Box<dyn std::error::Error>> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = CommandChildGuard::spawn(command)?;
    let stdout = child.take_stdout()?;
    let stderr = child.take_stderr()?;
    set_nonblocking_pipe(&stdout)?;
    set_nonblocking_pipe(&stderr)?;
    let deadline = Instant::now() + timeout;
    let stdout_reader = thread::spawn(move || read_bounded_output(stdout, deadline));
    let stderr_reader = thread::spawn(move || read_bounded_output(stderr, deadline));
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let text = join_command_output(stdout_reader, stderr_reader)?;
                child.disarm();
                return Ok((!status.success(), text));
            }
            Ok(None) if Instant::now() >= deadline => {
                let cleanup = child.kill_and_reap(Instant::now() + Duration::from_secs(2));
                let text = join_command_output(stdout_reader, stderr_reader)?;
                cleanup.map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("bounded systemd helper cleanup failed: {error}; output={text}"),
                    )
                })?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("systemd helper exceeded its bounded timeout; output={text}"),
                )
                .into());
            }
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(error) => {
                let cleanup = child.kill_and_reap(Instant::now() + Duration::from_secs(2));
                let _ = join_command_output(stdout_reader, stderr_reader);
                cleanup?;
                return Err(error.into());
            }
        }
    }
}

pub(crate) fn set_nonblocking_pipe(pipe: &impl AsFd) -> io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(pipe)?;
    rustix::fs::fcntl_setfl(pipe, flags | rustix::fs::OFlags::NONBLOCK).map_err(io::Error::from)
}

pub(crate) fn read_bounded_output(mut reader: impl Read, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut retained = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        if Instant::now() >= deadline {
            return Ok(retained);
        }
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(retained),
            Ok(read) => {
                let keep = MAX_COMMAND_OUTPUT.saturating_sub(retained.len()).min(read);
                retained.extend_from_slice(&buffer[..keep]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error),
        }
    }
}

pub(crate) fn join_command_output(
    stdout_reader: thread::JoinHandle<io::Result<Vec<u8>>>,
    stderr_reader: thread::JoinHandle<io::Result<Vec<u8>>>,
) -> Result<String, Box<dyn std::error::Error>> {
    let stdout = stdout_reader
        .join()
        .map_err(|_| io::Error::other("systemd stdout reader panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| io::Error::other("systemd stderr reader panicked"))??;
    let mut text = String::from_utf8_lossy(&stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&stderr));
    if text.len() > MAX_COMMAND_OUTPUT {
        let mut boundary = MAX_COMMAND_OUTPUT;
        while !text.is_char_boundary(boundary) {
            boundary -= 1;
        }
        text.truncate(boundary);
        text.push_str("...[truncated]");
    }
    Ok(text)
}

pub(crate) struct CommandChildGuard {
    child: Option<Child>,
    pidfd: Option<OwnedFd>,
}

impl CommandChildGuard {
    pub(crate) fn spawn(mut command: Command) -> io::Result<Self> {
        let child = command.spawn()?;
        let mut guard = Self {
            child: Some(child),
            pidfd: None,
        };
        let pidfd = {
            let child = guard
                .child
                .as_ref()
                .ok_or_else(|| io::Error::other("systemd helper lost its child"))?;
            rustix::process::pidfd_open(
                rustix::process::Pid::from_child(child),
                rustix::process::PidfdFlags::NONBLOCK,
            )
            .map_err(|error| io::Error::other(format!("cannot open helper pidfd: {error}")))?
        };
        guard.pidfd = Some(pidfd);
        Ok(guard)
    }

    pub(crate) fn take_stdout(&mut self) -> io::Result<std::process::ChildStdout> {
        self.child
            .as_mut()
            .ok_or_else(|| io::Error::other("systemd helper lost its child"))?
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("systemd helper stdout pipe was not created"))
    }

    pub(crate) fn take_stderr(&mut self) -> io::Result<std::process::ChildStderr> {
        self.child
            .as_mut()
            .ok_or_else(|| io::Error::other("systemd helper lost its child"))?
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("systemd helper stderr pipe was not created"))
    }

    pub(crate) fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.child
            .as_mut()
            .ok_or_else(|| io::Error::other("systemd helper lost its child"))?
            .try_wait()
    }

    pub(crate) fn kill_and_reap(&mut self, deadline: Instant) -> io::Result<()> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| io::Error::other("systemd helper lost its child"))?;
        let initial_wait_error = match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => None,
            Err(error) => Some(error),
        };
        let pidfd_error = self.pidfd.as_ref().and_then(|pidfd| {
            rustix::process::pidfd_send_signal(pidfd, rustix::process::Signal::KILL).err()
        });
        // A numeric Child::kill fallback is safe only after a fresh Ok(None)
        // observation and only when pidfd capture itself failed.  If the
        // initial wait was uncertain, the retained pidfd remains the only
        // exact signal authority.
        if self.pidfd.is_none() && initial_wait_error.is_none() {
            let _ = child.kill();
        }
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
                Ok(None) => {
                    let wait_detail = initial_wait_error
                        .map(|error| format!("; initial wait failed: {error}"))
                        .unwrap_or_default();
                    let signal_detail = pidfd_error
                        .map(|error| format!("; pidfd kill failed: {error}"))
                        .unwrap_or_default();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "systemd helper remained live after bounded kill{wait_detail}{signal_detail}"
                        ),
                    ));
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.child = None;
    }
}

impl Drop for CommandChildGuard {
    fn drop(&mut self) {
        if self.child.is_some()
            && let Err(error) = self.kill_and_reap(Instant::now() + Duration::from_secs(2))
        {
            eprintln!("systemd helper cleanup is uncertain: {error}");
        }
    }
}

pub(crate) fn show_unit(unit: &str) -> Result<ScopeProperties, Box<dyn std::error::Error>> {
    let mut command = systemd_command(SYSTEMCTL)?;
    command.args([
        "--user",
        "show",
        "--no-pager",
        "-p",
        "Id",
        "-p",
        "LoadState",
        "-p",
        "ActiveState",
        "-p",
        "ControlGroup",
        "-p",
        "Description",
        "-p",
        "Delegate",
        "-p",
        "KillMode",
        "-p",
        "SendSIGKILL",
        "-p",
        "RuntimeMaxUSec",
        "-p",
        "TimeoutStopUSec",
        "-p",
        "CollectMode",
        unit,
    ]);
    let (failed, output) = run_bounded(command, COMMAND_TIMEOUT)?;
    if failed && output.trim().is_empty() {
        return Err(io::Error::other("systemctl show failed without a diagnostic").into());
    }
    Ok(parse_properties(&output).map_err(io::Error::other)?)
}
