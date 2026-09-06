//! Linux systemd readiness/watchdog notifications.
//!
//! Notifications are emitted only by explicit reconciliation progress calls.
//! The notifier never starts a background heartbeat, so an alive but stalled
//! reconciler cannot falsely satisfy `WatchdogSec`.

use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_MESSAGE_BYTES: usize = 4_096;

/// Whether a notification was sent or deliberately not configured.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationResult {
    Sent,
    Disabled,
    Suppressed,
}

/// A bounded, synchronous sender for systemd's `NOTIFY_SOCKET` protocol.
#[derive(Debug)]
pub struct SystemdNotifier {
    socket: Option<UnixDatagram>,
    socket_path: Option<PathBuf>,
    watchdog_interval: Option<Duration>,
    ready_sent: bool,
    last_progress: Option<u64>,
    stopping_sent: bool,
}

impl SystemdNotifier {
    /// Build from systemd-provided environment.  Missing `NOTIFY_SOCKET` is an
    /// explicit disabled state, not a successful readiness signal.
    pub fn from_environment() -> Result<Self, String> {
        let socket = std::env::var_os("NOTIFY_SOCKET");
        let watchdog_interval = std::env::var("WATCHDOG_USEC")
            .ok()
            .map(|value| parse_watchdog_usec(&value))
            .transpose()?;
        let Some(socket_path) = socket else {
            return Ok(Self::disabled(watchdog_interval));
        };
        let socket_path = PathBuf::from(socket_path);
        Self::from_path(&socket_path, watchdog_interval)
    }

    /// Build against a filesystem Unix datagram path.  This constructor is
    /// useful for deterministic tests and for deployments using a filesystem
    /// notify socket.  Abstract Linux socket names are rejected explicitly;
    /// accepting one requires a reviewed sockaddr boundary.
    pub fn from_path(path: &Path, watchdog_interval: Option<Duration>) -> Result<Self, String> {
        if path.as_os_str().is_empty() || path.to_string_lossy().contains('\0') {
            return Err("systemd notify socket path is invalid".to_owned());
        }
        if path.to_string_lossy().starts_with('@') {
            return Err("abstract systemd notify sockets are not enabled in this build".to_owned());
        }
        let socket = UnixDatagram::unbound().map_err(|error| format!("notify socket: {error}"))?;
        Ok(Self {
            socket: Some(socket),
            socket_path: Some(path.to_owned()),
            watchdog_interval,
            ready_sent: false,
            last_progress: None,
            stopping_sent: false,
        })
    }

    /// Construct an explicit disabled notifier for non-systemd execution.
    #[must_use]
    pub fn disabled(watchdog_interval: Option<Duration>) -> Self {
        Self {
            socket: None,
            socket_path: None,
            watchdog_interval,
            ready_sent: false,
            last_progress: None,
            stopping_sent: false,
        }
    }

    /// Return the configured watchdog interval, if systemd supplied one.
    #[must_use]
    pub const fn watchdog_interval(&self) -> Option<Duration> {
        self.watchdog_interval
    }

    /// Publish one actual reconciliation-loop progress event.  The first event
    /// sends `READY=1`; later increasing sequence numbers send `WATCHDOG=1`.
    pub fn progress(&mut self, sequence: u64, status: &str) -> Result<NotificationResult, String> {
        if self.last_progress.is_some_and(|last| sequence <= last) {
            return Ok(NotificationResult::Suppressed);
        }
        validate_status(status)?;
        let mut fields = Vec::new();
        if !self.ready_sent {
            fields.push("READY=1");
            self.ready_sent = true;
        }
        if self.watchdog_interval.is_some() {
            fields.push("WATCHDOG=1");
        }
        fields.push("STATUS=");
        let message = format_fields(&fields, status, sequence)?;
        let result = self.send(&message)?;
        if result == NotificationResult::Sent {
            self.ready_sent = true;
            self.last_progress = Some(sequence);
        }
        Ok(result)
    }

    /// Publish a bounded shutdown notification before process exit.
    pub fn stopping(&mut self) -> Result<NotificationResult, String> {
        if self.stopping_sent {
            return Ok(NotificationResult::Suppressed);
        }
        let result = self.send("STOPPING=1\n")?;
        if result == NotificationResult::Sent {
            self.stopping_sent = true;
        }
        Ok(result)
    }

    fn send(&self, message: &str) -> Result<NotificationResult, String> {
        if message.len() > MAX_MESSAGE_BYTES {
            return Err("systemd notification exceeds byte bound".to_owned());
        }
        let (Some(socket), Some(path)) = (&self.socket, &self.socket_path) else {
            return Ok(NotificationResult::Disabled);
        };
        socket
            .send_to(message.as_bytes(), path)
            .map_err(|error| format!("systemd notification failed: {error}"))?;
        Ok(NotificationResult::Sent)
    }
}

fn parse_watchdog_usec(value: &str) -> Result<Duration, String> {
    let micros = value
        .parse::<u64>()
        .map_err(|_| "WATCHDOG_USEC is not an integer".to_owned())?;
    if micros == 0 {
        return Err("WATCHDOG_USEC must be greater than zero".to_owned());
    }
    Ok(Duration::from_micros(micros))
}

fn validate_status(status: &str) -> Result<(), String> {
    if status.is_empty() || status.len() > MAX_MESSAGE_BYTES || status.contains(['\0', '\n', '\r'])
    {
        return Err("systemd status is empty or contains control characters".to_owned());
    }
    Ok(())
}

fn format_fields(fields: &[&str], status: &str, sequence: u64) -> Result<String, String> {
    let mut message = String::new();
    for field in fields {
        if *field == "STATUS=" {
            message.push_str("STATUS=");
            message.push_str(status);
            message.push_str(";progress_sequence=");
            message.push_str(&sequence.to_string());
        } else {
            message.push_str(field);
        }
        message.push('\n');
    }
    if message.len() > MAX_MESSAGE_BYTES {
        return Err("systemd notification exceeds byte bound".to_owned());
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;
    use tempfile::{TempDir, tempdir};

    fn notifier() -> Result<(SystemdNotifier, UnixDatagram, TempDir), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&path)?;
        let notifier = SystemdNotifier::from_path(&path, Some(Duration::from_secs(30)))?;
        Ok((notifier, receiver, directory))
    }

    #[test]
    fn first_progress_is_ready_and_heartbeat() -> Result<(), Box<dyn std::error::Error>> {
        let (mut notifier, receiver, _directory) = notifier()?;
        assert_eq!(
            notifier.progress(1, "reconcile=started")?,
            NotificationResult::Sent
        );
        let mut bytes = [0_u8; MAX_MESSAGE_BYTES];
        let count = receiver.recv(&mut bytes)?;
        let message = std::str::from_utf8(&bytes[..count])?;
        assert!(message.contains("READY=1\n"));
        assert!(message.contains("WATCHDOG=1\n"));
        assert!(message.contains("progress_sequence=1"));
        Ok(())
    }

    #[test]
    fn stalled_sequence_does_not_emit_heartbeat() -> Result<(), Box<dyn std::error::Error>> {
        let (mut notifier, receiver, _directory) = notifier()?;
        notifier.progress(4, "first")?;
        let mut bytes = [0_u8; MAX_MESSAGE_BYTES];
        let _ = receiver.recv(&mut bytes)?;
        receiver.set_nonblocking(true)?;
        assert_eq!(
            notifier.progress(4, "duplicate")?,
            NotificationResult::Suppressed
        );
        assert!(receiver.recv(&mut bytes).is_err());
        Ok(())
    }

    #[test]
    fn stopping_is_idempotent_and_status_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let (mut notifier, receiver, _directory) = notifier()?;
        notifier.stopping()?;
        assert_eq!(notifier.stopping()?, NotificationResult::Suppressed);
        let mut bytes = [0_u8; MAX_MESSAGE_BYTES];
        let count = receiver.recv(&mut bytes)?;
        assert_eq!(&bytes[..count], b"STOPPING=1\n");
        assert!(notifier.progress(1, "bad\nstatus").is_err());
        Ok(())
    }

    #[test]
    fn disabled_notifier_reports_explicit_disabled_result() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut notifier = SystemdNotifier::disabled(None);
        assert_eq!(
            notifier.progress(1, "no-systemd")?,
            NotificationResult::Disabled
        );
        Ok(())
    }
}
