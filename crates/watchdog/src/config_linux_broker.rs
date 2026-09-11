//! Pure configuration for the optional Linux launch broker.
//!
//! The broker socket is a protected reference, not an authority handle.  This
//! module deliberately performs lexical checks only; socket metadata and the
//! authenticated broker peer are checked by the runtime client immediately
//! before a broker operation.

use super::WatchdogConfig;
#[cfg(target_os = "linux")]
use super::validate_local_path;
use crate::error::{Result, WatchdogError};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::path::Component;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Maximum pathname accepted by the Linux `AF_UNIX` pathname address.
/// Keeping a margin below the kernel limit also leaves room for platform
/// wrappers that append no additional bytes to the configured value.
#[cfg(any(target_os = "linux", test))]
const MAX_SOCKET_PATH_BYTES: usize = 100;
/// Keep this equal to the broker's bounded request deadline (two minutes).
#[cfg(any(target_os = "linux", test))]
const MAX_TIMEOUT_MS: u64 = 120_000;

/// Explicit, opt-in selection of the root-owned Linux launch broker.
///
/// `socket` and `timeout_ms` are the only selectable values.  Executables,
/// arguments, users, groups and capabilities remain in the broker's protected
/// policy and cannot be supplied by watchdog configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxBrokerConfig {
    /// Absolute local pathname of the broker's protected Unix socket.
    #[serde(alias = "socket_path")]
    pub socket: PathBuf,
    /// Bounded deadline for one broker request, in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl LinuxBrokerConfig {
    /// Validate the selector without reading the socket, creating endpoints,
    /// opening a connection, or otherwise causing an external effect.
    pub fn validate(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            if self.timeout_ms == 0 || self.timeout_ms > MAX_TIMEOUT_MS {
                return Err(WatchdogError::InvalidInput(
                    "Linux broker timeout must be between 1 and 120000 milliseconds".to_owned(),
                ));
            }
            validate_local_path(&self.socket, "Linux broker socket")?;
            let text = self.socket.to_str().ok_or_else(|| {
                WatchdogError::InvalidInput("Linux broker socket must be valid Unicode".to_owned())
            })?;
            if !self.socket.is_absolute()
                || text.len() > MAX_SOCKET_PATH_BYTES
                || self.socket.file_name().is_none()
                || text.chars().any(char::is_control)
                || text.ends_with('/')
                || text.split('/').any(|part| matches!(part, "." | ".."))
                || self
                    .socket
                    .components()
                    .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
                || text.starts_with("//")
            {
                return Err(WatchdogError::InvalidInput(
                    "Linux broker socket must be a bounded absolute local path without traversal"
                        .to_owned(),
                ));
            }
            if ["/dev", "/proc", "/sys"]
                .iter()
                .any(|root| self.socket == Path::new(root) || self.socket.starts_with(root))
            {
                return Err(WatchdogError::InvalidInput(
                    "Linux broker socket must use a protected service path".to_owned(),
                ));
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Report the platform boundary before inspecting Linux-specific
            // path syntax.  This keeps an explicitly selected Linux adapter
            // deterministic on other targets and avoids treating a Windows
            // path parser result as evidence about Linux broker support.
            Err(WatchdogError::Unsupported(
                "Linux broker selection is available only on Linux".to_owned(),
            ))
        }
    }

    /// Convert the validated bounded value to the broker client's deadline.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }

    /// Return the configured socket reference.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket
    }
}

impl WatchdogConfig {
    /// Whether this configuration explicitly selects the Linux broker.
    #[must_use]
    pub fn uses_linux_broker(&self) -> bool {
        self.linux_broker.is_some()
    }
}

const fn default_timeout_ms() -> u64 {
    30_000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket() -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            PathBuf::from("/run/ascension-watchdog/broker.sock")
        }
        #[cfg(not(target_os = "linux"))]
        {
            PathBuf::from("/tmp/ascension-watchdog-broker.sock")
        }
    }

    #[test]
    fn default_deadline_is_bounded_and_does_not_touch_the_socket() {
        let config = LinuxBrokerConfig {
            socket: socket(),
            timeout_ms: default_timeout_ms(),
        };
        assert_eq!(config.timeout(), Duration::from_secs(30));
        #[cfg(target_os = "linux")]
        {
            config.validate().expect("lexically valid broker selector");
            assert!(!config.socket_path().exists());
        }
        #[cfg(not(target_os = "linux"))]
        assert!(matches!(
            config.validate(),
            Err(WatchdogError::Unsupported(_))
        ));
    }

    #[test]
    fn selector_rejects_unbounded_or_special_socket_references() {
        for socket in [
            PathBuf::from("relative.sock"),
            PathBuf::from("/run/ascension-watchdog/../broker.sock"),
            PathBuf::from("/run/ascension-watchdog/./broker.sock"),
            PathBuf::from("/run/ascension-watchdog/"),
            PathBuf::from(format!("/run/{}", "x".repeat(MAX_SOCKET_PATH_BYTES))),
        ] {
            let config = LinuxBrokerConfig {
                socket,
                timeout_ms: 1,
            };
            assert!(config.validate().is_err());
        }
        #[cfg(target_os = "linux")]
        for socket in ["/dev/null", "/proc/broker.sock", "/sys/broker.sock"] {
            let config = LinuxBrokerConfig {
                socket: socket.into(),
                timeout_ms: 1,
            };
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn selector_timeout_and_unknown_fields_fail_closed() {
        for timeout_ms in [0, MAX_TIMEOUT_MS + 1] {
            let config = LinuxBrokerConfig {
                socket: socket(),
                timeout_ms,
            };
            assert!(config.validate().is_err());
        }
        let value = serde_json::json!({
            "socket": "/run/ascension-watchdog/broker.sock",
            "timeout_ms": 1000,
            "executable": "/bin/sh"
        });
        assert!(serde_json::from_value::<LinuxBrokerConfig>(value).is_err());
    }

    #[test]
    fn watchdog_defaults_keep_the_direct_linux_adapter_selected() {
        let config = WatchdogConfig::default();
        assert!(!config.uses_linux_broker());
        let encoded = serde_json::to_value(config).expect("watchdog config serializes");
        assert!(encoded.get("linux_broker").is_none());
    }
}
