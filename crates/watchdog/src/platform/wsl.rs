//! Explicit WSL invocation validation.

use std::path::PathBuf;

const MAX_DISTRO_BYTES: usize = 128;
const MAX_ARGUMENTS: usize = 32;
const MAX_ARGUMENT_BYTES: usize = 2_048;

/// A direct WSL executable invocation.  The distro is never inferred and no
/// login or shell is started by this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WslInvocation {
    pub distribution: String,
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub expected_endpoint: String,
}

impl WslInvocation {
    /// Validate exact distro, executable, argument and loopback endpoint policy.
    pub fn validate(&self) -> Result<(), WslInvocationError> {
        if self.distribution.is_empty()
            || self.distribution.len() > MAX_DISTRO_BYTES
            || self.distribution.contains(['\0', '\n', '\r'])
            || self.distribution == "."
            || self.distribution == ".."
        {
            return Err(WslInvocationError::Invalid(
                "distribution is invalid".to_owned(),
            ));
        }
        if !self.executable.is_absolute() || self.executable.as_os_str().is_empty() {
            return Err(WslInvocationError::Invalid(
                "WSL executable must be an absolute path".to_owned(),
            ));
        }
        if self.arguments.len() > MAX_ARGUMENTS
            || self
                .arguments
                .iter()
                .any(|argument| argument.len() > MAX_ARGUMENT_BYTES || argument.contains('\0'))
        {
            return Err(WslInvocationError::Invalid(
                "WSL arguments exceed bounds".to_owned(),
            ));
        }
        if !valid_loopback_endpoint(&self.expected_endpoint) {
            return Err(WslInvocationError::Invalid(
                "WSL endpoint must be an explicit loopback endpoint".to_owned(),
            ));
        }
        Ok(())
    }

    /// Return arguments suitable for a direct `wsl.exe` invocation.
    pub fn command_arguments(&self) -> Result<Vec<String>, WslInvocationError> {
        self.validate()?;
        let mut arguments = vec![
            "--distribution".to_owned(),
            self.distribution.clone(),
            "--exec".to_owned(),
            self.executable.to_string_lossy().into_owned(),
        ];
        arguments.extend(self.arguments.clone());
        Ok(arguments)
    }
}

fn valid_loopback_endpoint(value: &str) -> bool {
    let Some(port) = value.strip_prefix("127.0.0.1:") else {
        return false;
    };
    !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|port| port != 0)
        && value.len() <= 64
        && !value.contains(['\0', '\n', '\r'])
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WslInvocationError {
    Invalid(String),
    Unsupported(String),
}

impl std::fmt::Display for WslInvocationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid WSL invocation: {message}"),
            Self::Unsupported(message) => {
                write!(formatter, "unsupported WSL invocation: {message}")
            }
        }
    }
}

impl std::error::Error for WslInvocationError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn invocation() -> WslInvocation {
        WslInvocation {
            distribution: "Ubuntu-24.04".to_owned(),
            executable: PathBuf::from("/opt/ascension/bin/gateway"),
            arguments: vec!["--listen".to_owned(), "127.0.0.1:15525".to_owned()],
            expected_endpoint: "127.0.0.1:15525".to_owned(),
        }
    }

    #[test]
    fn direct_arguments_pin_distribution_and_exec() {
        assert_eq!(
            invocation().command_arguments().expect("valid invocation"),
            vec![
                "--distribution",
                "Ubuntu-24.04",
                "--exec",
                "/opt/ascension/bin/gateway",
                "--listen",
                "127.0.0.1:15525",
            ]
        );
    }

    #[test]
    fn wildcard_or_non_loopback_endpoint_is_rejected() {
        let mut invalid = invocation();
        invalid.expected_endpoint = "0.0.0.0:15525".to_owned();
        assert!(invalid.validate().is_err());
        invalid = invocation();
        invalid.distribution = "..".to_owned();
        assert!(invalid.validate().is_err());
        invalid = invocation();
        invalid.expected_endpoint = "127.0.0.1:0".to_owned();
        assert!(invalid.validate().is_err());
        invalid.expected_endpoint = "127.0.0.1:not-a-port".to_owned();
        assert!(invalid.validate().is_err());
    }
}
