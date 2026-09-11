//! Portable parser and policy for the fixed Windows SCM command line.
//!
//! The native SCM adapter consumes this exact policy, but the grammar itself
//! is deliberately independent of Win32 so malformed command lines are tested
//! on every host. Parsing is strict: accepted tokens must re-emit byte-for-byte
//! through the same Windows quoting function used by process creation.

const MAX_COMMAND_LINE_UTF16: usize = 32_767;
const MAX_EXECUTABLE_CHARS: usize = 32_768;
const MAX_CONFIG_CHARS: usize = 512;

/// SCM start modes accepted when removing an already-owned service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalStartMode {
    AutoStart,
    OnDemand,
    Disabled,
    Unsupported,
}

/// The two deployment paths extracted from the fixed service command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceCommandLine {
    pub executable: String,
    pub config: String,
}

/// A bounded service-command grammar or quoting error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceCommandError(String);

impl std::fmt::Display for ServiceCommandError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ServiceCommandError {}

/// Removal binds the exact owned service but does not require enabling it.
/// Install policy remains automatic; an operator may intentionally leave an
/// owned service manual or disabled while removing that same deployment.
pub fn validate_removal_start_mode(mode: RemovalStartMode) -> Result<(), ServiceCommandError> {
    match mode {
        RemovalStartMode::AutoStart | RemovalStartMode::OnDemand | RemovalStartMode::Disabled => {
            Ok(())
        }
        RemovalStartMode::Unsupported => Err(ServiceCommandError(
            "SCM service start mode is not a supported own-process removal mode".to_owned(),
        )),
    }
}

/// Emit one argument using the Windows `CommandLineToArgvW` quoting rules.
/// This is the existing process-launch emitter shared by SCM grammar tests.
#[must_use]
pub fn quote_windows(value: &str) -> String {
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        let mut quoted = String::from('"');
        let mut slashes = 0_usize;
        for character in value.chars() {
            if character == '\\' {
                slashes += 1;
            } else if character == '"' {
                quoted.extend(std::iter::repeat_n(
                    '\\',
                    slashes.saturating_mul(2).saturating_add(1),
                ));
                quoted.push(character);
                slashes = 0;
            } else {
                quoted.extend(std::iter::repeat_n('\\', slashes));
                quoted.push(character);
                slashes = 0;
            }
        }
        quoted.extend(std::iter::repeat_n('\\', slashes.saturating_mul(2)));
        quoted.push('"');
        quoted
    } else {
        value.to_owned()
    }
}

/// Emit the exact fixed service command line used by the grammar.
#[must_use]
pub fn render_service_command_line(executable: &str, config: &str) -> String {
    format!(
        "{} daemon --service --config {}",
        quote_windows(executable),
        quote_windows(config)
    )
}

/// Parse and validate the exact fixed `daemon --service --config PATH` form.
pub fn parse_service_command_line(
    command_line: &str,
) -> Result<ServiceCommandLine, ServiceCommandError> {
    let utf16_len = command_line.encode_utf16().count();
    if utf16_len == 0 || utf16_len > MAX_COMMAND_LINE_UTF16 {
        return Err(ServiceCommandError(
            "Windows service command line is empty or exceeds the bounded length".to_owned(),
        ));
    }
    let arguments = parse_windows_arguments(command_line)?;
    if arguments.len() != 5
        || arguments[1] != "daemon"
        || arguments[2] != "--service"
        || arguments[3] != "--config"
    {
        return Err(ServiceCommandError(
            "Windows service command line must be exactly daemon --service --config PATH"
                .to_owned(),
        ));
    }
    if arguments[0].is_empty()
        || arguments[0].chars().count() > MAX_EXECUTABLE_CHARS
        || arguments[4].is_empty()
        || arguments[4].chars().count() > MAX_CONFIG_CHARS
        || arguments
            .iter()
            .any(|argument| argument.contains('\0') || argument.contains('"'))
    {
        return Err(ServiceCommandError(
            "Windows service command line contains an empty, oversized, or unsafe argument"
                .to_owned(),
        ));
    }
    let canonical = arguments
        .iter()
        .map(|argument| quote_windows(argument))
        .collect::<Vec<_>>()
        .join(" ");
    if canonical != command_line {
        return Err(ServiceCommandError(
            "Windows service command line is not in the canonical quoted form".to_owned(),
        ));
    }
    Ok(ServiceCommandLine {
        executable: arguments[0].clone(),
        config: arguments[4].clone(),
    })
}

fn parse_windows_arguments(command_line: &str) -> Result<Vec<String>, ServiceCommandError> {
    let characters = command_line.chars().collect::<Vec<_>>();
    let mut arguments = Vec::new();
    let mut index = 0_usize;
    while index < characters.len() {
        while index < characters.len()
            && matches!(characters[index], ' ' | '\t' | '\n' | '\r' | '\u{000b}')
        {
            index += 1;
        }
        if index == characters.len() {
            break;
        }
        let mut argument = String::new();
        let mut quoted = false;
        loop {
            let mut slashes = 0_usize;
            while index < characters.len() && characters[index] == '\\' {
                slashes += 1;
                index += 1;
            }
            if index == characters.len() {
                argument.extend(std::iter::repeat_n('\\', slashes));
                break;
            }
            match characters[index] {
                '"' => {
                    argument.extend(std::iter::repeat_n('\\', slashes / 2));
                    if slashes % 2 == 1 {
                        argument.push('"');
                        index += 1;
                    } else if quoted && index + 1 < characters.len() && characters[index + 1] == '"'
                    {
                        argument.push('"');
                        index += 2;
                    } else {
                        quoted = !quoted;
                        index += 1;
                    }
                }
                character
                    if !quoted && matches!(character, ' ' | '\t' | '\n' | '\r' | '\u{000b}') =>
                {
                    argument.extend(std::iter::repeat_n('\\', slashes));
                    break;
                }
                character => {
                    argument.extend(std::iter::repeat_n('\\', slashes));
                    argument.push(character);
                    index += 1;
                }
            }
        }
        if quoted {
            return Err(ServiceCommandError(
                "Windows service command line contains an unterminated quote".to_owned(),
            ));
        }
        arguments.push(argument);
    }
    Ok(arguments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_grammar_handles_quoted_paths_and_backslashes() {
        let executable = r"C:\Program Files\Ascension\watchdog.exe";
        let config = r"C:\ProgramData\Ascension\Watchdog\watchdog.json";
        let line = render_service_command_line(executable, config);
        assert_eq!(
            line,
            r#""C:\Program Files\Ascension\watchdog.exe" daemon --service --config C:\ProgramData\Ascension\Watchdog\watchdog.json"#
        );
        let parsed = parse_service_command_line(&line).expect("canonical line must parse");
        assert_eq!(parsed.executable, executable);
        assert_eq!(parsed.config, config);
    }

    #[test]
    fn canonical_grammar_preserves_trailing_backslashes() {
        let executable = r"C:\Program Files\Ascension\watchdog.exe";
        let config = r"C:\ProgramData\Ascension\Watchdog\folder with space\";
        let line = render_service_command_line(executable, config);
        let parsed = parse_service_command_line(&line).expect("trailing slash must parse");
        assert_eq!(parsed.config, config);
    }

    #[test]
    fn malformed_or_mixed_command_lines_fail_closed() {
        let malformed = r#""C:\Program Files\Ascension\watchdog.exe daemon --service --config"#;
        assert!(parse_service_command_line(malformed).is_err());

        let unknown = r"C:\watchdog.exe daemon --service --unknown C:\watchdog.json";
        assert!(parse_service_command_line(unknown).is_err());

        let extra = r"C:\watchdog.exe daemon --service --config C:\watchdog.json extra";
        assert!(parse_service_command_line(extra).is_err());

        let unquoted_mixed =
            r"C:\Program Files\Ascension\watchdog.exe daemon --service --config C:\watchdog.json";
        assert!(parse_service_command_line(unquoted_mixed).is_err());

        let reordered = r"C:\watchdog.exe --service daemon --config C:\watchdog.json";
        assert!(parse_service_command_line(reordered).is_err());
    }

    #[test]
    fn command_line_and_argument_bounds_are_enforced() {
        let oversized_config = "C:\\".to_owned() + &"x".repeat(MAX_CONFIG_CHARS);
        let line = render_service_command_line(r"C:\watchdog.exe", &oversized_config);
        assert!(parse_service_command_line(&line).is_err());

        let oversized_line = "x".repeat(MAX_COMMAND_LINE_UTF16 + 1);
        assert!(parse_service_command_line(&oversized_line).is_err());
    }

    #[test]
    fn removal_policy_allows_manual_and_disabled_owned_services() {
        for mode in [
            RemovalStartMode::AutoStart,
            RemovalStartMode::OnDemand,
            RemovalStartMode::Disabled,
        ] {
            assert!(validate_removal_start_mode(mode).is_ok());
        }
        assert!(validate_removal_start_mode(RemovalStartMode::Unsupported).is_err());
    }
}
