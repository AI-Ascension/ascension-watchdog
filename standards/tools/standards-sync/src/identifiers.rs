//! Validators for identifiers, paths, commands, and review references.

use std::collections::BTreeSet;

pub(crate) fn unique(values: &[String]) -> bool {
    let mut set = BTreeSet::new();
    values.iter().all(|value| set.insert(value))
}

pub(crate) fn valid_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn valid_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn valid_prefixed_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_hex_digest)
}

pub(crate) fn valid_repository(value: &str) -> bool {
    let Some(name) = value.strip_prefix("AI-Ascension/") else {
        return false;
    };
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub(crate) fn valid_profile_id(value: &str) -> bool {
    (3..=49).contains(&value.len())
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub(crate) fn valid_profile_scope(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
}

pub(crate) fn valid_rule_scope(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

pub(crate) fn valid_language_scope(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub(crate) fn valid_check_name(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
}

pub(crate) fn is_upper_identifier(value: &str) -> bool {
    (2..=16).contains(&value.len())
        && value.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

pub(crate) fn ordinary_style_rule(value: &str) -> bool {
    matches!(
        value,
        "ASC-FMT-001" | "ASC-SIZE-001" | "ASC-SIZE-002" | "ASC-DES-001"
    )
}

pub(crate) fn valid_rule_id(value: &str) -> bool {
    let parts = value.split('-').collect::<Vec<_>>();
    parts.len() == 3
        && matches!(
            parts[0],
            "X" | "RUST" | "MANAGED" | "WEB" | "OPS" | "DOC" | "ASC"
        )
        && !parts[1].is_empty()
        && parts[1]
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        && parts[2].len() == 3
        && parts[2].bytes().all(|byte| byte.is_ascii_digit())
}

pub(crate) fn valid_exception_id(value: &str) -> bool {
    let parts = value.split('-').collect::<Vec<_>>();
    parts.len() == 3
        && parts[0] == "EXC"
        && !parts[1].is_empty()
        && parts[1]
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        && parts[2].len() == 3
        && parts[2].bytes().all(|byte| byte.is_ascii_digit())
}

pub(crate) fn valid_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains('\\')
        && !value.contains('*')
        && !value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
}

pub(crate) fn valid_target(value: &str) -> bool {
    valid_relative_path(value) || value == "."
}

pub(crate) fn contains_shell_operator(value: &str) -> bool {
    value.contains(';')
        || value.contains('|')
        || value.contains('&')
        || value.contains(char::from(96))
        || value.contains("$(")
        || value.contains('>')
        || value.contains('<')
}

pub(crate) fn has_safe_executable(value: &str) -> bool {
    value.split_whitespace().next().is_some_and(|executable| {
        executable
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
    })
}

pub(crate) fn valid_node_id(value: &str) -> bool {
    value.starts_with("R_kg")
        && value.len() > 4
        && value
            .bytes()
            .skip(4)
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

pub(crate) fn valid_review_url(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://github.com/AI-Ascension/") else {
        return false;
    };
    let mut parts = rest.split('/');
    let Some(repository) = parts.next() else {
        return false;
    };
    let Some(kind) = parts.next() else {
        return false;
    };
    let Some(number) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && valid_repository(&format!("AI-Ascension/{repository}"))
        && matches!(kind, "issues" | "pull")
        && !number.is_empty()
        && number.bytes().all(|byte| byte.is_ascii_digit())
}
