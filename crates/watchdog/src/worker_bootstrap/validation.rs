//! Policy validation and typed decoding for bootstrap JSON fields.

use super::{BootstrapError, ExpectedPeer, LinuxPeer, WindowsPeer};
use crate::worker_bootstrap::{
    MAX_COMPONENT_ID_BYTES, MAX_EXECUTABLE_PATH_BYTES, MAX_SID_AUTHORITY, MAX_SID_BYTES,
    MAX_SID_SUBAUTHORITIES,
};
use serde_json::{Map, Value};
use uuid::{Uuid, Version};

const LINUX_FIELDS: &[&str] = &[
    "platform",
    "pid",
    "creation_token",
    "executable",
    "executable_sha256",
    "uid",
    "gid",
];
const WINDOWS_FIELDS: &[&str] = &[
    "platform",
    "pid",
    "creation_token",
    "executable",
    "executable_sha256",
    "session_id",
    "sid",
];

pub(super) fn parse_expected_peer(value: Option<&Value>) -> Result<ExpectedPeer, BootstrapError> {
    let object = value
        .ok_or(BootstrapError::InvalidSchema)?
        .as_object()
        .ok_or(BootstrapError::InvalidPeer)?;
    let platform = string_field(object, "platform")?;
    match platform {
        "linux" => {
            require_exact_fields(object, LINUX_FIELDS, LINUX_FIELDS.len())?;
            let peer = LinuxPeer {
                pid: positive_pid(object.get("pid"))?,
                creation_token: string_field(object, "creation_token")?.to_owned(),
                executable: string_field(object, "executable")?.to_owned(),
                executable_sha256: string_field(object, "executable_sha256")?.to_owned(),
                uid: u32_number(object.get("uid"))?,
                gid: u32_number(object.get("gid"))?,
            };
            validate_linux_peer(&peer)?;
            Ok(ExpectedPeer::Linux(peer))
        }
        "windows" => {
            require_exact_fields(object, WINDOWS_FIELDS, WINDOWS_FIELDS.len())?;
            let peer = WindowsPeer {
                pid: positive_pid(object.get("pid"))?,
                creation_token: string_field(object, "creation_token")?.to_owned(),
                executable: string_field(object, "executable")?.to_owned(),
                executable_sha256: string_field(object, "executable_sha256")?.to_owned(),
                session_id: u32_number(object.get("session_id"))?,
                sid: string_field(object, "sid")?.to_owned(),
            };
            validate_windows_peer(&peer)?;
            Ok(ExpectedPeer::Windows(peer))
        }
        _ => Err(BootstrapError::InvalidPeer),
    }
}

pub(super) fn require_exact_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    expected_count: usize,
) -> Result<(), BootstrapError> {
    if object.len() != expected_count
        || object
            .keys()
            .any(|key| !allowed.iter().any(|allowed_key| *allowed_key == key))
    {
        return Err(BootstrapError::InvalidSchema);
    }
    Ok(())
}

pub(super) fn string_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, BootstrapError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(BootstrapError::InvalidSchema)
}

pub(super) fn unsigned_number(value: Option<&Value>) -> Result<u64, BootstrapError> {
    value
        .and_then(Value::as_u64)
        .ok_or(BootstrapError::InvalidNumber)
}

fn u32_number(value: Option<&Value>) -> Result<u32, BootstrapError> {
    let number = unsigned_number(value)?;
    u32::try_from(number).map_err(|_| BootstrapError::InvalidNumber)
}

fn positive_pid(value: Option<&Value>) -> Result<u32, BootstrapError> {
    let pid = u32_number(value)?;
    (pid != 0)
        .then_some(pid)
        .ok_or(BootstrapError::InvalidNumber)
}

pub(super) fn validate_uuid(value: Uuid) -> Result<(), BootstrapError> {
    if value.is_nil() || value.get_version() != Some(Version::Random) {
        return Err(BootstrapError::InvalidUuid);
    }
    Ok(())
}

pub(super) fn parse_uuid(value: &str) -> Result<Uuid, BootstrapError> {
    let uuid = Uuid::parse_str(value).map_err(|_| BootstrapError::InvalidUuid)?;
    if uuid.to_string() != value {
        return Err(BootstrapError::InvalidUuid);
    }
    validate_uuid(uuid)?;
    Ok(uuid)
}

pub(super) fn validate_component_id(value: &str) -> Result<(), BootstrapError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_COMPONENT_ID_BYTES
        || value == "."
        || value == ".."
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-' | b'.'))
    {
        return Err(BootstrapError::InvalidComponent);
    }
    Ok(())
}

pub(super) fn validate_linux_peer(peer: &LinuxPeer) -> Result<(), BootstrapError> {
    if peer.pid == 0 {
        return Err(BootstrapError::InvalidNumber);
    }
    parse_creation_token(&peer.creation_token)?;
    validate_linux_path(&peer.executable)?;
    validate_digest(&peer.executable_sha256)
}

pub(super) fn validate_windows_peer(peer: &WindowsPeer) -> Result<(), BootstrapError> {
    if peer.pid == 0 {
        return Err(BootstrapError::InvalidNumber);
    }
    parse_creation_token(&peer.creation_token)?;
    validate_windows_path(&peer.executable)?;
    validate_digest(&peer.executable_sha256)?;
    validate_sid(&peer.sid)
}

pub(super) fn parse_creation_token(value: &str) -> Result<u64, BootstrapError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 20
        || bytes[0] == b'0'
        || !bytes.iter().all(u8::is_ascii_digit)
    {
        return Err(BootstrapError::InvalidToken);
    }
    value
        .parse::<u64>()
        .map_err(|_| BootstrapError::InvalidToken)
}

fn validate_linux_path(value: &str) -> Result<(), BootstrapError> {
    if value.as_bytes().len() > MAX_EXECUTABLE_PATH_BYTES
        || value.as_bytes().first() != Some(&b'/')
        || value.contains('\0')
    {
        return Err(BootstrapError::InvalidPath);
    }
    Ok(())
}

fn validate_windows_path(value: &str) -> Result<(), BootstrapError> {
    let bytes = value.as_bytes();
    if bytes.len() > MAX_EXECUTABLE_PATH_BYTES
        || bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'\\'
        || value.contains('\0')
    {
        return Err(BootstrapError::InvalidPath);
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), BootstrapError> {
    let bytes = value.as_bytes();
    if bytes.len() != 64
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(BootstrapError::InvalidDigest);
    }
    Ok(())
}

fn validate_sid(value: &str) -> Result<(), BootstrapError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_SID_BYTES || !bytes.is_ascii() {
        return Err(BootstrapError::InvalidPeer);
    }
    let mut fields = value.split('-');
    if fields.next() != Some("S") || fields.next() != Some("1") {
        return Err(BootstrapError::InvalidPeer);
    }
    let authority = fields.next().ok_or(BootstrapError::InvalidPeer)?;
    parse_canonical_decimal(authority)
        .filter(|authority| *authority <= MAX_SID_AUTHORITY)
        .ok_or(BootstrapError::InvalidPeer)?;
    let subauthorities = fields.collect::<Vec<_>>();
    if subauthorities.is_empty() || subauthorities.len() > MAX_SID_SUBAUTHORITIES {
        return Err(BootstrapError::InvalidPeer);
    }
    if subauthorities.iter().any(|subauthority| {
        parse_canonical_decimal(subauthority).is_none_or(|value| value > u64::from(u32::MAX))
    }) {
        return Err(BootstrapError::InvalidPeer);
    }
    Ok(())
}

fn parse_canonical_decimal(value: &str) -> Option<u64> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || (bytes.len() > 1 && bytes[0] == b'0')
        || !bytes.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    value.parse::<u64>().ok()
}
