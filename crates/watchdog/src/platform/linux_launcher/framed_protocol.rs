//! Framed helper protocol and bounded bootstrap I/O.

use super::CHILD_CLEANUP_POLL;
use super::FRAME_MAGIC;
use super::FRAME_VERSION;
use super::GO_MAGIC;
use super::MAX_ARGUMENTS;
use super::MAX_ENVIRONMENT;
use super::MAX_FIELD_BYTES;
use super::MAX_FRAME_BYTES;
use super::O_CLOEXEC;
use super::O_NONBLOCK;
use super::helper_authorization::LinuxHelperRequest;
use super::protected_bootstrap::parent_fd_path;
use crate::platform::contract::AdapterError;
use crate::platform::contract::ComponentKind;
use crate::platform::contract::LaunchSpec;
use crate::platform::contract::SessionSelector;
use crate::platform::gateway_health::GatewayHealthBootstrap;
use crate::platform::gateway_health::GatewayHealthBootstrapError;
use rustix::fs::OFlags;
use rustix::fs::fcntl_getfl;
use rustix::fs::fcntl_setfl;
use rustix::fs::fstatfs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::fd::RawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use uuid::Uuid;
use uuid::Version;

pub(super) fn remaining_timeout(started: Instant, limit: Duration) -> Duration {
    limit.checked_sub(started.elapsed()).unwrap_or_default()
}

pub(super) fn read_exact_bounded(
    reader: &mut impl Read,
    bytes: &mut [u8],
    deadline: Instant,
    label: &str,
) -> Result<(), AdapterError> {
    let mut received = 0_usize;
    while received < bytes.len() {
        if Instant::now() >= deadline {
            return Err(AdapterError::Timeout(format!("{label} timed out")));
        }
        match reader.read(&mut bytes[received..]) {
            Ok(0) => {
                return Err(AdapterError::Unavailable(format!(
                    "{label} closed before completion"
                )));
            }
            Ok(count) => {
                received = received
                    .checked_add(count)
                    .ok_or_else(|| AdapterError::Invalid(format!("{label} byte count overflow")))?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(AdapterError::Timeout(format!("{label} timed out")));
                }
                thread::sleep(CHILD_CLEANUP_POLL.min(remaining));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(protocol_io(&error)),
        }
    }
    Ok(())
}

pub(super) fn read_frame_bounded(
    reader: &mut impl Read,
    timeout: Duration,
) -> Result<LinuxHelperRequest, AdapterError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let mut length = [0_u8; 4];
    read_exact_bounded(reader, &mut length, deadline, "Linux helper frame")?;
    let length = u32::from_le_bytes(length);
    let length = usize::try_from(length)
        .map_err(|_| AdapterError::Invalid("Linux helper frame length overflow".to_owned()))?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(AdapterError::Invalid(
            "Linux helper frame exceeds bounds".to_owned(),
        ));
    }
    let mut payload = vec![0_u8; length];
    read_exact_bounded(reader, &mut payload, deadline, "Linux helper frame")?;
    decode_frame(&payload)
}

pub(super) fn read_go_bounded(
    reader: &mut impl Read,
    timeout: Duration,
) -> Result<String, AdapterError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let mut magic = [0_u8; GO_MAGIC.len()];
    read_exact_bounded(reader, &mut magic, deadline, "Linux helper GO")?;
    if &magic != GO_MAGIC {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper received an invalid GO marker".to_owned(),
        ));
    }
    let mut length = [0_u8; 2];
    read_exact_bounded(reader, &mut length, deadline, "Linux helper GO nonce")?;
    let length = usize::from(u16::from_le_bytes(length));
    if length == 0 || length > MAX_FIELD_BYTES {
        return Err(AdapterError::Invalid(
            "Linux helper GO nonce exceeds bounds".to_owned(),
        ));
    }
    let mut value = vec![0_u8; length];
    read_exact_bounded(reader, &mut value, deadline, "Linux helper GO nonce")?;
    String::from_utf8(value)
        .map_err(|_| AdapterError::Invalid("Linux helper GO nonce is not UTF-8".to_owned()))
}

pub(super) fn validate_worker_boot_metadata(
    boot_id: &str,
    frame_sha256: &str,
) -> Result<(), AdapterError> {
    let boot = Uuid::parse_str(boot_id).map_err(|_| {
        AdapterError::Invalid("Linux worker boot metadata is not a UUIDv4".to_owned())
    })?;
    if boot.is_nil()
        || boot.get_version() != Some(Version::Random)
        || boot.get_variant() != uuid::Variant::RFC4122
        || boot.to_string() != boot_id
    {
        return Err(AdapterError::Invalid(
            "Linux worker boot metadata is not a canonical UUIDv4".to_owned(),
        ));
    }
    if frame_sha256.len() != 64
        || !frame_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AdapterError::Invalid(
            "Linux worker frame metadata is not a lowercase SHA-256".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn open_parent_worker_descriptor(
    parent_pid: u32,
    fd: RawFd,
) -> Result<File, AdapterError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK | O_CLOEXEC)
        .open(parent_fd_path(parent_pid, fd))
        .map_err(|error| {
            AdapterError::Unavailable(format!(
                "Linux parent worker pipe cannot be opened: {error}"
            ))
        })?;
    validate_worker_pipe_handle(&file)?;
    Ok(file)
}

pub(super) fn open_parent_gateway_health_descriptor(
    parent_pid: u32,
    fd: RawFd,
) -> Result<File, AdapterError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK | O_CLOEXEC)
        .open(parent_fd_path(parent_pid, fd))
        .map_err(|error| {
            AdapterError::Unavailable(format!(
                "Linux parent Gateway health pipe cannot be opened: {error}"
            ))
        })?;
    validate_gateway_health_pipe_handle(&file)?;
    Ok(file)
}

pub(super) fn validate_worker_pipe_handle(file: &File) -> Result<(), AdapterError> {
    let metadata = file.metadata().map_err(|error| {
        AdapterError::Unavailable(format!("Linux worker pipe metadata failed: {error}"))
    })?;
    if !metadata.file_type().is_fifo() {
        return Err(AdapterError::Invalid(
            "Linux worker bootstrap descriptor is not a FIFO".to_owned(),
        ));
    }
    let filesystem = fstatfs(file).map_err(|error| {
        AdapterError::Unavailable(format!(
            "Linux worker pipe filesystem metadata failed: {error}"
        ))
    })?;
    // Linux UAPI PIPEFS_MAGIC, compared in the platform field's native type.
    if filesystem.f_type != 0x5049_5045 {
        return Err(AdapterError::Invalid(
            "Linux worker bootstrap descriptor is not a kernel pipe".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_gateway_health_pipe_handle(file: &File) -> Result<(), AdapterError> {
    let metadata = file.metadata().map_err(|error| {
        AdapterError::Unavailable(format!(
            "Linux Gateway health pipe metadata failed: {error}"
        ))
    })?;
    if !metadata.file_type().is_fifo() {
        return Err(AdapterError::Invalid(
            "Linux Gateway health descriptor is not a FIFO".to_owned(),
        ));
    }
    let filesystem = fstatfs(file).map_err(|error| {
        AdapterError::Unavailable(format!(
            "Linux Gateway health pipe filesystem metadata failed: {error}"
        ))
    })?;
    if filesystem.f_type != 0x5049_5045 {
        return Err(AdapterError::Invalid(
            "Linux Gateway health descriptor is not a kernel pipe".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn set_worker_reader_blocking(file: &File) -> Result<(), AdapterError> {
    let mut flags = fcntl_getfl(file).map_err(|error| {
        AdapterError::Unavailable(format!("Linux worker pipe flags cannot be read: {error}"))
    })?;
    flags.remove(OFlags::NONBLOCK);
    fcntl_setfl(file, flags).map_err(|error| {
        AdapterError::Unavailable(format!("Linux worker pipe cannot become blocking: {error}"))
    })
}

pub(super) fn set_nonblocking<Fd: AsFd>(fd: Fd, label: &str) -> Result<(), AdapterError> {
    let mut flags = fcntl_getfl(&fd).map_err(|error| {
        AdapterError::Unavailable(format!("{label} flags cannot be read: {error}"))
    })?;
    flags.insert(OFlags::NONBLOCK);
    fcntl_setfl(&fd, flags).map_err(|error| {
        AdapterError::Unavailable(format!("{label} cannot become nonblocking: {error}"))
    })
}

/// Write one bounded protocol message to a nonblocking descriptor.
///
/// The helper request and GO messages are written through this loop so a
/// child that never reads stdin cannot pin the launcher indefinitely.  The
/// descriptor is expected to have `O_NONBLOCK`; the function also preserves a
/// single deadline across short writes and `WouldBlock` polls.
pub(super) fn write_bounded(
    writer: &mut impl Write,
    bytes: &[u8],
    timeout: Duration,
    label: &str,
) -> Result<(), AdapterError> {
    if bytes.is_empty() {
        return Ok(());
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let mut written = 0_usize;
    while written < bytes.len() {
        if Instant::now() >= deadline {
            return Err(AdapterError::Timeout(format!("{label} timed out")));
        }
        match writer.write(&bytes[written..]) {
            Ok(0) => {
                return Err(AdapterError::Unavailable(format!(
                    "{label} closed before completion"
                )));
            }
            Ok(count) => {
                written = written
                    .checked_add(count)
                    .ok_or_else(|| AdapterError::Invalid(format!("{label} byte count overflow")))?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(AdapterError::Timeout(format!("{label} timed out")));
                }
                thread::sleep(CHILD_CLEANUP_POLL.min(remaining));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(AdapterError::Io(format!("{label} failed: {error}")));
            }
        }
    }
    Ok(())
}

pub(super) fn write_worker_frame(
    writer: &mut File,
    frame: &[u8],
    timeout: Duration,
) -> Result<(), AdapterError> {
    if frame.is_empty() || frame.len() > crate::worker_bootstrap::MAX_FRAME_BYTES {
        return Err(AdapterError::Invalid(
            "Linux worker bootstrap frame exceeds bounds".to_owned(),
        ));
    }
    write_bounded(
        writer,
        frame,
        timeout,
        "Linux worker bootstrap frame handoff",
    )
}

pub(super) fn write_gateway_health_frame(
    writer: &mut File,
    frame: &[u8],
    timeout: Duration,
) -> Result<(), AdapterError> {
    if frame.len() != crate::platform::gateway_health::FRAME_BYTES {
        return Err(AdapterError::Invalid(
            "Linux Gateway health bootstrap frame has an invalid length".to_owned(),
        ));
    }
    write_bounded(
        writer,
        frame,
        timeout,
        "Linux Gateway health bootstrap frame handoff",
    )
}

pub(super) fn read_gateway_health_frame(
    reader: &mut File,
    request: &LinuxHelperRequest,
    timeout: Duration,
) -> Result<GatewayHealthBootstrap, AdapterError> {
    if request.specification.component != ComponentKind::Gateway {
        return Err(AdapterError::Unsupported(
            "Linux Gateway health bootstrap pipe requires the Gateway role".to_owned(),
        ));
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let mut frame = zeroize::Zeroizing::new([0_u8; crate::platform::gateway_health::FRAME_BYTES]);
    let mut received = 0_usize;
    while received < frame.len() {
        if Instant::now() >= deadline {
            return Err(AdapterError::Timeout(
                "Linux Gateway health bootstrap frame read timed out".to_owned(),
            ));
        }
        match reader.read(&mut frame[received..]) {
            Ok(0) => {
                return Err(AdapterError::Unavailable(
                    "Linux Gateway health bootstrap frame was truncated".to_owned(),
                ));
            }
            Ok(count) => {
                received = received.checked_add(count).ok_or_else(|| {
                    AdapterError::Invalid("Linux Gateway health frame read overflow".to_owned())
                })?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(AdapterError::Timeout(
                        "Linux Gateway health bootstrap frame read timed out".to_owned(),
                    ));
                }
                thread::sleep(CHILD_CLEANUP_POLL.min(remaining));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(AdapterError::Io(format!(
                    "Linux Gateway health bootstrap frame read failed: {error}"
                )));
            }
        }
    }
    let mut trailing = [0_u8; 1];
    loop {
        match reader.read(&mut trailing) {
            Ok(0) => break,
            Ok(_) => {
                return Err(AdapterError::Invalid(
                    "Linux Gateway health bootstrap frame has trailing bytes".to_owned(),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(AdapterError::Timeout(
                        "Linux Gateway health frame close was not observed".to_owned(),
                    ));
                }
                thread::sleep(CHILD_CLEANUP_POLL.min(remaining));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(AdapterError::Io(format!(
                    "Linux Gateway health frame trailing-byte check failed: {error}"
                )));
            }
        }
    }
    let bootstrap = GatewayHealthBootstrap::from_frame(frame.as_ref()).map_err(|error| {
        map_gateway_health_bootstrap_error(error, "Linux Gateway health bootstrap frame")
    })?;
    bootstrap.validate_for_launch(&request.specification)?;
    Ok(bootstrap)
}

pub(super) fn map_gateway_health_bootstrap_error(
    error: GatewayHealthBootstrapError,
    prefix: &str,
) -> AdapterError {
    match error {
        GatewayHealthBootstrapError::WrongRole => {
            AdapterError::Unsupported(format!("{prefix} requires the Gateway role"))
        }
        GatewayHealthBootstrapError::NonceMismatch => {
            AdapterError::IdentityMismatch(format!("{prefix} nonce differs from the launch"))
        }
        _ => AdapterError::Invalid(format!("{prefix} is invalid")),
    }
}

pub(super) fn encode_frame(
    specification: &LaunchSpec,
    cgroup_path: &Path,
) -> Result<Vec<u8>, AdapterError> {
    if !cgroup_path.is_absolute() {
        return Err(AdapterError::Invalid(
            "Linux helper cgroup path must be absolute".to_owned(),
        ));
    }
    let mut payload = Vec::with_capacity(1024);
    payload.extend_from_slice(FRAME_MAGIC);
    payload.push(FRAME_VERSION);
    payload.push(component_code(specification.component));
    match specification.session {
        SessionSelector::ActiveUser => payload.push(0),
        SessionSelector::Explicit(session) => {
            payload.push(1);
            payload.extend_from_slice(&session.to_le_bytes());
        }
    }
    payload.push(0);
    put_string(&mut payload, &specification.deployment_id)?;
    put_string(&mut payload, &specification.instance_id)?;
    put_string(&mut payload, &specification.incarnation)?;
    put_string(&mut payload, &specification.launch_nonce)?;
    put_path(&mut payload, cgroup_path)?;
    put_path(&mut payload, &specification.executable)?;
    put_string(&mut payload, &specification.executable_sha256)?;
    payload.extend_from_slice(
        &u64::try_from(specification.graceful_timeout.as_millis())
            .map_err(|_| AdapterError::Invalid("Linux graceful timeout overflow".to_owned()))?
            .to_le_bytes(),
    );
    payload.extend_from_slice(
        &u64::try_from(specification.force_timeout.as_millis())
            .map_err(|_| AdapterError::Invalid("Linux force timeout overflow".to_owned()))?
            .to_le_bytes(),
    );
    match specification.working_directory.as_deref() {
        Some(path) => {
            payload.push(1);
            put_path(&mut payload, path)?;
        }
        None => payload.push(0),
    }
    put_count(&mut payload, specification.arguments.len(), MAX_ARGUMENTS)?;
    for argument in &specification.arguments {
        put_string(&mut payload, argument)?;
    }
    put_count(
        &mut payload,
        specification.environment.len(),
        MAX_ENVIRONMENT,
    )?;
    for (name, value) in &specification.environment {
        put_string(&mut payload, name)?;
        put_string(&mut payload, value)?;
    }
    if payload.len() > MAX_FRAME_BYTES {
        return Err(AdapterError::Invalid(
            "Linux helper frame exceeds bounds".to_owned(),
        ));
    }
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(
        &u32::try_from(payload.len())
            .map_err(|_| AdapterError::Invalid("Linux helper frame length overflow".to_owned()))?
            .to_le_bytes(),
    );
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub(super) fn decode_frame(payload: &[u8]) -> Result<LinuxHelperRequest, AdapterError> {
    let mut cursor = Cursor::new(payload);
    let mut magic = [0_u8; FRAME_MAGIC.len()];
    cursor
        .read_exact(&mut magic)
        .map_err(|error| protocol_io(&error))?;
    if &magic != FRAME_MAGIC {
        return Err(AdapterError::Invalid(
            "Linux helper frame magic is invalid".to_owned(),
        ));
    }
    let version = read_byte(&mut cursor)?;
    if version != FRAME_VERSION {
        return Err(AdapterError::Unsupported(
            "Linux helper frame version is unsupported".to_owned(),
        ));
    }
    let component = component_from_code(read_byte(&mut cursor)?)?;
    let session_code = read_byte(&mut cursor)?;
    let session = match session_code {
        0 => SessionSelector::ActiveUser,
        1 => SessionSelector::Explicit(read_u32(&mut cursor)?),
        _ => {
            return Err(AdapterError::Invalid(
                "Linux helper session selector is invalid".to_owned(),
            ));
        }
    };
    let reserved = read_byte(&mut cursor)?;
    if reserved != 0 {
        return Err(AdapterError::Invalid(
            "Linux helper frame reserved byte is nonzero".to_owned(),
        ));
    }
    let deployment_id = read_string(&mut cursor, MAX_FIELD_BYTES)?;
    let instance_id = read_string(&mut cursor, MAX_FIELD_BYTES)?;
    let incarnation = read_string(&mut cursor, MAX_FIELD_BYTES)?;
    let launch_nonce = read_string(&mut cursor, MAX_FIELD_BYTES)?;
    let cgroup_path = read_path(&mut cursor)?;
    let executable = read_path(&mut cursor)?;
    let executable_sha256 = read_string(&mut cursor, MAX_FIELD_BYTES)?;
    let graceful_timeout = Duration::from_millis(read_u64(&mut cursor)?);
    let force_timeout = Duration::from_millis(read_u64(&mut cursor)?);
    let working_directory = match read_byte(&mut cursor)? {
        0 => None,
        1 => Some(read_path(&mut cursor)?),
        _ => {
            return Err(AdapterError::Invalid(
                "Linux helper working-directory marker is invalid".to_owned(),
            ));
        }
    };
    let argument_count = read_count(&mut cursor, MAX_ARGUMENTS)?;
    let mut arguments = Vec::with_capacity(argument_count);
    for _ in 0..argument_count {
        arguments.push(read_string(&mut cursor, MAX_FIELD_BYTES)?);
    }
    let environment_count = read_count(&mut cursor, MAX_ENVIRONMENT)?;
    let mut environment = Vec::with_capacity(environment_count);
    for _ in 0..environment_count {
        environment.push((
            read_string(&mut cursor, MAX_FIELD_BYTES)?,
            read_string(&mut cursor, MAX_FIELD_BYTES)?,
        ));
    }
    if cursor.position() != u64::try_from(payload.len()).unwrap_or(u64::MAX) {
        return Err(AdapterError::Invalid(
            "Linux helper frame contains trailing bytes".to_owned(),
        ));
    }
    let specification = LaunchSpec {
        deployment_id,
        instance_id,
        component,
        incarnation,
        launch_nonce,
        executable,
        executable_sha256,
        arguments,
        working_directory,
        environment,
        session,
        graceful_timeout,
        force_timeout,
    };
    specification.validate()?;
    Ok(LinuxHelperRequest {
        specification,
        cgroup_path,
    })
}

pub(super) fn protocol_io(error: &io::Error) -> AdapterError {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        AdapterError::Unavailable("Linux helper pipe closed before the next frame".to_owned())
    } else {
        AdapterError::Io(format!("Linux helper protocol I/O failed: {error}"))
    }
}

pub(super) fn component_code(component: ComponentKind) -> u8 {
    match component {
        ComponentKind::Gateway => 1,
        ComponentKind::Harness => 2,
        ComponentKind::HostBroker => 3,
        ComponentKind::Synthetic => 4,
    }
}

pub(super) fn component_from_code(code: u8) -> Result<ComponentKind, AdapterError> {
    match code {
        1 => Ok(ComponentKind::Gateway),
        2 => Ok(ComponentKind::Harness),
        3 => Ok(ComponentKind::HostBroker),
        4 => Ok(ComponentKind::Synthetic),
        _ => Err(AdapterError::Unsupported(
            "Linux helper component role is unsupported".to_owned(),
        )),
    }
}

pub(super) fn put_count(
    bytes: &mut Vec<u8>,
    count: usize,
    maximum: usize,
) -> Result<(), AdapterError> {
    if count > maximum {
        return Err(AdapterError::Invalid(
            "Linux helper collection exceeds bounds".to_owned(),
        ));
    }
    bytes.extend_from_slice(
        &u16::try_from(count)
            .map_err(|_| {
                AdapterError::Invalid("Linux helper collection length overflow".to_owned())
            })?
            .to_le_bytes(),
    );
    Ok(())
}

pub(super) fn read_count(reader: &mut impl Read, maximum: usize) -> Result<usize, AdapterError> {
    let mut bytes = [0_u8; 2];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| protocol_io(&error))?;
    let count = usize::from(u16::from_le_bytes(bytes));
    if count > maximum {
        return Err(AdapterError::Invalid(
            "Linux helper collection exceeds bounds".to_owned(),
        ));
    }
    Ok(count)
}

pub(super) fn put_path(bytes: &mut Vec<u8>, path: &Path) -> Result<(), AdapterError> {
    let value = path.to_str().ok_or_else(|| {
        AdapterError::Invalid("Linux helper paths must be valid UTF-8".to_owned())
    })?;
    put_string(bytes, value)
}

pub(super) fn read_path(reader: &mut impl Read) -> Result<PathBuf, AdapterError> {
    Ok(PathBuf::from(read_string(reader, MAX_FIELD_BYTES)?))
}

pub(super) fn put_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), AdapterError> {
    if value.is_empty() || value.len() > MAX_FIELD_BYTES || value.contains('\0') {
        return Err(AdapterError::Invalid(
            "Linux helper string is outside bounds".to_owned(),
        ));
    }
    bytes.extend_from_slice(
        &u16::try_from(value.len())
            .map_err(|_| AdapterError::Invalid("Linux helper string length overflow".to_owned()))?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

pub(super) fn put_string_io(writer: &mut impl Write, value: &str) -> io::Result<()> {
    let length = u16::try_from(value.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "string is too long"))?;
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(value.as_bytes())
}

pub(super) fn read_string(reader: &mut impl Read, maximum: usize) -> Result<String, AdapterError> {
    let mut length = [0_u8; 2];
    reader
        .read_exact(&mut length)
        .map_err(|error| protocol_io(&error))?;
    let length = usize::from(u16::from_le_bytes(length));
    if length == 0 || length > maximum {
        return Err(AdapterError::Invalid(
            "Linux helper string is outside bounds".to_owned(),
        ));
    }
    let mut bytes = vec![0_u8; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| protocol_io(&error))?;
    String::from_utf8(bytes)
        .map_err(|_| AdapterError::Invalid("Linux helper string is not UTF-8".to_owned()))
}

pub(super) fn read_byte(reader: &mut impl Read) -> Result<u8, AdapterError> {
    let mut byte = [0_u8; 1];
    reader
        .read_exact(&mut byte)
        .map_err(|error| protocol_io(&error))?;
    Ok(byte[0])
}

pub(super) fn read_u64(reader: &mut impl Read) -> Result<u64, AdapterError> {
    let mut bytes = [0_u8; 8];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| protocol_io(&error))?;
    Ok(u64::from_le_bytes(bytes))
}

pub(super) fn read_u32(reader: &mut impl Read) -> Result<u32, AdapterError> {
    let mut bytes = [0_u8; 4];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| protocol_io(&error))?;
    Ok(u32::from_le_bytes(bytes))
}
