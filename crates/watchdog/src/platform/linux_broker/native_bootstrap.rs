//! Descriptor-only stdin handoff to PID 1. No bootstrap bytes are placed in
//! D-Bus property data, unit metadata, environment, or persistent storage.

use super::super::bootstrap::BrokerBootstrapLaunch;
use super::super::{BrokerError, BrokerRequest, BrokerResult};
use rustix::fs::{MemfdFlags, Mode, SealFlags, fchmod, fcntl_add_seals, memfd_create};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsFd;
use zbus::zvariant::{Fd, OwnedValue, Value};

pub(super) fn stdin_property(
    request: &BrokerRequest,
    bootstrap: &BrokerBootstrapLaunch,
) -> BrokerResult<OwnedValue> {
    bootstrap.validate_for_request(request)?;
    let descriptor = memfd_create(
        "ascension-broker-bootstrap",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .map_err(|_| failure("cannot allocate broker bootstrap descriptor"))?;
    let mut file = File::from(descriptor);
    file.write_all(bootstrap.frame())
        .map_err(|_| failure("cannot populate broker bootstrap descriptor"))?;
    fchmod(&file, Mode::RUSR)
        .map_err(|_| failure("cannot restrict broker bootstrap descriptor"))?;
    fcntl_add_seals(
        &file,
        SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL,
    )
    .map_err(|_| failure("cannot seal broker bootstrap descriptor"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| failure("cannot rewind broker bootstrap descriptor"))?;
    // try_to_owned duplicates the held descriptor. Dropping `file` cannot
    // invalidate the property; the D-Bus value owns its CLOEXEC duplicate.
    Value::new(Fd::from(file.as_fd()))
        .try_to_owned()
        .map_err(|_| failure("cannot encode broker bootstrap descriptor"))
}

fn failure(message: &str) -> BrokerError {
    BrokerError::Unavailable(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::gateway_health::GatewayHealthBootstrap;
    use crate::platform::linux_broker::BrokerComponent;
    use rustix::fs::fcntl_get_seals;
    use std::io::Read;
    use uuid::Uuid;
    use zbus::zvariant::serialized::Context;
    use zbus::zvariant::{LE, OwnedValue, to_bytes};

    fn bootstrap() -> Result<(BrokerRequest, BrokerBootstrapLaunch), Box<dyn std::error::Error>> {
        let request = BrokerRequest {
            component: BrokerComponent::Gateway,
            instance: "gateway".to_owned(),
            incarnation: "runtime-1".to_owned(),
            nonce: "00000000-0000-4000-8000-000000000011".to_owned(),
        };
        let health = GatewayHealthBootstrap::new(Uuid::parse_str(&request.nonce)?, [0x7b; 32])?;
        let frame = BrokerBootstrapLaunch::for_gateway(
            &request,
            "00000000-0000-4000-8000-000000000022",
            &health,
        )?;
        Ok((request, frame))
    }

    #[test]
    fn dbus_stdin_property_owns_one_sealed_descriptor_not_frame_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let (request, bootstrap) = bootstrap()?;
        let property = stdin_property(&request, &bootstrap)?;
        let properties = vec![("StandardInputFileDescriptor", property)];
        let aux: Vec<(String, Vec<(String, OwnedValue)>)> = Vec::new();
        let body = ("test.service", "fail", properties, aux);
        let encoded = to_bytes(Context::new_dbus(LE, 0), &body)?;
        assert_eq!(encoded.fds().len(), 1);
        assert!(
            !encoded
                .windows(bootstrap.frame().len())
                .any(|part| part == bootstrap.frame())
        );
        assert!(!encoded.windows(32).any(|part| part == [0x7b; 32]));
        let seals = fcntl_get_seals(encoded.fds()[0].as_fd())?;
        assert!(
            seals
                .contains(SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL)
        );
        let mut input = File::from(encoded.fds()[0].as_fd().try_clone_to_owned()?);
        assert!(input.write_all(b"tamper").is_err());
        let mut received = Vec::new();
        input.read_to_end(&mut received)?;
        assert_eq!(received, bootstrap.frame());
        let mut tail = [0_u8; 1];
        assert_eq!(input.read(&mut tail)?, 0);
        Ok(())
    }

    #[test]
    fn fd_value_roundtrip_survives_original_property_drop() -> Result<(), Box<dyn std::error::Error>>
    {
        let (request, bootstrap) = bootstrap()?;
        let property = stdin_property(&request, &bootstrap)?;
        let encoded = to_bytes(Context::new_dbus(LE, 0), &property)?;
        drop(property);
        let (decoded, consumed): (OwnedValue, usize) = encoded.deserialize()?;
        assert_eq!(consumed, encoded.len());
        let descriptor = Fd::try_from(decoded)?;
        let mut input = File::from(descriptor.as_fd().try_clone_to_owned()?);
        let mut received = Vec::new();
        input.read_to_end(&mut received)?;
        assert_eq!(received, bootstrap.frame());
        Ok(())
    }

    #[test]
    fn mismatched_launch_cannot_allocate_stdin_property() -> Result<(), Box<dyn std::error::Error>>
    {
        let (mut request, bootstrap) = bootstrap()?;
        request.nonce = "00000000-0000-4000-8000-000000000033".to_owned();
        assert!(stdin_property(&request, &bootstrap).is_err());
        Ok(())
    }
}
