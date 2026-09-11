//! Fixed, one-shot Gateway health bootstrap material.
//!
//! This protocol is deliberately separate from the Harness worker bootstrap.
//! The native launcher accepts it only through the typed Gateway launch path
//! and writes the exact fixed frame to a private anonymous-pipe reader.

use crate::contract::{ComponentKind, PlatformError, WindowsLaunchSpec};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// The dedicated Gateway health bootstrap marker.
const MAGIC: &[u8; 8] = b"STS2GH01";
/// Number of bytes in the UUID launch nonce.
const NONCE_BYTES: usize = 16;
/// Number of bytes in the one-shot health key.
const KEY_BYTES: usize = 32;
/// Size of one complete Gateway health bootstrap frame.
pub const GATEWAY_HEALTH_BOOTSTRAP_FRAME_BYTES: usize = MAGIC.len() + NONCE_BYTES + KEY_BYTES;

/// A validated, fixed Gateway health frame.
///
/// The frame is kept in zeroizing storage and this type intentionally exposes
/// neither a derived `Debug` implementation nor any serialization surface.
/// Its only native consumer is the Windows launch path in this crate.
pub struct GatewayHealthBootstrapLaunch {
    frame: Zeroizing<[u8; GATEWAY_HEALTH_BOOTSTRAP_FRAME_BYTES]>,
}

impl fmt::Debug for GatewayHealthBootstrapLaunch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayHealthBootstrapLaunch")
            .field("frame_bytes", &self.frame.len())
            .finish()
    }
}

impl GatewayHealthBootstrapLaunch {
    /// Construct a frame bound to one exact Gateway [`WindowsLaunchSpec`].
    ///
    /// The launch nonce must be canonical, non-nil `UUIDv4` text.  The key is
    /// copied into zeroizing frame storage and cleared before this method
    /// returns.  A zero key is rejected because it cannot authenticate a
    /// health channel.
    pub fn new(
        specification: &WindowsLaunchSpec,
        mut key: [u8; KEY_BYTES],
    ) -> Result<Self, PlatformError> {
        let result = (|| {
            if specification.component != ComponentKind::Gateway {
                return Err(PlatformError::Unsupported(
                    "Gateway health bootstrap is only valid for the Gateway role".to_owned(),
                ));
            }
            let nonce = parse_uuid_v4(&specification.launch_nonce)?;
            if key.iter().all(|byte| *byte == 0) {
                return Err(PlatformError::Invalid(
                    "Gateway health bootstrap key cannot be all zero".to_owned(),
                ));
            }
            let mut frame = Zeroizing::new([0_u8; GATEWAY_HEALTH_BOOTSTRAP_FRAME_BYTES]);
            frame[..MAGIC.len()].copy_from_slice(MAGIC);
            frame[MAGIC.len()..MAGIC.len() + NONCE_BYTES].copy_from_slice(&nonce);
            frame[MAGIC.len() + NONCE_BYTES..].copy_from_slice(&key);
            Ok(Self { frame })
        })();
        key.zeroize();
        result
    }

    /// Decode one exact fixed frame for later launch binding.
    ///
    /// The role and launch nonce are checked by [`Self::validate_for_launch`]
    /// before the native launch begins.  Invalid input is cleared before the
    /// error is returned.
    pub fn from_frame(
        mut frame: [u8; GATEWAY_HEALTH_BOOTSTRAP_FRAME_BYTES],
    ) -> Result<Self, PlatformError> {
        let result = (|| {
            if frame[..MAGIC.len()] != *MAGIC {
                return Err(PlatformError::Invalid(
                    "Gateway health bootstrap frame has invalid magic".to_owned(),
                ));
            }
            let nonce_start = MAGIC.len();
            let nonce_end = nonce_start + NONCE_BYTES;
            validate_uuid_v4(&frame[nonce_start..nonce_end])?;
            if frame[nonce_end..].iter().all(|byte| *byte == 0) {
                return Err(PlatformError::Invalid(
                    "Gateway health bootstrap key cannot be all zero".to_owned(),
                ));
            }
            let mut stored = Zeroizing::new([0_u8; GATEWAY_HEALTH_BOOTSTRAP_FRAME_BYTES]);
            stored.copy_from_slice(&frame);
            Ok(Self { frame: stored })
        })();
        frame.zeroize();
        result
    }

    /// Validate role and exact `UUIDv4` nonce binding before process creation.
    pub fn validate_for_launch(
        &self,
        specification: &WindowsLaunchSpec,
    ) -> Result<(), PlatformError> {
        if specification.component != ComponentKind::Gateway {
            return Err(PlatformError::Unsupported(
                "Gateway health bootstrap is only valid for the Gateway role".to_owned(),
            ));
        }
        let expected = parse_uuid_v4(&specification.launch_nonce)?;
        let actual = &self.frame[MAGIC.len()..MAGIC.len() + NONCE_BYTES];
        if actual != expected {
            return Err(PlatformError::IdentityMismatch(
                "Gateway health bootstrap nonce differs from Windows launch nonce".to_owned(),
            ));
        }
        Ok(())
    }

    /// Return the exact frame to the private native launcher.
    #[cfg(any(windows, test))]
    pub(crate) fn frame(&self) -> &[u8] {
        self.frame.as_ref()
    }
}

fn parse_uuid_v4(value: &str) -> Result<[u8; NONCE_BYTES], PlatformError> {
    if value.len() != 36
        || !value
            .as_bytes()
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 8 | 13 | 18 | 23) == (*byte == b'-'))
    {
        return Err(PlatformError::Invalid(
            "Gateway health bootstrap nonce must be canonical UUIDv4 text".to_owned(),
        ));
    }
    let mut bytes = [0_u8; NONCE_BYTES];
    let mut output = 0;
    for (index, byte) in value.bytes().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            continue;
        }
        if output % 2 == 0 {
            bytes[output / 2] = hex(byte)? << 4;
        } else {
            bytes[output / 2] |= hex(byte)?;
        }
        output += 1;
    }
    validate_uuid_v4(&bytes)?;
    Ok(bytes)
}

fn validate_uuid_v4(bytes: &[u8]) -> Result<(), PlatformError> {
    if bytes.len() != NONCE_BYTES
        || bytes.iter().all(|byte| *byte == 0)
        || bytes[6] & 0xf0 != 0x40
        || bytes[8] & 0xc0 != 0x80
    {
        return Err(PlatformError::Invalid(
            "Gateway health bootstrap nonce must be a non-nil UUIDv4".to_owned(),
        ));
    }
    Ok(())
}

fn hex(byte: u8) -> Result<u8, PlatformError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(PlatformError::Invalid(
            "Gateway health bootstrap nonce contains non-hexadecimal text".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::SessionSelector;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    const NONCE: &str = "00112233-4455-4677-8899-aabbccddeeff";

    fn specification(component: ComponentKind, nonce: &str) -> WindowsLaunchSpec {
        let executable = PathBuf::from(r"C:\ascension\gateway.exe");
        // Codec tests validate role/nonce/frame semantics only. The native
        // launcher separately validates OS paths and executable allowlists.
        WindowsLaunchSpec {
            component,
            executable,
            arguments: Vec::new(),
            environment: BTreeMap::new(),
            working_directory: None,
            session: SessionSelector::CurrentService,
            launch_nonce: nonce.to_owned(),
            graceful_timeout_ms: 500,
            force_timeout_ms: 5_000,
        }
    }

    #[test]
    fn fixed_frame_has_magic_nonce_key_and_no_secret_debug_output() {
        let launch = GatewayHealthBootstrapLaunch::new(
            &specification(ComponentKind::Gateway, NONCE),
            [7_u8; KEY_BYTES],
        )
        .expect("valid Gateway health bootstrap");
        assert_eq!(launch.frame().len(), GATEWAY_HEALTH_BOOTSTRAP_FRAME_BYTES);
        assert_eq!(&launch.frame()[..MAGIC.len()], MAGIC);
        assert_eq!(
            &launch.frame()[MAGIC.len()..MAGIC.len() + NONCE_BYTES],
            &[
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]
        );
        let debug = format!("{launch:?}");
        assert!(!debug.contains('7'));
        assert!(debug.contains("frame_bytes"));
    }

    #[test]
    fn fixed_frame_decode_keeps_exact_launch_binding() {
        let specification = specification(ComponentKind::Gateway, NONCE);
        let launch = GatewayHealthBootstrapLaunch::new(&specification, [7_u8; KEY_BYTES])
            .expect("valid Gateway health bootstrap");
        let frame: [u8; GATEWAY_HEALTH_BOOTSTRAP_FRAME_BYTES] =
            launch.frame().try_into().expect("fixed frame size");
        let decoded =
            GatewayHealthBootstrapLaunch::from_frame(frame).expect("valid Gateway health frame");
        assert!(decoded.validate_for_launch(&specification).is_ok());
    }

    #[test]
    fn malformed_frame_role_nonce_and_key_fail_closed() {
        let gateway_specification = specification(ComponentKind::Gateway, NONCE);
        assert!(
            GatewayHealthBootstrapLaunch::new(&gateway_specification, [0_u8; KEY_BYTES]).is_err()
        );
        assert!(
            GatewayHealthBootstrapLaunch::new(
                &specification(ComponentKind::Harness, NONCE),
                [1_u8; KEY_BYTES]
            )
            .is_err()
        );
        assert!(
            GatewayHealthBootstrapLaunch::new(&gateway_specification, [1_u8; KEY_BYTES]).is_ok()
        );
        let mut frame = [0_u8; GATEWAY_HEALTH_BOOTSTRAP_FRAME_BYTES];
        frame[..MAGIC.len()].copy_from_slice(MAGIC);
        assert!(GatewayHealthBootstrapLaunch::from_frame(frame).is_err());
        let mut frame = [0_u8; GATEWAY_HEALTH_BOOTSTRAP_FRAME_BYTES];
        frame[..MAGIC.len()].copy_from_slice(b"BAD-GH01");
        assert!(GatewayHealthBootstrapLaunch::from_frame(frame).is_err());
    }

    #[test]
    fn frame_nonce_must_match_exact_gateway_launch() {
        let first = specification(ComponentKind::Gateway, NONCE);
        let second = specification(
            ComponentKind::Gateway,
            "00112233-4455-4677-8899-aabbccddeef0",
        );
        let launch = GatewayHealthBootstrapLaunch::new(&first, [1_u8; KEY_BYTES])
            .expect("valid Gateway health bootstrap");
        assert!(launch.validate_for_launch(&first).is_ok());
        assert!(matches!(
            launch.validate_for_launch(&second),
            Err(PlatformError::IdentityMismatch(_))
        ));
    }

    #[test]
    fn nonce_parser_requires_uuidv4() {
        assert!(
            GatewayHealthBootstrapLaunch::new(
                &specification(
                    ComponentKind::Gateway,
                    "00000000-0000-4000-8000-000000000000"
                ),
                [1_u8; KEY_BYTES]
            )
            .is_ok()
        );
        for nonce in [
            "00112233-4455-4677-0899-aabbccddeeff",
            "001122334455-4677-8899-aabbccddeeff",
            "00112233-4455-5677-8899-aabbccddeeff",
            "00112233-4455-4677-8899-AABBCCDDEEFF",
        ] {
            assert!(
                GatewayHealthBootstrapLaunch::new(
                    &specification(ComponentKind::Gateway, nonce),
                    [1_u8; KEY_BYTES]
                )
                .is_err()
            );
        }
    }
}
