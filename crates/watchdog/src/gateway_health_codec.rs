//! Watchdog-owned implementation of the versioned gateway health MAC contract.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::{HealthError, MAX_BODY_BYTES};

type HealthMac = Hmac<Sha256>;

fn start(key: &[u8; 32], domain: &[u8], challenge: &[u8; 32]) -> Result<HealthMac, HealthError> {
    let mut mac = HealthMac::new_from_slice(key).map_err(|_| HealthError::Authentication)?;
    mac.update(domain);
    mac.update(&[0]);
    field(&mut mac, b"GET")?;
    field(&mut mac, b"/health/status/v1")?;
    field(&mut mac, challenge)?;
    Ok(mac)
}

fn field(mac: &mut HealthMac, value: &[u8]) -> Result<(), HealthError> {
    let length = u32::try_from(value.len()).map_err(|_| HealthError::Bounds)?;
    mac.update(&length.to_be_bytes());
    mac.update(value);
    Ok(())
}

pub(super) fn request_tag(
    key: &[u8; 32],
    challenge: &[u8; 32],
    nonce: &[u8; 16],
    sequence: u64,
) -> Result<String, HealthError> {
    if sequence == 0 {
        return Err(HealthError::Sequence);
    }
    let mut mac = start(key, b"sts2-gateway-health-request-v1", challenge)?;
    mac.update(nonce);
    mac.update(&sequence.to_be_bytes());
    Ok(hex(&mac.finalize().into_bytes()))
}

pub(super) fn verify_response(
    key: &[u8; 32],
    challenge: &[u8; 32],
    status: u16,
    body: &[u8],
    header: &str,
) -> Result<(), HealthError> {
    if body.len() > MAX_BODY_BYTES || !matches!(status, 200 | 503) {
        return Err(HealthError::Bounds);
    }
    let tag = decode_tag(header)?;
    let mut mac = start(key, b"sts2-gateway-health-attestation-v1", challenge)?;
    mac.update(&status.to_be_bytes());
    field(&mut mac, body)?;
    mac.verify_slice(&tag)
        .map_err(|_| HealthError::Authentication)
}

fn decode_tag(header: &str) -> Result<[u8; 32], HealthError> {
    if header.len() != 64 {
        return Err(HealthError::Authentication);
    }
    let mut tag = [0; 32];
    for (output, digits) in tag.iter_mut().zip(header.as_bytes().chunks_exact(2)) {
        let digit = |byte| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(HealthError::Authentication),
        };
        *output = (digit(digits[0])? << 4) | digit(digits[1])?;
    }
    Ok(tag)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_published_response_vector_matches_independent_consumer() {
        let body = br#"{"contract":"sts2-gateway-health-v1"}"#;
        let tag = "674b6bd499ba354c4d2296a38c20855a2be27eae2462d4f644bea9dea4f96ddb";
        assert_eq!(
            verify_response(&[0x22; 32], &[0x11; 32], 200, body, tag),
            Ok(())
        );
        assert!(verify_response(&[0x23; 32], &[0x11; 32], 200, body, tag).is_err());
        assert!(verify_response(&[0x22; 32], &[0x12; 32], 200, body, tag).is_err());
        assert!(verify_response(&[0x22; 32], &[0x11; 32], 503, body, tag).is_err());
        assert!(verify_response(&[0x22; 32], &[0x11; 32], 200, b"{}", tag).is_err());
        assert!(verify_response(&[0x22; 32], &[0x11; 32], 200, body, &tag.to_uppercase()).is_err());
    }

    #[test]
    fn request_tags_bind_both_launch_and_sequence() -> Result<(), HealthError> {
        let tag = request_tag(&[1; 32], &[2; 32], &[3; 16], 1)?;
        assert_ne!(tag, request_tag(&[1; 32], &[2; 32], &[4; 16], 1)?);
        assert_ne!(tag, request_tag(&[1; 32], &[2; 32], &[3; 16], 2)?);
        assert!(request_tag(&[1; 32], &[2; 32], &[3; 16], 0).is_err());
        Ok(())
    }
}
