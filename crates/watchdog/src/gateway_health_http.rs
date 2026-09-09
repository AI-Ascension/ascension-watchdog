//! Fixed HTTP/1.1 loopback exchange; no redirects, compression, or chunking.

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Instant;

use super::{HealthError, MAX_BODY_BYTES, remaining};

const MAX_HEADERS: usize = 16 * 1024;
const MAX_HEADER_COUNT: usize = 32;

pub(super) struct Response {
    pub(super) status: u16,
    pub(super) tag: String,
    pub(super) body: Vec<u8>,
}

pub(super) fn exchange(
    address: SocketAddr,
    request: &[u8],
    deadline: Instant,
) -> Result<Response, HealthError> {
    let mut stream = TcpStream::connect_timeout(&address, remaining(deadline)?)
        .map_err(|error| io_error(&error))?;
    let mut sent = 0;
    while sent < request.len() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|error| io_error(&error))?;
        match stream.write(&request[sent..]) {
            Ok(0) => return Err(HealthError::Transport),
            Ok(count) => sent += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(io_error(&error)),
        }
    }
    let mut received = Vec::with_capacity(MAX_HEADERS);
    let header_end = loop {
        if let Some(end) = received.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break end + 4;
        }
        if received.len() >= MAX_HEADERS {
            return Err(HealthError::Bounds);
        }
        let mut chunk = [0; 2048];
        let count = read(&mut stream, &mut chunk, deadline)?;
        if count == 0 {
            return Err(HealthError::Framing);
        }
        received.extend_from_slice(&chunk[..count]);
    };
    if header_end > MAX_HEADERS {
        return Err(HealthError::Bounds);
    }
    let (status, length, tag) = headers(&received[..header_end])?;
    let mut body = received.split_off(header_end);
    if body.len() > length {
        return Err(HealthError::Framing);
    }
    body.reserve(length.saturating_sub(body.len()));
    while body.len() < length {
        let mut chunk = [0; 4096];
        let limit = chunk.len().min(length - body.len());
        let count = read(&mut stream, &mut chunk[..limit], deadline)?;
        if count == 0 {
            return Err(HealthError::Framing);
        }
        body.extend_from_slice(&chunk[..count]);
    }
    // The fixed protocol closes every connection. Do not accept a second
    // message or silently consume unbounded trailing data from this peer.
    if read(&mut stream, &mut [0; 1], deadline)? != 0 {
        return Err(HealthError::Framing);
    }
    remaining(deadline)?;
    Ok(Response { status, tag, body })
}

fn read(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<usize, HealthError> {
    loop {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|error| io_error(&error))?;
        match stream.read(buffer) {
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            result => return result.map_err(|error| io_error(&error)),
        }
    }
}

fn io_error(error: &std::io::Error) -> HealthError {
    if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) {
        HealthError::Deadline
    } else {
        HealthError::Transport
    }
}

fn headers(bytes: &[u8]) -> Result<(u16, usize, String), HealthError> {
    if !bytes.is_ascii() {
        return Err(HealthError::Framing);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| HealthError::Framing)?;
    let mut lines = text.split("\r\n");
    let first = lines.next().ok_or(HealthError::Framing)?;
    let mut status_parts = first.splitn(3, ' ');
    if status_parts.next() != Some("HTTP/1.1") {
        return Err(HealthError::Framing);
    }
    let status = match status_parts.next() {
        Some("200") => 200,
        Some("503") => 503,
        _ => return Err(HealthError::Unavailable),
    };
    if !status_parts.next().is_some_and(|value| {
        !value.is_empty() && value.bytes().all(|byte| (32..127).contains(&byte))
    }) {
        return Err(HealthError::Framing);
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if headers.len() >= MAX_HEADER_COUNT {
            return Err(HealthError::Bounds);
        }
        let (name, value) = line.split_once(':').ok_or(HealthError::Framing)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(HealthError::Framing);
        }
        let value = value.trim_matches(' ');
        if value.bytes().any(|byte| !(32..127).contains(&byte)) {
            return Err(HealthError::Framing);
        }
        if headers.insert(name.to_ascii_lowercase(), value).is_some() {
            return Err(HealthError::Framing);
        }
    }
    if headers.contains_key("transfer-encoding") || headers.contains_key("content-encoding") {
        return Err(HealthError::Framing);
    }
    if !matches!(
        headers.get("content-type"),
        Some(&"application/json" | &"application/json; charset=utf-8")
    ) {
        return Err(HealthError::Framing);
    }
    if !headers
        .get("connection")
        .is_some_and(|value| value.eq_ignore_ascii_case("close"))
    {
        return Err(HealthError::Framing);
    }
    let raw_length = headers.get("content-length").ok_or(HealthError::Framing)?;
    let length: usize = raw_length.parse().map_err(|_| HealthError::Bounds)?;
    if length == 0 || length > MAX_BODY_BYTES || length.to_string() != *raw_length {
        return Err(HealthError::Bounds);
    }
    let tag = headers
        .get("x-sts2-health-attestation")
        .ok_or(HealthError::Authentication)?;
    if tag.len() != 64 {
        return Err(HealthError::Authentication);
    }
    Ok((status, length, (*tag).to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(extra: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\nConnection: close\r\nX-STS2-Health-Attestation: {}\r\n{extra}\r\n", "a".repeat(64)).into_bytes()
    }

    #[test]
    fn rejects_duplicate_and_ambiguous_http_framing() {
        assert!(headers(&response("")).is_ok());
        for extra in [
            "content-length: 2\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Content-Encoding: gzip\r\n",
            "X-STS2-Health-Attestation: duplicate\r\n",
        ] {
            assert!(headers(&response(extra)).is_err());
        }
    }
}
