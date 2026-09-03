//! PROXY protocol (v1 and v2) source-address extraction, parsed by the `ppp`
//! crate. Eris reads it only from trusted peers. Any bytes read past the header
//! are returned so the HTTP parser can consume them.

use ppp::{HeaderResult, PartialResult, v1, v2};
use std::io;
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

/// A PROXY v1 header is at most 107 bytes; a v2 header is bounded by its length
/// field. This cap stops a peer that never completes a header.
const READ_CAP: usize = 536;

/// The resolved source IP (if any) and any leftover bytes belonging to the next
/// protocol layer.
pub type Outcome = (Option<IpAddr>, Vec<u8>);

/// Read and parse a PROXY header from `stream`.
///
/// When the stream does not begin with a valid PROXY header (misconfiguration,
/// a health check, or plain HTTP), the source is `None` and all bytes read are
/// handed back so the caller can still parse them as HTTP.
pub async fn read<S>(stream: &mut S, idle: Duration) -> io::Result<Outcome>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(64);
    let mut chunk = [0u8; 256];

    loop {
        let header = HeaderResult::parse(&buf);
        if !header.is_incomplete() {
            return Ok(resolve(header, &buf));
        }
        if buf.len() > READ_CAP {
            return Ok((None, buf));
        }
        match timeout(idle, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => return Ok((None, buf)),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok((None, buf)),
        }
    }
}

fn resolve(header: HeaderResult<'_>, buf: &[u8]) -> Outcome {
    match header {
        HeaderResult::V1(Ok(h)) => {
            let len = h.header.len();
            let ip = match h.addresses {
                v1::Addresses::Tcp4(a) => Some(IpAddr::V4(a.source_address)),
                v1::Addresses::Tcp6(a) => Some(IpAddr::V6(a.source_address)),
                v1::Addresses::Unknown => None,
            };
            (ip, buf[len..].to_vec())
        }
        HeaderResult::V2(Ok(h)) => {
            let len = h.len();
            let ip = match h.addresses {
                v2::Addresses::IPv4(a) => Some(IpAddr::V4(a.source_address)),
                v2::Addresses::IPv6(a) => Some(IpAddr::V6(a.source_address)),
                _ => None,
            };
            (ip, buf[len..].to_vec())
        }
        // Terminal parse error: not a PROXY header, so hand the bytes back.
        _ => (None, buf.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn run(bytes: &[u8]) -> Outcome {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let payload = bytes.to_vec();
        tokio::spawn(async move {
            let _ = a.write_all(&payload).await;
        });
        read(&mut b, Duration::from_secs(1)).await.unwrap()
    }

    #[tokio::test]
    async fn v1_tcp4() {
        let (ip, rest) =
            run(b"PROXY TCP4 203.0.113.7 10.0.0.1 56324 443\r\nGET / HTTP/1.1\r\n").await;
        assert_eq!(ip, Some("203.0.113.7".parse().unwrap()));
        assert_eq!(rest, b"GET / HTTP/1.1\r\n");
    }

    #[tokio::test]
    async fn v2_tcp4() {
        // Signature + v2/PROXY + AF_INET/STREAM + 12-byte address block.
        let mut h = vec![
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
        ];
        h.push(0x21);
        h.push(0x11);
        h.extend_from_slice(&12u16.to_be_bytes());
        h.extend_from_slice(&[203, 0, 113, 9]);
        h.extend_from_slice(&[10, 0, 0, 1]);
        h.extend_from_slice(&[0xdc, 0x04]);
        h.extend_from_slice(&[0x01, 0xbb]);
        h.extend_from_slice(b"GET / HTTP/1.1\r\n");

        let (ip, rest) = run(&h).await;
        assert_eq!(ip, Some("203.0.113.9".parse().unwrap()));
        assert_eq!(rest, b"GET / HTTP/1.1\r\n");
    }

    #[tokio::test]
    async fn plain_http_is_passed_through() {
        let (ip, rest) = run(b"GET / HTTP/1.1\r\n\r\n").await;
        assert_eq!(ip, None);
        assert_eq!(rest, b"GET / HTTP/1.1\r\n\r\n");
    }
}
