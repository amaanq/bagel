//! PROXY protocol v1 and v2 source-address extraction.

use std::{
   io,
   net::{
      IpAddr,
      SocketAddr,
   },
   time::Duration,
};

use ppp::{
   HeaderResult,
   PartialResult,
   v1,
   v2,
};
use tokio::{
   io::{
      AsyncRead,
      AsyncReadExt,
   },
   time::timeout,
};

/// A PROXY v1 header is at most 107 bytes, while a v2 header is bounded by its
/// length field. This cap stops a peer that never completes a header.
const READ_CAP: usize = 536;

/// The resolved source IP (if any) and any leftover bytes belonging to the next
/// protocol layer.
pub type Outcome = (Option<IpAddr>, Vec<u8>);

/// Outcome of parsing a PROXY header from an already-buffered prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
   /// A complete header. `source` is `None` for UNKNOWN/LOCAL/unsupported
   /// families. `consumed` is the header length to skip either way.
   Complete {
      source:   Option<SocketAddr>,
      consumed: usize,
   },
   /// More bytes are needed to decide.
   Incomplete,
   /// The bytes are not a PROXY header at all.
   NotProxy,
}

/// Parse a PROXY v1 or v2 header at the start of `buf` without consuming a
/// stream.
#[must_use]
pub fn parse(buf: &[u8]) -> Parsed {
   let header = HeaderResult::parse(buf);
   if header.is_incomplete() {
      return Parsed::Incomplete;
   }
   match header {
      HeaderResult::V1(Ok(h)) => {
         let consumed = h.header.len();
         let source = match h.addresses {
            v1::Addresses::Tcp4(a) => {
               Some(SocketAddr::new(IpAddr::V4(a.source_address), a.source_port))
            },
            v1::Addresses::Tcp6(a) => {
               Some(SocketAddr::new(IpAddr::V6(a.source_address), a.source_port))
            },
            v1::Addresses::Unknown => None,
         };
         Parsed::Complete { source, consumed }
      },
      HeaderResult::V2(Ok(h)) => {
         let consumed = h.len();
         let source = match h.addresses {
            v2::Addresses::IPv4(a) => {
               Some(SocketAddr::new(IpAddr::V4(a.source_address), a.source_port))
            },
            v2::Addresses::IPv6(a) => {
               Some(SocketAddr::new(IpAddr::V6(a.source_address), a.source_port))
            },
            _ => None,
         };
         Parsed::Complete { source, consumed }
      },
      _ => Parsed::NotProxy,
   }
}

/// Build a PROXY protocol v1 header line for an outbound connection. Mixed
/// address families have no v1 encoding and fall back to `UNKNOWN`.
#[must_use]
pub fn build_v1(src: SocketAddr, dst: SocketAddr) -> String {
   let proto = match (src.is_ipv4(), dst.is_ipv4()) {
      (true, true) => "TCP4",
      (false, false) => "TCP6",
      _ => return "PROXY UNKNOWN\r\n".to_owned(),
   };
   format!(
      "PROXY {proto} {src_ip} {dst_ip} {src_port} {dst_port}\r\n",
      src_ip = src.ip(),
      dst_ip = dst.ip(),
      src_port = src.port(),
      dst_port = dst.port(),
   )
}

/// Build a PROXY protocol v2 header for an outbound connection. Mixed address
/// families fall back to a LOCAL command with `AF_UNSPEC`.
#[must_use]
pub fn build_v2(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
   let mut out = vec![
      0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
   ];
   match (src.ip(), dst.ip()) {
      (IpAddr::V4(s), IpAddr::V4(d)) => {
         out.push(0x21);
         out.push(0x11);
         out.extend_from_slice(&12u16.to_be_bytes());
         out.extend_from_slice(&s.octets());
         out.extend_from_slice(&d.octets());
         out.extend_from_slice(&src.port().to_be_bytes());
         out.extend_from_slice(&dst.port().to_be_bytes());
      },
      (IpAddr::V6(s), IpAddr::V6(d)) => {
         out.push(0x21);
         out.push(0x21);
         out.extend_from_slice(&36u16.to_be_bytes());
         out.extend_from_slice(&s.octets());
         out.extend_from_slice(&d.octets());
         out.extend_from_slice(&src.port().to_be_bytes());
         out.extend_from_slice(&dst.port().to_be_bytes());
      },
      _ => {
         out.push(0x20);
         out.push(0x00);
         out.extend_from_slice(&0u16.to_be_bytes());
      },
   }
   out
}

/// Read and parse a PROXY header from `stream`.
pub async fn read<S>(stream: &mut S, idle: Duration) -> io::Result<Outcome>
where
   S: AsyncRead + Unpin,
{
   let mut buf = Vec::with_capacity(64);
   let mut chunk = [0u8; 256];

   loop {
      match parse(&buf) {
         Parsed::Complete { source, consumed } => {
            return Ok((source.map(|a| a.ip()), buf[consumed..].to_vec()));
         },
         Parsed::NotProxy => return Ok((None, buf)),
         Parsed::Incomplete => {},
      }
      if buf.len() > READ_CAP {
         return Ok((None, buf));
      }
      match timeout(idle, stream.read(&mut chunk)).await {
         Ok(Ok(0)) | Err(_) => return Ok((None, buf)),
         Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
         Ok(Err(e)) => return Err(e),
      }
   }
}

#[cfg(test)]
mod tests {
   use tokio::io::AsyncWriteExt;

   use super::*;

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
   async fn plain_http_is_passed_through() {
      let (ip, rest) = run(b"GET / HTTP/1.1\r\n\r\n").await;
      assert_eq!(ip, None);
      assert_eq!(rest, b"GET / HTTP/1.1\r\n\r\n");
   }

   #[test]
   fn parse_short_prefix_is_incomplete() {
      assert_eq!(parse(b"PROXY TCP4 19"), Parsed::Incomplete);
   }

   #[test]
   fn build_v1_mixed_families_is_unknown() {
      let src: SocketAddr = "192.168.1.1:12345".parse().unwrap();
      let dst: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
      assert_eq!(build_v1(src, dst), "PROXY UNKNOWN\r\n");
      assert_eq!(parse(build_v1(src, dst).as_bytes()), Parsed::Complete {
         source:   None,
         consumed: 15,
      });
   }
   #[test]
   fn build_v2_roundtrips_through_parse() {
      let src: SocketAddr = "192.168.1.1:12345".parse().unwrap();
      let dst: SocketAddr = "10.0.0.1:80".parse().unwrap();
      let buf = build_v2(src, dst);
      assert_eq!(parse(&buf), Parsed::Complete {
         source:   Some(src),
         consumed: buf.len(),
      });
   }

   #[test]
   fn build_v2_v6_roundtrips_through_parse() {
      let src: SocketAddr = "[2001:db8::1]:4444".parse().unwrap();
      let dst: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
      let buf = build_v2(src, dst);
      assert_eq!(parse(&buf), Parsed::Complete {
         source:   Some(src),
         consumed: buf.len(),
      });
   }
}
