pub mod body;
pub mod cache;
pub mod challenge;
/// Gated because it is the only user of `hickory-resolver`, which a config
/// with no `crawlers` block never reaches.
#[cfg(feature = "fcrdns")]
pub mod crawler;
pub mod error;
pub mod host;
pub mod maze;
pub mod metrics;
pub mod net;
pub mod proxy;
pub mod routes;
pub mod rule;
pub mod server;
#[cfg(test)]
#[path = "../solver.rs"]
mod solver;
pub mod state;

mod state_validation;
pub mod tag_fetcher;
pub mod template;
pub mod tls;

use std::net::{
   IpAddr,
   Ipv4Addr,
   Ipv6Addr,
};

pub use bagel_config::web as config;

/// Encode bytes as a lowercase hex string using a lookup table (zero
/// intermediate allocations).
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
   const HEX: &[u8; 16] = b"0123456789abcdef";
   let mut out = String::with_capacity(bytes.len() * 2);
   for &byte in bytes {
      out.push(HEX[(byte >> 4) as usize] as char);
      out.push(HEX[(byte & 0xF) as usize] as char);
   }
   out
}

#[must_use]
pub fn hex_decode(hex: &str) -> Option<Vec<u8>> {
   if !hex.len().is_multiple_of(2) {
      return None;
   }
   (0..hex.len())
      .step_by(2)
      .map(|idx| u8::from_str_radix(&hex[idx..idx + 2], 16).ok())
      .collect()
}

/// Canonical source-network identity using /24 for IPv4 and /64 for IPv6.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceNetwork {
   V4([u8; 4]),
   V6([u8; 16]),
}

impl SourceNetwork {
   #[must_use]
   pub fn from_ip(ip: IpAddr) -> Self {
      match ip {
         IpAddr::V4(v4) => {
            let mut oct = v4.octets();
            oct[3] = 0;
            Self::V4(oct)
         },
         IpAddr::V6(v6) => {
            let mut oct = v6.octets();
            oct[8..].fill(0);
            Self::V6(oct)
         },
      }
   }

   /// Canonical binary encoding, a family tag and prefix length followed by
   /// the masked address bytes.
   #[must_use]
   pub fn to_bytes(&self) -> Vec<u8> {
      match self {
         Self::V4(oct) => {
            let mut bytes = vec![0x04, 0x18];
            bytes.extend_from_slice(oct);
            bytes
         },
         Self::V6(oct) => {
            let mut bytes = vec![0x06, 0x40];
            bytes.extend_from_slice(oct);
            bytes
         },
      }
   }

   /// The same prefix as an `ipnetwork` value for the defense plane.
   #[must_use]
   pub fn to_ip_network(&self) -> ipnetwork::IpNetwork {
      match self {
         Self::V4(oct) => {
            ipnetwork::IpNetwork::V4(
               ipnetwork::Ipv4Network::new(Ipv4Addr::from(*oct), 24)
                  .expect("24 is a valid v4 prefix"),
            )
         },
         Self::V6(oct) => {
            ipnetwork::IpNetwork::V6(
               ipnetwork::Ipv6Network::new(Ipv6Addr::from(*oct), 64)
                  .expect("64 is a valid v6 prefix"),
            )
         },
      }
   }
}

impl std::fmt::Display for SourceNetwork {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      match self {
         Self::V4(oct) => write!(f, "{}.{}.{}.0/24", oct[0], oct[1], oct[2]),
         Self::V6(oct) => {
            let seg = |idx: usize| u16::from_be_bytes([oct[idx * 2], oct[idx * 2 + 1]]);
            write!(
               f,
               "{:x}:{:x}:{:x}:{:x}::/64",
               seg(0),
               seg(1),
               seg(2),
               seg(3)
            )
         },
      }
   }
}

/// Compute the network prefix string for an IP address.
/// IPv4: /24 (first 3 octets), IPv6: /64 (first 4 segments).
#[must_use]
pub fn ip_network_prefix(ip: IpAddr) -> String {
   SourceNetwork::from_ip(ip).to_string()
}

pub mod smear;
