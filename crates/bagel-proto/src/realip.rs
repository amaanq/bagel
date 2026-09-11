//! Resolve client IPs from trusted proxy forwarding headers.

use std::net::IpAddr;

use bagel_core::{
   Error,
   Result,
};
use ipnetwork::IpNetwork;

/// The set of networks whose forwarding headers Bagel will trust.
#[derive(Clone, Default)]
pub struct TrustedProxies(Vec<IpNetwork>);

impl TrustedProxies {
   pub fn new(cidrs: &[String]) -> Result<Self> {
      let nets = cidrs
         .iter()
         .map(|s| {
            s.parse::<IpNetwork>()
               .map_err(|e| Error::Network(e.to_string()))
         })
         .collect::<Result<_>>()?;
      Ok(Self(nets))
   }

   #[must_use]
   pub fn contains(&self, ip: IpAddr) -> bool {
      self.0.iter().any(|net| net.contains(ip))
   }

   /// Resolve the client IP from the socket peer and trusted forwarding data.
   #[must_use]
   pub fn client_ip(&self, peer: IpAddr, forwarded_for: Option<&str>) -> IpAddr {
      if !self.contains(peer) {
         return peer;
      }
      self.peel(peer, forwarded_for)
   }

   /// Peel a trusted forwarding header and return the first untrusted hop.
   #[must_use]
   fn peel(&self, peer: IpAddr, forwarded_for: Option<&str>) -> IpAddr {
      let Some(header) = forwarded_for else {
         return peer;
      };

      let mut first_valid = None;
      for entry in header.split(',').rev() {
         let Ok(ip) = entry.trim().parse::<IpAddr>() else {
            continue;
         };
         first_valid.get_or_insert(ip);
         if !self.contains(ip) {
            return ip;
         }
      }
      // Every hop was trusted (or unparseable): fall back to the closest
      // valid address, or the peer if the header held nothing usable.
      first_valid.unwrap_or(peer)
   }
}

/// Select the request address from the peer and trusted forwarding headers.
#[derive(Clone, Default)]
pub struct ClientIpPolicy {
   header:  Option<String>,
   trusted: Option<TrustedProxies>,
}

impl ClientIpPolicy {
   /// Build a policy. `trusted` is `None` when the operator configured no list.
   pub fn new(header: Option<String>, trusted: Option<&[String]>) -> Result<Self> {
      let trusted = trusted.map(TrustedProxies::new).transpose()?;
      Ok(Self { header, trusted })
   }

   #[must_use]
   pub fn header_name(&self) -> Option<&str> {
      self.header.as_deref()
   }

   /// Whether `peer` is a listed proxy. Without a list nothing is trusted,
   /// which is the gate for accepting a PROXY protocol header.
   #[must_use]
   pub fn trusts(&self, peer: IpAddr) -> bool {
      self
         .trusted
         .as_ref()
         .is_some_and(|trusted| trusted.contains(peer))
   }

   /// Resolve the client address from the socket peer and the configured
   /// header's value (the caller looks the header up by `header_name`).
   #[must_use]
   pub fn resolve(&self, peer: IpAddr, header_value: Option<&str>) -> IpAddr {
      match (&self.header, &self.trusted) {
         (Some(_), Some(trusted)) => trusted.client_ip(peer, header_value),
         _ => peer,
      }
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   fn ip(s: &str) -> IpAddr {
      s.parse().unwrap()
   }

   #[test]
   fn untrusted_peer_ignores_header() {
      let tp = TrustedProxies::new(&["10.0.0.0/8".into()]).unwrap();
      // Peer is a real client, not a proxy: never trust its XFF.
      assert_eq!(tp.client_ip(ip("8.8.8.8"), Some("1.2.3.4")), ip("8.8.8.8"));
   }

   #[test]
   fn trusted_peer_uses_rightmost_untrusted() {
      let tp = TrustedProxies::new(&["10.0.0.0/8".into()]).unwrap();
      // Client -> edge proxy (spoofed 9.9.9.9 injected by client) -> bagel.
      // 10.0.0.2 is a trusted hop, so 203.0.113.7 is the real client.
      assert_eq!(
         tp.client_ip(ip("10.0.0.1"), Some("9.9.9.9, 203.0.113.7, 10.0.0.2")),
         ip("203.0.113.7")
      );
   }

   fn policy_with_list() -> ClientIpPolicy {
      ClientIpPolicy::new(Some("x-forwarded-for".into()), Some(&["10.0.0.0/8".into()])).unwrap()
   }

   #[test]
   fn trusts_only_listed_peers() {
      assert!(policy_with_list().trusts(ip("10.1.2.3")));
      assert!(!policy_with_list().trusts(ip("8.8.8.8")));
   }
}
