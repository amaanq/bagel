use std::{
   net::IpAddr,
   time::Duration,
};

use tokio::{
   net::lookup_host,
   time::timeout,
};

use super::types::{
   ChallengeContext,
   IssueResult,
};
use crate::net::decay_map::DecayMap;

/// Checks the client IP against a DNS blocklist without the client ever
/// seeing it. Verdicts are cached so one address costs one lookup per TTL.
pub struct DnsblChallenge {
   pub dnsbl_host: String,
   pub cache:      DecayMap<IpAddr, bool>,
   pub timeout:    Duration,
}

impl DnsblChallenge {
   #[must_use]
   pub fn new(dnsbl_host: String, ttl: Duration) -> Self {
      Self {
         dnsbl_host,
         cache: DecayMap::new(ttl),
         timeout: Duration::from_secs(1),
      }
   }

   /// Issue: look up the IP in the DNSBL asynchronously.
   /// Returns Passed if the IP is clean, Failed if listed, Skip if no client
   /// IP.
   pub async fn issue(&self, ctx: &ChallengeContext<'_>) -> IssueResult {
      let Some(ip) = ctx.client_ip else {
         return IssueResult::Skip;
      };

      if let Some(listed) = self.cache.get(&ip) {
         if listed {
            tracing::debug!(ip = %ip, dnsbl = self.dnsbl_host, "IP listed in DNSBL (cached)");
            return IssueResult::Failed;
         }
         return IssueResult::Passed;
      }

      let query = build_dnsbl_query(ip, &self.dnsbl_host);

      let listed = match timeout(self.timeout, lookup_host(format!("{query}:0"))).await {
         Ok(result) => result.is_ok_and(|mut addrs| addrs.next().is_some()),
         Err(_) => return IssueResult::Skip,
      };

      self.cache.set(ip, listed);

      if listed {
         tracing::debug!(ip = %ip, dnsbl = self.dnsbl_host, "IP listed in DNSBL");
         IssueResult::Failed
      } else {
         IssueResult::Passed
      }
   }
}

fn build_dnsbl_query(ip: IpAddr, dnsbl_host: &str) -> String {
   match ip {
      IpAddr::V4(v4) => {
         let octets = v4.octets();
         format!(
            "{}.{}.{}.{}.{}",
            octets[3], octets[2], octets[1], octets[0], dnsbl_host
         )
      },
      IpAddr::V6(v6) => {
         // Nibble-reversed format
         let bytes = v6.octets();
         let mut nibbles = String::with_capacity(64 + dnsbl_host.len() + 1);
         for &byte in bytes.iter().rev() {
            use std::fmt::Write as _;
            let _ = write!(nibbles, "{:x}.{:x}.", byte & 0x0F, (byte >> 4) & 0x0F);
         }
         nibbles.push_str(dnsbl_host);
         nibbles
      },
   }
}
