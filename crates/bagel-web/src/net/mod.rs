pub mod decay_map;
pub mod loader;
pub mod radb;
pub mod rate;

use std::{
   net::IpAddr,
   sync::Arc,
};

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use tokio::sync::Notify;

/// Connection-scoped drop signal used to cancel transport without writing a
/// response.
#[derive(Clone, Default)]
pub struct DropHandle(Arc<Notify>);

impl DropHandle {
   #[must_use]
   pub fn new() -> Self {
      Self(Arc::new(Notify::new()))
   }

   pub fn trigger(&self) {
      self.0.notify_one();
   }

   pub async fn dropped(&self) {
      self.0.notified().await;
   }
}

/// A set of IP networks for prefix matching.
/// Uses a Patricia trie (`IpNetworkTable`) for O(prefix-length) lookups.
pub struct IpNetTrie {
   table: IpNetworkTable<()>,
   len:   usize,
}

impl Clone for IpNetTrie {
   fn clone(&self) -> Self {
      // Rebuild from iteration since IpNetworkTable doesn't impl Clone
      let mut table = IpNetworkTable::new();
      for (net, ()) in self.table.iter() {
         table.insert(net, ());
      }
      Self {
         table,
         len: self.len,
      }
   }

   fn clone_from(&mut self, source: &Self) {
      *self = source.clone();
   }
}

impl IpNetTrie {
   #[must_use]
   pub fn new() -> Self {
      Self {
         table: IpNetworkTable::new(),
         len:   0,
      }
   }

   pub fn from_prefixes(prefixes: &[String]) -> Self {
      let mut table = IpNetworkTable::new();
      let mut count = 0;
      for prefix in prefixes {
         if let Ok(net) = prefix.parse::<IpNetwork>() {
            table.insert(net, ());
            count += 1;
         } else if let Ok(ip) = prefix.parse::<IpAddr>() {
            let net = match ip {
               IpAddr::V4(v4) => IpNetwork::new(IpAddr::V4(v4), 32).unwrap(),
               IpAddr::V6(v6) => IpNetwork::new(IpAddr::V6(v6), 128).unwrap(),
            };
            table.insert(net, ());
            count += 1;
         } else {
            tracing::warn!(prefix, "invalid IP prefix, skipping");
         }
      }
      Self { table, len: count }
   }

   #[must_use]
   pub fn contains(&self, ip: IpAddr) -> bool {
      self.table.longest_match(ip).is_some()
   }
}

impl Default for IpNetTrie {
   fn default() -> Self {
      Self::new()
   }
}
