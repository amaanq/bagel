//! Per-IP tarpit admission.

use std::{
   net::IpAddr,
   sync::{
      Arc,
      atomic::{
         AtomicUsize,
         Ordering,
      },
   },
};

use dashmap::{
   DashMap,
   mapref::entry::Entry,
};
use metrics::gauge;

/// Shared tarpit admission state.
pub struct State {
   active:       AtomicUsize,
   /// Active tarpits by source. Entries exist only while a connection lives,
   /// so this remains bounded by the global connection cap.
   active_by_ip: DashMap<IpAddr, usize>,
}

impl State {
   #[must_use]
   pub fn new() -> Self {
      Self {
         active:       AtomicUsize::new(0),
         active_by_ip: DashMap::new(),
      }
   }

   #[must_use]
   pub fn active_count(&self) -> usize {
      self.active.load(Ordering::Relaxed)
   }

   /// Enter a tarpit when this source has spare concurrent capacity.
   #[expect(
      clippy::cast_precision_loss,
      reason = "the count is bounded by max-connections, far below 2^53"
   )]
   pub fn try_enter_tarpit(self: &Arc<Self>, ip: IpAddr, cap: usize) -> Option<ActiveGuard> {
      let mut entry = self.active_by_ip.entry(ip).or_insert(0);
      if *entry >= cap {
         return None;
      }
      *entry += 1;
      drop(entry);
      let n = self.active.fetch_add(1, Ordering::Relaxed) + 1;
      gauge!("bagel_active_connections").set(n as f64);
      Some(ActiveGuard {
         state: Arc::clone(self),
         ip:    Some(ip),
      })
   }
}

impl Default for State {
   fn default() -> Self {
      Self::new()
   }
}

/// RAII guard for an active tarpit connection.
pub struct ActiveGuard {
   state: Arc<State>,
   ip:    Option<IpAddr>,
}

impl Drop for ActiveGuard {
   #[expect(
      clippy::cast_precision_loss,
      reason = "the count is bounded by max-connections, far below 2^53"
   )]
   fn drop(&mut self) {
      if let Some(ip) = self.ip
         && let Entry::Occupied(mut entry) = self.state.active_by_ip.entry(ip)
      {
         if *entry.get() == 1 {
            entry.remove();
         } else {
            *entry.get_mut() -= 1;
         }
      }
      let n = self.state.active.fetch_sub(1, Ordering::Relaxed) - 1;
      gauge!("bagel_active_connections").set(n as f64);
   }
}

#[cfg(test)]
mod tests {
   use std::net::Ipv4Addr;

   use super::*;

   fn ip(n: u8) -> IpAddr {
      IpAddr::V4(Ipv4Addr::new(1, 2, 3, n))
   }

   #[test]
   fn per_ip_tarpit_cap_releases_on_disconnect() {
      let state = Arc::new(State::new());
      let first = state.try_enter_tarpit(ip(1), 1).expect("first slot");
      assert!(state.try_enter_tarpit(ip(1), 1).is_none());
      assert!(state.try_enter_tarpit(ip(2), 1).is_some());
      drop(first);
      assert!(state.try_enter_tarpit(ip(1), 1).is_some());
   }
}
