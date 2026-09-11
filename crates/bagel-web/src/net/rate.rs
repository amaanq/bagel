use std::{
   collections::HashMap,
   hash::{
      DefaultHasher,
      Hash,
      Hasher as _,
   },
   sync::Mutex,
   time::Instant,
};

use crate::SourceNetwork;

pub const SHARD_COUNT: usize = 64;
pub const DEFAULT_CAPACITY: usize = 65_536;
pub const MIN_CAPACITY: usize = 1_024;
pub const MAX_CAPACITY: usize = 1_048_576;

const WINDOW: usize = 60;

/// Immutable per-request view of the normal rate counters, taken after the
/// current request has been counted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RateSnapshot {
   pub last_1s:  u32,
   pub last_10s: u32,
   pub last_60s: u32,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct RateKey {
   host:    String,
   network: SourceNetwork,
}

#[derive(Clone)]
struct Entry {
   buckets:   [u32; WINDOW],
   last_tick: u64,
   last_used: u64,
}

#[derive(Default)]
struct Shard {
   entries: HashMap<RateKey, Entry>,
   used:    u64,
}

/// Sharded LRU tracker of per-key request counts over sixty one-second
/// buckets of monotonic time. Only requests entering ordinary policy
/// evaluation are recorded here.
pub struct RateTracker {
   shards:         Vec<Mutex<Shard>>,
   shard_capacity: usize,
   capacity:       usize,
   epoch:          Instant,
}

impl RateTracker {
   #[must_use]
   pub fn new(capacity: usize) -> Self {
      Self {
         shards: std::iter::repeat_with(|| Mutex::new(Shard::default()))
            .take(SHARD_COUNT)
            .collect(),
         shard_capacity: capacity.div_ceil(SHARD_COUNT).max(1),
         capacity,
         epoch: Instant::now(),
      }
   }

   #[must_use]
   pub const fn capacity(&self) -> usize {
      self.capacity
   }

   /// Count the current request and return the counts including it.
   #[must_use]
   pub fn record(&self, host: &str, network: SourceNetwork) -> RateSnapshot {
      self.record_at(host, network, self.epoch.elapsed().as_secs())
   }

   #[must_use]
   pub fn record_at(&self, host: &str, network: SourceNetwork, tick: u64) -> RateSnapshot {
      let key = RateKey {
         host: host.to_owned(),
         network,
      };

      let mut hasher = DefaultHasher::new();
      key.hash(&mut hasher);
      let shard = &self.shards[(hasher.finish() as usize) % SHARD_COUNT];

      let mut shard = shard
         .lock()
         .unwrap_or_else(std::sync::PoisonError::into_inner);
      shard.used += 1;
      let used = shard.used;

      if !shard.entries.contains_key(&key) && shard.entries.len() >= self.shard_capacity {
         Self::evict(&mut shard.entries, tick);
      }

      let entry = shard.entries.entry(key).or_insert_with(|| {
         Entry {
            buckets:   [0; WINDOW],
            last_tick: tick,
            last_used: used,
         }
      });
      entry.last_used = used;

      if tick > entry.last_tick {
         let stale = (tick - entry.last_tick).min(WINDOW as u64);
         for offset in 0..stale {
            entry.buckets[((tick - offset) % WINDOW as u64) as usize] = 0;
         }
         entry.last_tick = tick;
      }

      let current = (tick % WINDOW as u64) as usize;
      entry.buckets[current] = entry.buckets[current].saturating_add(1);

      let sum = |span: u64| {
         (0..span.min(tick + 1))
            .map(|offset| entry.buckets[((tick + WINDOW as u64 - offset) % WINDOW as u64) as usize])
            .fold(0_u32, u32::saturating_add)
      };

      RateSnapshot {
         last_1s:  entry.buckets[current],
         last_10s: sum(10),
         last_60s: sum(60),
      }
   }

   fn evict(entries: &mut HashMap<RateKey, Entry>, tick: u64) {
      entries.retain(|_, entry| entry.last_tick + WINDOW as u64 > tick);
      if let Some(oldest) = entries
         .iter()
         .min_by_key(|(_, entry)| entry.last_used)
         .map(|(key, _)| key.clone())
      {
         entries.remove(&oldest);
      }
   }

   #[must_use]
   pub fn len(&self) -> usize {
      self
         .shards
         .iter()
         .map(|shard| {
            shard
               .lock()
               .unwrap_or_else(std::sync::PoisonError::into_inner)
               .entries
               .len()
         })
         .sum()
   }

   #[must_use]
   pub fn is_empty(&self) -> bool {
      self.len() == 0
   }
}

#[cfg(test)]
mod tests {
   use std::net::{
      IpAddr,
      Ipv4Addr,
   };

   use super::*;

   fn net(last: u8) -> SourceNetwork {
      SourceNetwork::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, last, 1)))
   }

   #[test]
   fn windows_rotate() {
      let tracker = RateTracker::new(MIN_CAPACITY);
      for tick in 0..30 {
         let _ = tracker.record_at("example.test", net(0), tick);
      }
      let snap = tracker.record_at("example.test", net(0), 30);
      assert_eq!(snap.last_1s, 1);
      assert_eq!(snap.last_10s, 10);
      assert_eq!(snap.last_60s, 31);

      let snap = tracker.record_at("example.test", net(0), 89);
      assert_eq!(snap.last_1s, 1);
      assert_eq!(snap.last_10s, 1);
      assert_eq!(snap.last_60s, 2);

      let snap = tracker.record_at("example.test", net(0), 200);
      assert_eq!(snap.last_60s, 1);
   }

   #[test]
   fn capacity_stays_bounded() {
      let tracker = RateTracker::new(MIN_CAPACITY);
      for host_index in 0..(MIN_CAPACITY * 2) {
         let _ = tracker.record_at(&format!("host-{host_index}.test"), net(0), 100);
      }
      assert!(tracker.len() <= MIN_CAPACITY);
   }

   #[test]
   fn distinct_keys_do_not_share_counts() {
      let tracker = RateTracker::new(MIN_CAPACITY);
      for _ in 0..5 {
         let _ = tracker.record_at("example.test", net(0), 100);
      }
      let snap = tracker.record_at("example.test", net(1), 100);
      assert_eq!(snap.last_60s, 1);
      let snap = tracker.record_at("other.test", net(0), 100);
      assert_eq!(snap.last_60s, 1);
   }
}
