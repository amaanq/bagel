use std::{
   collections::HashMap,
   sync::Mutex,
   time::{
      Duration,
      Instant,
   },
};

use super::keys::frame;
use crate::SourceNetwork;

pub const MEMORY_CAPACITY: usize = 65_536;

struct Entry {
   expires: Instant,
   maze:    String,
}

/// Process-local poison memory keyed by opaque HMAC identifiers.
#[derive(Default)]
pub struct PoisonStore {
   inner: Mutex<HashMap<[u8; 32], Entry>>,
}

/// Compute the memory identifier for one host, maze, and source network.
#[must_use]
pub fn memory_id(
   memory_key: &[u8; 32],
   canonical_host: &str,
   maze_name: &str,
   source: SourceNetwork,
) -> [u8; 32] {
   let mut input = frame(b"bagel poison memory v1");
   input.extend_from_slice(&frame(canonical_host.as_bytes()));
   input.extend_from_slice(&frame(maze_name.as_bytes()));
   input.extend_from_slice(&frame(&source.to_bytes()));
   let tag = ring::hmac::sign(
      &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, memory_key),
      &input,
   );
   tag.as_ref().try_into().expect("hmac output is 32 bytes")
}

impl PoisonStore {
   #[must_use]
   pub fn new() -> Self {
      Self::default()
   }

   pub fn set(&self, id: [u8; 32], maze: &str, ttl: Duration) {
      let mut map = self
         .inner
         .lock()
         .unwrap_or_else(std::sync::PoisonError::into_inner);
      if map.len() >= MEMORY_CAPACITY && !map.contains_key(&id) {
         let now = Instant::now();
         map.retain(|_, entry| entry.expires > now);
         if map.len() >= MEMORY_CAPACITY
            && let Some(oldest) = map
               .iter()
               .min_by_key(|(_, entry)| entry.expires)
               .map(|(key, _)| *key)
         {
            map.remove(&oldest);
         }
      }
      map.insert(id, Entry {
         expires: Instant::now() + ttl,
         maze:    maze.to_owned(),
      });
   }

   #[must_use]
   pub fn contains(&self, id: &[u8; 32]) -> bool {
      self
         .inner
         .lock()
         .unwrap_or_else(std::sync::PoisonError::into_inner)
         .get(id)
         .is_some_and(|entry| entry.expires > Instant::now())
   }

   /// Drop every entry for one maze.
   pub fn purge_maze(&self, maze: &str) {
      self
         .inner
         .lock()
         .unwrap_or_else(std::sync::PoisonError::into_inner)
         .retain(|_, entry| entry.maze != maze);
   }

   #[must_use]
   pub fn len(&self) -> usize {
      self
         .inner
         .lock()
         .unwrap_or_else(std::sync::PoisonError::into_inner)
         .len()
   }

   #[must_use]
   pub fn is_empty(&self) -> bool {
      self.len() == 0
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn entries_expire() {
      let store = PoisonStore::new();
      let id = [1_u8; 32];
      store.set(id, "default", Duration::from_millis(20));
      assert!(store.contains(&id));
      std::thread::sleep(Duration::from_millis(30));
      assert!(!store.contains(&id));
   }
}
