use std::{
   collections::HashMap,
   hash::Hash,
   sync::RwLock,
   time::{
      Duration,
      Instant,
   },
};

const MAX_ENTRIES: usize = 65_536;

/// A concurrent map where entries expire after a TTL.
pub struct DecayMap<K: Eq + Hash, V> {
   inner: RwLock<HashMap<K, (V, Instant)>>,
   ttl:   Duration,
}

impl<K: Eq + Hash, V: Clone> DecayMap<K, V> {
   #[must_use]
   pub fn new(ttl: Duration) -> Self {
      Self {
         inner: RwLock::new(HashMap::new()),
         ttl,
      }
   }

   pub fn get(&self, key: &K) -> Option<V> {
      let map = self.inner.read().ok()?;
      let (value, inserted) = map.get(key)?;
      if inserted.elapsed() > self.ttl {
         // Eviction is left to cleanup() to avoid a read→write lock upgrade
         drop(map);
         None
      } else {
         Some(value.clone())
      }
   }

   pub fn set(&self, key: K, value: V) {
      if let Ok(mut map) = self.inner.write() {
         let now = Instant::now();
         map.retain(|_, (_, inserted)| now.duration_since(*inserted) <= self.ttl);
         if map.len() < MAX_ENTRIES || map.contains_key(&key) {
            map.insert(key, (value, now));
         }
      }
   }

   pub fn set_with_ttl(&self, key: K, value: V, ttl: Duration) {
      let fake_insert = Instant::now()
         .checked_sub(self.ttl.checked_sub(ttl).unwrap())
         .unwrap();
      if let Ok(mut map) = self.inner.write() {
         let now = Instant::now();
         map.retain(|_, (_, inserted)| now.duration_since(*inserted) <= self.ttl);
         if map.len() < MAX_ENTRIES || map.contains_key(&key) {
            map.insert(key, (value, fake_insert));
         }
      }
   }

   pub fn len(&self) -> usize {
      self.inner.read().map_or(0, |map| map.len())
   }

   pub fn is_empty(&self) -> bool {
      self.inner.read().map_or(true, |map| map.is_empty())
   }
}
