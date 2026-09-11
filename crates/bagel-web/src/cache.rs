use std::{
   fs,
   path::PathBuf,
   time::{
      Duration,
      SystemTime,
   },
};

use crate::{
   error,
   hex_encode,
};

/// File-based TTL cache for network lists and other fetched data.
pub struct FileCache {
   dir: PathBuf,
   ttl: Duration,
}

impl FileCache {
   pub fn new(dir: PathBuf, ttl: Duration) -> error::Result<Self> {
      fs::create_dir_all(&dir)?;
      Ok(Self { dir, ttl })
   }

   fn cache_path(&self, key: &str) -> PathBuf {
      let digest = ring::digest::digest(&ring::digest::SHA256, key.as_bytes());
      let hash = hex_encode(&digest.as_ref()[..8]);
      self.dir.join(hash)
   }

   #[must_use]
   pub fn get(&self, key: &str) -> Option<String> {
      let path = self.cache_path(key);
      let metadata = fs::metadata(&path).ok()?;
      let modified = metadata.modified().ok()?;
      let age = SystemTime::now().duration_since(modified).ok()?;

      if age > self.ttl {
         return None;
      }

      fs::read_to_string(&path).ok()
   }

   pub fn set(&self, key: &str, data: &str) -> error::Result<()> {
      let path = self.cache_path(key);
      fs::write(&path, data)?;
      Ok(())
   }
}
