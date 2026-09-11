pub mod keys;
pub mod memory;
pub mod path;
pub mod render;
pub mod renderer;
pub mod token;

use std::{
   collections::HashMap,
   sync::Arc,
};

use crate::config::policy::MazeConfig;

/// One maze with its derived keys for one canonical host.
#[derive(Clone)]
pub struct MazeRuntime {
   pub name:   String,
   pub keys:   keys::MazeKeys,
   pub config: MazeConfig,
}

/// Route-prefix table for one canonical host.
#[derive(Default)]
pub struct MazeTable {
   pub by_prefix: HashMap<String, Arc<MazeRuntime>>,
}

impl MazeTable {
   #[must_use]
   pub fn by_name(&self, name: &str) -> Option<Arc<MazeRuntime>> {
      self
         .by_prefix
         .values()
         .find(|runtime| runtime.name == name)
         .map(Arc::clone)
   }
}

#[must_use]
pub fn is_valid_maze_name(name: &str) -> bool {
   let mut bytes = name.bytes();
   let Some(first) = bytes.next() else {
      return false;
   };
   name.len() <= 64
      && first.is_ascii_lowercase()
      && bytes.all(|byte| {
         byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
      })
}

/// Build the per-host maze table, refusing the host on a route prefix
/// collision rather than picking a maze arbitrarily.
pub fn build_table(
   master: &[u8; 32],
   canonical_host: &str,
   mazes: &[MazeConfig],
) -> Result<MazeTable, String> {
   let mut table = MazeTable::default();
   for maze in mazes {
      let derived = keys::derive_maze_keys(master, canonical_host, &maze.name);
      let prefix = derived.route_prefix.clone();
      let runtime = Arc::new(MazeRuntime {
         name:   maze.name.clone(),
         keys:   derived,
         config: maze.clone(),
      });
      if let Some(existing) = table.by_prefix.insert(prefix, runtime) {
         return Err(format!(
            "maze route prefix collision between '{}' and '{}' on host '{canonical_host}'",
            existing.name, maze.name
         ));
      }
   }
   Ok(table)
}
