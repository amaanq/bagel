use std::sync::LazyLock;

use data_encoding::{
   Encoding,
   Specification,
};
use ring::hkdf;

/// Canonical lowercase RFC 4648 Base32 without padding, so every minted maze
/// URL survives crawler-side lowercasing byte for byte.
pub static BASE32_LOWER: LazyLock<Encoding> = LazyLock::new(|| {
   let mut spec = Specification::new();
   spec.symbols.push_str("abcdefghijklmnopqrstuvwxyz234567");
   spec.encoding().expect("valid base32 specification")
});

pub const ROUTE_PREFIX_LEN: usize = 20;

/// Four-byte unsigned big-endian length followed by the exact bytes. Every
/// variable-length cryptographic field is framed so adjacent fields cannot be
/// repartitioned.
#[must_use]
pub fn frame(value: &[u8]) -> Vec<u8> {
   let mut framed = Vec::with_capacity(4 + value.len());
   framed.extend_from_slice(&(value.len() as u32).to_be_bytes());
   framed.extend_from_slice(value);
   framed
}

#[derive(Clone)]
pub struct MazeKeys {
   pub mac_key:      [u8; 32],
   pub binding_key:  [u8; 32],
   pub route_key:    [u8; 32],
   pub render_key:   [u8; 32],
   pub decoy_key:    [u8; 32],
   pub memory_key:   [u8; 32],
   pub route_prefix: String,
}

fn expand(prk: &hkdf::Prk, info: &[&[u8]]) -> [u8; 32] {
   let mut key = [0_u8; 32];
   prk.expand(info, hkdf::HKDF_SHA256)
      .expect("HKDF output length is valid")
      .fill(&mut key)
      .expect("HKDF output length is valid");
   key
}

/// Derive the deployment-wide poison master from the persisted Ed25519 PKCS8
/// DER bytes.
#[must_use]
pub fn poison_master(pkcs8_der: &[u8]) -> [u8; 32] {
   let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"bagel poison root v1").extract(pkcs8_der);
   expand(&prk, &[&frame(b"master")])
}

/// Derive the six per-host, per-maze keys and the lowercase route prefix.
#[must_use]
pub fn derive_maze_keys(master: &[u8; 32], canonical_host: &str, maze_name: &str) -> MazeKeys {
   let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"bagel maze v1").extract(master);
   let host = frame(canonical_host.as_bytes());
   let name = frame(maze_name.as_bytes());

   let derive = |label: &[u8]| expand(&prk, &[&frame(label), &host, &name]);

   let route_key = derive(b"route");
   let route_prefix = BASE32_LOWER.encode(&route_key[..12]);

   MazeKeys {
      mac_key: derive(b"mac"),
      binding_key: derive(b"binding"),
      route_key,
      render_key: derive(b"render"),
      decoy_key: derive(b"decoy"),
      memory_key: derive(b"memory"),
      route_prefix,
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   const SEED_A: &[u8] = b"seed-a-pkcs8-der-bytes";

   fn keys(seed: &[u8], host: &str, maze: &str) -> MazeKeys {
      derive_maze_keys(&poison_master(seed), host, maze)
   }

   #[test]
   fn framing_prevents_ambiguous_partitions() {
      assert_ne!(
         keys(SEED_A, "ab", "c").mac_key,
         keys(SEED_A, "a", "bc").mac_key
      );
      assert_ne!(
         keys(SEED_A, "", "abc").mac_key,
         keys(SEED_A, "abc", "").mac_key
      );
   }

   #[test]
   fn route_prefix_is_twenty_lowercase_base32_chars() {
      let keys = keys(SEED_A, "example.test", "default");
      assert_eq!(keys.route_prefix.len(), 20);
      assert!(
         keys
            .route_prefix
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
      );
   }
}
