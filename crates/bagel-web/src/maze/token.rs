use std::sync::LazyLock;

use ring::rand::{
   SecureRandom as _,
   SystemRandom,
};

use super::keys::{
   BASE32_LOWER,
   MazeKeys,
   frame,
};
use crate::SourceNetwork;

pub const TOKEN_LEN: usize = 58;
pub const TOKEN_ENCODED_LEN: usize = 93;
pub const TOKEN_VERSION: u8 = 1;
pub const FLAG_BOUND: u8 = 0b0000_0001;

const HEADER_LEN: usize = TOKEN_LEN - 16;

static CSPRNG: LazyLock<SystemRandom> = LazyLock::new(SystemRandom::new);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenClass {
   ValidReturn,
   Transfer,
   Unbound,
   Expired,
   Invalid,
   Malformed,
}

impl TokenClass {
   #[must_use]
   pub const fn as_str(self) -> &'static str {
      match self {
         Self::ValidReturn => "valid_return",
         Self::Transfer => "transfer",
         Self::Unbound => "unbound",
         Self::Expired => "expired",
         Self::Invalid => "invalid",
         Self::Malformed => "malformed",
      }
   }

   /// Only a valid bound return gets authenticated links and sets poison
   /// memory. Everything else renders a decoy.
   #[must_use]
   pub const fn is_authenticated(self) -> bool {
      matches!(self, Self::ValidReturn)
   }
}

fn binding_value(binding_key: &[u8; 32], source: SourceNetwork) -> [u8; 16] {
   let mut input = frame(b"bagel maze binding v1");
   input.extend_from_slice(&frame(&source.to_bytes()));
   let tag = ring::hmac::sign(
      &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, binding_key),
      &input,
   );
   tag.as_ref()[..16].try_into().expect("mac is 32 bytes")
}

fn compute_tag(mac_key: &[u8; 32], header: &[u8; HEADER_LEN], maze_path: &str) -> [u8; 16] {
   let mut input = frame(b"bagel maze token v1");
   input.extend_from_slice(header);
   input.extend_from_slice(&frame(maze_path.as_bytes()));
   let tag = ring::hmac::sign(
      &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, mac_key),
      &input,
   );
   tag.as_ref()[..16].try_into().expect("mac is 32 bytes")
}

fn build(
   keys: &MazeKeys,
   maze_path: &str,
   source: Option<SourceNetwork>,
   expires: u64,
   corrupt_tag: bool,
) -> String {
   let mut nonce = [0_u8; 16];
   CSPRNG
      .fill(&mut nonce)
      .expect("system CSPRNG failed, refusing to mint with a zero nonce");

   let (flags, binding) = source.map_or((0, [0_u8; 16]), |network| {
      (FLAG_BOUND, binding_value(&keys.binding_key, network))
   });

   let mut header = [0_u8; HEADER_LEN];
   header[0] = TOKEN_VERSION;
   header[1] = flags;
   header[2..10].copy_from_slice(&expires.to_be_bytes());
   header[10..26].copy_from_slice(&nonce);
   header[26..42].copy_from_slice(&binding);

   let mut tag = compute_tag(&keys.mac_key, &header, maze_path);
   if corrupt_tag {
      tag[0] ^= 0b0000_0001;
   }

   let mut token = [0_u8; TOKEN_LEN];
   token[..HEADER_LEN].copy_from_slice(&header);
   token[HEADER_LEN..].copy_from_slice(&tag);
   BASE32_LOWER.encode(&token)
}

/// Mint a valid token for the given path, bound to the source network when
/// one is resolved. The nonce is fresh CSPRNG output for every link.
#[must_use]
pub fn mint(
   keys: &MazeKeys,
   maze_path: &str,
   source: Option<SourceNetwork>,
   expires: u64,
) -> String {
   build(keys, maze_path, source, expires, false)
}

/// Mint a canonical decoy token that fails validation.
#[must_use]
pub fn mint_decoy(
   keys: &MazeKeys,
   maze_path: &str,
   source: Option<SourceNetwork>,
   expires: u64,
) -> String {
   build(keys, maze_path, source, expires, true)
}

/// Classify a presented token. Validation order is fixed: decode, structure,
/// tag, expiry, binding.
#[must_use]
pub fn classify(
   keys: &MazeKeys,
   maze_path: &str,
   encoded: &str,
   source: Option<SourceNetwork>,
   now: u64,
) -> TokenClass {
   if encoded.len() != TOKEN_ENCODED_LEN {
      return TokenClass::Malformed;
   }
   let Ok(raw) = BASE32_LOWER.decode(encoded.as_bytes()) else {
      return TokenClass::Malformed;
   };
   if raw.len() != TOKEN_LEN || BASE32_LOWER.encode(&raw) != encoded {
      return TokenClass::Malformed;
   }

   if raw[0] != TOKEN_VERSION || raw[1] & !FLAG_BOUND != 0 {
      return TokenClass::Malformed;
   }

   let header: [u8; HEADER_LEN] = raw[..HEADER_LEN].try_into().expect("length checked");
   let expected_tag = compute_tag(&keys.mac_key, &header, maze_path);
   if !constant_time_eq::constant_time_eq(&raw[HEADER_LEN..], &expected_tag) {
      return TokenClass::Invalid;
   }

   let expires = u64::from_be_bytes(raw[2..10].try_into().expect("length checked"));
   if expires < now {
      return TokenClass::Expired;
   }

   if raw[1] & FLAG_BOUND == 0 {
      return TokenClass::Unbound;
   }

   let bound = source.is_some_and(|network| {
      constant_time_eq::constant_time_eq(&raw[26..42], &binding_value(&keys.binding_key, network))
   });
   if bound {
      TokenClass::ValidReturn
   } else {
      TokenClass::Transfer
   }
}

#[cfg(test)]
mod tests {
   use std::net::{
      IpAddr,
      Ipv4Addr,
      Ipv6Addr,
   };

   use super::{
      super::keys::{
         derive_maze_keys,
         poison_master,
      },
      *,
   };

   fn keys() -> MazeKeys {
      derive_maze_keys(
         &poison_master(b"token-test-seed"),
         "example.test",
         "default",
      )
   }

   fn v4(a: u8, b: u8, c: u8, d: u8) -> SourceNetwork {
      SourceNetwork::from_ip(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
   }

   fn v6(tail: u16) -> SourceNetwork {
      SourceNetwork::from_ip(IpAddr::V6(Ipv6Addr::new(
         0x2001, 0xDB8, 1, 2, tail, tail, tail, tail,
      )))
   }

   #[test]
   fn classification_covers_every_outcome() {
      let keys = keys();
      let here = Some(v4(10, 1, 2, 3));
      let near = Some(v4(10, 1, 2, 200));
      let far = Some(v4(10, 99, 2, 3));

      for (label, minted, presented, now, expected) in [
         ("same network", here, here, 500, TokenClass::ValidReturn),
         (
            "v4 change in prefix",
            here,
            near,
            500,
            TokenClass::ValidReturn,
         ),
         (
            "v6 change in prefix",
            Some(v6(3)),
            Some(v6(9)),
            500,
            TokenClass::ValidReturn,
         ),
         ("cross prefix reuse", here, far, 500, TokenClass::Transfer),
         ("unresolved source", here, None, 500, TokenClass::Transfer),
         (
            "expiry outranks binding",
            here,
            far,
            2000,
            TokenClass::Expired,
         ),
         ("unbound mint", None, here, 500, TokenClass::Unbound),
      ] {
         let token = mint(&keys, "foo", minted, 1000);
         assert_eq!(token.len(), TOKEN_ENCODED_LEN, "{label}");
         let class = classify(&keys, "foo", &token, presented, now);
         assert_eq!(class, expected, "{label}");
      }

      let token = mint(&keys, "foo/bar", here, 1000);
      let seed = poison_master(b"token-test-seed");
      let other_host = derive_maze_keys(&seed, "other.test", "default");
      let other_maze = derive_maze_keys(&seed, "example.test", "other");

      for (label, against, path) in [
         ("cross host replay", &other_host, "foo/bar"),
         ("cross maze replay", &other_maze, "foo/bar"),
         ("path modification", &keys, "foo/baz"),
      ] {
         let class = classify(against, path, &token, here, 500);
         assert_eq!(class, TokenClass::Invalid, "{label}");
      }

      let mut reserved = [0_u8; TOKEN_LEN];
      reserved[0] = TOKEN_VERSION;
      reserved[1] = 0b0000_0010;

      for (label, bad) in [
         ("reserved flag", BASE32_LOWER.encode(&reserved)),
         ("uppercased", token.to_uppercase()),
         ("padded", format!("{token}=")),
         ("truncated", token[..TOKEN_ENCODED_LEN - 1].to_owned()),
      ] {
         let class = classify(&keys, "foo/bar", &bad, here, 500);
         assert_eq!(class, TokenClass::Malformed, "{label}");
      }
   }

   #[test]
   fn decoy_tokens_are_canonical_but_always_fail_the_mac() {
      let keys = keys();
      let decoy = mint_decoy(&keys, "foo", Some(v4(10, 1, 2, 3)), 1000);
      assert_eq!(decoy.len(), TOKEN_ENCODED_LEN);
      assert!(
         decoy
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
      );
      assert_eq!(
         classify(&keys, "foo", &decoy, Some(v4(10, 1, 2, 3)), 500),
         TokenClass::Invalid
      );
   }
}
