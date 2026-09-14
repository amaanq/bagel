//! The blob the page hands the solver and the blob the solver posts back.
//!
//! Both are a four byte IV followed by the payload `XORed` with an `xorshift32`
//! keystream. This hides nothing from a client that runs the module, it only
//! keeps the key and difficulty out of the page source.

pub const IV_LEN: usize = 4;
pub const KEY_LEN: usize = 32;
pub const HANDOFF_LEN: usize = IV_LEN + KEY_LEN + 3;
pub const SOLUTION_LEN: usize = IV_LEN + KEY_LEN + 9;

/// Which proof the module must produce.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
   /// SHA-256(key || nonce) opens with `difficulty` zero nibbles.
   Sha256,
   /// A scratchpad walk seeded by SHA-256(key || nonce) ends in `difficulty`
   /// zero bits.
   Scratch,
}

impl Kind {
   const fn tag(self) -> u8 {
      match self {
         Self::Sha256 => 0,
         Self::Scratch => 1,
      }
   }

   const fn from_tag(tag: u8) -> Option<Self> {
      match tag {
         0 => Some(Self::Sha256),
         1 => Some(Self::Scratch),
         _ => None,
      }
   }
}

pub struct Handoff {
   pub key:         [u8; KEY_LEN],
   pub kind:        Kind,
   pub difficulty:  u8,
   /// Scratchpad size as a power of two block count, zero for SHA-256.
   pub blocks_log2: u8,
}

pub struct Solution {
   pub key:        [u8; KEY_LEN],
   pub nonce:      u64,
   pub difficulty: u8,
}

fn keystream<'a>(iv: [u8; IV_LEN], data: impl IntoIterator<Item = &'a mut u8>) {
   let mut state = u32::from_le_bytes(iv) | 1;
   for byte in data {
      state ^= state << 13;
      state ^= state >> 17;
      state ^= state << 5;
      *byte ^= (state >> 24) as u8;
   }
}

#[must_use]
pub fn pack_handoff(iv: [u8; IV_LEN], handoff: &Handoff) -> [u8; HANDOFF_LEN] {
   const _: () = assert!(
      IV_LEN + KEY_LEN + 3 == HANDOFF_LEN,
      "pack_handoff writes three tail bytes"
   );
   let mut out = [0_u8; HANDOFF_LEN];
   let tail = [handoff.kind.tag(), handoff.difficulty, handoff.blocks_log2];
   for (slot, byte) in out
      .iter_mut()
      .zip(iv.into_iter().chain(handoff.key).chain(tail))
   {
      *slot = byte;
   }
   keystream(iv, out.iter_mut().skip(IV_LEN));
   out
}

#[must_use]
pub fn unpack_handoff(blob: &[u8]) -> Option<Handoff> {
   let blob: &[u8; HANDOFF_LEN] = blob.try_into().ok()?;
   let (&iv, sealed) = blob.split_first_chunk::<IV_LEN>()?;
   let mut body = [0_u8; HANDOFF_LEN - IV_LEN];
   for (slot, byte) in body.iter_mut().zip(sealed) {
      *slot = *byte;
   }
   keystream(iv, &mut body);
   Some(Handoff {
      key:         *body.first_chunk::<KEY_LEN>()?,
      kind:        Kind::from_tag(body[KEY_LEN])?,
      difficulty:  body[KEY_LEN + 1],
      blocks_log2: body[KEY_LEN + 2],
   })
}

#[must_use]
pub fn pack_solution(iv: [u8; IV_LEN], solution: &Solution) -> [u8; SOLUTION_LEN] {
   const _: () = assert!(
      IV_LEN + KEY_LEN + 8 + 1 == SOLUTION_LEN,
      "pack_solution writes an eight byte nonce and one difficulty byte"
   );
   let mut out = [0_u8; SOLUTION_LEN];
   for (slot, byte) in out.iter_mut().zip(
      iv.into_iter()
         .chain(solution.key)
         .chain(solution.nonce.to_be_bytes())
         .chain([solution.difficulty]),
   ) {
      *slot = byte;
   }
   keystream(iv, out.iter_mut().skip(IV_LEN));
   out
}

#[must_use]
pub fn unpack_solution(blob: &[u8]) -> Option<Solution> {
   let blob: &[u8; SOLUTION_LEN] = blob.try_into().ok()?;
   let (&iv, sealed) = blob.split_first_chunk::<IV_LEN>()?;
   let mut body = [0_u8; SOLUTION_LEN - IV_LEN];
   for (slot, byte) in body.iter_mut().zip(sealed) {
      *slot = *byte;
   }
   keystream(iv, &mut body);
   let (&key, rest) = body.split_first_chunk::<KEY_LEN>()?;
   Some(Solution {
      key,
      nonce: u64::from_be_bytes(*rest.first_chunk::<8>()?),
      difficulty: body[KEY_LEN + 8],
   })
}
