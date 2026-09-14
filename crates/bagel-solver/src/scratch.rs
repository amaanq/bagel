//! A scratchpad proof. Filling the pad is sequential and the walk reads it
//! in a data-dependent order, so every attempt touches `blocks * 32` bytes
//! and a batch solver gains little over a browser.

use crate::sha256::{
   KeyBlock,
   hash_pair,
   leading_zero_bits,
};

pub const MIN_BLOCKS_LOG2: u8 = 11;
pub const MAX_BLOCKS_LOG2: u8 = 15;

/// Walk the pad for one nonce and report whether the final digest opens
/// with `bits` zero bits. `pad` must hold at least `2^blocks_log2` blocks.
#[must_use]
pub fn satisfies(
   pad: &mut [[u8; 32]],
   key: &mut KeyBlock,
   nonce: u64,
   blocks_log2: u8,
   bits: u32,
) -> bool {
   let blocks = 1_usize << blocks_log2;
   let Some(pad) = pad.get_mut(..blocks) else {
      return false;
   };
   let seed = key.digest(nonce);
   pad[0] = seed;
   for index in 1..blocks {
      pad[index] = hash_pair(&pad[index - 1], &seed);
   }
   let mut acc = seed;
   for _ in 0..blocks {
      let pick = u32::from_le_bytes([acc[0], acc[1], acc[2], acc[3]]) as usize & (blocks - 1);
      acc = hash_pair(&acc, &pad[pick]);
      pad[pick] = acc;
   }
   leading_zero_bits(&acc, bits)
}
