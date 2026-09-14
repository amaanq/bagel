#[rustfmt::skip]
const K: [u32; 64] = [
   0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
   0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
   0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
   0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7, 0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
   0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
   0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
   0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
   0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
];

#[rustfmt::skip]
const H0: [u32; 8] = [
   0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
   0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
];

#[expect(
   clippy::many_single_char_names,
   reason = "the FIPS 180-4 working variables"
)]
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
   let mut w = [0_u32; 64];
   for (word, chunk) in w.iter_mut().zip(block.chunks_exact(4)) {
      *word = u32::from_be_bytes(chunk.try_into().expect("chunks_exact yields four bytes"));
   }
   for i in 16..64 {
      let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
      let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16]
         .wrapping_add(s0)
         .wrapping_add(w[i - 7])
         .wrapping_add(s1);
   }

   let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
   for i in 0..64 {
      let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
      let ch = (e & f) ^ (!e & g);
      let t1 = h
         .wrapping_add(s1)
         .wrapping_add(ch)
         .wrapping_add(K[i])
         .wrapping_add(w[i]);
      let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
      let maj = (a & b) ^ (a & c) ^ (b & c);
      let t2 = s0.wrapping_add(maj);
      h = g;
      g = f;
      f = e;
      e = d.wrapping_add(t1);
      d = c;
      c = b;
      b = a;
      a = t1.wrapping_add(t2);
   }
   for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
      *slot = slot.wrapping_add(value);
   }
}

/// SHA-256 of two 32 byte inputs, which fills one block and pads a second.
#[must_use]
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
   let mut block = [0_u8; 64];
   block[..32].copy_from_slice(left);
   block[32..].copy_from_slice(right);
   let mut state = H0;
   compress(&mut state, &block);
   let mut tail = [0_u8; 64];
   tail[0] = 0x80;
   tail[62..].copy_from_slice(&(64_u16 * 8).to_be_bytes());
   compress(&mut state, &tail);
   to_bytes(&state)
}

fn to_bytes(state: &[u32; 8]) -> [u8; 32] {
   let mut out = [0_u8; 32];
   for (chunk, word) in out.chunks_exact_mut(4).zip(state) {
      chunk.copy_from_slice(&word.to_be_bytes());
   }
   out
}

/// Whether the digest opens with at least `bits` zero bits.
#[must_use]
pub fn leading_zero_bits(digest: &[u8; 32], bits: u32) -> bool {
   let mut remaining = bits;
   for byte in digest {
      if remaining == 0 {
         return true;
      }
      let zeros = byte.leading_zeros();
      if zeros < remaining.min(8) {
         return false;
      }
      remaining = remaining.saturating_sub(8);
   }
   remaining == 0
}

/// One padded block holding `key || nonce`, so each attempt only rewrites
/// the nonce bytes and compresses once.
pub struct KeyBlock {
   block: [u8; 64],
}

impl KeyBlock {
   #[must_use]
   pub fn new(key: &[u8; 32]) -> Self {
      let mut block = [0_u8; 64];
      block[..32].copy_from_slice(key);
      block[40] = 0x80;
      block[62..].copy_from_slice(&(40_u16 * 8).to_be_bytes());
      Self { block }
   }

   /// SHA-256(key || nonce).
   #[must_use]
   pub fn digest(&mut self, nonce: u64) -> [u8; 32] {
      self.block[32..40].copy_from_slice(&nonce.to_be_bytes());
      let mut state = H0;
      compress(&mut state, &self.block);
      to_bytes(&state)
   }

   /// Whether SHA-256(key || nonce) opens with `bits` zero bits.
   #[must_use]
   pub fn satisfies(&mut self, nonce: u64, bits: u32) -> bool {
      leading_zero_bits(&self.digest(nonce), bits)
   }
}
