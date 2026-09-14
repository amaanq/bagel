//! The blob the page hands the solver and the blob the solver posts back.
//!
//! Both are a four byte IV followed by the payload `XORed` with an `xorshift32`
//! keystream. This hides nothing from a client that runs the module, it only
//! keeps the key and difficulty out of the page source.

pub const IV_LEN: usize = 4;
pub const KEY_LEN: usize = 32;
pub const HANDOFF_LEN: usize = IV_LEN + KEY_LEN + 1;
pub const SOLUTION_LEN: usize = IV_LEN + KEY_LEN + 8;

fn keystream(iv: [u8; IV_LEN], data: &mut [u8]) {
   let mut state = u32::from_le_bytes(iv) | 1;
   for byte in data {
      state ^= state << 13;
      state ^= state >> 17;
      state ^= state << 5;
      *byte ^= (state >> 24) as u8;
   }
}

#[must_use]
pub fn pack_handoff(iv: [u8; IV_LEN], key: &[u8; KEY_LEN], difficulty: u8) -> [u8; HANDOFF_LEN] {
   let mut out = [0_u8; HANDOFF_LEN];
   out[..IV_LEN].copy_from_slice(&iv);
   out[IV_LEN..IV_LEN + KEY_LEN].copy_from_slice(key);
   out[IV_LEN + KEY_LEN] = difficulty;
   keystream(iv, &mut out[IV_LEN..]);
   out
}

#[must_use]
pub fn unpack_handoff(blob: &[u8]) -> Option<([u8; KEY_LEN], u8)> {
   let blob: &[u8; HANDOFF_LEN] = blob.try_into().ok()?;
   let mut body = [0_u8; HANDOFF_LEN - IV_LEN];
   body.copy_from_slice(&blob[IV_LEN..]);
   keystream(blob[..IV_LEN].try_into().ok()?, &mut body);
   let key = body[..KEY_LEN].try_into().ok()?;
   Some((key, body[KEY_LEN]))
}

#[must_use]
pub fn pack_solution(iv: [u8; IV_LEN], key: &[u8; KEY_LEN], nonce: u64) -> [u8; SOLUTION_LEN] {
   let mut out = [0_u8; SOLUTION_LEN];
   out[..IV_LEN].copy_from_slice(&iv);
   out[IV_LEN..IV_LEN + KEY_LEN].copy_from_slice(key);
   out[IV_LEN + KEY_LEN..].copy_from_slice(&nonce.to_be_bytes());
   keystream(iv, &mut out[IV_LEN..]);
   out
}

#[must_use]
pub fn unpack_solution(blob: &[u8]) -> Option<([u8; KEY_LEN], u64)> {
   let blob: &[u8; SOLUTION_LEN] = blob.try_into().ok()?;
   let mut body = [0_u8; SOLUTION_LEN - IV_LEN];
   body.copy_from_slice(&blob[IV_LEN..]);
   keystream(blob[..IV_LEN].try_into().ok()?, &mut body);
   let key = body[..KEY_LEN].try_into().ok()?;
   let nonce = u64::from_be_bytes(body[KEY_LEN..].try_into().ok()?);
   Some((key, nonce))
}
