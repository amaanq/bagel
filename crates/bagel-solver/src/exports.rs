use core::cell::UnsafeCell;

use crate::{
   codec,
   sha256::KeyBlock,
};

struct State {
   buf: [u8; 64],
   key: [u8; codec::KEY_LEN],
}

/// wasm32 has one thread, so the static is never observed concurrently.
struct Shared(UnsafeCell<State>);

unsafe impl Sync for Shared {}

static STATE: Shared = Shared(UnsafeCell::new(State {
   buf: [0; 64],
   key: [0; codec::KEY_LEN],
}));

#[expect(
   clippy::mut_from_ref,
   reason = "single-threaded wasm module owning one static state"
)]
fn state() -> &'static mut State {
   unsafe { &mut *STATE.0.get() }
}

#[unsafe(no_mangle)]
pub extern "C" fn buf() -> *mut u8 {
   state().buf.as_mut_ptr()
}

/// Decode the handoff blob left in the buffer and remember its key.
///
/// Returns the difficulty, or -1 when the blob is malformed.
#[unsafe(no_mangle)]
pub extern "C" fn unpack(len: u32) -> i32 {
   let st = state();
   let Some(blob) = st.buf.get(..len as usize) else {
      return -1;
   };
   match codec::unpack_handoff(blob) {
      Some((key, difficulty)) => {
         st.key = key;
         i32::from(difficulty)
      },
      None => -1,
   }
}

/// Try `count` nonces from `start`, returning the first that satisfies the
/// difficulty or -1 so the caller can yield and continue.
#[unsafe(no_mangle)]
pub extern "C" fn solve(start: u64, count: u32, difficulty: u32) -> i64 {
   let mut block = KeyBlock::new(&state().key);
   let end = start.saturating_add(u64::from(count));
   (start..end)
      .find(|&nonce| block.satisfies(nonce, difficulty))
      .and_then(|nonce| i64::try_from(nonce).ok())
      .unwrap_or(-1)
}

/// Write the sealed solution into the buffer and return its length.
#[unsafe(no_mangle)]
pub extern "C" fn seal(nonce: u64, iv: u32) -> u32 {
   let st = state();
   let sealed = codec::pack_solution(iv.to_le_bytes(), &st.key, nonce);
   st.buf[..codec::SOLUTION_LEN].copy_from_slice(&sealed);
   codec::SOLUTION_LEN as u32
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
   core::arch::wasm32::unreachable()
}
