use core::cell::UnsafeCell;

use crate::{
   codec::{
      self,
      Handoff,
      Kind,
      Solution,
   },
   scratch,
   sha256::KeyBlock,
};

const PAD_BLOCKS: usize = 1 << scratch::MAX_BLOCKS_LOG2;
const BUF_LEN: usize = 64;

const _: () = assert!(
   codec::SOLUTION_LEN <= BUF_LEN,
   "the sealed solution has to fit in the handoff buffer"
);

struct State {
   buf:     [u8; BUF_LEN],
   handoff: Handoff,
   pad:     [[u8; 32]; PAD_BLOCKS],
}

/// wasm32 has one thread, so the static is never observed concurrently.
struct Shared(UnsafeCell<State>);

unsafe impl Sync for Shared {}

static STATE: Shared = Shared(UnsafeCell::new(State {
   buf:     [0; BUF_LEN],
   handoff: Handoff {
      key:         [0; codec::KEY_LEN],
      kind:        Kind::Sha256,
      difficulty:  0,
      blocks_log2: 0,
   },
   pad:     [[0; 32]; PAD_BLOCKS],
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

/// Decode the handoff blob left in the buffer and remember it. Returns the
/// difficulty, or -1 when the blob is malformed.
#[unsafe(no_mangle)]
pub extern "C" fn unpack(len: u32) -> i32 {
   let st = state();
   let Some(handoff) = st.buf.get(..len as usize).and_then(codec::unpack_handoff) else {
      return -1;
   };
   if handoff.kind == Kind::Scratch && handoff.blocks_log2 > scratch::MAX_BLOCKS_LOG2 {
      return -1;
   }
   let difficulty = i32::from(handoff.difficulty);
   st.handoff = handoff;
   difficulty
}

/// Try `count` nonces from `start`, returning the first that satisfies the
/// handoff or -1 so the caller can yield and continue.
#[unsafe(no_mangle)]
pub extern "C" fn solve(start: u64, count: u32) -> i64 {
   let st = state();
   let mut key = KeyBlock::new(&st.handoff.key);
   let bits = u32::from(st.handoff.difficulty);
   let end = start.saturating_add(u64::from(count));
   let found = match st.handoff.kind {
      Kind::Sha256 => (start..end).find(|&nonce| key.satisfies(nonce, bits)),
      Kind::Scratch => {
         let blocks_log2 = st.handoff.blocks_log2;
         (start..end)
            .find(|&nonce| scratch::satisfies(&mut st.pad, &mut key, nonce, blocks_log2, bits))
      },
   };
   found
      .and_then(|nonce| i64::try_from(nonce).ok())
      .unwrap_or(-1)
}

/// Write the sealed solution into the buffer and return its length.
#[unsafe(no_mangle)]
pub extern "C" fn seal(nonce: u64, iv: u32) -> u32 {
   let st = state();
   let solution = Solution {
      key: st.handoff.key,
      nonce,
      difficulty: st.handoff.difficulty,
   };
   let sealed = codec::pack_solution(iv.to_le_bytes(), &solution);
   for (slot, byte) in st.buf.iter_mut().zip(sealed) {
      *slot = byte;
   }
   codec::SOLUTION_LEN as u32
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
   core::arch::wasm32::unreachable()
}
