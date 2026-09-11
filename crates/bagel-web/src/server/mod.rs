//! Web request plane, split into listener, maze, and pipeline modules.

mod listen;
mod maze;
mod pipeline;
mod pipeline_evaluate;

#[cfg(test)] use listen::*;
pub use listen::{
   build_shared,
   generate_key_seed_hex,
   key_seed_hex,
   reload_shared,
   serve,
};
pub(crate) use pipeline::handle_request;

#[cfg(test)] mod tests;
