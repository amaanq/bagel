//! The proof-of-work solver bagel ships, plus the codec that wraps the
//! challenge handoff and the posted solution.

#![cfg_attr(target_arch = "wasm32", no_std)]

pub mod codec;
pub mod scratch;
pub mod sha256;

#[cfg(target_arch = "wasm32")] mod exports;
