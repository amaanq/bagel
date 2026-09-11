//! Trap signatures and report categories shared by the web and defense planes.

pub mod category;
pub mod classify;

pub use category::{
   Category,
   categorize,
};
pub use classify::{
   Classifier,
   TrapReason,
   Verdict,
   decode_path,
};
