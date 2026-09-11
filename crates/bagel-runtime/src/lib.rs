//! Bagel runtime: the accept loop and the components it orchestrates (state,
//! classification, proxying, tarpitting, the firewall, and metrics).

pub mod admin;
pub mod category;
pub mod classify;
pub mod defense;
mod defense_maintenance;
pub mod detector;
pub mod firewall;
pub mod metrics;
pub mod offense;
pub mod server;
pub mod source;
mod source_address_set;
mod source_file;
mod source_journal;
pub mod state;
pub mod store;
pub mod tarpit;

pub use classify::{
   Classifier,
   Verdict,
};
pub use defense::ActiveLeases;
pub use firewall::Firewall;
pub use offense::{
   Offense,
   OffenseKind,
   WebOffenseSource,
};
pub use server::Handles;
pub use state::State;
#[cfg(test)] mod defense_tests;
