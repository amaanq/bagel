//! Eris runtime: the accept loop and the components it orchestrates (state,
//! classification, proxying, tarpitting, the firewall, and metrics).

pub mod admin;
pub mod category;
pub mod classify;
pub mod defense;
pub mod detector;
pub mod firewall;
pub mod metrics;
pub mod proxy;
pub mod server;
pub mod source;
pub mod state;
pub mod store;
pub mod tarpit;

pub use classify::{Classifier, Verdict};
pub use firewall::Firewall;
pub use server::Handles;
pub use state::State;
