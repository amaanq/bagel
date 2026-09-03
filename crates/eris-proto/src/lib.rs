//! Protocol parsing for Eris: HTTP request heads, the PROXY protocol, and real
//! client IP resolution. These are pure, reusable networking utilities with no
//! dependency on the tarpit runtime.

pub mod http;
pub mod proxy_protocol;
pub mod realip;

pub use realip::TrustedProxies;
