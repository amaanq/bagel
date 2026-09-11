//! HTTP, PROXY, and client-IP protocol utilities.

pub mod http;
pub mod proxy_protocol;
pub mod realip;

pub use realip::{
   ClientIpPolicy,
   TrustedProxies,
};
