//! Real client IP resolution.
//!
//! When Eris runs behind a TLS terminator or load balancer, the socket peer is
//! the proxy, not the attacker. Using the peer IP directly would whitelist every
//! request (the proxy is usually on a trusted network) and, worse, could get the
//! proxy itself blocked, blackholing all traffic.
//!
//! We only trust forwarding information from peers explicitly configured as
//! trusted proxies. Anything from an untrusted peer is ignored, so a client
//! cannot spoof its own address by sending an `X-Forwarded-For` header.

use eris_core::{Error, Result};
use ipnetwork::IpNetwork;
use std::net::IpAddr;

/// The set of networks whose forwarding headers Eris will trust.
#[derive(Clone, Default)]
pub struct TrustedProxies(Vec<IpNetwork>);

impl TrustedProxies {
    /// Parse trusted-proxy CIDR networks.
    pub fn new(cidrs: &[String]) -> Result<Self> {
        let nets = cidrs
            .iter()
            .map(|s| {
                s.parse::<IpNetwork>()
                    .map_err(|e| Error::Network(e.to_string()))
            })
            .collect::<Result<_>>()?;
        Ok(Self(nets))
    }

    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|net| net.contains(ip))
    }

    /// Resolve the real client IP from the socket peer and an optional
    /// forwarded-for header value.
    ///
    /// If the peer is not a trusted proxy, the peer IP is authoritative and the
    /// header is ignored. If it is trusted, we walk the header from right to
    /// left and return the first address that is not itself a trusted proxy;
    /// this defeats client-supplied spoofing while still peeling off any chain
    /// of trusted hops.
    #[must_use]
    pub fn client_ip(&self, peer: IpAddr, forwarded_for: Option<&str>) -> IpAddr {
        if !self.contains(peer) {
            return peer;
        }
        let Some(header) = forwarded_for else {
            return peer;
        };

        let mut first_valid = None;
        for entry in header.split(',').rev() {
            let Ok(ip) = entry.trim().parse::<IpAddr>() else {
                continue;
            };
            first_valid.get_or_insert(ip);
            if !self.contains(ip) {
                return ip;
            }
        }
        // Every hop was trusted (or unparseable): fall back to the closest
        // valid address, or the peer if the header held nothing usable.
        first_valid.unwrap_or(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn untrusted_peer_ignores_header() {
        let tp = TrustedProxies::new(&["10.0.0.0/8".into()]).unwrap();
        // Peer is a real client, not a proxy: never trust its XFF.
        assert_eq!(tp.client_ip(ip("8.8.8.8"), Some("1.2.3.4")), ip("8.8.8.8"));
    }

    #[test]
    fn trusted_peer_uses_rightmost_untrusted() {
        let tp = TrustedProxies::new(&["10.0.0.0/8".into()]).unwrap();
        // Client -> edge proxy (spoofed 9.9.9.9 injected by client) -> eris.
        // 10.0.0.2 is a trusted hop; 203.0.113.7 is the real client.
        assert_eq!(
            tp.client_ip(ip("10.0.0.1"), Some("9.9.9.9, 203.0.113.7, 10.0.0.2")),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn missing_header_falls_back_to_peer() {
        let tp = TrustedProxies::new(&["10.0.0.0/8".into()]).unwrap();
        assert_eq!(tp.client_ip(ip("10.0.0.1"), None), ip("10.0.0.1"));
    }

    #[test]
    fn invalid_cidr_is_error() {
        assert!(TrustedProxies::new(&["not-a-cidr".into()]).is_err());
    }
}
