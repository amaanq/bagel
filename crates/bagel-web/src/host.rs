use std::net::{
   IpAddr,
   Ipv4Addr,
   Ipv6Addr,
};

/// Canonical host identity shared by routing, policy, cookies, logs, and
/// metrics.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalHost {
   text: String,
   ip:   Option<IpAddr>,
}

impl CanonicalHost {
   /// Canonicalize one authority string.
   pub fn parse(authority: &str) -> Result<Self, String> {
      if authority.contains('@') {
         return Err("authority must not contain user information".into());
      }

      if let Some(rest) = authority.strip_prefix('[') {
         let (literal, tail) = rest.split_once(']').ok_or("unterminated IPv6 literal")?;
         if !tail.is_empty() {
            let port = tail
               .strip_prefix(':')
               .ok_or("malformed authority after IPv6 literal")?;
            validate_port(port)?;
         }
         if literal.contains('%') {
            return Err("scoped IPv6 zone identifiers are not allowed".into());
         }
         let ip: Ipv6Addr = literal
            .parse()
            .map_err(|_| "invalid IPv6 literal".to_owned())?;
         return Ok(Self::from_ip(IpAddr::V6(ip)));
      }

      let host = match authority.split_once(':') {
         Some((host, port)) => {
            if port.contains(':') {
               return Err("IPv6 literals require brackets".into());
            }
            validate_port(port)?;
            host
         },
         None => authority,
      };

      if host.is_empty() {
         return Err("empty host".into());
      }

      if let Ok(v4) = host.parse::<Ipv4Addr>() {
         return Ok(Self::from_ip(IpAddr::V4(v4)));
      }

      if !host.is_ascii() {
         return Err("non-ASCII host, expected the punycode A-label form".into());
      }

      let ascii = host.to_ascii_lowercase();
      let ascii = ascii.strip_suffix('.').unwrap_or(&ascii);
      if !is_valid_dns_name(ascii) {
         return Err("invalid DNS host".into());
      }

      Ok(Self {
         text: ascii.to_owned(),
         ip:   None,
      })
   }

   #[must_use]
   pub fn from_ip(ip: IpAddr) -> Self {
      Self {
         text: ip.to_string(),
         ip:   Some(ip),
      }
   }

   #[must_use]
   pub fn as_str(&self) -> &str {
      &self.text
   }

   /// IP literal hosts get host-only challenge cookies with no Domain.
   #[must_use]
   pub const fn is_ip(&self) -> bool {
      self.ip.is_some()
   }
}

impl std::fmt::Display for CanonicalHost {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      f.write_str(&self.text)
   }
}

fn is_valid_dns_name(name: &str) -> bool {
   !name.is_empty()
      && name.len() <= 253
      && name.split('.').all(|label| {
         !label.is_empty()
            && label.len() <= 63
            && label.bytes().all(|byte| {
               byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
      })
}

fn validate_port(port: &str) -> Result<(), String> {
   if port.is_empty() || port.parse::<u16>().is_err() {
      return Err(format!("invalid port '{port}'"));
   }
   Ok(())
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn equivalent_spellings_produce_one_host() {
      let expected = CanonicalHost::parse("example.com").unwrap();
      for spelling in [
         "EXAMPLE.com",
         "example.com:8080",
         "example.com.",
         "eXaMpLe.CoM:443",
         "example.com.:80",
      ] {
         assert_eq!(
            CanonicalHost::parse(spelling).unwrap(),
            expected,
            "{spelling}"
         );
      }
      assert_eq!(expected.as_str(), "example.com");
      assert!(!expected.is_ip());
   }

   #[test]
   fn punycode_canonicalizes_and_unicode_is_rejected() {
      let expected = CanonicalHost::parse("xn--mnchen-3ya.example").unwrap();
      assert_eq!(expected.as_str(), "xn--mnchen-3ya.example");
      for spelling in [
         "XN--MNCHEN-3YA.EXAMPLE",
         "xn--mnchen-3ya.example.",
         "Xn--Mnchen-3ya.Example:8443",
      ] {
         assert_eq!(
            CanonicalHost::parse(spelling).unwrap(),
            expected,
            "{spelling}"
         );
      }

      let oversized_label = format!("{}.example", "a".repeat(64));
      let oversized_name = format!("{0}.{0}.{0}.{0}.{0}", "b".repeat(60));
      for bad in [
         "m\u{fc}nchen.example",
         "xn--mnchen-3ya.ex\u{e4}mple",
         "a..b",
         "..",
         oversized_label.as_str(),
         oversized_name.as_str(),
      ] {
         assert!(CanonicalHost::parse(bad).is_err(), "{bad}");
      }
   }

   #[test]
   fn malformed_authorities_are_rejected() {
      for bad in [
         "",
         "user@example.com",
         "example.com:notaport",
         "example.com:",
         "[::1",
         "[::1%eth0]",
         "::1",
         "exa mple.com",
      ] {
         assert!(CanonicalHost::parse(bad).is_err(), "{bad}");
      }
   }
}
