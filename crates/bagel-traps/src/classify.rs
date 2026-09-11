//! Request classification for proxy and tarpit decisions.

use std::{
   borrow::Cow,
   net::IpAddr,
};

use bagel_core::{
   Error,
   Result,
};
use ipnetwork::IpNetwork;
use regex::{
   Regex,
   RegexSet,
};

/// Percent-decode one path for classification without modifying the request.
#[must_use]
pub fn decode_path(path: &str) -> Cow<'_, str> {
   if !path.contains('%') {
      return Cow::Borrowed(path);
   }
   let bytes = path.as_bytes();
   let mut out = Vec::with_capacity(bytes.len());
   let mut i = 0;
   while i < bytes.len() {
      if bytes[i] == b'%'
         && i + 2 < bytes.len()
         && let (Some(hi), Some(lo)) = (
            (bytes[i + 1] as char).to_digit(16),
            (bytes[i + 2] as char).to_digit(16),
         )
      {
         out.push((hi * 16 + lo) as u8);
         i += 3;
      } else {
         out.push(bytes[i]);
         i += 1;
      }
   }
   Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

/// Why a request was trapped, carried by [`Verdict::Tarpit`] so the caller can
/// report and meter each dimension separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapReason {
   /// The request path matched trap pattern at this index.
   Path(usize),
   /// The `User-Agent` matched abusive-agent pattern at this index.
   UserAgent(usize),
   /// The source exceeded its per-IP request-rate budget.
   Rate,
   /// The `User-Agent` claims to be a known crawler at this index, but the
   /// source IP is outside that crawler's published ranges: a forgery.
   Impersonator(usize),
}

/// What to do with a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
   /// Forward to the real backend.
   Proxy,
   /// Trap it. The payload records why.
   Tarpit(TrapReason),
}

/// Matches requests against path traps and abusive user-agent traps, honouring
/// an IP whitelist.
pub struct Classifier {
   traps:     RegexSet,
   ua_traps:  RegexSet,
   whitelist: Vec<IpNetwork>,
   /// Known crawlers and the networks they legitimately crawl from. A UA that
   /// matches but whose IP is outside the networks is a forgery.
   verified:  Vec<VerifiedCrawler>,
}

/// A recognised crawler: a matcher on the `User-Agent` and the networks it
/// is allowed to originate from.
struct VerifiedCrawler {
   ua:       Regex,
   networks: Vec<IpNetwork>,
}

impl Classifier {
   /// Compile the path and user-agent pattern sets and parse the whitelist
   /// CIDR networks.
   pub fn new(patterns: &[String], ua_patterns: &[String], whitelist: &[String]) -> Result<Self> {
      let traps = RegexSet::new(patterns).map_err(|e| Error::Pattern(e.to_string()))?;
      let ua_traps = RegexSet::new(ua_patterns).map_err(|e| Error::Pattern(e.to_string()))?;
      let whitelist = whitelist
         .iter()
         .map(|s| {
            s.parse::<IpNetwork>()
               .map_err(|e| Error::Network(e.to_string()))
         })
         .collect::<Result<_>>()?;
      Ok(Self {
         traps,
         ua_traps,
         whitelist,
         verified: Vec::new(),
      })
   }

   /// Attach the crawler policy: verified-crawler definitions (each a label, a
   /// `User-Agent` regex, and the CIDRs it may crawl from). Returns `self` so
   /// it chains onto [`Classifier::new`].
   pub fn with_crawler_policy(
      mut self,
      verified_crawlers: &[(String, String, Vec<String>)],
      no_block_networks: &[String],
   ) -> Result<Self> {
      let _ = no_block_networks;
      self.verified = verified_crawlers
         .iter()
         .map(|(_, ua, cidrs)| {
            Ok(VerifiedCrawler {
               ua:       Regex::new(ua).map_err(|e| Error::Pattern(e.to_string()))?,
               networks: cidrs
                  .iter()
                  .map(|s| {
                     s.parse::<IpNetwork>()
                        .map_err(|e| Error::Network(e.to_string()))
                  })
                  .collect::<Result<_>>()?,
            })
         })
         .collect::<Result<_>>()?;
      Ok(self)
   }

   /// Classify a request by path, user agent, and source IP.
   #[must_use]
   pub fn classify(&self, path: &str, user_agent: Option<&str>, ip: IpAddr) -> Verdict {
      if self.is_whitelisted(ip) {
         return Verdict::Proxy;
      }
      // Verify crawlers before applying traps.
      if let Some(ua) = user_agent {
         for (i, crawler) in self.verified.iter().enumerate() {
            if crawler.ua.is_match(ua) {
               return if crawler.networks.iter().any(|net| net.contains(ip)) {
                  Verdict::Proxy
               } else {
                  Verdict::Tarpit(TrapReason::Impersonator(i))
               };
            }
         }
      }
      let decoded = decode_path(path);
      // Resolve the matched category only after a trap fires.
      if self.traps.is_match(&decoded) {
         let idx = self.traps.matches(&decoded).iter().next().unwrap_or(0);
         return Verdict::Tarpit(TrapReason::Path(idx));
      }
      if let Some(ua) = user_agent
         && self.ua_traps.is_match(ua)
      {
         let idx = self.ua_traps.matches(ua).iter().next().unwrap_or(0);
         return Verdict::Tarpit(TrapReason::UserAgent(idx));
      }
      Verdict::Proxy
   }

   /// Whether `ip` belongs to a network excluded from tarpitting.
   #[must_use]
   pub fn is_whitelisted(&self, ip: IpAddr) -> bool {
      self.whitelist.iter().any(|net| net.contains(ip))
   }
}

#[cfg(test)]
mod tests {
   use std::net::Ipv4Addr;

   use super::*;

   fn classifier() -> Classifier {
      Classifier::new(
         &["/wp-admin".into(), r"/\.env".into()],
         &[r"(?i)ClaudeBot".into(), r"Firefox/47\.0".into()],
         &["127.0.0.0/8".into(), "10.0.0.0/8".into()],
      )
      .unwrap()
   }

   #[test]
   fn traps_matching_paths() {
      let c = classifier();
      let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
      assert!(matches!(
         c.classify("/wp-admin/index.php", None, ip),
         Verdict::Tarpit(TrapReason::Path(0))
      ));
      assert!(matches!(
         c.classify("/.env", None, ip),
         Verdict::Tarpit(TrapReason::Path(1))
      ));
      assert_eq!(c.classify("/index.html", None, ip), Verdict::Proxy);
   }

   #[test]
   fn traps_abusive_user_agents() {
      let c = classifier();
      let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
      // A legit-looking path with an AI-scraper UA is still trapped.
      assert!(matches!(
         c.classify("/notashelf/beer", Some("ClaudeBot/1.0"), ip),
         Verdict::Tarpit(TrapReason::UserAgent(0))
      ));
      // A forged, impossibly old browser UA.
      assert!(matches!(
         c.classify("/", Some("Mozilla/5.0 ... Firefox/47.0"), ip),
         Verdict::Tarpit(TrapReason::UserAgent(1))
      ));
      // A real browser on a normal path passes.
      assert_eq!(
         c.classify("/", Some("Mozilla/5.0 Firefox/140.0"), ip),
         Verdict::Proxy
      );
   }

   #[test]
   fn path_trap_beats_ua_trap() {
      let c = classifier();
      let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
      // Both signatures fire, and the path probe wins so it is reported as
      // such.
      assert!(matches!(
         c.classify("/.env", Some("ClaudeBot/1.0"), ip),
         Verdict::Tarpit(TrapReason::Path(_))
      ));
   }

   fn crawler_classifier() -> Classifier {
      classifier()
         .with_crawler_policy(
            &[("Googlebot".into(), r"(?i)Googlebot".into(), vec![
               "66.249.64.0/19".into(),
            ])],
            &["104.16.0.0/13".into()],
         )
         .unwrap()
   }

   #[test]
   fn verified_crawler_from_valid_range_is_never_trapped() {
      let c = crawler_classifier();
      let google = IpAddr::V4(Ipv4Addr::new(66, 249, 66, 1));
      // Real Googlebot is proxied even on a path that would otherwise trap,
      // so search indexing is never caught in the tarpit.
      assert_eq!(
         c.classify("/.env", Some("Googlebot/2.1"), google),
         Verdict::Proxy
      );
      let impostor = IpAddr::V4(Ipv4Addr::new(45, 33, 1, 1));
      assert!(matches!(
         c.classify("/", Some("Googlebot/2.1"), impostor),
         Verdict::Tarpit(TrapReason::Impersonator(0))
      ));
   }

   #[test]
   fn percent_encoded_probes_do_not_evade() {
      let c = classifier();
      let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
      // `%2e` == `.`, `%2f` == `/`: the encoded forms must trap the same as
      // their decoded equivalents.
      assert!(matches!(
         c.classify("/%2eenv", None, ip),
         Verdict::Tarpit(_)
      ));
      assert!(matches!(
         c.classify("/$(pwd)/%2eenv%2eproduction", None, ip),
         Verdict::Tarpit(_)
      ));
   }

   #[test]
   fn whitelist_is_never_trapped() {
      let c = classifier();
      let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
      assert!(c.is_whitelisted(ip));
      assert_eq!(c.classify("/wp-admin", None, ip), Verdict::Proxy);
      // Not even an abusive agent trips a whitelisted source.
      assert_eq!(c.classify("/", Some("ClaudeBot/1.0"), ip), Verdict::Proxy);
   }

   /// The built-in defaults must compile and catch the real scanner traffic.
   #[test]
   fn default_patterns_trap_common_scans() {
      let cfg = bagel_config::Config::default();
      let c = Classifier::new(
         &cfg.trap_patterns,
         &cfg.trap_user_agents,
         &cfg.whitelist_networks,
      )
      .unwrap();
      let ip = IpAddr::V4(Ipv4Addr::new(34, 34, 103, 0));

      let trapped = [
         "/.env.production",
         "/.env.bak",
         "/.env~",
         "/.svn/entries",
         "/.svn/wc.db",
         "/config.yaml",
         "/config.json",
         "/config.js",
         "/.git/HEAD",
         "/settings.json",
         "/secrets.yml",
         "/application-dev.yml",
         "/application.properties",
         "/web.config",
         "/wp-config.php.save",
         "/wp-config.php~",
         "/wp-config.txt",
         "/appsettings.Production.json",
         "/credentials.json",
         "/.aws/credentials",
         "/docker-compose.yml",
         "/.yarnrc",
         "/actuator/env",
         "/../../etc/passwd",
         "/containers/json",
         "/.ssh/id_rsa",
         "/terraform.tfstate",
         "/.vscode/sftp.json",
         // Percent-encoded probes must decode and trap just the same.
         "/%2egit/config",
         "/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
      ];
      for path in trapped {
         assert!(
            matches!(c.classify(path, None, ip), Verdict::Tarpit(_)),
            "expected {path} to be tarpitted"
         );
      }

      // Ordinary requests still pass through.
      for path in ["/", "/index.html", "/assets/app.js", "/api/v1/users"] {
         assert_eq!(
            c.classify(path, None, ip),
            Verdict::Proxy,
            "{path} wrongly trapped"
         );
      }
   }
}
