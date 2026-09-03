//! Request classification: decide whether a request is proxied to the backend
//! or dropped into the tarpit.

use eris_core::{Error, Result};
use ipnetwork::IpNetwork;
use regex::{Regex, RegexSet};
use std::borrow::Cow;
use std::net::IpAddr;

/// Percent-decode a request path for matching only.
///
/// Scanners routinely encode probes to slip past naive path matching:
/// `/%2egit/config` is `/.git/config`, `/%2eenv` is `/.env`. Matching the raw
/// path would let those through to the backend. We decode a private copy used
/// solely for classification and categorisation; the request replayed to the
/// backend is always the untouched original.
///
/// Only `%XX` escapes are resolved (one pass, so `%252e` stays `%2e` rather
/// than collapsing to `.`; single-encoding is what appears in the wild). When
/// the path has no `%`, the borrow is returned without allocating, so the
/// common legitimate request pays only a scan for `%`.
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
    /// Trap it; the payload records why.
    Tarpit(TrapReason),
}

/// Matches requests against path traps, abusive user-agent traps, and an
/// expensive-endpoint set (for rate weighting), honouring an IP whitelist.
pub struct Classifier {
    traps: RegexSet,
    labels: Vec<String>,
    ua_traps: RegexSet,
    ua_labels: Vec<String>,
    /// Endpoints whose crawl is disproportionately expensive (git history:
    /// blob/blame/archive/upload-pack). Requests here are weighted heavily by
    /// the rate limiter so enumeration trips it long before casual browsing.
    git_history: RegexSet,
    git_scan_weight: u32,
    /// The subset of git endpoints that are ruinous for a backend to serve:
    /// archive/tarball generation and full clone/fetch packs. These carry a
    /// heavier weight still, because a handful of them can OOM a git forge.
    git_expensive: RegexSet,
    git_expensive_weight: u32,
    whitelist: Vec<IpNetwork>,
    /// Known crawlers and the networks they legitimately crawl from. A UA that
    /// matches but whose IP is outside the networks is a forgery.
    verified: Vec<VerifiedCrawler>,
    /// Networks that may be tarpitted but never firewall-blocked, so a shared
    /// address (Cloudflare, CGNAT) cannot take genuine users offline.
    no_block: Vec<IpNetwork>,
}

/// A recognised crawler: its label, a matcher on the `User-Agent`, and the
/// networks it is allowed to originate from.
struct VerifiedCrawler {
    label: String,
    ua: Regex,
    networks: Vec<IpNetwork>,
}

impl Classifier {
    /// Compile the path, user-agent, and git-history pattern sets and parse the
    /// whitelist CIDR networks.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        patterns: &[String],
        ua_patterns: &[String],
        whitelist: &[String],
        git_history_patterns: &[String],
        git_scan_weight: u32,
        git_expensive_patterns: &[String],
        git_expensive_weight: u32,
    ) -> Result<Self> {
        let traps = RegexSet::new(patterns).map_err(|e| Error::Pattern(e.to_string()))?;
        let ua_traps = RegexSet::new(ua_patterns).map_err(|e| Error::Pattern(e.to_string()))?;
        let git_history =
            RegexSet::new(git_history_patterns).map_err(|e| Error::Pattern(e.to_string()))?;
        let git_expensive =
            RegexSet::new(git_expensive_patterns).map_err(|e| Error::Pattern(e.to_string()))?;
        let whitelist = whitelist
            .iter()
            .map(|s| {
                s.parse::<IpNetwork>()
                    .map_err(|e| Error::Network(e.to_string()))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            traps,
            labels: patterns.to_vec(),
            ua_traps,
            ua_labels: ua_patterns.to_vec(),
            git_history,
            git_scan_weight: git_scan_weight.max(1),
            git_expensive,
            git_expensive_weight: git_expensive_weight.max(1),
            whitelist,
            verified: Vec::new(),
            no_block: Vec::new(),
        })
    }

    /// Attach the crawler policy: verified-crawler definitions (each a label, a
    /// `User-Agent` regex, and the CIDRs it may crawl from) and the networks
    /// that must never be firewall-blocked. Returns `self` so it chains onto
    /// [`Classifier::new`].
    pub fn with_crawler_policy(
        mut self,
        verified_crawlers: &[(String, String, Vec<String>)],
        no_block_networks: &[String],
    ) -> Result<Self> {
        self.verified = verified_crawlers
            .iter()
            .map(|(label, ua, cidrs)| {
                Ok(VerifiedCrawler {
                    label: label.clone(),
                    ua: Regex::new(ua).map_err(|e| Error::Pattern(e.to_string()))?,
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
        self.no_block = no_block_networks
            .iter()
            .map(|s| {
                s.parse::<IpNetwork>()
                    .map_err(|e| Error::Network(e.to_string()))
            })
            .collect::<Result<_>>()?;
        Ok(self)
    }

    /// Classify a request by path, user agent, and source IP.
    ///
    /// A path trap takes precedence over a user-agent trap: a scanner hitting
    /// `/.env` is reported for the probe regardless of the agent it forged. The
    /// path is percent-decoded before matching so an encoded probe cannot evade
    /// the trap set; see [`decode_path`]. The user agent is matched as-is.
    ///
    /// A [`Verdict::Proxy`] here does not mean the request is innocent, only
    /// that no signature fired; the caller still applies the rate limiter.
    #[must_use]
    pub fn classify(&self, path: &str, user_agent: Option<&str>, ip: IpAddr) -> Verdict {
        if self.is_whitelisted(ip) {
            return Verdict::Proxy;
        }
        // Verified crawlers are settled before any trap fires. A UA claiming to
        // be a known crawler from one of its published networks is proxied
        // untouched (protecting search indexing); the same claim from anywhere
        // else is a forgery and is trapped. This runs first so a legitimate
        // crawler is never caught by a path or rate signal.
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
        // `is_match` short-circuits with no allocation, so the common (legit)
        // path stays cheap. Only resolve the matched index, which allocates a
        // match set, once a trap has actually fired.
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

    /// Whether this (already percent-decoded) path is an expensive git-history
    /// endpoint that the rate limiter should weight heavily.
    #[must_use]
    pub fn is_git_history(&self, path: &str) -> bool {
        self.git_history.is_match(path)
    }

    /// The rate-limiter cost of a request path: ruinous git operations
    /// (archive/clone packs) cost the most, ordinary git-history browsing costs
    /// a heavy multiple, and everything else costs one. Checked most-expensive
    /// first so an archive request is never undercounted as a plain browse.
    #[must_use]
    pub fn request_cost(&self, path: &str) -> u32 {
        if self.git_expensive.is_match(path) {
            self.git_expensive_weight
        } else if self.is_git_history(path) {
            self.git_scan_weight
        } else {
            1
        }
    }

    /// Whether `ip` belongs to a network excluded from tarpitting.
    #[must_use]
    pub fn is_whitelisted(&self, ip: IpAddr) -> bool {
        self.whitelist.iter().any(|net| net.contains(ip))
    }

    /// Whether `ip` is in a tarpit-only network that must never be
    /// firewall-blocked (shared infrastructure like Cloudflare or CGNAT).
    #[must_use]
    pub fn is_no_block(&self, ip: IpAddr) -> bool {
        self.no_block.iter().any(|net| net.contains(ip))
    }

    /// Whether this is a legitimate verified crawler: its UA matches a known
    /// crawler and its IP falls in that crawler's published networks. Used to
    /// exempt real crawlers from the rate limiter as well as the traps.
    #[must_use]
    pub fn is_verified_crawler(&self, user_agent: Option<&str>, ip: IpAddr) -> bool {
        user_agent.is_some_and(|ua| {
            self.verified
                .iter()
                .any(|c| c.ua.is_match(ua) && c.networks.iter().any(|net| net.contains(ip)))
        })
    }

    /// Label of the crawler an impersonator was forging, for metrics.
    #[must_use]
    pub fn impersonator_label(&self, idx: usize) -> &str {
        self.verified
            .get(idx)
            .map_or("unknown", |c| c.label.as_str())
    }

    /// Human-readable label for a matched path pattern, for metrics.
    #[must_use]
    pub fn label(&self, idx: usize) -> &str {
        self.labels.get(idx).map_or("unknown", String::as_str)
    }

    /// Human-readable label for a matched user-agent pattern, for metrics.
    #[must_use]
    pub fn ua_label(&self, idx: usize) -> &str {
        self.ua_labels.get(idx).map_or("unknown", String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn classifier() -> Classifier {
        Classifier::new(
            &["/wp-admin".into(), r"/\.env".into()],
            &[r"(?i)ClaudeBot".into(), r"Firefox/47\.0".into()],
            &["127.0.0.0/8".into(), "10.0.0.0/8".into()],
            &[r"(?i)/(?:blob|blame|raw|archive)(?:/|$)".into()],
            10,
            &[r"(?i)/archive/".into(), r"(?i)git-upload-pack".into()],
            40,
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
        // Both signatures fire; the path probe wins so it is reported as such.
        assert!(matches!(
            c.classify("/.env", Some("ClaudeBot/1.0"), ip),
            Verdict::Tarpit(TrapReason::Path(_))
        ));
    }

    #[test]
    fn default_ua_patterns_trap_scrapers_and_forged_browsers() {
        let cfg = eris_config::Config::default();
        let c = Classifier::new(
            &cfg.trap_patterns,
            &cfg.trap_user_agents,
            &cfg.whitelist_networks,
            &cfg.git_history_patterns,
            cfg.git_scan_weight,
            &cfg.git_expensive_patterns,
            cfg.git_expensive_weight,
        )
        .unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(34, 34, 103, 0));

        // AI scrapers and forged, impossibly old Firefox builds are trapped.
        for ua in [
            "Mozilla/5.0 AppleWebKit/537.36 (compatible; ClaudeBot/1.0)",
            "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
            "Bytespider",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
            "Mozilla/5.0 ... Firefox/89.0",
        ] {
            assert!(
                matches!(c.classify("/", Some(ua), ip), Verdict::Tarpit(_)),
                "expected UA to be trapped: {ua}"
            );
        }

        // Current browsers and real search-engine/git clients pass untouched.
        for ua in [
            "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
            "Mozilla/5.0 ... Firefox/90.0",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "git/2.52.0",
        ] {
            assert_eq!(
                c.classify("/", Some(ua), ip),
                Verdict::Proxy,
                "UA wrongly trapped: {ua}"
            );
        }
    }

    #[test]
    fn git_history_is_weighted() {
        let c = classifier();
        assert!(c.is_git_history("/notashelf/beer/blob/main/Cargo.lock"));
        assert!(c.is_git_history("/notashelf/beer/blame/main/README.md"));
        // Ordinary browse costs the git-history weight.
        assert_eq!(c.request_cost("/notashelf/beer/blob/main/Cargo.lock"), 10);
        assert!(!c.is_git_history("/notashelf/beer"));
        assert_eq!(c.request_cost("/notashelf/beer"), 1);
        // Ruinous operations cost the expensive weight, checked first so an
        // archive is never undercounted as a plain browse.
        assert_eq!(c.request_cost("/notashelf/beer/archive/main.tar.gz"), 40);
        assert_eq!(c.request_cost("/notashelf/beer.git/git-upload-pack"), 40);
    }

    fn crawler_classifier() -> Classifier {
        classifier()
            .with_crawler_policy(
                &[(
                    "Googlebot".into(),
                    r"(?i)Googlebot".into(),
                    vec!["66.249.64.0/19".into()],
                )],
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
        // And it is recognised as verified, so the caller also skips the rate
        // limiter for it.
        assert!(c.is_verified_crawler(Some("Googlebot/2.1"), google));
        let impostor = IpAddr::V4(Ipv4Addr::new(45, 33, 1, 1));
        assert!(!c.is_verified_crawler(Some("Googlebot/2.1"), impostor));
    }

    #[test]
    fn forged_crawler_from_wrong_range_is_trapped() {
        let c = crawler_classifier();
        let impostor = IpAddr::V4(Ipv4Addr::new(45, 33, 1, 1));
        // A "Googlebot" from outside Google's range is an impersonator.
        assert!(matches!(
            c.classify("/", Some("Googlebot/2.1"), impostor),
            Verdict::Tarpit(TrapReason::Impersonator(0))
        ));
        assert_eq!(c.impersonator_label(0), "Googlebot");
    }

    #[test]
    fn no_block_networks_are_recognised() {
        let c = crawler_classifier();
        assert!(c.is_no_block(IpAddr::V4(Ipv4Addr::new(104, 16, 5, 5))));
        assert!(!c.is_no_block(IpAddr::V4(Ipv4Addr::new(45, 33, 1, 1))));
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
    fn decode_path_leaves_plain_paths_borrowed() {
        assert!(matches!(
            decode_path("/wp-admin"),
            std::borrow::Cow::Borrowed(_)
        ));
        assert_eq!(decode_path("/%2egit/config"), "/.git/config");
        // A lone or malformed `%` is passed through untouched.
        assert_eq!(decode_path("/100%25.php"), "/100%.php");
        assert_eq!(decode_path("/trailing%"), "/trailing%");
    }

    #[test]
    fn whitelist_is_never_trapped() {
        let c = classifier();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(c.is_whitelisted(ip));
        assert_eq!(c.classify("/wp-admin", None, ip), Verdict::Proxy);
        // Not even an abusive agent trips a whitelisted source.
        assert_eq!(c.classify("/", Some("ClaudeBot/1.0"), ip), Verdict::Proxy);
    }

    #[test]
    fn invalid_pattern_is_an_error() {
        assert!(Classifier::new(&["(".into()], &[], &[], &[], 1, &[], 1).is_err());
        assert!(Classifier::new(&[], &["(".into()], &[], &[], 1, &[], 1).is_err());
        assert!(Classifier::new(&[], &[], &[], &["(".into()], 1, &[], 1).is_err());
        assert!(Classifier::new(&[], &[], &[], &[], 1, &["(".into()], 1).is_err());
    }

    /// The built-in defaults must compile and catch the real scanner traffic.
    #[test]
    fn default_patterns_trap_common_scans() {
        let cfg = eris_config::Config::default();
        let c = Classifier::new(
            &cfg.trap_patterns,
            &cfg.trap_user_agents,
            &cfg.whitelist_networks,
            &cfg.git_history_patterns,
            cfg.git_scan_weight,
            &cfg.git_expensive_patterns,
            cfg.git_expensive_weight,
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
