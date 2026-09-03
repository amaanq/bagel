//! Configuration: layered defaults, then an optional JSON file, then CLI/env
//! overrides. `Config` is the single source of truth consumed by the rest of
//! the program.

use clap::Parser;
use directories::ProjectDirs;
use eris_core::{Error, Result};
use ipnetwork::IpNetwork;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// One independently-admitted tarpit endpoint.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum Listener {
    /// The existing classified reverse-proxy endpoint.
    Http {
        name: String,
        listen_addr: String,
        #[serde(default)]
        policy: Option<String>,
        #[serde(default)]
        backend_addr: Option<String>,
        #[serde(default)]
        max_tarpit_conns: Option<usize>,
    },
    /// An SSH-shaped endpoint that only slowly emits banner-like junk.
    Ssh {
        name: String,
        listen_addr: String,
        #[serde(default)]
        policy: Option<String>,
        #[serde(default)]
        max_tarpit_conns: Option<usize>,
        #[serde(default)]
        min_delay_ms: Option<u64>,
        #[serde(default)]
        max_delay_ms: Option<u64>,
        #[serde(default)]
        max_tarpit_secs: Option<u64>,
        #[serde(default)]
        line_length: Option<usize>,
    },
}

impl Listener {
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Http { name, .. } | Self::Ssh { name, .. } => name,
        }
    }

    #[must_use]
    pub fn listen_addr(&self) -> &str {
        match self {
            Self::Http { listen_addr, .. } | Self::Ssh { listen_addr, .. } => listen_addr,
        }
    }

    #[must_use]
    pub fn policy(&self) -> Option<&str> {
        match self {
            Self::Http { policy, .. } | Self::Ssh { policy, .. } => policy.as_deref(),
        }
    }

    #[must_use]
    pub const fn protocol(&self) -> &'static str {
        match self {
            Self::Http { .. } => "http",
            Self::Ssh { .. } => "ssh",
        }
    }

    #[must_use]
    pub fn max_tarpit_conns(&self, default: usize) -> usize {
        match self {
            Self::Http {
                max_tarpit_conns, ..
            }
            | Self::Ssh {
                max_tarpit_conns, ..
            } => max_tarpit_conns.unwrap_or(default),
        }
    }
}

/// Position used when a durable source checkpoint does not exist yet.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StartPosition {
    Beginning,
    #[default]
    End,
}

/// A durable stream of records presented to one or more policies.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Source {
    Journal {
        #[serde(default)]
        match_groups: Vec<BTreeMap<String, String>>,
        #[serde(default)]
        start: StartPosition,
        #[serde(default = "default_max_entry_bytes")]
        max_entry_bytes: usize,
    },
    File {
        path: PathBuf,
        #[serde(default)]
        start: StartPosition,
        #[serde(default = "default_poll_interval_ms")]
        poll_interval_ms: u64,
        #[serde(default = "default_max_line_bytes")]
        max_line_bytes: usize,
    },
    AddressSet {
        path: PathBuf,
    },
    Listener {
        listener: String,
    },
}

/// Extracts a literal client address and, optionally, the event timestamp.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Detector {
    Regex {
        #[serde(default)]
        prefilter: Option<String>,
        /// Patterns may capture `attempt_key` to count distinct evidence
        /// inside the policy's rolling window.
        patterns: Vec<String>,
        #[serde(default)]
        context_patterns: Vec<String>,
        #[serde(default)]
        max_context_lines: usize,
        #[serde(default = "default_context_window_secs")]
        context_window_secs: u64,
        #[serde(default)]
        ignore_patterns: Vec<String>,
        #[serde(default = "default_address_capture")]
        address_capture: String,
        #[serde(default)]
        timestamp_capture: Option<String>,
        #[serde(default)]
        timestamp_format: Option<String>,
    },
    Json {
        #[serde(default)]
        equals: BTreeMap<String, String>,
        address_pointer: String,
        #[serde(default)]
        timestamp_pointer: Option<String>,
        #[serde(default)]
        timestamp_format: Option<String>,
    },
}

const fn default_context_window_secs() -> u64 {
    120
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

/// Network effect produced by a policy ban.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    Observe,
    Drop {
        protocol: TransportProtocol,
        ports: Vec<u16>,
    },
    DropProtocol {
        protocol: TransportProtocol,
    },
    DropAll,
    Reject {
        protocol: TransportProtocol,
        ports: Vec<u16>,
    },
    RejectProtocol {
        protocol: TransportProtocol,
    },
    RejectAll,
    TarpitRedirect {
        protocol: TransportProtocol,
        ports: Vec<u16>,
        listener: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct BanSchedule {
    /// `None` creates a permanent ban.
    pub duration_secs: Option<u64>,
    pub factor: u64,
    pub multipliers: Vec<u64>,
    pub jitter_secs: u64,
    pub max_duration_secs: u64,
    pub overall: bool,
}

impl Default for BanSchedule {
    fn default() -> Self {
        Self {
            duration_secs: Some(600),
            factor: 4,
            multipliers: vec![4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048],
            jitter_secs: 720,
            max_duration_secs: 18_000_000,
            overall: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Policy {
    pub source: String,
    pub detector: Detector,
    #[serde(default)]
    pub ignore_networks: Vec<String>,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_findtime_secs")]
    pub findtime_secs: u64,
    #[serde(default)]
    pub ban: BanSchedule,
    pub action: Action,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    #[default]
    Required,
    Observe,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Enforcement {
    pub mode: EnforcementMode,
    pub table: String,
    pub chain_priority: i32,
    pub reconcile_interval_secs: u64,
}

impl Default for Enforcement {
    fn default() -> Self {
        Self {
            mode: EnforcementMode::Required,
            table: "eris".into(),
            chain_priority: -10,
            reconcile_interval_secs: 15,
        }
    }
}

const fn default_max_entry_bytes() -> usize {
    1_048_576
}

const fn default_poll_interval_ms() -> u64 {
    250
}

const fn default_max_line_bytes() -> usize {
    1_048_576
}

fn default_address_capture() -> String {
    "address".into()
}

const fn default_max_attempts() -> u32 {
    7
}

const fn default_findtime_secs() -> u64 {
    600
}

/// A recognised search crawler: a `User-Agent` regex and the CIDR networks it
/// is allowed to crawl from. A match from inside the networks is proxied; a
/// match from outside is an impersonator and is trapped.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct VerifiedCrawler {
    /// Human-readable name, used only for reporting/metrics.
    pub name: String,
    /// Regex matched against the request `User-Agent`.
    pub ua_pattern: String,
    /// CIDR networks the crawler legitimately originates from.
    pub networks: Vec<String>,
}

/// Parse command-line arguments (and environment overrides).
#[must_use]
pub fn parse() -> Args {
    Args::parse()
}

/// Command-line arguments. Overridable values are `Option`; when unset they
/// fall back to the config file, then to `Config::default`.
#[derive(Parser, Debug)]
#[command(
    name = "eris-daemon",
    author,
    version,
    about = "The Eris tarpit daemon"
)]
pub struct Args {
    /// Path to a JSON configuration file.
    #[arg(long, env = "ERIS_CONFIG")]
    pub config_file: Option<PathBuf>,

    /// Validate the resolved configuration and exit without starting services.
    #[arg(long)]
    pub check_config: bool,

    /// Address to listen on for incoming HTTP traffic (ip:port).
    #[arg(long, env = "ERIS_LISTEN_ADDR")]
    pub listen_addr: Option<String>,

    /// Address to expose Prometheus metrics and status on (ip:port).
    #[arg(long, env = "ERIS_METRICS_ADDR")]
    pub metrics_addr: Option<String>,

    /// Disable the metrics/status server.
    #[arg(long)]
    pub disable_metrics: bool,

    /// Path of the admin control socket.
    #[arg(long, env = "ERIS_ADMIN_SOCKET")]
    pub admin_socket: Option<PathBuf>,

    /// Disable the admin control socket.
    #[arg(long)]
    pub disable_admin: bool,

    /// Backend to proxy legitimate requests to (ip:port).
    #[arg(long, env = "ERIS_BACKEND_ADDR")]
    pub backend_addr: Option<String>,

    /// Minimum delay between tarpit chunks, in milliseconds.
    #[arg(long)]
    pub min_delay_ms: Option<u64>,

    /// Maximum delay between tarpit chunks, in milliseconds.
    #[arg(long)]
    pub max_delay_ms: Option<u64>,

    /// Maximum time to hold a tarpit connection, in seconds.
    #[arg(long)]
    pub max_tarpit_secs: Option<u64>,

    /// Block an IP after this many tarpit hits.
    #[arg(long)]
    pub block_threshold: Option<u32>,

    /// Maximum number of concurrent tarpit connections.
    #[arg(long)]
    pub max_tarpit_conns: Option<usize>,

    /// Maximum number of concurrent connections of any kind.
    #[arg(long)]
    pub max_connections: Option<usize>,

    /// Expect a PROXY protocol header from trusted proxies.
    #[arg(long)]
    pub proxy_protocol: bool,

    /// Trusted proxy CIDR. Repeatable; replaces the configured list if given.
    #[arg(long = "trusted-proxy")]
    pub trusted_proxy: Vec<String>,

    /// Do not touch nftables; keep blocking in memory only.
    #[arg(long)]
    pub disable_firewall: bool,

    /// Base directory for data and cache (overrides XDG locations).
    #[arg(long)]
    pub base_dir: Option<PathBuf>,

    /// Log level: trace, debug, info, warn, error.
    #[arg(long, default_value = "info", env = "ERIS_LOG")]
    pub log_level: String,
}

/// Resolved runtime configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub listen_addr: String,
    pub metrics_addr: String,
    pub disable_metrics: bool,
    /// Path of the admin control socket.
    pub admin_socket: PathBuf,
    /// Disable the admin control socket entirely.
    pub disable_admin: bool,
    pub backend_addr: String,

    /// Independently configured HTTP and SSH endpoints.
    pub listeners: Vec<Listener>,

    /// Named durable record streams consumed by defense policies.
    pub sources: BTreeMap<String, Source>,
    /// Named detection, escalation, and enforcement policies.
    pub policies: BTreeMap<String, Policy>,
    pub enforcement: Enforcement,
    pub database_path: PathBuf,
    /// Retention window for expired automatic-ban escalation history.
    pub history_retention_secs: u64,
    pub journalctl_path: PathBuf,
    pub nft_path: PathBuf,
    /// Networks which no automatic or manual action may block.
    pub protected_networks: Vec<String>,

    pub min_delay_ms: u64,
    pub max_delay_ms: u64,
    pub max_tarpit_secs: u64,
    /// Smallest tarpit body chunk, in bytes. Segment-sized chunks read like a
    /// slow real transfer; single bytes betray a tarpit.
    pub tarpit_chunk_min_bytes: usize,
    /// Largest tarpit body chunk, in bytes.
    pub tarpit_chunk_max_bytes: usize,
    /// `Server` header presented on every deceptive response.
    pub deception_server: String,
    /// Percent of probed paths answered with a `404` error page instead of a
    /// bait, so the tarpit looks like a hardened server rather than one that
    /// answers everything `200`. Keyed on the path, so a URL is answered
    /// consistently. A higher share plants fewer honeytokens.
    pub deception_not_found_pct: u8,
    /// Percent of probed paths answered with a `403` error page. Together with
    /// `deception_not_found_pct` this must not exceed 100.
    pub deception_forbidden_pct: u8,
    pub block_threshold: u32,
    pub max_tarpit_conns: usize,
    /// Maximum concurrent tarpits from one source IP across all endpoints.
    pub max_tarpit_conns_per_ip: usize,
    /// Bound each socket write, so non-reading peers cannot pin a tarpit slot.
    pub tarpit_write_timeout_secs: u64,

    /// Cap on concurrent connections of any kind. Bounds total resource use.
    pub max_connections: usize,
    /// Total budget for reading a request head, in seconds (anti-slowloris).
    pub header_timeout_secs: u64,
    /// Timeout for connecting to the backend, in seconds.
    pub backend_connect_timeout_secs: u64,
    /// Idle timeout for a proxied connection, in seconds.
    pub proxy_idle_timeout_secs: u64,
    /// How long connection draining is allowed to take on shutdown, in seconds.
    pub drain_timeout_secs: u64,

    /// Expect a PROXY protocol header from trusted proxies.
    pub proxy_protocol: bool,
    /// Header used to read the real client IP from trusted proxies.
    pub real_ip_header: String,
    /// Networks whose forwarding information Eris trusts.
    pub trusted_proxies: Vec<String>,

    pub enable_firewall: bool,
    /// Trap patterns, matched against the request path as regexes.
    pub trap_patterns: Vec<String>,
    /// User-agent trap patterns (regexes). A request whose `User-Agent` matches
    /// is tarpitted regardless of path: AI-training scrapers and forged agents
    /// that hammer legitimate URLs. Search engines are deliberately absent so
    /// they may still crawl; the rate limiter reins them in if they enumerate.
    pub trap_user_agents: Vec<String>,
    /// CIDR networks that are never tarpitted.
    pub whitelist_networks: Vec<String>,

    /// Enable the per-IP request-rate limiter (volume floods and git-history
    /// enumeration). Signature-based path/UA traps run regardless.
    pub enable_rate_limit: bool,
    /// Length of the rate-limit accounting window, in seconds.
    pub rate_limit_window_secs: u64,
    /// Request-cost budget per window before a source is tarpitted. Ordinary
    /// requests cost one; git-history requests cost `git_scan_weight`.
    pub rate_limit_max_requests: u32,
    /// Cost multiplier for an expensive git-history request, so a handful of
    /// casual history views stay under budget but enumeration trips it fast.
    pub git_scan_weight: u32,
    /// Regexes marking expensive git-history endpoints (blob/blame/archive/…)
    /// that the rate limiter weights by `git_scan_weight`.
    pub git_history_patterns: Vec<String>,
    /// Cost multiplier for a ruinous git operation (archive/tarball generation
    /// and full clone/fetch packs). A handful of these can OOM a git forge, so
    /// they weigh more than a plain browse and trip the rate limiter sooner.
    pub git_expensive_weight: u32,
    /// Regexes marking the ruinous git operations weighted by
    /// `git_expensive_weight`. A subset of `git_history_patterns`; matched
    /// first, so an archive is never undercounted as an ordinary browse.
    pub git_expensive_patterns: Vec<String>,

    /// Known search crawlers and the networks they legitimately originate from.
    /// A request whose UA matches one of these is proxied untouched when its IP
    /// is in the crawler's ranges (so search indexing is never tarpitted) and
    /// trapped as an impersonator when it is not (a scanner forging a crawler
    /// UA to dodge blocks).
    pub verified_crawlers: Vec<VerifiedCrawler>,
    /// Networks that may be tarpitted but are never added to the firewall
    /// blocklist. Shared infrastructure (Cloudflare, CGNAT) lives here so one
    /// abuser behind a shared address cannot take genuine users offline.
    pub no_block_networks: Vec<String>,

    /// Evict sub-threshold hit records unseen for this many seconds.
    pub hit_ttl_secs: u64,
    /// Hard cap on tracked IPs and rate-limiter windows. When rate-limiter
    /// capacity is exhausted, new sources are tarpitted rather than allocated.
    pub max_tracked_ips: usize,

    pub corpora_dir: PathBuf,
    pub scripts_dir: PathBuf,
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        let (data_dir, cache_dir) = default_dirs();
        Self {
            listen_addr: "0.0.0.0:8888".into(),
            // Localhost by default: metrics and status leak operational detail
            // and must be exposed deliberately, not by accident.
            metrics_addr: "127.0.0.1:9100".into(),
            disable_metrics: false,
            admin_socket: PathBuf::from(eris_core::DEFAULT_ADMIN_SOCKET),
            disable_admin: false,
            backend_addr: "127.0.0.1:80".into(),
            listeners: Vec::new(),
            sources: BTreeMap::new(),
            policies: BTreeMap::new(),
            enforcement: Enforcement::default(),
            database_path: data_dir.join("eris.sqlite3"),
            history_retention_secs: 86_400,
            journalctl_path: PathBuf::from("/usr/bin/journalctl"),
            nft_path: PathBuf::from("/usr/sbin/nft"),
            protected_networks: vec!["127.0.0.0/8".into(), "::1/128".into()],

            min_delay_ms: 1000,
            max_delay_ms: 15000,
            max_tarpit_secs: 600,
            tarpit_chunk_min_bytes: 64,
            tarpit_chunk_max_bytes: 1400,
            deception_server: "nginx/1.24.0".into(),
            // A minority of probes 404/403 for realism; the majority still bait
            // so honeytokens keep being planted.
            deception_not_found_pct: 20,
            deception_forbidden_pct: 8,
            block_threshold: 3,
            max_tarpit_conns: 4096,
            max_tarpit_conns_per_ip: 16,
            tarpit_write_timeout_secs: 15,

            max_connections: 8192,
            header_timeout_secs: 10,
            backend_connect_timeout_secs: 5,
            proxy_idle_timeout_secs: 60,
            drain_timeout_secs: 10,

            proxy_protocol: false,
            real_ip_header: "x-forwarded-for".into(),
            trusted_proxies: Vec::new(),

            enable_firewall: true,
            trap_patterns: default_patterns(),
            trap_user_agents: default_ua_patterns(),
            whitelist_networks: default_whitelist(),

            enable_rate_limit: true,
            rate_limit_window_secs: 60,
            // ~5 cheap requests/second sustained before trapping.
            rate_limit_max_requests: 300,
            // 300 / 10 => ~30 git-history views per minute before trapping.
            git_scan_weight: 10,
            git_history_patterns: default_git_history_patterns(),
            // 300 / 40 => ~7 archive/clone operations per minute before
            // trapping; these are what actually OOM a backend under scraping.
            git_expensive_weight: 40,
            git_expensive_patterns: default_git_expensive_patterns(),
            verified_crawlers: default_verified_crawlers(),
            no_block_networks: default_no_block_networks(),

            hit_ttl_secs: 86_400,
            max_tracked_ips: 1_000_000,

            corpora_dir: data_dir.join("corpora"),
            scripts_dir: data_dir.join("scripts"),
            data_dir,
            cache_dir,
        }
    }
}

impl Config {
    /// Build the effective config from CLI args, layering file over defaults
    /// and CLI/env over both.
    pub fn resolve(args: &Args) -> Result<Self> {
        let mut cfg = match &args.config_file {
            Some(path) => Self::load_file(path)?,
            None => Self::default(),
        };

        if let Some(base) = &args.base_dir {
            cfg.data_dir = base.join("data");
            cfg.cache_dir = base.join("cache");
            cfg.corpora_dir = cfg.data_dir.join("corpora");
            cfg.scripts_dir = cfg.data_dir.join("scripts");
            cfg.database_path = cfg.data_dir.join("eris.sqlite3");
        }

        // Each provided (`Some`) CLI/env value overrides the layered config.
        macro_rules! apply {
            ($($field:ident),+ $(,)?) => {
                $(if let Some(v) = args.$field.clone() { cfg.$field = v; })+
            };
        }
        apply!(
            listen_addr,
            metrics_addr,
            admin_socket,
            backend_addr,
            min_delay_ms,
            max_delay_ms,
            max_tarpit_secs,
            block_threshold,
            max_tarpit_conns,
            max_connections,
        );

        // Flags and lists that do not map one-to-one onto a config field.
        cfg.proxy_protocol |= args.proxy_protocol;
        cfg.disable_metrics |= args.disable_metrics;
        cfg.disable_admin |= args.disable_admin;
        cfg.enable_firewall &= !args.disable_firewall;
        if args.disable_firewall {
            cfg.enforcement.mode = EnforcementMode::Observe;
        }
        if !args.trusted_proxy.is_empty() {
            cfg.trusted_proxies = args.trusted_proxy.clone();
        }

        cfg.validate()?;
        Ok(cfg)
    }

    fn load_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|e| Error::Config(format!("{}: {e}", path.display())))
    }

    fn validate(&self) -> Result<()> {
        if self.min_delay_ms > self.max_delay_ms {
            return Err(Error::Config(
                "min_delay_ms must not exceed max_delay_ms".into(),
            ));
        }
        if self.history_retention_secs == 0 {
            return Err(Error::Config(
                "history_retention_secs must be non-zero".into(),
            ));
        }
        if self.tarpit_chunk_min_bytes == 0 {
            return Err(Error::Config(
                "tarpit_chunk_min_bytes must be non-zero".into(),
            ));
        }
        if self.tarpit_chunk_min_bytes > self.tarpit_chunk_max_bytes {
            return Err(Error::Config(
                "tarpit_chunk_min_bytes must not exceed tarpit_chunk_max_bytes".into(),
            ));
        }
        if u16::from(self.deception_not_found_pct) + u16::from(self.deception_forbidden_pct) > 100 {
            return Err(Error::Config(
                "deception_not_found_pct + deception_forbidden_pct must not exceed 100".into(),
            ));
        }
        for (name, value) in [
            ("max_tarpit_conns", self.max_tarpit_conns),
            ("max_tarpit_conns_per_ip", self.max_tarpit_conns_per_ip),
            ("max_connections", self.max_connections),
            ("max_tracked_ips", self.max_tracked_ips),
        ] {
            if value == 0 {
                return Err(Error::Config(format!("{name} must be non-zero")));
            }
        }
        for (name, value) in [
            ("header_timeout_secs", self.header_timeout_secs),
            (
                "backend_connect_timeout_secs",
                self.backend_connect_timeout_secs,
            ),
            ("proxy_idle_timeout_secs", self.proxy_idle_timeout_secs),
            ("tarpit_write_timeout_secs", self.tarpit_write_timeout_secs),
        ] {
            if value == 0 {
                return Err(Error::Config(format!("{name} must be non-zero")));
            }
        }
        if self.proxy_protocol && self.trusted_proxies.is_empty() {
            return Err(Error::Config(
                "proxy_protocol requires at least one trusted_proxies entry".into(),
            ));
        }
        if self.enable_rate_limit {
            if self.rate_limit_window_secs == 0 {
                return Err(Error::Config(
                    "rate_limit_window_secs must be non-zero when rate limiting is enabled".into(),
                ));
            }
            if self.rate_limit_max_requests == 0 {
                return Err(Error::Config(
                    "rate_limit_max_requests must be non-zero when rate limiting is enabled".into(),
                ));
            }
            if self.git_scan_weight == 0 {
                return Err(Error::Config("git_scan_weight must be non-zero".into()));
            }
            if self.git_expensive_weight == 0 {
                return Err(Error::Config(
                    "git_expensive_weight must be non-zero".into(),
                ));
            }
        }
        let mut names = HashSet::new();
        let mut addrs = HashSet::new();
        let mut endpoint_capacity = 0usize;
        for listener in &self.listeners {
            if listener.name().is_empty() || !names.insert(listener.name()) {
                return Err(Error::Config(
                    "listener names must be non-empty and unique".into(),
                ));
            }
            if !addrs.insert(listener.listen_addr()) {
                return Err(Error::Config("listener addresses must be unique".into()));
            }
            let cap = listener.max_tarpit_conns(self.max_tarpit_conns);
            if cap == 0 || cap > self.max_connections {
                return Err(Error::Config(format!(
                    "listener {} has an invalid max_tarpit_conns",
                    listener.name()
                )));
            }
            endpoint_capacity = endpoint_capacity.saturating_add(cap);
            if let Listener::Ssh {
                min_delay_ms,
                max_delay_ms,
                max_tarpit_secs,
                line_length,
                ..
            } = listener
                && (line_length.is_some_and(|n| n == 0)
                    || max_tarpit_secs.is_some_and(|n| n == 0)
                    || min_delay_ms.unwrap_or(self.min_delay_ms)
                        > max_delay_ms.unwrap_or(self.max_delay_ms))
            {
                return Err(Error::Config(format!(
                    "invalid SSH listener {}",
                    listener.name()
                )));
            }
        }
        if endpoint_capacity > self.max_connections {
            return Err(Error::Config(
                "sum of listener max_tarpit_conns exceeds max_connections".into(),
            ));
        }
        self.validate_defense()?;
        Ok(())
    }

    fn validate_defense(&self) -> Result<()> {
        if self.enforcement.table.is_empty()
            || !self
                .enforcement
                .table
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(Error::Config(
                "enforcement.table must be a non-empty nftables identifier".into(),
            ));
        }
        if self.enforcement.reconcile_interval_secs == 0 {
            return Err(Error::Config(
                "enforcement.reconcile_interval_secs must be non-zero".into(),
            ));
        }
        for (name, path) in [
            ("database_path", &self.database_path),
            ("journalctl_path", &self.journalctl_path),
            ("nft_path", &self.nft_path),
        ] {
            if path.as_os_str().is_empty() {
                return Err(Error::Config(format!("{name} must not be empty")));
            }
        }

        validate_cidrs("protected_networks", &self.protected_networks)?;
        validate_cidrs("trusted_proxies", &self.trusted_proxies)?;
        validate_cidrs("whitelist_networks", &self.whitelist_networks)?;
        validate_cidrs("no_block_networks", &self.no_block_networks)?;
        for crawler in &self.verified_crawlers {
            validate_cidrs(
                &format!("verified_crawlers.{}.networks", crawler.name),
                &crawler.networks,
            )?;
        }

        let listener_names: HashSet<_> = self
            .listeners
            .iter()
            .map(|listener| listener.name())
            .collect();
        let mut listener_sources = BTreeMap::new();
        for (name, source) in &self.sources {
            if name.is_empty() {
                return Err(Error::Config("source names must not be empty".into()));
            }
            match source {
                Source::Journal {
                    match_groups,
                    max_entry_bytes,
                    ..
                } => {
                    if *max_entry_bytes == 0 {
                        return Err(Error::Config(format!(
                            "source {name} max_entry_bytes must be non-zero"
                        )));
                    }
                    if match_groups.iter().any(|group| {
                        group
                            .iter()
                            .any(|(field, value)| field.is_empty() || value.is_empty())
                    }) {
                        return Err(Error::Config(format!(
                            "source {name} journal match fields and values must not be empty"
                        )));
                    }
                }
                Source::File {
                    path,
                    poll_interval_ms,
                    max_line_bytes,
                    ..
                } => {
                    if path.as_os_str().is_empty() {
                        return Err(Error::Config(format!(
                            "source {name} path must not be empty"
                        )));
                    }
                    if *poll_interval_ms == 0 || *max_line_bytes == 0 {
                        return Err(Error::Config(format!(
                            "source {name} polling interval and line limit must be non-zero"
                        )));
                    }
                }
                Source::AddressSet { path } => {
                    if path.as_os_str().is_empty() {
                        return Err(Error::Config(format!(
                            "source {name} path must not be empty"
                        )));
                    }
                }
                Source::Listener { listener } => {
                    if !listener_names.contains(listener.as_str()) {
                        return Err(Error::Config(format!(
                            "source {name} references unknown listener {listener}"
                        )));
                    }
                    if listener_sources
                        .insert(listener.as_str(), name.as_str())
                        .is_some()
                    {
                        return Err(Error::Config(format!(
                            "listener {listener} has more than one source"
                        )));
                    }
                }
            }
        }

        for (name, policy) in &self.policies {
            if name.is_empty() {
                return Err(Error::Config("policy names must not be empty".into()));
            }
            if !self.sources.contains_key(&policy.source) {
                return Err(Error::Config(format!(
                    "policy {name} references unknown source {}",
                    policy.source
                )));
            }
            if policy.max_attempts == 0 || policy.findtime_secs == 0 {
                return Err(Error::Config(format!(
                    "policy {name} max_attempts and findtime_secs must be non-zero"
                )));
            }
            validate_ban_schedule(name, &policy.ban)?;
            validate_detector(name, &policy.detector)?;
            validate_cidrs(
                &format!("policies.{name}.ignore_networks"),
                &policy.ignore_networks,
            )?;
            validate_action(name, &policy.action, &self.listeners)?;
        }

        for listener in &self.listeners {
            let Some(policy_name) = listener.policy() else {
                continue;
            };
            let policy = self.policies.get(policy_name).ok_or_else(|| {
                Error::Config(format!(
                    "listener {} references unknown policy {policy_name}",
                    listener.name()
                ))
            })?;
            let expected_source = listener_sources.get(listener.name()).ok_or_else(|| {
                Error::Config(format!(
                    "listener {} has a policy but no listener source",
                    listener.name()
                ))
            })?;
            if policy.source != **expected_source {
                return Err(Error::Config(format!(
                    "listener {} policy {policy_name} uses source {}, expected {expected_source}",
                    listener.name(),
                    policy.source
                )));
            }
        }
        Ok(())
    }

    /// Return the explicitly configured endpoints.
    #[must_use]
    pub fn resolved_listeners(&self) -> Vec<Listener> {
        self.listeners.clone()
    }

    /// Create the data, cache, corpora, and scripts directories.
    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        for dir in [
            &self.data_dir,
            &self.cache_dir,
            &self.corpora_dir,
            &self.scripts_dir,
        ] {
            std::fs::create_dir_all(dir)?;
        }
        Ok(())
    }
}

fn validate_ban_schedule(policy: &str, ban: &BanSchedule) -> Result<()> {
    if ban.duration_secs.is_some_and(|duration| duration == 0)
        || ban.factor == 0
        || ban.multipliers.contains(&0)
        || ban.max_duration_secs == 0
    {
        return Err(Error::Config(format!(
            "policy {policy} ban durations, factor, and multipliers must be non-zero"
        )));
    }
    Ok(())
}

fn validate_detector(policy: &str, detector: &Detector) -> Result<()> {
    match detector {
        Detector::Regex {
            prefilter,
            patterns,
            context_patterns,
            max_context_lines,
            context_window_secs,
            ignore_patterns,
            address_capture,
            timestamp_capture,
            timestamp_format,
        } => {
            if patterns.is_empty() || patterns.iter().any(String::is_empty) {
                return Err(Error::Config(format!(
                    "policy {policy} regex detector requires non-empty patterns"
                )));
            }
            if ignore_patterns.iter().any(String::is_empty) {
                return Err(Error::Config(format!(
                    "policy {policy} ignore patterns must not be empty"
                )));
            }
            if context_patterns.iter().any(String::is_empty)
                || (context_patterns.is_empty() != (*max_context_lines == 0))
                || *max_context_lines > 64
                || *context_window_secs == 0
            {
                return Err(Error::Config(format!(
                    "policy {policy} context patterns require 1 to 64 context lines and a non-zero window"
                )));
            }
            validate_capture_name(policy, "address_capture", address_capture)?;
            if let Some(capture) = timestamp_capture {
                validate_capture_name(policy, "timestamp_capture", capture)?;
            }
            for pattern in patterns {
                let regex = compile_regex(policy, "pattern", pattern)?;
                if !regex
                    .capture_names()
                    .flatten()
                    .any(|capture| capture == address_capture)
                {
                    return Err(Error::Config(format!(
                        "every policy {policy} regex pattern must contain the named address capture {address_capture}"
                    )));
                }
                if let Some(capture) = timestamp_capture
                    && !regex
                        .capture_names()
                        .flatten()
                        .any(|candidate| candidate == capture)
                {
                    return Err(Error::Config(format!(
                        "every policy {policy} regex pattern must contain the named timestamp capture {capture}"
                    )));
                }
            }
            for pattern in context_patterns {
                let regex = compile_regex(policy, "context pattern", pattern)?;
                if !regex
                    .capture_names()
                    .flatten()
                    .any(|capture| capture == address_capture)
                {
                    return Err(Error::Config(format!(
                        "every policy {policy} context pattern must contain the named address capture {address_capture}"
                    )));
                }
            }
            for pattern in ignore_patterns {
                compile_regex(policy, "ignore pattern", pattern)?;
            }
            if let Some(prefilter) = prefilter {
                let regex = compile_regex(policy, "prefilter", prefilter)?;
                if !regex
                    .capture_names()
                    .flatten()
                    .any(|name| name == "content")
                {
                    return Err(Error::Config(format!(
                        "policy {policy} prefilter must contain a named content capture"
                    )));
                }
            }
            validate_timestamp_format(policy, timestamp_format.as_deref())?;
        }
        Detector::Json {
            equals,
            address_pointer,
            timestamp_pointer,
            timestamp_format,
        } => {
            validate_json_pointer(policy, "address_pointer", address_pointer)?;
            if let Some(pointer) = timestamp_pointer {
                validate_json_pointer(policy, "timestamp_pointer", pointer)?;
            }
            for pointer in equals.keys() {
                validate_json_pointer(policy, "equals key", pointer)?;
            }
            validate_timestamp_format(policy, timestamp_format.as_deref())?;
        }
    }
    Ok(())
}

fn compile_regex(policy: &str, field: &str, pattern: &str) -> Result<Regex> {
    Regex::new(pattern).map_err(|error| {
        Error::Config(format!(
            "policy {policy} has an invalid regex {field} {pattern:?}: {error}"
        ))
    })
}

fn validate_capture_name(policy: &str, field: &str, capture: &str) -> Result<()> {
    if capture.is_empty()
        || !capture
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || capture.as_bytes()[0].is_ascii_digit()
    {
        return Err(Error::Config(format!(
            "policy {policy} {field} is not a valid capture name"
        )));
    }
    Ok(())
}

fn validate_timestamp_format(policy: &str, format: Option<&str>) -> Result<()> {
    if format.is_some_and(|format| {
        !matches!(format, "rfc3339" | "unix")
            && !(format.starts_with("strptime:") && format.len() > "strptime:".len())
    }) {
        return Err(Error::Config(format!(
            "policy {policy} timestamp_format must be rfc3339, unix, or strptime:<format>"
        )));
    }
    Ok(())
}

fn validate_json_pointer(policy: &str, field: &str, pointer: &str) -> Result<()> {
    if pointer.is_empty()
        || !pointer.starts_with('/')
        || pointer
            .as_bytes()
            .windows(2)
            .any(|pair| pair[0] == b'~' && !matches!(pair[1], b'0' | b'1'))
        || pointer.ends_with('~')
    {
        return Err(Error::Config(format!(
            "policy {policy} {field} must be a non-empty JSON pointer"
        )));
    }
    Ok(())
}

fn validate_action(policy: &str, action: &Action, listeners: &[Listener]) -> Result<()> {
    match action {
        Action::Observe
        | Action::DropProtocol { .. }
        | Action::DropAll
        | Action::RejectProtocol { .. }
        | Action::RejectAll => Ok(()),
        Action::Drop { ports, .. } | Action::Reject { ports, .. } => validate_ports(policy, ports),
        Action::TarpitRedirect {
            protocol,
            ports,
            listener,
        } => {
            if *protocol != TransportProtocol::Tcp {
                return Err(Error::Config(format!(
                    "policy {policy} tarpit redirect must use TCP"
                )));
            }
            validate_ports(policy, ports)?;
            let target = listeners
                .iter()
                .find(|candidate| candidate.name() == listener)
                .ok_or_else(|| {
                    Error::Config(format!(
                        "policy {policy} references unknown tarpit listener {listener}"
                    ))
                })?;
            let address = target
                .listen_addr()
                .parse::<SocketAddr>()
                .map_err(|error| {
                    Error::Config(format!(
                        "policy {policy} tarpit listener {listener} has invalid address: {error}"
                    ))
                })?;
            if address.port() == 0 {
                return Err(Error::Config(format!(
                    "policy {policy} tarpit listener {listener} uses port zero"
                )));
            }
            Ok(())
        }
    }
}

fn validate_ports(policy: &str, ports: &[u16]) -> Result<()> {
    if ports.is_empty() || ports.contains(&0) {
        return Err(Error::Config(format!(
            "policy {policy} scoped action requires non-zero ports"
        )));
    }
    Ok(())
}

fn validate_cidrs(field: &str, cidrs: &[String]) -> Result<()> {
    for cidr in cidrs {
        if !cidr.contains('/') {
            return Err(Error::Config(format!(
                "{field} contains invalid CIDR {cidr:?}"
            )));
        }
        cidr.parse::<IpNetwork>().map_err(|error| {
            Error::Config(format!("{field} contains invalid CIDR {cidr:?}: {error}"))
        })?;
    }
    Ok(())
}

fn default_dirs() -> (PathBuf, PathBuf) {
    ProjectDirs::from("dev", "notashelf", "eris").map_or_else(
        || (PathBuf::from("./data"), PathBuf::from("./cache")),
        |dirs| {
            (
                dirs.data_dir().to_path_buf(),
                dirs.cache_dir().to_path_buf(),
            )
        },
    )
}

fn default_patterns() -> Vec<String> {
    [
        // PHP / WordPress probes.
        r"/vendor/phpunit",
        r"eval-stdin\.php",
        r"/wp-admin",
        r"/wp-login\.php",
        r"/xmlrpc\.php",
        r"/wp-config",
        r"/wp-content",
        r"/wp-includes",
        r"/wp-json",
        r"/phpMyAdmin",
        r"/phpmyadmin",
        r"/adminer",
        r"/phpinfo",
        r"/solr/",
        r"/cgi-bin/",
        // VCS and dotfile leaks. `/\.env` already covers `.env.prod`,
        // `.env.bak`, `.env~` and friends; `/\.git` covers `.git/config` etc.
        r"/\.env",
        r"/\.git",
        r"/\.svn",
        r"/\.hg",
        r"/\.bzr",
        r"/\.aws",
        r"/\.yarnrc",
        r"/\.npmrc",
        r"/\.netrc",
        // Config / secret files by common name (any extension: json, yaml, yml,
        // js, php, properties, backups, ...).
        r"/config\.",
        r"/settings\.",
        r"/secrets\.",
        r"/credentials\.",
        r"/appsettings",
        r"/application[.-]",
        r"/docker-compose",
        r"/web\.config",
        // Java application descriptors (Tomcat/Spring war internals).
        r"(?i)WEB-INF",
        // JavaScript framework internals abused for RCE probes (Next.js data
        // routes carrying `?cmd=` payloads).
        r"/_next/",
        // App framework actuators / health-and-env leaks, and the Tomcat
        // manager app.
        r"/actuator/",
        r"/manager/html",
        // Path traversal and local file inclusion. The classifier percent-
        // decodes first, so `%2e%2e%2f` is caught here as `../`; the `%2e`
        // pattern additionally catches *double*-encoded probes (`%252e`),
        // which single-pass decoding leaves as `%2e`.
        r"\.\./",
        r"%2e",
        r"/etc/passwd",
        r"/etc/shadow",
        r"/etc/hosts",
        r"/etc/ssh",
        r"/etc/nginx",
        r"/etc/apache",
        r"/proc/",
        // Shell histories: a read means an LFI win.
        r"/\.bash_history",
        r"/\.mysql_history",
        // Container and infrastructure exposure.
        r"/containers/json",
        r":2375",
        r"/\.kube",
        r"/\.docker",
        r"/\.terraform",
        r"\.tfstate",
        r"\.tfvars",
        // SSH keys and password databases.
        r"/\.ssh",
        r"/id_rsa",
        r"/id_ed25519",
        r"/\.htpasswd",
        // Editor/IDE metadata leaks.
        r"/\.vscode",
        // Common dropped-webshell filenames, including numbered variants
        // (`shell20211028.php`) and wrapped names (`zwso.php`).
        r"/(?:shell\d*|\w*wso\w*|c99\w*|r57\w*|alfa\w*|b374k)\.php",
        // Rogue SMTP-injection scripts probed by the Azure webshell fleet.
        r"makeasmtp",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

/// Abusive user-agent traps. Deliberately excludes Googlebot/Bingbot/Applebot
/// and real `git` clients so legitimate crawling and cloning still work; those
/// are reined in only by the rate limiter if they enumerate git history.
fn default_ua_patterns() -> Vec<String> {
    [
        // AI-training / LLM scrapers. These exist to vacuum content wholesale;
        // trapping them wastes the crawler's time instead of feeding it.
        r"(?i)ClaudeBot",
        r"(?i)anthropic-ai",
        r"(?i)Claude-Web",
        r"(?i)GPTBot",
        r"(?i)OAI-SearchBot",
        r"(?i)ChatGPT-User",
        r"(?i)CCBot",
        r"(?i)Google-Extended",
        r"(?i)Bytespider",
        r"(?i)Amazonbot",
        r"(?i)Meta-?External(?:Agent|Fetcher)",
        r"(?i)FacebookBot",
        r"(?i)Applebot-Extended",
        r"(?i)PerplexityBot",
        r"(?i)YouBot",
        r"(?i)Diffbot",
        r"(?i)ImagesiftBot",
        r"(?i)Omgili(?:bot)?",
        r"(?i)DataForSeoBot",
        r"(?i)Timpibot",
        r"(?i)cohere-ai",
        r"(?i)Scrapy",
        // Generic scripting/HTTP libraries: near-always automation against a
        // web git UI, never an interactive user. `git/x.y` clients are NOT here.
        r"(?i)python-requests",
        r"(?i)\bGo-http-client\b",
        r"(?i)\bnode-fetch\b",
        r"(?i)\baiohttp\b",
        r"(?i)\bokhttp\b",
        r"(?i)libwww-perl",
        // Active vulnerability/mass scanners.
        r"(?i)\b(?:zgrab|masscan|nikto|nuclei|sqlmap|Nmap|WPScan)\b",
        // Impossibly old browser strings: with current Firefox past 150, any
        // major version below 90 in production is a forgery. The log's worst
        // flooder forged exactly this (`Firefox/47.0`). Raise or lower the
        // ceiling in config as the real baseline moves.
        r"\bFirefox/(?:[1-9]|[1-8][0-9])\.0\b",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

/// Expensive git-history endpoints (Forgejo/Gitea URL shapes). Casual browsing
/// touches a few of these; enumeration touches thousands, which is what the
/// weighted rate limiter is meant to catch.
fn default_git_history_patterns() -> Vec<String> {
    [
        // File content and history views: blob, raw, blame, per-commit,
        // archive tarballs, and diff comparisons.
        r"(?i)/(?:blob|raw|blame|commit|archive|compare)(?:/|$)",
        // Gitea/Forgejo source-at-ref browsing.
        r"(?i)/(?:src|commits)/(?:branch|tag|commit)/",
        // Smart-HTTP clone/fetch: a full pack is the most expensive of all.
        r"(?i)git-(?:upload|receive)-pack",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

/// The ruinous git operations: archive/tarball generation (the server has to
/// pack a whole tree per request) and full clone/fetch packs. A scraper pulling
/// these repeatedly is what OOMs a git forge, so they weigh the most.
fn default_git_expensive_patterns() -> Vec<String> {
    [r"(?i)/archive/", r"(?i)git-(?:upload|receive)-pack"]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

/// Major search crawlers with their published source ranges. A UA claiming one
/// of these from outside its ranges is a forgery and is trapped; from inside,
/// it is proxied so indexing is never harmed. Ranges are the stable, published
/// crawler blocks (not general cloud), so being inside them is itself proof.
fn default_verified_crawlers() -> Vec<VerifiedCrawler> {
    let c = |name: &str, ua: &str, nets: &[&str]| VerifiedCrawler {
        name: name.to_string(),
        ua_pattern: ua.to_string(),
        networks: nets.iter().map(|s| (*s).to_string()).collect(),
    };
    vec![
        c(
            "Googlebot",
            r"(?i)Googlebot|APIs-Google|AdsBot-Google|Google-InspectionTool",
            &["66.249.64.0/19", "34.100.182.96/28", "35.247.243.240/28"],
        ),
        c(
            "Bingbot",
            r"(?i)bingbot|BingPreview|msnbot|adidxbot",
            &[
                "40.77.0.0/16",
                "157.55.0.0/16",
                "207.46.0.0/16",
                "13.66.0.0/16",
                "204.79.197.0/24",
            ],
        ),
        c(
            "DuckDuckBot",
            r"(?i)DuckDuckBot|DuckAssistBot",
            &["20.191.45.212/32", "40.88.21.235/32", "51.116.131.0/24"],
        ),
        // Rust's `regex` crate has no look-around, lol
        c("Applebot", r"(?i)Applebot(?:[^-]|$)", &["17.0.0.0/8"]),
    ]
}

/// Shared-infrastructure networks that must never be firewall-blocked: a drop
/// there would take down every genuine user behind the same address. Tarpitting
/// still applies. This is Cloudflare's published IPv4 and IPv6 space plus
/// loopback.
fn default_no_block_networks() -> Vec<String> {
    [
        "127.0.0.0/8",
        "::1/128",
        // Cloudflare (https://www.cloudflare.com/ips-v4).
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        // Cloudflare (https://www.cloudflare.com/ips-v6).
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

fn default_whitelist() -> Vec<String> {
    [
        "127.0.0.0/8",
        "::1/128",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Args {
        Args {
            config_file: None,
            check_config: false,
            listen_addr: None,
            metrics_addr: None,
            disable_metrics: false,
            admin_socket: None,
            disable_admin: false,
            backend_addr: None,
            min_delay_ms: None,
            max_delay_ms: None,
            max_tarpit_secs: None,
            block_threshold: None,
            max_tarpit_conns: None,
            max_connections: None,
            proxy_protocol: false,
            trusted_proxy: Vec::new(),
            disable_firewall: false,
            base_dir: None,
            log_level: "info".into(),
        }
    }

    #[test]
    fn defaults_are_valid() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn cli_overrides_file_and_default() {
        let a = Args {
            listen_addr: Some("127.0.0.1:1234".into()),
            disable_metrics: true,
            min_delay_ms: Some(50),
            max_delay_ms: Some(100),
            block_threshold: Some(9),
            max_tarpit_conns: Some(16),
            max_connections: Some(32),
            disable_firewall: true,
            base_dir: Some(PathBuf::from("/tmp/eris-test")),
            ..args()
        };

        let cfg = Config::resolve(&a).unwrap();
        assert_eq!(cfg.listen_addr, "127.0.0.1:1234");
        assert_eq!(cfg.metrics_addr, "127.0.0.1:9100"); // untouched default
        assert!(cfg.disable_metrics);
        assert_eq!(cfg.min_delay_ms, 50);
        assert_eq!(cfg.max_tarpit_conns, 16);
        assert_eq!(cfg.max_connections, 32);
        assert!(!cfg.enable_firewall);
        assert_eq!(cfg.data_dir, PathBuf::from("/tmp/eris-test/data"));
    }

    #[test]
    fn rejects_inverted_delays() {
        let cfg = Config {
            min_delay_ms: 10,
            max_delay_ms: 5,
            ..Config::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_conn_cap_below_tarpit_cap() {
        let cfg = Config {
            max_connections: 10,
            max_tarpit_conns: 100,
            listeners: vec![Listener::Http {
                name: "web".into(),
                listen_addr: "127.0.0.1:1".into(),
                policy: None,
                backend_addr: None,
                max_tarpit_conns: None,
            }],
            ..Config::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn proxy_protocol_requires_trusted_proxy() {
        let cfg = Config {
            proxy_protocol: true,
            trusted_proxies: vec![],
            ..Config::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn no_listener_is_created_implicitly() {
        let cfg = Config::default();
        assert!(cfg.resolved_listeners().is_empty());
    }

    #[test]
    fn rejects_duplicate_listener_names_and_invalid_ssh_line_length() {
        let cfg = Config {
            listeners: vec![
                Listener::Http {
                    name: "web".into(),
                    listen_addr: "127.0.0.1:1".into(),
                    policy: None,
                    backend_addr: None,
                    max_tarpit_conns: None,
                },
                Listener::Ssh {
                    name: "web".into(),
                    listen_addr: "127.0.0.1:2".into(),
                    policy: None,
                    max_tarpit_conns: None,
                    min_delay_ms: None,
                    max_delay_ms: None,
                    max_tarpit_secs: None,
                    line_length: Some(0),
                },
            ],
            ..Config::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn listener_capacities_reserve_global_capacity() {
        let cfg = Config {
            max_connections: 3,
            listeners: vec![
                Listener::Http {
                    name: "web".into(),
                    listen_addr: "127.0.0.1:1".into(),
                    policy: None,
                    backend_addr: None,
                    max_tarpit_conns: Some(2),
                },
                Listener::Ssh {
                    name: "ssh".into(),
                    listen_addr: "127.0.0.1:2".into(),
                    policy: None,
                    max_tarpit_conns: Some(2),
                    min_delay_ms: None,
                    max_delay_ms: None,
                    max_tarpit_secs: None,
                    line_length: None,
                },
            ],
            ..Config::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn typed_defense_schema_is_valid_with_tarpit_defaults() {
        let cfg: Config = serde_json::from_value(serde_json::json!({
            "listeners": [{
                "protocol": "ssh",
                "name": "ssh",
                "listen_addr": "0.0.0.0:22",
                "policy": "ssh-abuse"
            }],
            "sources": {
                "listener-ssh": {
                    "kind": "listener",
                    "listener": "ssh"
                }
            },
            "policies": {
                "ssh-abuse": {
                    "source": "listener-ssh",
                    "detector": {
                        "kind": "regex",
                        "patterns": ["(?P<address>[0-9A-Fa-f:.]+)"]
                    },
                    "action": { "kind": "drop_all" }
                }
            },
            "enforcement": {
                "mode": "required",
                "table": "eris",
                "chain_priority": -10,
                "reconcile_interval_secs": 15
            }
        }))
        .unwrap();

        cfg.validate().unwrap();
        assert_eq!(cfg.database_path, Config::default().database_path);
        assert_eq!(cfg.policies["ssh-abuse"].max_attempts, 7);
    }

    #[test]
    fn rejects_broken_source_listener_policy_relationships() {
        let mut cfg = Config::default();
        cfg.sources.insert(
            "listener-ssh".into(),
            Source::Listener {
                listener: "missing".into(),
            },
        );
        assert!(cfg.validate().is_err());

        cfg.sources.clear();
        cfg.policies.insert(
            "ssh-abuse".into(),
            Policy {
                source: "missing".into(),
                detector: Detector::Regex {
                    prefilter: None,
                    patterns: vec!["(?P<address>[0-9.]+)".into()],
                    context_patterns: Vec::new(),
                    max_context_lines: 0,
                    context_window_secs: default_context_window_secs(),
                    ignore_patterns: Vec::new(),
                    address_capture: "address".into(),
                    timestamp_capture: None,
                    timestamp_format: None,
                },
                ignore_networks: Vec::new(),
                max_attempts: 3,
                findtime_secs: 600,
                ban: BanSchedule::default(),
                action: Action::DropAll,
            },
        );
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_detectors_without_required_named_captures() {
        let detector = Detector::Regex {
            prefilter: Some("failed login".into()),
            patterns: vec!["from (?P<address>[0-9.]+)".into()],
            context_patterns: Vec::new(),
            max_context_lines: 0,
            context_window_secs: default_context_window_secs(),
            ignore_patterns: Vec::new(),
            address_capture: "address".into(),
            timestamp_capture: None,
            timestamp_format: None,
        };
        assert!(validate_detector("ssh", &detector).is_err());

        let detector = Detector::Regex {
            prefilter: None,
            patterns: vec!["from ([0-9.]+)".into()],
            context_patterns: Vec::new(),
            max_context_lines: 0,
            context_window_secs: default_context_window_secs(),
            ignore_patterns: Vec::new(),
            address_capture: "address".into(),
            timestamp_capture: None,
            timestamp_format: None,
        };
        assert!(validate_detector("ssh", &detector).is_err());
    }

    #[test]
    fn rejects_invalid_networks_and_scoped_actions() {
        assert!(validate_cidrs("test", &["192.0.2.1/33".into()]).is_err());
        assert!(validate_cidrs("test", &["192.0.2.1".into()]).is_err());
        assert!(
            validate_action(
                "ssh",
                &Action::Drop {
                    protocol: TransportProtocol::Tcp,
                    ports: Vec::new(),
                },
                &[],
            )
            .is_err()
        );
        assert!(
            validate_action(
                "ssh",
                &Action::TarpitRedirect {
                    protocol: TransportProtocol::Udp,
                    ports: vec![22],
                    listener: "ssh".into(),
                },
                &[],
            )
            .is_err()
        );
    }
}
