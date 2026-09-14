//! Defense configuration and validation.

use std::{
   collections::{
      BTreeMap,
      HashSet,
   },
   fmt,
   path::{
      Path,
      PathBuf,
   },
};

use bagel_core::{
   Error,
   Result,
};
use etcetera::BaseStrategy as _;
use pound::Parse;
use serde::{
   Deserialize,
   Serialize,
};

mod decode;
pub mod kdl;
mod validation;
#[cfg(test)]
use validation::{
   validate_action,
   validate_cidrs,
   validate_detector,
};
pub mod web;

/// Map a byte offset in config text to a 1-based line and column.
pub(crate) fn locate(text: &str, offset: usize) -> (usize, usize) {
   let mut line = 1;
   let mut column = 1;
   for (index, ch) in text.char_indices() {
      if index >= offset {
         break;
      }
      if ch == '\n' {
         line += 1;
         column = 1;
      } else {
         column += 1;
      }
   }
   (line, column)
}

pub(crate) fn relocate(text: &str, path: &Path, err: Error) -> Error {
   match err {
      Error::ConfigAt { offset, message } => {
         let (line, column) = locate(text, offset);
         Error::Config(format!("{}:{line}:{column}: {message}", path.display()))
      },
      other => other,
   }
}

/// Both planes' configuration as read from one KDL document. Web plane nodes
/// sit at the top level exactly as before and the defense plane lives under
/// one `defense { }` block.
#[derive(Clone)]
pub struct Bagel {
   pub web:     web::Config,
   pub defense: Config,
}

impl Bagel {
   pub fn parse(text: &str, path: &Path) -> Result<Self> {
      let doc = knead::parse(text).map_err(|err| {
         Error::ConfigParse {
            path:   path.to_owned(),
            source: Box::new(err),
         }
      })?;
      let mut web = web::Config::default();
      let mut defense = Config::default();
      let mut seen = HashSet::new();
      for node in doc.nodes() {
         web::reject_repeated(&mut seen, node).map_err(|err| relocate(text, path, err))?;
         if node.name().value() == "defense" {
            defense = kdl::parse_defense(node).map_err(|err| relocate(text, path, err))?;
         } else if !web
            .apply_node(node)
            .map_err(|err| relocate(text, path, err))?
         {
            return Err(relocate(
               text,
               path,
               Error::config_at(
                  node.span().offset(),
                  format!("unknown top-level config key '{}'", node.name().value()),
               ),
            ));
         }
      }
      Ok(Self { web, defense })
   }

   pub fn load(path: &Path) -> Result<Self> {
      let text = std::fs::read_to_string(path).map_err(|err| {
         Error::Config(format!(
            "failed to read config file {}: {err}",
            path.display()
         ))
      })?;
      Self::parse(&text, path)
   }

   /// Layer defaults, then the KDL file if any, then CLI
   /// and environment overrides, and validate the defense plane.
   pub fn resolve(args: &Args) -> Result<Self> {
      let (web, defense) = match &args.config {
         Some(path) => {
            let bagel = Self::load(path)?;
            (bagel.web, bagel.defense)
         },
         None => (web::Config::default(), Config::default()),
      };
      let mut bagel = Self {
         web,
         defense: Config::apply_args(defense, args),
      };
      if !args.trusted_proxy.is_empty() {
         bagel.web.trusted_proxies = Some(args.trusted_proxy.clone());
      }
      bagel.share_plane_settings();
      bagel.defense.validate()?;
      bagel.validate_planes()?;
      Ok(bagel)
   }

   /// Checks that only make sense once both planes are known.
   pub fn validate_planes(&self) -> Result<()> {
      validate_web_trust(&self.web)?;
      let web_sources = self
         .defense
         .sources
         .values()
         .filter(|source| matches!(source, Source::Web))
         .count();
      if web_sources > 1 {
         return Err(Error::Config(
            "only one web source may be configured, the web plane attaches to a single one".into(),
         ));
      }
      Ok(())
   }

   /// The top-level `trusted-proxies` list is the only one, and the deception
   /// directories default to the defense data directory.
   fn share_plane_settings(&mut self) {
      if self.web.deception.corpora.is_none() {
         self.web.deception.corpora = Some(self.defense.corpora_dir.clone());
      }
      if self.web.deception.scripts.is_none() {
         self.web.deception.scripts = Some(self.defense.scripts_dir.clone());
      }
      self.defense.trusted_proxies = self.web.trusted_proxies.clone().unwrap_or_default();
   }
}

/// Validate the trusted proxy configuration used for client identity.
pub fn validate_web_trust(web: &web::Config) -> Result<()> {
   if web.trusted_proxies.is_none() {
      if web.client_ip_header.is_some() {
         return Err(Error::Config(
            "client-ip-header requires trusted-proxies, an untrusted forwarding header never \
             supplies identity"
               .into(),
         ));
      }
      if web.client_tls_header.is_some() {
         return Err(Error::Config(
            "client-tls-header requires trusted-proxies, an untrusted forwarding header never \
             supplies a fingerprint"
               .into(),
         ));
      }
      if web.bind.proxy_protocol {
         return Err(Error::Config(
            "bind proxy-protocol requires trusted-proxies so only listed peers can supply a \
             source address"
               .into(),
         ));
      }
   }
   Ok(())
}

/// One independently-admitted tarpit endpoint.
#[derive(Clone, PartialEq, Eq, knead_derive::Decode)]
pub struct Listener {
   #[knead(argument)]
   pub name:             String,
   #[knead(property(name = "listen"))]
   pub listen_addr:      String,
   #[knead(property)]
   pub policy:           Option<String>,
   #[knead(property)]
   pub max_tarpit_conns: Option<usize>,
   #[knead(property)]
   pub min_delay_ms:     Option<u64>,
   #[knead(property)]
   pub max_delay_ms:     Option<u64>,
   #[knead(property)]
   pub max_tarpit_secs:  Option<u64>,
   #[knead(property)]
   pub line_length:      Option<usize>,
}

impl Listener {
   #[must_use]
   pub fn name(&self) -> &str {
      &self.name
   }

   #[must_use]
   pub fn listen_addr(&self) -> &str {
      &self.listen_addr
   }

   #[must_use]
   pub fn policy(&self) -> Option<&str> {
      self.policy.as_deref()
   }

   #[must_use]
   pub fn max_tarpit_conns(&self, default: usize) -> usize {
      self.max_tarpit_conns.unwrap_or(default)
   }
}

/// Position used when a durable source checkpoint does not exist yet.
#[derive(Clone, Copy, Default, PartialEq, Eq, knead_derive::DecodeScalar)]
pub enum StartPosition {
   Beginning,
   #[default]
   End,
}

/// A durable stream of records presented to one or more policies.
#[derive(Clone, PartialEq, Eq, knead_derive::Decode)]
pub enum Source {
   Journal {
      #[knead(children(name = "match"), unwrap(properties))]
      match_groups:    Vec<BTreeMap<String, String>>,
      #[knead(property, default)]
      start:           StartPosition,
      #[knead(property, default = default_max_entry_bytes())]
      max_entry_bytes: usize,
   },
   File {
      #[knead(property)]
      path:             PathBuf,
      #[knead(property, default)]
      start:            StartPosition,
      #[knead(property, default = default_poll_interval_ms())]
      poll_interval_ms: u64,
      #[knead(property, default = default_max_line_bytes())]
      max_line_bytes:   usize,
   },
   AddressSet {
      #[knead(property)]
      path: PathBuf,
   },
   Listener {
      #[knead(property)]
      listener: String,
   },
   /// Offense records pushed in-process by the HTTP data plane, attached at
   /// startup through `Defense::web_source`.
   Web,
}

/// Extracts a literal client address and, optionally, the event timestamp.
#[derive(Clone, PartialEq, Eq)]
pub enum Detector {
   Regex {
      prefilter:           Option<String>,
      /// Patterns may capture `attempt_key` to count distinct evidence
      /// inside the policy's rolling window.
      patterns:            Vec<String>,
      context_patterns:    Vec<String>,
      max_context_lines:   usize,
      context_window_secs: u64,
      ignore_patterns:     Vec<String>,
      address_capture:     String,
      timestamp_capture:   Option<String>,
      timestamp_format:    Option<String>,
   },
   Json {
      equals:            BTreeMap<String, String>,
      address_pointer:   String,
      timestamp_pointer: Option<String>,
      group_key_pointer: Option<String>,
      timestamp_format:  Option<String>,
   },
}

const fn default_context_window_secs() -> u64 {
   120
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq, knead_derive::DecodeScalar)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
   Tcp,
   Udp,
}

impl fmt::Display for TransportProtocol {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.write_str(match self {
         Self::Tcp => "tcp",
         Self::Udp => "udp",
      })
   }
}

/// Network effect produced by a policy ban.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, knead_derive::Decode)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
   Observe,
   Drop {
      #[knead(property)]
      protocol: TransportProtocol,
      #[knead(child, unwrap(arguments))]
      ports:    Vec<u16>,
   },
   DropProtocol {
      #[knead(property)]
      protocol: TransportProtocol,
   },
   DropAll,
   Reject {
      #[knead(property)]
      protocol: TransportProtocol,
      #[knead(child, unwrap(arguments))]
      ports:    Vec<u16>,
   },
   RejectProtocol {
      #[knead(property)]
      protocol: TransportProtocol,
   },
   RejectAll,
   TarpitRedirect {
      #[knead(property)]
      protocol: TransportProtocol,
      #[knead(child, unwrap(arguments))]
      ports:    Vec<u16>,
      #[knead(property)]
      listener: String,
   },
}

impl Action {
   /// What a firewall rule needs, or `None` for the actions that produce no
   /// rule.
   #[must_use]
   pub fn block_parts(&self) -> Option<(BlockVerdict, BlockTarget<'_>)> {
      let (verdict, target) = match self {
         Self::Observe | Self::TarpitRedirect { .. } => return None,
         Self::Drop { protocol, ports } => {
            (BlockVerdict::Drop, BlockTarget::Ports(*protocol, ports))
         },
         Self::DropProtocol { protocol } => (BlockVerdict::Drop, BlockTarget::Protocol(*protocol)),
         Self::DropAll => (BlockVerdict::Drop, BlockTarget::All),
         Self::Reject { protocol, ports } => {
            (BlockVerdict::Reject, BlockTarget::Ports(*protocol, ports))
         },
         Self::RejectProtocol { protocol } => {
            (BlockVerdict::Reject, BlockTarget::Protocol(*protocol))
         },
         Self::RejectAll => (BlockVerdict::Reject, BlockTarget::All),
      };
      Some((verdict, target))
   }
}

impl fmt::Display for Action {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      if let Some((verdict, target)) = self.block_parts() {
         match target {
            BlockTarget::Ports(protocol, ports) => {
               write!(f, "{verdict} {protocol} {}", format_ports(ports))
            },
            BlockTarget::Protocol(protocol) => write!(f, "{verdict}_protocol {protocol}"),
            BlockTarget::All => write!(f, "{verdict}_all"),
         }
      } else if let Self::TarpitRedirect {
         protocol,
         ports,
         listener,
      } = self
      {
         write!(
            f,
            "tarpit_redirect {protocol} {} -> {listener}",
            format_ports(ports)
         )
      } else {
         f.write_str("observe")
      }
   }
}

/// Whether a blocking action discards traffic silently or answers with an
/// ICMP or TCP reset.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BlockVerdict {
   Drop,
   Reject,
}

/// How much traffic a blocking action covers.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BlockTarget<'a> {
   Ports(TransportProtocol, &'a [u16]),
   Protocol(TransportProtocol),
   All,
}

impl fmt::Display for BlockVerdict {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.write_str(match self {
         Self::Drop => "drop",
         Self::Reject => "reject",
      })
   }
}

fn format_ports(ports: &[u16]) -> String {
   ports
      .iter()
      .map(u16::to_string)
      .collect::<Vec<_>>()
      .join(",")
}

#[derive(Clone, PartialEq, Eq)]
pub struct BanSchedule {
   /// `None` creates a permanent ban.
   pub duration_secs:     Option<u64>,
   pub factor:            u64,
   pub multipliers:       Vec<u64>,
   pub jitter_secs:       u64,
   pub max_duration_secs: u64,
   pub overall:           bool,
}

impl Default for BanSchedule {
   fn default() -> Self {
      Self {
         duration_secs:     Some(600),
         factor:            4,
         multipliers:       vec![4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048],
         jitter_secs:       720,
         max_duration_secs: 18_000_000,
         overall:           true,
      }
   }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Policy {
   pub source:          String,
   pub detector:        Detector,
   pub ignore_networks: Vec<String>,
   pub max_attempts:    u32,
   pub findtime_secs:   u64,
   pub ban:             BanSchedule,
   pub action:          Action,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, knead_derive::DecodeScalar)]
pub enum EnforcementMode {
   #[default]
   Required,
   Observe,
}

#[derive(Clone, Debug, PartialEq, Eq, knead_derive::Decode)]
pub struct Enforcement {
   #[knead(property, default = Enforcement::default().mode)]
   pub mode:                    EnforcementMode,
   #[knead(property, default = Enforcement::default().table)]
   pub table:                   String,
   #[knead(property, default = Enforcement::default().chain_priority)]
   pub chain_priority:          i32,
   #[knead(property, default = Enforcement::default().reconcile_interval_secs)]
   pub reconcile_interval_secs: u64,
}

impl Default for Enforcement {
   fn default() -> Self {
      Self {
         mode:                    EnforcementMode::Required,
         table:                   "bagel".into(),
         chain_priority:          -10,
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

/// A search crawler and its allowed source networks.
#[derive(Clone, PartialEq, Eq, knead_derive::Decode)]
pub struct VerifiedCrawler {
   /// Human-readable name, used only for reporting/metrics.
   #[knead(argument)]
   pub name:       String,
   /// Regex matched against the request `User-Agent`.
   #[knead(property)]
   pub ua_pattern: String,
   /// CIDR networks the crawler legitimately originates from.
   #[knead(child, unwrap(arguments), default)]
   pub networks:   Vec<String>,
}

#[must_use]
#[expect(
   clippy::print_stderr,
   clippy::exit,
   reason = "argument decoding runs before the logger exists, and a non-UTF-8 argument has to \
             stop startup rather than be silently dropped"
)]
pub fn parse() -> Args {
   for variable in Args::SPEC.args.iter().filter_map(|argument| argument.env) {
      if let Err(std::env::VarError::NotUnicode(_)) = std::env::var(variable) {
         eprintln!("{variable} must be valid UTF-8");
         std::process::exit(2);
      }
   }
   let arguments: Vec<String> = std::env::args_os()
      .skip(1)
      .map(|argument| {
         argument.into_string().unwrap_or_else(|_| {
            eprintln!("command-line arguments must be valid UTF-8");
            std::process::exit(2);
         })
      })
      .collect();
   Args::parse_from(arguments.iter().map(String::as_str))
}

/// Proxy daemon and SSH tarpit that delays and bans malicious scanners.
#[derive(Parse)]
#[pound(name = "bagel-daemon")]
#[expect(
   clippy::struct_excessive_bools,
   reason = "each flag is one independent command-line switch, and grouping them into enums would \
             rename the switches"
)]
pub struct Args {
   /// Path to the KDL configuration file covering both planes.
   #[pound(long, env = "BAGEL_CONFIG")]
   pub config: Option<PathBuf>,

   /// Validate the resolved configuration and exit without starting services.
   #[pound(long)]
   pub check_config: bool,

   /// Generate a new Ed25519 key seed, print it, and exit.
   #[pound(long)]
   pub generate_key: bool,

   /// Hex-encoded PKCS8 seed for the web plane's Ed25519 key, which keeps
   /// challenge cookies and maze routes stable across restarts.
   #[pound(long, env = "BAGEL_KEY_SEED")]
   pub key_seed: Option<String>,

   /// File holding the hex-encoded PKCS8 seed, typically a systemd credential.
   #[pound(long, env = "BAGEL_KEY_SEED_FILE")]
   pub key_seed_file: Option<PathBuf>,

   /// Address to expose Prometheus metrics and status on (ip:port).
   #[pound(long, env = "BAGEL_METRICS_ADDR")]
   pub metrics_addr: Option<String>,

   /// Disable the metrics/status server.
   #[pound(long)]
   pub disable_metrics: bool,

   #[pound(long, env = "BAGEL_ADMIN_SOCKET")]
   pub admin_socket: Option<PathBuf>,

   #[pound(long)]
   pub disable_admin: bool,

   /// Minimum delay between tarpit chunks, in milliseconds.
   #[pound(long)]
   pub min_delay_ms: Option<u64>,

   /// Maximum delay between tarpit chunks, in milliseconds.
   #[pound(long)]
   pub max_delay_ms: Option<u64>,

   /// Maximum time to hold a tarpit connection, in seconds.
   #[pound(long)]
   pub max_tarpit_secs: Option<u64>,

   /// Maximum number of concurrent tarpit connections.
   #[pound(long)]
   pub max_tarpit_conns: Option<usize>,

   /// Maximum number of concurrent connections of any kind.
   #[pound(long)]
   pub max_connections: Option<usize>,

   /// Expect a PROXY protocol header from trusted proxies.
   #[pound(long)]
   pub proxy_protocol: bool,

   /// Trusted proxy CIDR for both planes. Repeatable, replaces the configured
   /// list.
   #[pound(long = "trusted-proxy")]
   pub trusted_proxy: Vec<String>,

   /// Keep blocking in memory only and never touch nftables.
   #[pound(long)]
   pub disable_firewall: bool,

   /// Base directory for data and cache (overrides XDG locations).
   #[pound(long)]
   pub base_dir: Option<PathBuf>,

   /// Log level: trace, debug, info, warn, error.
   #[pound(long, default = "info", env = "BAGEL_LOG")]
   pub log_level: String,
}

/// Resolved runtime configuration.
#[derive(Clone)]
#[expect(
   clippy::struct_excessive_bools,
   reason = "each flag is one independent config toggle, and the whole program reads them by name"
)]
pub struct Config {
   pub metrics_addr:    String,
   pub disable_metrics: bool,
   pub admin_socket:    PathBuf,
   pub disable_admin:   bool,

   /// Independently configured SSH tarpit endpoints.
   pub listeners: Vec<Listener>,

   /// Named durable record streams consumed by defense policies.
   pub sources:                BTreeMap<String, Source>,
   /// Named detection, escalation, and enforcement policies.
   pub policies:               BTreeMap<String, Policy>,
   pub enforcement:            Enforcement,
   pub database_path:          PathBuf,
   pub history_retention_secs: u64,
   pub journalctl_path:        PathBuf,
   pub nft_path:               PathBuf,
   /// Networks which no automatic or manual action may block.
   pub protected_networks:     Vec<String>,

   pub min_delay_ms:              u64,
   pub max_delay_ms:              u64,
   pub max_tarpit_secs:           u64,
   /// Smallest tarpit body chunk, in bytes. Segment-sized chunks read like a
   /// slow real transfer. Single bytes betray a tarpit.
   pub tarpit_chunk_min_bytes:    usize,
   pub tarpit_chunk_max_bytes:    usize,
   pub max_tarpit_conns:          usize,
   /// Maximum concurrent tarpits from one source IP across all endpoints.
   pub max_tarpit_conns_per_ip:   usize,
   /// Bound each socket write, so non-reading peers cannot pin a tarpit slot.
   pub tarpit_write_timeout_secs: u64,

   /// Cap on concurrent connections of any kind. Bounds total resource use.
   pub max_connections:    usize,
   pub drain_timeout_secs: u64,

   pub proxy_protocol:  bool,
   /// Networks whose forwarding information Bagel trusts.
   pub trusted_proxies: Vec<String>,

   pub enable_firewall:    bool,
   /// Trap patterns, matched against the request path as regexes.
   pub trap_patterns:      Vec<String>,
   /// User-agent trap patterns matched regardless of path.
   pub trap_user_agents:   Vec<String>,
   pub whitelist_networks: Vec<String>,

   /// Search crawlers and their source networks.
   pub verified_crawlers: Vec<VerifiedCrawler>,
   /// Networks that may be tarpitted but never enter the firewall blocklist.
   pub no_block_networks: Vec<String>,

   pub corpora_dir: PathBuf,
   pub scripts_dir: PathBuf,
   pub data_dir:    PathBuf,
   pub cache_dir:   PathBuf,
}

impl Default for Config {
   fn default() -> Self {
      let (data_dir, cache_dir) = default_dirs();
      Self {
         // Localhost by default: metrics and status leak operational detail
         // and must be exposed deliberately, not by accident.
         metrics_addr: "127.0.0.1:9100".into(),
         disable_metrics: false,
         admin_socket: PathBuf::from(bagel_core::DEFAULT_ADMIN_SOCKET),
         disable_admin: false,
         listeners: Vec::new(),
         sources: BTreeMap::new(),
         policies: BTreeMap::new(),
         enforcement: Enforcement::default(),
         database_path: data_dir.join("bagel.sqlite3"),
         history_retention_secs: 86_400,
         journalctl_path: PathBuf::from("journalctl"),
         nft_path: PathBuf::from("nft"),
         protected_networks: vec!["127.0.0.0/8".into(), "::1/128".into()],

         min_delay_ms: 1000,
         max_delay_ms: 15000,
         max_tarpit_secs: 600,
         tarpit_chunk_min_bytes: 64,
         tarpit_chunk_max_bytes: 1400,
         max_tarpit_conns: 4096,
         max_tarpit_conns_per_ip: 16,
         tarpit_write_timeout_secs: 15,

         max_connections: 8192,
         drain_timeout_secs: 10,

         proxy_protocol: false,
         trusted_proxies: Vec::new(),

         enable_firewall: true,
         trap_patterns: default_patterns(),
         trap_user_agents: default_ua_patterns(),
         whitelist_networks: default_whitelist(),

         verified_crawlers: default_verified_crawlers(),
         no_block_networks: default_no_block_networks(),

         corpora_dir: data_dir.join("corpora"),
         scripts_dir: data_dir.join("scripts"),
         data_dir,
         cache_dir,
      }
   }
}

impl Config {
   fn apply_args(mut cfg: Self, args: &Args) -> Self {
      if let Some(base) = &args.base_dir {
         cfg.data_dir = base.join("data");
         cfg.cache_dir = base.join("cache");
         cfg.corpora_dir = cfg.data_dir.join("corpora");
         cfg.scripts_dir = cfg.data_dir.join("scripts");
         cfg.database_path = cfg.data_dir.join("bagel.sqlite3");
      }

      // Each provided (`Some`) CLI/env value overrides the layered config.
      macro_rules! apply {
            ($($field:ident),+ $(,)?) => {
                $(if let Some(v) = args.$field.clone() { cfg.$field = v; })+
            };
        }
      apply!(
         metrics_addr,
         admin_socket,
         min_delay_ms,
         max_delay_ms,
         max_tarpit_secs,
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
      cfg
   }

   fn validate(&self) -> Result<()> {
      validation::validate_config(self)
   }

   #[must_use]
   pub fn resolved_listeners(&self) -> Vec<Listener> {
      self.listeners.clone()
   }

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

fn default_dirs() -> (PathBuf, PathBuf) {
   etcetera::choose_base_strategy().map_or_else(
      |_| (PathBuf::from("./data"), PathBuf::from("./cache")),
      |base| {
         (
            base.data_dir().join("bagel"),
            base.cache_dir().join("bagel"),
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
      // `.env.bak`, `.env~` and friends. `/\.git` covers `.git/config` etc.
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
      // Path traversal and local file inclusion after one decode pass.
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
   .map(|s| (*s).to_owned())
   .collect()
}

/// Default user-agent traps, excluding verified crawlers and git clients.
fn default_ua_patterns() -> Vec<String> {
   [
      // AI-training / LLM scrapers. These exist to vacuum content wholesale,
      // so trapping them wastes the crawler's time instead of feeding it.
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
   .map(|s| (*s).to_owned())
   .collect()
}

/// Major search crawlers with their published source ranges.
fn default_verified_crawlers() -> Vec<VerifiedCrawler> {
   let c = |name: &str, ua: &str, nets: &[&str]| {
      VerifiedCrawler {
         name:       name.to_owned(),
         ua_pattern: ua.to_owned(),
         networks:   nets.iter().map(|s| (*s).to_owned()).collect(),
      }
   };
   vec![
      c(
         "Googlebot",
         r"(?i)Googlebot|APIs-Google|AdsBot-Google|Google-InspectionTool",
         &["66.249.64.0/19", "34.100.182.96/28", "35.247.243.240/28"],
      ),
      c("Bingbot", r"(?i)bingbot|BingPreview|msnbot|adidxbot", &[
         "40.77.0.0/16",
         "157.55.0.0/16",
         "207.46.0.0/16",
         "13.66.0.0/16",
         "204.79.197.0/24",
      ]),
      c("DuckDuckBot", r"(?i)DuckDuckBot|DuckAssistBot", &[
         "20.191.45.212/32",
         "40.88.21.235/32",
         "51.116.131.0/24",
      ]),
      c("Applebot", r"(?i)Applebot(?:[^-]|$)", &["17.0.0.0/8"]),
   ]
}

/// Shared infrastructure that must never be firewall-blocked.
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
   .map(|s| (*s).to_owned())
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
   .map(|s| (*s).to_owned())
   .collect()
}

#[cfg(test)]
mod tests {
   use super::*;

   fn args() -> Args {
      Args {
         config:           None,
         key_seed:         None,
         key_seed_file:    None,
         check_config:     false,
         generate_key:     false,
         metrics_addr:     None,
         disable_metrics:  false,
         admin_socket:     None,
         disable_admin:    false,
         min_delay_ms:     None,
         max_delay_ms:     None,
         max_tarpit_secs:  None,
         max_tarpit_conns: None,
         max_connections:  None,
         proxy_protocol:   false,
         trusted_proxy:    Vec::new(),
         disable_firewall: false,
         base_dir:         None,
         log_level:        "info".into(),
      }
   }

   #[test]
   fn defaults_are_valid() {
      Config::default().validate().unwrap();
   }

   #[test]
   fn cli_overrides_file_and_default() {
      let a = Args {
         metrics_addr: Some("127.0.0.1:1234".into()),
         disable_metrics: true,
         min_delay_ms: Some(50),
         max_delay_ms: Some(100),
         max_tarpit_conns: Some(16),
         max_connections: Some(32),
         disable_firewall: true,
         base_dir: Some(PathBuf::from("/tmp/bagel-test")),
         ..args()
      };

      let cfg = Bagel::resolve(&a).unwrap().defense;
      assert_eq!(cfg.metrics_addr, "127.0.0.1:1234");
      assert!(cfg.disable_metrics);
      assert_eq!(cfg.min_delay_ms, 50);
      assert_eq!(cfg.max_tarpit_conns, 16);
      assert_eq!(cfg.max_connections, 32);
      assert!(!cfg.enable_firewall);
      assert_eq!(cfg.data_dir, PathBuf::from("/tmp/bagel-test/data"));
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
         listeners: vec![Listener {
            name:             "web".into(),
            listen_addr:      "127.0.0.1:1".into(),
            policy:           None,
            max_tarpit_conns: None,
            min_delay_ms:     None,
            max_delay_ms:     None,
            max_tarpit_secs:  None,
            line_length:      None,
         }],
         ..Config::default()
      };
      assert!(cfg.validate().is_err());
   }

   #[test]
   fn identity_sources_require_trusted_proxies() {
      for text in [
         "client-ip-header \"x-forwarded-for\"\n",
         "bind { proxy-protocol #true }\n",
      ] {
         let bagel = Bagel::parse(text, Path::new("test.kdl")).unwrap();
         let err = bagel.validate_planes().unwrap_err().to_string();
         assert!(err.contains("trusted-proxies"), "{err}");
      }

      let text = r#"
client-ip-header "x-forwarded-for"
bind { proxy-protocol #true }
trusted-proxies "10.0.0.0/8"
defense {
    sources { source "web" kind="web" }
}
"#;
      Bagel::parse(text, Path::new("test.kdl"))
         .unwrap()
         .validate_planes()
         .unwrap();

      let text = r#"
defense {
    sources { source "web" kind="web"; source "web2" kind="web" }
}
"#;
      let err = Bagel::parse(text, Path::new("test.kdl"))
         .unwrap()
         .validate_planes()
         .unwrap_err()
         .to_string();
      assert!(err.contains("only one web source"), "{err}");
   }

   #[test]
   fn semantic_errors_carry_line_numbers() {
      let text = "bind {}\npolicy {}\nbind { network \"udp\" }\n";
      let err = Bagel::parse(text, Path::new("test.kdl"))
         .err()
         .expect("a repeated bind node should not decode")
         .to_string();
      assert!(err.contains("test.kdl:3:"), "{err}");
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
            Listener {
               name:             "web".into(),
               listen_addr:      "127.0.0.1:1".into(),
               policy:           None,
               max_tarpit_conns: None,
               min_delay_ms:     None,
               max_delay_ms:     None,
               max_tarpit_secs:  None,
               line_length:      None,
            },
            Listener {
               name:             "web".into(),
               listen_addr:      "127.0.0.1:2".into(),
               policy:           None,
               max_tarpit_conns: None,
               min_delay_ms:     None,
               max_delay_ms:     None,
               max_tarpit_secs:  None,
               line_length:      Some(0),
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
            Listener {
               name:             "web".into(),
               listen_addr:      "127.0.0.1:1".into(),
               policy:           None,
               max_tarpit_conns: Some(2),
               min_delay_ms:     None,
               max_delay_ms:     None,
               max_tarpit_secs:  None,
               line_length:      None,
            },
            Listener {
               name:             "ssh".into(),
               listen_addr:      "127.0.0.1:2".into(),
               policy:           None,
               max_tarpit_conns: Some(2),
               min_delay_ms:     None,
               max_delay_ms:     None,
               max_tarpit_secs:  None,
               line_length:      None,
            },
         ],
         ..Config::default()
      };
      assert!(cfg.validate().is_err());
   }

   #[test]
   fn rejects_broken_source_listener_policy_relationships() {
      let mut cfg = Config::default();
      cfg.sources.insert("listener-ssh".into(), Source::Listener {
         listener: "missing".into(),
      });
      assert!(cfg.validate().is_err());

      cfg.sources.clear();
      cfg.policies.insert("ssh-abuse".into(), Policy {
         source:          "missing".into(),
         detector:        Detector::Regex {
            prefilter:           None,
            patterns:            vec!["(?P<address>[0-9.]+)".into()],
            context_patterns:    Vec::new(),
            max_context_lines:   0,
            context_window_secs: default_context_window_secs(),
            ignore_patterns:     Vec::new(),
            address_capture:     "address".into(),
            timestamp_capture:   None,
            timestamp_format:    None,
         },
         ignore_networks: Vec::new(),
         max_attempts:    3,
         findtime_secs:   600,
         ban:             BanSchedule::default(),
         action:          Action::DropAll,
      });
      assert!(cfg.validate().is_err());
   }

   #[test]
   fn rejects_detectors_without_required_named_captures() {
      let detector = Detector::Regex {
         prefilter:           Some("failed login".into()),
         patterns:            vec!["from (?P<address>[0-9.]+)".into()],
         context_patterns:    Vec::new(),
         max_context_lines:   0,
         context_window_secs: default_context_window_secs(),
         ignore_patterns:     Vec::new(),
         address_capture:     "address".into(),
         timestamp_capture:   None,
         timestamp_format:    None,
      };
      assert!(validate_detector("ssh", &detector).is_err());

      let detector = Detector::Regex {
         prefilter:           None,
         patterns:            vec!["from ([0-9.]+)".into()],
         context_patterns:    Vec::new(),
         max_context_lines:   0,
         context_window_secs: default_context_window_secs(),
         ignore_patterns:     Vec::new(),
         address_capture:     "address".into(),
         timestamp_capture:   None,
         timestamp_format:    None,
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
               ports:    Vec::new(),
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
               ports:    vec![22],
               listener: "ssh".into(),
            },
            &[],
         )
         .is_err()
      );
   }
}
