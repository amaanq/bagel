use std::{
   collections::{
      HashMap,
      HashSet,
   },
   fs,
   io,
   path::Path,
   str::FromStr,
   time::Duration,
};

use bagel_core::{
   Error,
   Result,
};
use decision::{
   RuleInput,
   ThresholdInput,
};
use knead::{
   ast::{
      Literal,
      Node,
      Value,
   },
   decode::DecodeScalar,
   errors::{
      Error as DecodeError,
      ErrorKind,
   },
};

use crate::{
   kdl::children,
   relocate,
};

mod decision;

/// Network definition: how to obtain a list of IP prefixes.
#[derive(Clone)]
pub struct NetworkConfig {
   pub name:    String,
   pub sources: Vec<NetworkSource>,
}

#[derive(Clone)]
pub enum NetworkFilter {
   /// jq-style filter path (e.g. `.prefixes[].ip_prefix`).
   Jq(String),
   /// Regex with a `prefix` named capture group.
   Regex(String),
   /// No filter: one prefix per line.
   None,
}

#[derive(Clone)]
pub enum NetworkSource {
   Url {
      url:    String,
      filter: NetworkFilter,
   },
   File {
      path:   String,
      filter: NetworkFilter,
   },
   Asn(u32),
   Inline(Vec<String>),
}

/// Named condition expression (reusable via `($name)` substitution).
#[derive(Clone, knead_derive::Decode)]
pub struct ConditionConfig {
   #[knead(argument)]
   pub name: String,
   #[knead(property)]
   pub expr: RhaiExpression,
}

#[derive(Clone)]
pub struct ChallengeConfig {
   pub name:          String,
   pub runtime:       String,
   pub duration_secs: u64,
   pub parameters:    HashMap<String, String>,
}

#[derive(Clone)]
pub struct RuleConfig {
   pub name:       String,
   pub condition:  Option<RhaiExpression>,
   pub action:     String,
   pub challenges: Vec<String>,
   pub settings:   RuleSettings,
   pub children:   Vec<Self>,
}

#[derive(Clone, Default)]
pub struct RuleSettings {
   pub http_code:        Option<u16>,
   pub pass_action:      Option<String>,
   pub fail_action:      Option<String>,
   /// Response headers to add (`Context` action).
   pub response_headers: Vec<(String, String)>,
   /// Request headers to add (`Context` action).
   pub request_headers:  Vec<(String, String)>,
   /// Proxy rewrite pattern.
   pub match_re:         Option<String>,
   pub rewrite:          Option<String>,
   pub backend:          Option<String>,
   /// Maze name (`tarpit` action).
   pub maze:             Option<String>,
   /// Offense kind (`report` action).
   pub kind:             Option<String>,
   /// Proof-of-work difficulty override (`challenge` and `check` actions).
   pub difficulty:       Option<u32>,
}

/// One weighted scoring signal inside a scorecard.
#[derive(Clone, knead_derive::Decode)]
pub struct SignalConfig {
   #[knead(argument)]
   pub name:      String,
   #[knead(property)]
   pub condition: RhaiExpression,
   #[knead(property)]
   pub weight:    u32,
}

/// One positional threshold inside a scorecard.
#[derive(Clone)]
pub struct ThresholdConfig {
   pub value:      u32,
   pub action:     String,
   pub challenges: Vec<String>,
   pub settings:   RuleSettings,
}

#[derive(Clone)]
pub struct ScorecardConfig {
   pub name:       String,
   pub condition:  Option<RhaiExpression>,
   pub mode:       Option<String>,
   pub signals:    Vec<SignalConfig>,
   pub thresholds: Vec<ThresholdConfig>,
}

#[derive(Clone, Default)]
pub struct ScoringConfig {
   pub rate_capacity: Option<usize>,
   pub scorecards:    Vec<ScorecardConfig>,
}

/// One verified-crawler provider for forward-confirmed reverse DNS.
#[derive(Clone, PartialEq, Eq, knead_derive::Decode)]
pub struct CrawlerConfig {
   #[knead(argument)]
   pub name:     String,
   /// Lowercase DNS suffixes with a leading dot, matched at label
   /// boundaries.
   #[knead(child, unwrap(arguments))]
   pub suffixes: Vec<String>,
}

/// One configured external renderer. `builtin` is reserved and needs no
/// block.
#[derive(Clone, PartialEq, Eq)]
pub struct RendererConfig {
   pub name:            String,
   pub kind:            String,
   pub endpoint:        String,
   pub timeout:         Duration,
   pub max_body:        usize,
   pub max_concurrency: usize,
   pub rate:            u32,
   pub burst:           u32,
   pub decoy_rate:      u32,
   pub decoy_burst:     u32,
   pub cooldown:        Duration,
}

impl Default for RendererConfig {
   fn default() -> Self {
      Self {
         name:            String::new(),
         kind:            String::new(),
         endpoint:        String::new(),
         timeout:         Duration::from_secs(2),
         max_body:        262_144,
         max_concurrency: 128,
         rate:            50,
         burst:           200,
         decoy_rate:      10,
         decoy_burst:     40,
         cooldown:        Duration::from_mins(1),
      }
   }
}

/// One configured maze. The reserved renderer name `builtin` needs no
/// renderer block.
#[derive(Clone, PartialEq, Eq)]
pub struct MazeConfig {
   pub name:       String,
   pub renderer:   String,
   pub token_ttl:  Duration,
   pub memory_ttl: Duration,
   pub min_links:  u32,
   pub max_links:  u32,
   pub min_bytes:  u32,
   pub max_bytes:  u32,
}

impl Default for MazeConfig {
   fn default() -> Self {
      Self {
         name:       String::new(),
         renderer:   "builtin".to_owned(),
         token_ttl:  Duration::from_hours(24),
         memory_ttl: Duration::from_hours(1),
         min_links:  8,
         max_links:  16,
         min_bytes:  8_192,
         max_bytes:  32_768,
      }
   }
}

/// Parse a duration with an explicit unit, e.g. `"60s"`, `"30m"`, `"24h"`,
/// `"7d"`.
#[must_use]
pub fn parse_duration(text: &str) -> Option<Duration> {
   let unit_at = text.find(|ch: char| !ch.is_ascii_digit())?;
   let value: u64 = text[..unit_at].parse().ok()?;
   let secs = match &text[unit_at..] {
      "s" => value,
      "m" => value.checked_mul(60)?,
      "h" => value.checked_mul(3_600)?,
      "d" => value.checked_mul(86_400)?,
      _ => return None,
   };
   Some(Duration::from_secs(secs))
}

#[derive(Clone, Default)]
pub struct PolicyConfig {
   pub networks:   Vec<NetworkConfig>,
   pub conditions: Vec<ConditionConfig>,
   pub challenges: Vec<ChallengeConfig>,
   pub rules:      Vec<RuleConfig>,
   pub scoring:    Option<ScoringConfig>,
   pub mazes:      Vec<MazeConfig>,
   pub renderers:  Vec<RendererConfig>,
   pub crawlers:   Vec<CrawlerConfig>,
}

impl PolicyConfig {
   /// Merge another policy into this one (appending networks, conditions,
   /// challenges, and rules). Used for `--policy-dir` snippet loading.
   pub fn merge(&mut self, other: Self) {
      self.networks.extend(other.networks);
      self.conditions.extend(other.conditions);
      self.challenges.extend(other.challenges);
      self.rules.extend(other.rules);
      self.mazes.extend(other.mazes);
      self.renderers.extend(other.renderers);
      self.crawlers.extend(other.crawlers);
      if let Some(other_scoring) = other.scoring {
         match self.scoring {
            Some(ref mut scoring) => {
               scoring.scorecards.extend(other_scoring.scorecards);
               if other_scoring.rate_capacity.is_some() {
                  scoring.rate_capacity = other_scoring.rate_capacity;
               }
            },
            None => self.scoring = Some(other_scoring),
         }
      }
   }

   /// Load all `.kdl` files from a directory, parse each as a policy node,
   /// and merge them into a single `PolicyConfig`.
   pub fn load_dir(dir: &Path) -> Result<Self> {
      let mut merged = Self::default();

      let mut entries: Vec<_> = fs::read_dir(dir)
         .and_then(Iterator::collect::<io::Result<Vec<_>>>)
         .map_err(|err| {
            Error::Config(format!(
               "failed to read policy dir {}: {err}",
               dir.display()
            ))
         })?;
      entries.retain(|entry| entry.path().extension().is_some_and(|ext| ext == "kdl"));

      // Sort by filename for deterministic ordering
      entries.sort_by_key(fs::DirEntry::file_name);

      for entry in entries {
         let path = entry.path();
         let text = fs::read_to_string(&path).map_err(|err| {
            Error::Config(format!(
               "failed to read policy file {}: {err}",
               path.display()
            ))
         })?;

         let doc = knead::parse(&text).map_err(|err| {
            Error::ConfigParse {
               path:   path.clone(),
               source: Box::new(err),
            }
         })?;

         // Each snippet file can contain a top-level `policy` node or
         // direct policy children (networks, conditions, challenges, rules)
         for node in doc.nodes() {
            let snippet = if node.name().value() == "policy" {
               Self::from_kdl(node)
            } else {
               Self::from_section(node)
            }
            .map_err(|error| relocate(&text, &path, error))?;
            merged.merge(snippet);
         }

         tracing::debug!(file = %path.display(), "loaded policy snippet");
      }

      Ok(merged)
   }

   pub fn from_kdl(node: &Node) -> Result<Self> {
      let mut policy = Self::default();
      let mut seen = HashSet::new();

      for child in children(node) {
         if !seen.insert(child.name().value()) {
            return Err(Error::config_at(
               child.span().offset(),
               format!("duplicate policy section '{}'", child.name().value()),
            ));
         }
         policy.merge(Self::from_section(child)?);
      }

      Ok(policy)
   }

   fn from_section(node: &Node) -> Result<Self> {
      let mut policy = Self::default();
      let offset = node.span().offset();
      match node.name().value() {
         "networks" => {
            let input: NetworksInput = crate::decode::node(node)?;
            let networks = unique(offset, "network", input.networks, |network| &network.name)?;
            policy.networks = networks
               .into_iter()
               .map(|network| network.into_config(offset))
               .collect::<Result<_>>()?;
         },
         "conditions" => {
            let input: ConditionsInput = crate::decode::node(node)?;
            policy.conditions = unique(offset, "condition", input.conditions, |condition| {
               &condition.name
            })?;
         },
         "challenges" => {
            let input: ChallengesInput = crate::decode::node(node)?;
            let challenges = unique(offset, "challenge", input.challenges, |c| &c.name)?;
            policy.challenges = challenges.into_iter().map(Into::into).collect();
         },
         "rules" => {
            let input: RulesInput = crate::decode::node(node)?;
            let rules = unique(offset, "rule", input.rules, RuleInput::name)?;
            policy.rules = rules.into_iter().map(Into::into).collect();
         },
         "scoring" => {
            let input: ScoringInput = crate::decode::node(node)?;
            let scorecards = unique(offset, "scorecard", input.scorecards, |card| &card.name)?;
            policy.scoring = Some(ScoringConfig {
               rate_capacity: input.rate_capacity,
               scorecards:    scorecards
                  .into_iter()
                  .map(|card| card.into_config(offset))
                  .collect::<Result<_>>()?,
            });
         },
         "mazes" => {
            let input: MazesInput = crate::decode::node(node)?;
            let mazes = unique(offset, "maze", input.mazes, |maze| &maze.name)?;
            policy.mazes = mazes.into_iter().map(Into::into).collect();
         },
         "renderers" => {
            let input: RenderersInput = crate::decode::node(node)?;
            let renderers = unique(offset, "renderer", input.renderers, |r| &r.name)?;
            policy.renderers = renderers.into_iter().map(Into::into).collect();
         },
         "crawlers" => {
            let input: CrawlersInput = crate::decode::node(node)?;
            policy.crawlers = unique(offset, "crawler", input.crawlers, |c| &c.name)?;
         },
         unknown => {
            return Err(Error::config_at(
               offset,
               format!("unknown policy section '{unknown}'"),
            ));
         },
      }
      Ok(policy)
   }
}

/// Reject a repeated name inside a section, reported at the section node.
fn unique<Item>(
   offset: usize,
   what: &str,
   items: Vec<Item>,
   name: impl Fn(&Item) -> &str,
) -> Result<Vec<Item>> {
   let mut seen = HashSet::new();
   for item in &items {
      if !seen.insert(name(item)) {
         return Err(Error::config_at(
            offset,
            format!("duplicate {what} '{}'", name(item)),
         ));
      }
   }
   Ok(items)
}

#[derive(knead_derive::Decode)]
struct NetworksInput {
   #[knead(children(name = "network"))]
   networks: Vec<NetworkInput>,
}

#[derive(knead_derive::Decode)]
struct NetworkInput {
   #[knead(argument)]
   name:    String,
   #[knead(children)]
   sources: Vec<NetworkSourceInput>,
}

#[derive(knead_derive::Decode)]
enum NetworkSourceInput {
   Url {
      #[knead(argument)]
      url:    String,
      #[knead(property)]
      filter: Option<String>,
      #[knead(property)]
      jq:     Option<String>,
      #[knead(property)]
      regex:  Option<String>,
   },
   File {
      #[knead(argument)]
      path:   String,
      #[knead(property)]
      filter: Option<String>,
      #[knead(property)]
      jq:     Option<String>,
      #[knead(property)]
      regex:  Option<String>,
   },
   Asn(#[knead(argument)] u32),
   Prefixes(#[knead(arguments)] Vec<String>),
}

impl NetworkInput {
   fn into_config(self, offset: usize) -> Result<NetworkConfig> {
      let name = self.name;
      let sources = self
         .sources
         .into_iter()
         .map(|source| {
            Ok(match source {
               NetworkSourceInput::Url {
                  url,
                  filter,
                  jq,
                  regex,
               } => {
                  NetworkSource::Url {
                     url,
                     filter: convert_network_filter(offset, &name, filter.as_deref(), jq, regex)?,
                  }
               },
               NetworkSourceInput::File {
                  path,
                  filter,
                  jq,
                  regex,
               } => {
                  NetworkSource::File {
                     path,
                     filter: convert_network_filter(offset, &name, filter.as_deref(), jq, regex)?,
                  }
               },
               NetworkSourceInput::Asn(number) => NetworkSource::Asn(number),
               NetworkSourceInput::Prefixes(prefixes) if prefixes.is_empty() => {
                  return Err(Error::config_at(
                     offset,
                     format!(
                        "policy: networks: network {name:?}: prefixes: expected at least one \
                         prefix"
                     ),
                  ));
               },
               NetworkSourceInput::Prefixes(prefixes) => NetworkSource::Inline(prefixes),
            })
         })
         .collect::<Result<_>>()?;
      Ok(NetworkConfig { name, sources })
   }
}

fn convert_network_filter(
   offset: usize,
   name: &str,
   filter: Option<&str>,
   jq: Option<String>,
   regex: Option<String>,
) -> Result<NetworkFilter> {
   match (filter, jq, regex) {
      (None, None, None) => Ok(NetworkFilter::None),
      (Some("jq"), Some(path), None) => Ok(NetworkFilter::Jq(path)),
      (Some("regex"), None, Some(pattern)) => Ok(NetworkFilter::Regex(pattern)),
      _ => {
         Err(Error::config_at(
            offset,
            format!(
               "policy: networks: network {name:?}: filter must be jq with a jq property or regex \
                with a regex property"
            ),
         ))
      },
   }
}

#[derive(knead_derive::Decode)]
struct ConditionsInput {
   #[knead(children(name = "condition"))]
   conditions: Vec<ConditionConfig>,
}

/// A rhai condition expression. An explicit type annotation on the value may
/// only name `rhai`.
#[derive(Clone)]
pub struct RhaiExpression(String);

impl AsRef<str> for RhaiExpression {
   fn as_ref(&self) -> &str {
      &self.0
   }
}

impl DecodeScalar for RhaiExpression {
   fn type_check(value: &Value) -> std::result::Result<(), DecodeError> {
      if let Some(type_name) = &value.type_name
         && type_name.value != "rhai"
      {
         return Err(DecodeError::new(
            ErrorKind::Type,
            type_name.span,
            "expected a rhai type annotation",
         ));
      }
      Ok(())
   }

   fn decode(value: &Value) -> std::result::Result<Self, DecodeError> {
      Self::type_check(value)?;
      match &value.literal {
         Literal::String(text) => Ok(Self(text.to_string())),
         _ => {
            Err(DecodeError::new(
               ErrorKind::Type,
               value.span,
               "expected a string",
            ))
         },
      }
   }
}

struct ParamValue(String);

impl DecodeScalar for ParamValue {
   fn type_check(_value: &Value) -> std::result::Result<(), DecodeError> {
      Ok(())
   }

   fn decode(value: &Value) -> std::result::Result<Self, DecodeError> {
      match &value.literal {
         Literal::String(text) | Literal::Decimal(text) => Ok(Self(text.to_string())),
         Literal::Integer(number) => Ok(Self(number.to_string())),
         Literal::Bool(flag) => {
            Ok(Self(if *flag {
               "true".to_owned()
            } else {
               "false".to_owned()
            }))
         },
         Literal::Null => {
            Err(DecodeError::new(
               ErrorKind::Unsupported,
               value.span,
               "challenge parameters cannot be null",
            ))
         },
         _ => {
            Err(DecodeError::new(
               ErrorKind::Unsupported,
               value.span,
               "unsupported challenge parameter",
            ))
         },
      }
   }
}

#[derive(knead_derive::Decode)]
struct ChallengesInput {
   #[knead(children(name = "challenge"))]
   challenges: Vec<ChallengeInput>,
}

#[derive(knead_derive::Decode)]
struct ChallengeInput {
   #[knead(argument)]
   name:       String,
   #[knead(property)]
   runtime:    String,
   #[knead(property, default = 7 * 24 * 3_600)]
   duration:   u64,
   #[knead(properties)]
   parameters: HashMap<String, ParamValue>,
}

impl From<ChallengeInput> for ChallengeConfig {
   fn from(input: ChallengeInput) -> Self {
      Self {
         name:          input.name,
         runtime:       input.runtime,
         duration_secs: input.duration,
         parameters:    input
            .parameters
            .into_iter()
            .map(|(key, value)| (key, value.0))
            .collect(),
      }
   }
}

#[derive(knead_derive::Decode)]
struct CrawlersInput {
   #[knead(children(name = "crawler"))]
   crawlers: Vec<CrawlerConfig>,
}

struct DurationArg(pub Duration);

impl FromStr for DurationArg {
   type Err = String;

   fn from_str(text: &str) -> std::result::Result<Self, Self::Err> {
      parse_duration(text)
         .map(Self)
         .ok_or_else(|| format!("invalid duration {text:?}"))
   }
}

#[derive(knead_derive::Decode)]
struct RenderersInput {
   #[knead(children(name = "renderer"))]
   renderers: Vec<RendererInput>,
}

#[derive(knead_derive::Decode)]
struct RendererInput {
   #[knead(argument)]
   name:            String,
   #[knead(property)]
   kind:            String,
   #[knead(child, unwrap(argument), default = RendererConfig::default().endpoint)]
   endpoint:        String,
   #[knead(child, unwrap(argument, str), default = DurationArg(RendererConfig::default().timeout))]
   timeout:         DurationArg,
   #[knead(child, unwrap(argument), default = RendererConfig::default().max_body)]
   max_body:        usize,
   #[knead(child, unwrap(argument), default = RendererConfig::default().max_concurrency)]
   max_concurrency: usize,
   #[knead(child, unwrap(argument), default = RendererConfig::default().rate)]
   rate:            u32,
   #[knead(child, unwrap(argument), default = RendererConfig::default().burst)]
   burst:           u32,
   #[knead(child, unwrap(argument), default = RendererConfig::default().decoy_rate)]
   decoy_rate:      u32,
   #[knead(child, unwrap(argument), default = RendererConfig::default().decoy_burst)]
   decoy_burst:     u32,
   #[knead(child, unwrap(argument, str), default = DurationArg(RendererConfig::default().cooldown))]
   cooldown:        DurationArg,
}

impl From<RendererInput> for RendererConfig {
   fn from(input: RendererInput) -> Self {
      Self {
         name:            input.name,
         kind:            input.kind,
         endpoint:        input.endpoint,
         timeout:         input.timeout.0,
         max_body:        input.max_body,
         max_concurrency: input.max_concurrency,
         rate:            input.rate,
         burst:           input.burst,
         decoy_rate:      input.decoy_rate,
         decoy_burst:     input.decoy_burst,
         cooldown:        input.cooldown.0,
      }
   }
}

#[derive(knead_derive::Decode)]
struct MazesInput {
   #[knead(children(name = "maze"))]
   mazes: Vec<MazeInput>,
}

#[derive(knead_derive::Decode)]
struct MazeInput {
   #[knead(argument)]
   name:       String,
   #[knead(property, default = MazeConfig::default().renderer)]
   renderer:   String,
   #[knead(child, unwrap(argument, str), default = DurationArg(MazeConfig::default().token_ttl))]
   token_ttl:  DurationArg,
   #[knead(child, unwrap(argument, str), default = DurationArg(MazeConfig::default().memory_ttl))]
   memory_ttl: DurationArg,
   #[knead(child, unwrap(argument), default = MazeConfig::default().min_links)]
   min_links:  u32,
   #[knead(child, unwrap(argument), default = MazeConfig::default().max_links)]
   max_links:  u32,
   #[knead(child, unwrap(argument), default = MazeConfig::default().min_bytes)]
   min_bytes:  u32,
   #[knead(child, unwrap(argument), default = MazeConfig::default().max_bytes)]
   max_bytes:  u32,
}

impl From<MazeInput> for MazeConfig {
   fn from(input: MazeInput) -> Self {
      Self {
         name:       input.name,
         renderer:   input.renderer,
         token_ttl:  input.token_ttl.0,
         memory_ttl: input.memory_ttl.0,
         min_links:  input.min_links,
         max_links:  input.max_links,
         min_bytes:  input.min_bytes,
         max_bytes:  input.max_bytes,
      }
   }
}

#[derive(knead_derive::Decode)]
struct ScoringInput {
   #[knead(property)]
   rate_capacity: Option<usize>,
   #[knead(children(name = "scorecard"))]
   scorecards:    Vec<ScorecardInput>,
}

#[derive(knead_derive::Decode)]
struct ScorecardInput {
   #[knead(argument)]
   name:      String,
   #[knead(property)]
   condition: Option<RhaiExpression>,
   #[knead(property)]
   mode:      Option<String>,
   #[knead(children)]
   entries:   Vec<ScorecardChild>,
}

#[derive(knead_derive::Decode)]
enum ScorecardChild {
   Signal(SignalConfig),
   Threshold(ThresholdInput),
}

impl ScorecardInput {
   fn into_config(self, offset: usize) -> Result<ScorecardConfig> {
      let mut signals = Vec::new();
      let mut thresholds = Vec::new();
      for entry in self.entries {
         match entry {
            ScorecardChild::Signal(signal) => signals.push(signal),
            ScorecardChild::Threshold(threshold) => thresholds.push(threshold.into()),
         }
      }
      let signals = unique(offset, "signal", signals, |signal| &signal.name)?;
      Ok(ScorecardConfig {
         name: self.name,
         condition: self.condition,
         mode: self.mode,
         signals,
         thresholds,
      })
   }
}

#[derive(knead_derive::Decode)]
struct RulesInput {
   #[knead(children(name = "rule"))]
   rules: Vec<RuleInput>,
}
