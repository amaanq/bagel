pub mod backend;
pub mod bind;
pub mod policy;

use std::{
   collections::{
      HashMap,
      HashSet,
   },
   fs,
   hash::BuildHasher,
   path::{
      Path,
      PathBuf,
   },
};

pub use backend::{
   BackendConfig,
   BackendUrl,
};
use bagel_core::{
   Error,
   Result,
};
pub use bind::{
   BindConfig,
   BindNetwork,
   TlsConfig,
};
use knead::ast::Node;
pub use policy::PolicyConfig;

use crate::{
   decode::{
      Argument,
      Arguments,
      node as decode_node,
   },
   kdl::validate_dribble,
};

/// A named link for display on challenge/error pages.
#[derive(Clone, knead_derive::Decode)]
pub struct LinkConfig {
   #[knead(argument)]
   pub name: String,
   #[knead(argument)]
   pub url:  String,
}

#[derive(knead_derive::Decode)]
struct LinkList {
   #[knead(children(name = "link"))]
   links: Vec<LinkConfig>,
}

#[derive(knead_derive::Decode)]
struct BackendList {
   #[knead(children(name = "backend"))]
   backends: Vec<BackendConfig>,
}

#[derive(knead_derive::Decode)]
struct StringEntry {
   #[knead(node_name)]
   key:   String,
   #[knead(argument)]
   value: String,
}

#[derive(knead_derive::Decode)]
struct StringList {
   #[knead(children)]
   entries: Vec<StringEntry>,
}

/// Deceptive page generation backing the `smear` action.
#[derive(Debug, Clone, PartialEq, Eq, knead_derive::Decode)]
pub struct DeceptionConfig {
   #[knead(child, unwrap(argument))]
   pub corpora:       Option<PathBuf>,
   #[knead(child, unwrap(argument))]
   pub scripts:       Option<PathBuf>,
   #[knead(child, unwrap(argument), default = DeceptionConfig::default().server)]
   pub server:        String,
   #[knead(child, unwrap(argument), default = DeceptionConfig::default().not_found_pct)]
   pub not_found_pct: u8,
   #[knead(child, unwrap(argument), default = DeceptionConfig::default().forbidden_pct)]
   pub forbidden_pct: u8,
}

impl Default for DeceptionConfig {
   fn default() -> Self {
      Self {
         corpora:       None,
         scripts:       None,
         server:        "nginx/1.24.0".to_owned(),
         not_found_pct: 20,
         forbidden_pct: 8,
      }
   }
}

impl DeceptionConfig {
   pub fn validate(&self) -> Result<()> {
      if u16::from(self.not_found_pct) + u16::from(self.forbidden_pct) > 100 {
         return Err(Error::Config(
            "deception: not-found-pct plus forbidden-pct exceeds 100".into(),
         ));
      }
      Ok(())
   }
}

/// Pacing and admission limits for `smear` responses.
#[derive(Debug, Clone, PartialEq, Eq, knead_derive::Decode)]
pub struct SmearConfig {
   #[knead(child, unwrap(argument), default = SmearConfig::default().min_delay_ms)]
   pub min_delay_ms:   u64,
   #[knead(child, unwrap(argument), default = SmearConfig::default().max_delay_ms)]
   pub max_delay_ms:   u64,
   #[knead(child, unwrap(argument), default = SmearConfig::default().max_secs)]
   pub max_secs:       u64,
   #[knead(child, unwrap(argument), default = SmearConfig::default().chunk_min)]
   pub chunk_min:      usize,
   #[knead(child, unwrap(argument), default = SmearConfig::default().chunk_max)]
   pub chunk_max:      usize,
   #[knead(child, unwrap(argument), default = SmearConfig::default().max_concurrent)]
   pub max_concurrent: usize,
}

impl Default for SmearConfig {
   fn default() -> Self {
      Self {
         min_delay_ms:   1_000,
         max_delay_ms:   15_000,
         max_secs:       600,
         chunk_min:      64,
         chunk_max:      1_400,
         max_concurrent: 4_096,
      }
   }
}

impl SmearConfig {
   pub fn validate(&self) -> Result<()> {
      const MAX_SECS: u64 = 24 * 60 * 60;
      validate_dribble(
         "smear",
         self.min_delay_ms,
         self.max_delay_ms,
         self.chunk_min,
         self.chunk_max,
      )?;
      if self.max_concurrent == 0 {
         return Err(Error::Config(
            "smear: max-concurrent must not be zero".into(),
         ));
      }
      if !(1..=MAX_SECS).contains(&self.max_secs) {
         return Err(Error::Config(
            "smear: max-secs must be between 1 second and 24 hours".into(),
         ));
      }
      Ok(())
   }
}

/// Top-level bagel configuration parsed from KDL.
#[derive(Clone)]
pub struct Config {
   pub bind:                     BindConfig,
   pub challenge_http_code:      u16,
   pub cache_dir:                Option<String>,
   pub client_ip_header:         Option<String>,
   pub trusted_proxies:          Option<Vec<String>>,
   pub backends:                 Vec<BackendConfig>,
   pub policy:                   PolicyConfig,
   /// Configurable strings for templates (title, message overrides).
   pub strings:                  HashMap<String, String>,
   pub links:                    Vec<LinkConfig>,
   pub challenge_template_logo:  Option<String>,
   /// Template theme: "gruvbox" (default) or "minimal".
   pub challenge_template_theme: Option<String>,
   pub deception:                DeceptionConfig,
   pub smear:                    SmearConfig,
}

impl Default for Config {
   fn default() -> Self {
      Self {
         bind:                     BindConfig::default(),
         challenge_http_code:      418,
         cache_dir:                None,
         client_ip_header:         None,
         trusted_proxies:          None,
         backends:                 Vec::new(),
         policy:                   PolicyConfig::default(),
         strings:                  HashMap::new(),
         links:                    Vec::new(),
         challenge_template_logo:  None,
         challenge_template_theme: None,
         deception:                DeceptionConfig::default(),
         smear:                    SmearConfig::default(),
      }
   }
}

impl Config {
   /// Load config from a KDL file, merging with defaults.
   pub fn load(path: &Path) -> Result<Self> {
      let text = fs::read_to_string(path).map_err(|err| {
         Error::Config(format!(
            "failed to read config file {}: {err}",
            path.display()
         ))
      })?;

      Self::parse(&text, path)
   }

   pub fn parse(text: &str, path: &Path) -> Result<Self> {
      let doc = knead::parse(text).map_err(|err| {
         Error::ConfigParse {
            path:   path.to_owned(),
            source: Box::new(err),
         }
      })?;

      let mut config = Self::default();
      let mut seen = HashSet::new();
      for node in doc.nodes() {
         reject_repeated(&mut seen, node).map_err(|err| crate::relocate(text, path, err))?;
         if !config
            .apply_node(node)
            .map_err(|err| crate::relocate(text, path, err))?
         {
            return Err(crate::relocate(
               text,
               path,
               Error::config_at(
                  node.span().offset(),
                  format!("unknown top-level config key '{}'", node.name().value()),
               ),
            ));
         }
      }
      Ok(config)
   }

   /// Apply one top-level web configuration node.
   pub fn apply_node(&mut self, node: &Node) -> Result<bool> {
      let offset = node.span().offset();
      match node.name().value() {
         "bind" => {
            self.bind = decode_node(node)?;
         },
         "challenge-http-code" => {
            let Argument(code) = decode_node::<Argument<u16>>(node)?;
            if !(100..=999).contains(&code) {
               return Err(Error::config_at(
                  offset,
                  format!("challenge-http-code: {code} is out of range"),
               ));
            }
            self.challenge_http_code = code;
         },
         "client-ip-header" => {
            let Argument(header) = decode_node::<Argument<String>>(node)?;
            self.client_ip_header = Some(header);
         },
         "trusted-proxies" => {
            let Arguments(proxies) = decode_node::<Arguments<String>>(node)?;
            if proxies.is_empty() {
               return Err(Error::config_at(
                  offset,
                  "trusted-proxies: list at least one network or omit the node",
               ));
            }
            self.trusted_proxies = Some(proxies);
         },
         "cache" => {
            let Argument(directory) = decode_node::<Argument<String>>(node)?;
            self.cache_dir = Some(directory);
         },
         "backends" => {
            let list: BackendList = decode_node(node)?;
            self.backends = list.backends;
         },
         "policy" => {
            self.policy = PolicyConfig::from_kdl(node)?;
         },
         "policy-dir" => {
            let Argument(directory) = decode_node::<Argument<String>>(node)?;
            self
               .policy
               .merge(PolicyConfig::load_dir(Path::new(&directory))?);
         },
         "strings" => {
            let list: StringList = decode_node(node)?;
            self.strings.extend(
               list
                  .entries
                  .into_iter()
                  .map(|entry| (entry.key, entry.value)),
            );
         },
         "links" => {
            let list: LinkList = decode_node(node)?;
            if list
               .links
               .iter()
               .any(|link| link.name.is_empty() || link.url.is_empty())
            {
               return Err(Error::config_at(
                  offset,
                  "links: link: name and URL must not be empty",
               ));
            }
            self.links.extend(list.links);
         },
         "challenge-template-theme" => {
            let Argument(theme) = decode_node::<Argument<String>>(node)?;
            if !matches!(theme.as_str(), "gruvbox" | "minimal") {
               return Err(Error::config_at(
                  offset,
                  format!("challenge-template-theme: unknown theme {theme:?}"),
               ));
            }
            self.challenge_template_theme = Some(theme);
         },
         "challenge-template-logo" => {
            let Argument(logo) = decode_node::<Argument<String>>(node)?;
            self.challenge_template_logo = Some(logo);
         },
         "deception" => {
            self.deception = decode_node(node)?;
         },
         "smear" => {
            self.smear = decode_node(node)?;
         },
         _ => return Ok(false),
      }
      Ok(true)
   }
}

/// Every top-level node except `policy-dir` replaces the whole setting, so a
/// second copy would silently discard the first.
pub fn reject_repeated<'a, Hasher: BuildHasher>(
   seen: &mut HashSet<&'a str, Hasher>,
   node: &'a Node,
) -> Result<()> {
   let name = node.name().value();
   if name != "policy-dir" && !seen.insert(name) {
      return Err(Error::config_at(
         node.span().offset(),
         format!("'{name}' may appear only once"),
      ));
   }
   Ok(())
}
