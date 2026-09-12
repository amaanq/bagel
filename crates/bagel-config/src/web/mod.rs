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

/// One validated `challenge-template` override, e.g. `accent "#b16286"`.
///
/// Values are restricted at load so rendering them into a `style` attribute
/// cannot smuggle extra declarations: colors must be hex, lengths must be
/// plain, and the font stack may not contain declaration-breaking characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThemeVar {
   pub name:  String,
   pub value: String,
}

/// Operator theme overrides, applied on top of `challenge-template-theme`.
///
/// Every name is one of the properties `CustomTheme::validate` accepts;
/// anything else is a load error rather than something quietly ignored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CustomTheme {
   pub vars: Vec<ThemeVar>,
}

impl CustomTheme {
   #[must_use]
   pub const fn is_empty(&self) -> bool {
      self.vars.is_empty()
   }

   /// The last value wins, matching how repeated `strings` entries merge.
   #[must_use]
   pub fn get(&self, name: &str) -> Option<&str> {
      self
         .vars
         .iter()
         .rev()
         .find(|var| var.name == name)
         .map(|var| var.value.as_str())
   }

   /// Check one `challenge-template` property and value.
   pub fn validate(name: &str, value: &str) -> Result<()> {
      let ok = match name {
         "fg" | "bg" | "accent" | "card-bg" | "border" | "error" | "title-color" | "link-color" => {
            is_hex_color(value)
         },
         "radius" => is_css_length(value),
         "font" => {
            !value.is_empty()
               && value.bytes().all(|byte| {
                  byte.is_ascii_alphanumeric()
                     || matches!(byte, b' ' | b',' | b'\'' | b'"' | b'-' | b'_')
               })
         },
         "color-scheme" => matches!(value, "light" | "dark"),
         _ => {
            return Err(Error::Config(format!(
               "challenge-template: unknown property {name:?}, expected one of fg, bg, accent, \
                card-bg, border, error, title-color, link-color, radius, font, color-scheme",
            )));
         },
      };
      if ok {
         Ok(())
      } else {
         Err(Error::Config(format!(
            "challenge-template: invalid value {value:?} for property {name:?}",
         )))
      }
   }
}

fn is_hex_color(value: &str) -> bool {
   let digits = value.strip_prefix('#').unwrap_or("");
   matches!(digits.len(), 3 | 4 | 6 | 8) && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_css_length(value: &str) -> bool {
   if value == "0" {
      return true;
   }
   let number = value
      .strip_suffix("px")
      .or_else(|| value.strip_suffix("rem"))
      .or_else(|| value.strip_suffix("em"))
      .or_else(|| value.strip_suffix('%'))
      .unwrap_or("");
   if number.is_empty() {
      return false;
   }
   let mut parts = number.split('.');
   let whole = parts.next().unwrap_or("");
   let valid_whole = !whole.is_empty() && whole.bytes().all(|byte| byte.is_ascii_digit());
   let valid_fraction = parts.next().is_none_or(|fraction| {
      !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit())
   });
   valid_whole && valid_fraction && parts.next().is_none()
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
   /// Operator theme overrides from the `challenge-template` block, applied
   /// on top of the base theme.
   pub challenge_template:       CustomTheme,
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
         challenge_template:       CustomTheme::default(),
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
         "challenge-template" => {
            let list: StringList = decode_node(node)?;
            let mut vars = Vec::with_capacity(list.entries.len());
            for entry in list.entries {
               if let Err(err) = CustomTheme::validate(&entry.key, &entry.value) {
                  return Err(Error::config_at(offset, err.to_string()));
               }
               vars.push(ThemeVar {
                  name:  entry.key,
                  value: entry.value,
               });
            }
            self.challenge_template = CustomTheme { vars };
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

#[cfg(test)]
mod tests {
   use super::*;

   fn parse(text: &str) -> Result<Config> {
      Config::parse(text, Path::new("test.kdl"))
   }

   #[test]
   fn custom_theme_defaults_empty() {
      let config = parse("").unwrap();
      assert!(config.challenge_template.is_empty());
   }

   #[test]
   fn custom_theme_accepts_known_properties() {
      let config = parse(
         r##"challenge-template {
           fg "#ebdbb2"
           bg "#282828"
           accent "#b16286"
           card-bg "#3c3836"
           border "#504945"
           error "#fb4934"
           title-color "#fabd2f"
           link-color "#83a598"
           radius "12px"
           font "Inter, system-ui, sans-serif"
           color-scheme "dark"
         }"##,
      )
      .unwrap();
      let theme = config.challenge_template;
      assert!(!theme.is_empty());
      assert_eq!(theme.get("accent"), Some("#b16286"));
      assert_eq!(theme.get("radius"), Some("12px"));
      assert_eq!(theme.get("font"), Some("Inter, system-ui, sans-serif"));
      assert_eq!(theme.get("color-scheme"), Some("dark"));
      assert_eq!(theme.get("unknown"), None);
   }

   #[test]
   fn custom_theme_rejects_unknown_property() {
      let err = parse("challenge-template { watermark \"x\" }")
         .err()
         .expect("unknown theme properties must be rejected")
         .to_string();
      assert!(err.contains("unknown property"), "{err}");
   }

   #[test]
   fn custom_theme_rejects_bad_values() {
      for (name, value) in [
         ("accent", "red"),
         ("accent", "#12345"),
         ("accent", "#fff; color: red"),
         ("bg", "oklch(0.5 0.1 20)"),
         ("radius", "12"),
         ("radius", "1em;evil:x"),
         ("font", "a;b"),
         ("font", "url(x)"),
         ("color-scheme", "auto"),
      ] {
         let err = parse(&format!("challenge-template {{ {name} \"{value}\" }}"))
            .err()
            .expect("invalid theme values must be rejected")
            .to_string();
         assert!(err.contains("invalid value"), "{name}={value}: {err}");
      }
   }
}
