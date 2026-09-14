use std::time::Duration;

#[cfg(feature = "fcrdns")]
use crate::config::policy::CrawlerConfig;
use crate::{
   config::{
      Config,
      policy::MazeConfig,
   },
   error,
   maze,
   proxy::backend::BackendPool,
   rule::{
      RuleState,
      action::Action,
      scoring::ScoringState,
   },
};

/// Validate crawler providers and normalize their suffixes to canonical
/// lowercase DNS names with a leading dot, so matches always sit at a label
/// boundary.
#[cfg(feature = "fcrdns")]
pub fn normalize_crawler_providers(config: &Config) -> error::Result<Vec<CrawlerConfig>> {
   let mut names = std::collections::HashSet::new();
   let mut providers = Vec::new();

   for crawler in &config.policy.crawlers {
      if !maze::is_valid_maze_name(&crawler.name) {
         return Err(error::Error::Config(format!(
            "invalid crawler name '{}'",
            crawler.name
         )));
      }
      if !names.insert(crawler.name.as_str()) {
         return Err(error::Error::Config(format!(
            "duplicate crawler '{}'",
            crawler.name
         )));
      }
      if crawler.suffixes.is_empty() {
         return Err(error::Error::Config(format!(
            "crawler '{}' requires at least one DNS suffix",
            crawler.name
         )));
      }

      let mut suffixes = Vec::new();
      for suffix in &crawler.suffixes {
         let host =
            crate::host::CanonicalHost::parse(suffix.trim_start_matches('.')).map_err(|err| {
               error::Error::Config(format!(
                  "crawler '{}': invalid suffix '{suffix}': {err}",
                  crawler.name
               ))
            })?;
         if host.is_ip() {
            return Err(error::Error::Config(format!(
               "crawler '{}': suffix '{suffix}' must be a DNS name",
               crawler.name
            )));
         }
         suffixes.push(format!(".{host}"));
      }

      providers.push(CrawlerConfig {
         name: crawler.name.clone(),
         suffixes,
      });
   }

   Ok(providers)
}

fn validate_renderer_limits(renderer: &crate::config::policy::RendererConfig) -> error::Result<()> {
   let ctx = |msg: String| error::Error::Config(format!("renderer '{}': {msg}", renderer.name));
   if renderer.timeout.is_zero() || renderer.timeout > Duration::from_mins(1) {
      return Err(ctx("timeout must be between 1 and 60 seconds".into()));
   }
   if renderer.cooldown.is_zero() || renderer.cooldown > Duration::from_hours(1) {
      return Err(ctx("cooldown must be between 1 second and 1 hour".into()));
   }
   if !(1_024..=8_388_608).contains(&renderer.max_body) {
      return Err(ctx("max-body must be between 1024 and 8388608".into()));
   }
   if !(1..=4_096).contains(&renderer.max_concurrency) {
      return Err(ctx("max-concurrency must be between 1 and 4096".into()));
   }
   if renderer.rate == 0
      || renderer.burst == 0
      || renderer.decoy_rate == 0
      || renderer.decoy_burst == 0
   {
      return Err(ctx("rates and bursts must be positive".into()));
   }
   Ok(())
}

pub fn validate_renderers(config: &Config) -> error::Result<()> {
   let mut names = std::collections::HashSet::new();
   for renderer in &config.policy.renderers {
      let ctx = |msg: String| error::Error::Config(format!("renderer '{}': {msg}", renderer.name));
      if renderer.name == "builtin" || !maze::is_valid_maze_name(&renderer.name) {
         return Err(error::Error::Config(format!(
            "invalid renderer name '{}'",
            renderer.name
         )));
      }
      if !names.insert(renderer.name.as_str()) {
         return Err(error::Error::Config(format!(
            "duplicate renderer '{}'",
            renderer.name
         )));
      }
      match renderer.kind.as_str() {
         "iocaine" => {},
         "markov" => {
            if !renderer.endpoint.is_empty() {
               return Err(ctx(
                  "markov renderers run in-process and take no endpoint".into(),
               ));
            }
            validate_renderer_limits(renderer)?;
            continue;
         },
         other => return Err(ctx(format!("unknown renderer kind '{other}'"))),
      }

      let uri: http::Uri = renderer
         .endpoint
         .parse()
         .map_err(|err| ctx(format!("invalid endpoint: {err}")))?;
      let scheme_ok = uri
         .scheme_str()
         .is_some_and(|scheme| scheme == "http" || scheme == "https");
      if !scheme_ok {
         return Err(ctx("endpoint must be an HTTP or HTTPS URL".into()));
      }
      let has_credentials = uri
         .authority()
         .is_none_or(|authority| authority.as_str().contains('@'));
      if has_credentials {
         return Err(ctx("endpoint must not contain credentials".into()));
      }

      validate_renderer_limits(renderer)?;
   }
   Ok(())
}

pub fn validate_mazes(config: &Config, seed_persistent: bool) -> error::Result<()> {
   let mazes = &config.policy.mazes;
   if mazes.is_empty() {
      return Ok(());
   }

   let mut names = std::collections::HashSet::new();
   for maze in mazes {
      let ctx = |msg: String| error::Error::Config(format!("maze '{}': {msg}", maze.name));
      if !maze::is_valid_maze_name(&maze.name) {
         return Err(error::Error::Config(format!(
            "invalid maze name '{}'",
            maze.name
         )));
      }
      if !names.insert(maze.name.as_str()) {
         return Err(error::Error::Config(format!(
            "duplicate maze '{}'",
            maze.name
         )));
      }
      if maze.renderer != "builtin"
         && !config
            .policy
            .renderers
            .iter()
            .any(|renderer| renderer.name == maze.renderer)
      {
         return Err(ctx(format!("unknown renderer '{}'", maze.renderer)));
      }
      let token_secs = maze.token_ttl.as_secs();
      if !(60..=7 * 86_400).contains(&token_secs) {
         return Err(ctx(format!(
            "token-ttl {token_secs}s is outside 60 seconds through seven days"
         )));
      }
      if maze.memory_ttl.is_zero() || maze.memory_ttl > Duration::from_hours(8_760) {
         return Err(ctx(
            "memory-ttl must be between 1 second and 365 days".into(),
         ));
      }
      if maze.min_links == 0 || maze.max_links > 64 || maze.min_links > maze.max_links {
         return Err(ctx(format!(
            "link limits {}..{} are outside 1..=64 or inverted",
            maze.min_links, maze.max_links
         )));
      }
      if maze.min_bytes < 1_024 || maze.max_bytes > 1_048_576 || maze.min_bytes > maze.max_bytes {
         return Err(ctx(format!(
            "byte limits {}..{} are outside 1024..=1048576 or inverted",
            maze.min_bytes, maze.max_bytes
         )));
      }
   }

   if !seed_persistent {
      return Err(error::Error::Config(
         "maze support requires a persistent key seed (--key-seed or --key-seed-file), since \
          restarting must never silently change live maze routes"
            .into(),
      ));
   }
   if config.bind.passthrough {
      return Err(error::Error::Config(
         "passthrough and maze support cannot both be enabled".into(),
      ));
   }

   Ok(())
}

fn tarpit_maze_known(maze_name: &str, mazes: &[MazeConfig], site: &str) -> error::Result<()> {
   if mazes.iter().any(|maze| maze.name == maze_name) {
      Ok(())
   } else {
      Err(error::Error::Config(format!(
         "{site}: references unknown maze '{maze_name}'"
      )))
   }
}

pub fn validate_tarpit_references(
   rules: &[RuleState],
   scoring: Option<&ScoringState>,
   mazes: &[MazeConfig],
) -> error::Result<()> {
   fn walk(rules: &[RuleState], mazes: &[MazeConfig]) -> error::Result<()> {
      for rule in rules {
         if let Action::Tarpit { maze } | Action::Lure { maze } = &rule.action {
            tarpit_maze_known(maze, mazes, &format!("rule '{}'", rule.name))?;
         }
         walk(&rule.children, mazes)?;
      }
      Ok(())
   }
   walk(rules, mazes)?;

   if let Some(scoring) = scoring {
      for card in &scoring.scorecards {
         for threshold in &card.thresholds {
            if let Action::Tarpit { maze } = &threshold.action {
               tarpit_maze_known(
                  maze,
                  mazes,
                  &format!("scorecard '{}' threshold {}", card.name, threshold.value),
               )?;
            }
         }
      }
   }

   Ok(())
}

pub fn validate_proxy_backends(rules: &[RuleState], backends: &BackendPool) -> error::Result<()> {
   for rule in rules {
      if let crate::rule::action::Action::Proxy { backend, .. } = &rule.action
         && backends.by_name(backend).is_none()
      {
         return Err(error::Error::Config(format!(
            "rule '{}': proxy action references unknown backend '{backend}'",
            rule.name
         )));
      }
      validate_proxy_backends(&rule.children, backends)?;
   }
   Ok(())
}
