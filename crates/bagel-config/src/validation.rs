use std::{
   collections::{
      BTreeMap,
      HashSet,
   },
   net::SocketAddr,
};

use bagel_core::{
   Error,
   Result,
};
use ipnetwork::IpNetwork;
use regex::Regex;

use crate::{
   Action,
   BanSchedule,
   Config,
   Detector,
   Listener,
   Source,
   TransportProtocol,
   kdl,
};

pub fn validate_config(config: &Config) -> Result<()> {
   const MAX_TARPIT_SECS: u64 = 24 * 60 * 60;
   kdl::validate_dribble(
      "defense: tarpit",
      config.min_delay_ms,
      config.max_delay_ms,
      config.tarpit_chunk_min_bytes,
      config.tarpit_chunk_max_bytes,
   )?;
   if !(1..=MAX_TARPIT_SECS).contains(&config.max_tarpit_secs) {
      return Err(Error::Config(
         "max_tarpit_secs must be between 1 second and 24 hours".into(),
      ));
   }
   if config.history_retention_secs == 0 {
      return Err(Error::Config(
         "history_retention_secs must be non-zero".into(),
      ));
   }
   for (name, value) in [
      ("max_tarpit_conns", config.max_tarpit_conns),
      ("max_tarpit_conns_per_ip", config.max_tarpit_conns_per_ip),
      ("max_connections", config.max_connections),
   ] {
      if value == 0 {
         return Err(Error::Config(format!("{name} must be non-zero")));
      }
   }
   if config.tarpit_write_timeout_secs == 0 {
      return Err(Error::Config(
         "tarpit_write_timeout_secs must be non-zero".into(),
      ));
   }
   if config.proxy_protocol && config.trusted_proxies.is_empty() {
      return Err(Error::Config(
         "proxy_protocol requires at least one trusted_proxies entry".into(),
      ));
   }
   let mut names = HashSet::new();
   let mut addrs = HashSet::new();
   let mut endpoint_capacity = 0usize;
   for listener in &config.listeners {
      if listener.name().is_empty() || !names.insert(listener.name()) {
         return Err(Error::Config(
            "listener names must be non-empty and unique".into(),
         ));
      }
      if !addrs.insert(listener.listen_addr()) {
         return Err(Error::Config("listener addresses must be unique".into()));
      }
      let cap = listener.max_tarpit_conns(config.max_tarpit_conns);
      if cap == 0 || cap > config.max_connections {
         return Err(Error::Config(format!(
            "listener {} has an invalid max_tarpit_conns",
            listener.name()
         )));
      }
      endpoint_capacity = endpoint_capacity.saturating_add(cap);
      if listener.line_length.is_some_and(|n| n == 0)
         || listener
            .max_tarpit_secs
            .is_some_and(|n| !(1..=MAX_TARPIT_SECS).contains(&n))
         || listener.min_delay_ms.unwrap_or(config.min_delay_ms)
            > listener.max_delay_ms.unwrap_or(config.max_delay_ms)
      {
         return Err(Error::Config(format!(
            "invalid SSH listener {}",
            listener.name()
         )));
      }
   }
   if endpoint_capacity > config.max_connections {
      return Err(Error::Config(
         "sum of listener max_tarpit_conns exceeds max_connections".into(),
      ));
   }
   validate_defense(config)?;
   Ok(())
}

fn validate_defense(config: &Config) -> Result<()> {
   if config.enforcement.table.is_empty()
      || !config
         .enforcement
         .table
         .bytes()
         .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
   {
      return Err(Error::Config(
         "enforcement.table must be a non-empty nftables identifier".into(),
      ));
   }
   if config.enforcement.reconcile_interval_secs == 0 {
      return Err(Error::Config(
         "enforcement.reconcile_interval_secs must be non-zero".into(),
      ));
   }
   for (name, path) in [
      ("database_path", &config.database_path),
      ("journalctl_path", &config.journalctl_path),
      ("nft_path", &config.nft_path),
   ] {
      if path.as_os_str().is_empty() {
         return Err(Error::Config(format!("{name} must not be empty")));
      }
   }

   validate_cidrs("protected_networks", &config.protected_networks)?;
   validate_cidrs("trusted_proxies", &config.trusted_proxies)?;
   validate_cidrs("whitelist_networks", &config.whitelist_networks)?;
   validate_cidrs("no_block_networks", &config.no_block_networks)?;
   for pattern in &config.trap_patterns {
      compile_regex("trap_patterns", "pattern", pattern)?;
   }
   for pattern in &config.trap_user_agents {
      compile_regex("trap_user_agents", "pattern", pattern)?;
   }
   for crawler in &config.verified_crawlers {
      if crawler.ua_pattern.is_empty() {
         return Err(Error::Config(format!(
            "verified_crawlers.{} ua_pattern must not be empty, it would match every agent",
            crawler.name
         )));
      }
      compile_regex(
         &format!("verified_crawlers.{}", crawler.name),
         "ua_pattern",
         &crawler.ua_pattern,
      )?;
      validate_cidrs(
         &format!("verified_crawlers.{}.networks", crawler.name),
         &crawler.networks,
      )?;
   }

   let listener_sources = validate_sources(config)?;
   validate_policies(config, &listener_sources)?;

   Ok(())
}

fn validate_sources(config: &Config) -> Result<BTreeMap<String, String>> {
   let listener_names: HashSet<_> = config.listeners.iter().map(Listener::name).collect();
   let mut listener_sources = BTreeMap::new();
   for (name, source) in &config.sources {
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
         },
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
         },
         Source::AddressSet { path } => {
            if path.as_os_str().is_empty() {
               return Err(Error::Config(format!(
                  "source {name} path must not be empty"
               )));
            }
         },
         Source::Listener { listener } => {
            if !listener_names.contains(listener.as_str()) {
               return Err(Error::Config(format!(
                  "source {name} references unknown listener {listener}"
               )));
            }
            if listener_sources
               .insert(listener.as_str().to_owned(), name.clone())
               .is_some()
            {
               return Err(Error::Config(format!(
                  "listener {listener} has more than one source"
               )));
            }
         },
         Source::Web => {},
      }
   }
   Ok(listener_sources)
}

fn validate_policies(config: &Config, listener_sources: &BTreeMap<String, String>) -> Result<()> {
   for (name, policy) in &config.policies {
      if name.is_empty() {
         return Err(Error::Config("policy names must not be empty".into()));
      }
      if !config.sources.contains_key(&policy.source) {
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
      validate_action(name, &policy.action, &config.listeners)?;
   }

   for listener in &config.listeners {
      let Some(policy_name) = listener.policy() else {
         continue;
      };
      let policy = config.policies.get(policy_name).ok_or_else(|| {
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
      if policy.source != *expected_source {
         return Err(Error::Config(format!(
            "listener {} policy {policy_name} uses source {}, expected {expected_source}",
            listener.name(),
            policy.source
         )));
      }
   }
   Ok(())
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

pub fn validate_detector(policy: &str, detector: &Detector) -> Result<()> {
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
               "policy {policy} context patterns require 1 to 64 context lines and a non-zero \
                window"
            )));
         }
         validate_capture_name(policy, "address_capture", address_capture)?;
         if let Some(capture) = timestamp_capture {
            validate_capture_name(policy, "timestamp_capture", capture)?;
         }
         validate_regex_patterns(
            policy,
            patterns,
            context_patterns,
            address_capture,
            timestamp_capture.as_deref(),
         )?;
         for pattern in ignore_patterns {
            compile_regex(&format!("policy {policy}"), "ignore pattern", pattern)?;
         }
         if let Some(prefilter) = prefilter {
            let regex = compile_regex(&format!("policy {policy}"), "prefilter", prefilter)?;
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
      },
      Detector::Json {
         equals,
         address_pointer,
         timestamp_pointer,
         group_key_pointer,
         timestamp_format,
      } => {
         validate_json_pointer(policy, "address_pointer", address_pointer)?;
         if let Some(pointer) = timestamp_pointer {
            validate_json_pointer(policy, "timestamp_pointer", pointer)?;
         }
         if let Some(pointer) = group_key_pointer {
            validate_json_pointer(policy, "group_key_pointer", pointer)?;
         }
         for pointer in equals.keys() {
            validate_json_pointer(policy, "equals key", pointer)?;
         }
         validate_timestamp_format(policy, timestamp_format.as_deref())?;
      },
   }
   Ok(())
}

fn validate_regex_patterns(
   policy: &str,
   patterns: &[String],
   context_patterns: &[String],
   address_capture: &str,
   timestamp_capture: Option<&str>,
) -> Result<()> {
   for pattern in patterns {
      let regex = compile_regex(&format!("policy {policy}"), "pattern", pattern)?;
      if !regex
         .capture_names()
         .flatten()
         .any(|capture| capture == address_capture)
      {
         return Err(Error::Config(format!(
            "every policy {policy} regex pattern must contain the named address capture \
             {address_capture}"
         )));
      }
      if let Some(capture) = timestamp_capture
         && !regex
            .capture_names()
            .flatten()
            .any(|candidate| candidate == capture)
      {
         return Err(Error::Config(format!(
            "every policy {policy} regex pattern must contain the named timestamp capture \
             {capture}"
         )));
      }
   }
   for pattern in context_patterns {
      let regex = compile_regex(&format!("policy {policy}"), "context pattern", pattern)?;
      if !regex
         .capture_names()
         .flatten()
         .any(|capture| capture == address_capture)
      {
         return Err(Error::Config(format!(
            "every policy {policy} context pattern must contain the named address capture \
             {address_capture}"
         )));
      }
   }
   Ok(())
}

fn compile_regex(scope: &str, field: &str, pattern: &str) -> Result<Regex> {
   Regex::new(pattern).map_err(|error| {
      Error::Config(format!(
         "{scope} has an invalid regex {field} {pattern:?}: {error}"
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
   let Some(candidate) = format else {
      return Ok(());
   };
   let known = matches!(candidate, "rfc3339" | "unix")
      || candidate
         .strip_prefix("strptime:")
         .is_some_and(|rest| !rest.is_empty());
   if !known {
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
         .any(|pair| matches!(pair, [b'~', escape] if !matches!(*escape, b'0' | b'1')))
      || pointer.ends_with('~')
   {
      return Err(Error::Config(format!(
         "policy {policy} {field} must be a non-empty JSON pointer"
      )));
   }
   Ok(())
}

pub fn validate_action(policy: &str, action: &Action, listeners: &[Listener]) -> Result<()> {
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
      },
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

pub fn validate_cidrs(field: &str, cidrs: &[String]) -> Result<()> {
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
