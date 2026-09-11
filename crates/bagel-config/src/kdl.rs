use std::{
   collections::BTreeMap,
   path::PathBuf,
};

use bagel_core::{
   Error,
   Result,
};
use knead::ast::{
   Document,
   Node,
};

use super::{
   Config,
   Enforcement,
   Listener,
   Source,
   VerifiedCrawler,
};

/// Parse a `defense { }` KDL node into a `Config` starting from defaults.
pub fn parse_defense(node: &Node) -> Result<Config> {
   if node.name().value() != "defense" {
      return Err(Error::config_at(
         node.span().offset(),
         format!("expected defense node, found {:?}", node.name().value()),
      ));
   }
   let input: DefenseInput = crate::decode::node(node)?;
   let offset = node.span().offset();
   let mut sources = BTreeMap::new();
   for named in input.sources.sources {
      if sources.insert(named.name.clone(), named.value.0).is_some() {
         return Err(Error::config_at(
            offset,
            format!("duplicate source {:?}", named.name),
         ));
      }
   }
   let mut policies = BTreeMap::new();
   for named in input.policies.policies {
      if policies
         .insert(named.name.clone(), named.value.into())
         .is_some()
      {
         return Err(Error::config_at(
            offset,
            format!("duplicate policy {:?}", named.name),
         ));
      }
   }
   let defaults = Config::default();
   let verified_crawlers = input
      .verified_crawlers
      .map_or_else(|| defaults.verified_crawlers.clone(), |list| list.crawlers);
   Ok(Config {
      metrics_addr: input.metrics_addr,
      disable_metrics: input.disable_metrics,
      admin_socket: input.admin_socket,
      disable_admin: input.disable_admin,
      listeners: input.listeners.ssh,
      sources,
      policies,
      enforcement: input.enforcement,
      database_path: input.store,
      history_retention_secs: input.history_retention_secs,
      journalctl_path: input.journalctl,
      nft_path: input.nft,
      protected_networks: input.protected_networks,
      min_delay_ms: input.tarpit.min_delay_ms,
      max_delay_ms: input.tarpit.max_delay_ms,
      max_tarpit_secs: input.tarpit.max_tarpit_secs,
      tarpit_chunk_min_bytes: input.tarpit.tarpit_chunk_min_bytes,
      tarpit_chunk_max_bytes: input.tarpit.tarpit_chunk_max_bytes,
      max_tarpit_conns: input.tarpit.max_tarpit_conns,
      max_tarpit_conns_per_ip: input.tarpit.max_tarpit_conns_per_ip,
      tarpit_write_timeout_secs: input.tarpit.tarpit_write_timeout_secs,
      max_connections: input.max_connections,
      drain_timeout_secs: input.drain_timeout_secs,
      proxy_protocol: input.proxy_protocol,
      enable_firewall: input.firewall,
      trap_patterns: input.trap_patterns,
      trap_user_agents: input.trap_user_agents,
      whitelist_networks: input.whitelist_networks,
      verified_crawlers,
      no_block_networks: input.no_block_networks,
      data_dir: input.data_dir,
      cache_dir: input.cache_dir,
      ..defaults
   })
}

#[derive(knead_derive::Decode)]
#[expect(
   clippy::struct_excessive_bools,
   reason = "each flag mirrors one independent KDL toggle, and pairing them into enums would \
             rename the config keys"
)]
struct DefenseInput {
   #[knead(child, unwrap(argument), default = Config::default().metrics_addr)]
   metrics_addr:           String,
   #[knead(child, unwrap(argument), default = Config::default().disable_metrics)]
   disable_metrics:        bool,
   #[knead(child, unwrap(argument), default = Config::default().admin_socket)]
   admin_socket:           PathBuf,
   #[knead(child, unwrap(argument), default = Config::default().disable_admin)]
   disable_admin:          bool,
   #[knead(child, unwrap(argument), default = Config::default().database_path)]
   store:                  PathBuf,
   #[knead(child, unwrap(argument), default = Config::default().history_retention_secs)]
   history_retention_secs: u64,
   #[knead(child, unwrap(argument), default = Config::default().journalctl_path)]
   journalctl:             PathBuf,
   #[knead(child, unwrap(argument), default = Config::default().nft_path)]
   nft:                    PathBuf,
   #[knead(child, unwrap(arguments), default = Config::default().protected_networks)]
   protected_networks:     Vec<String>,
   #[knead(child, unwrap(arguments), default = Config::default().no_block_networks)]
   no_block_networks:      Vec<String>,
   #[knead(child, unwrap(arguments), default = Config::default().whitelist_networks)]
   whitelist_networks:     Vec<String>,
   #[knead(child, unwrap(arguments), default = Config::default().trap_patterns)]
   trap_patterns:          Vec<String>,
   #[knead(child, unwrap(arguments), default = Config::default().trap_user_agents)]
   trap_user_agents:       Vec<String>,
   #[knead(child, unwrap(argument), default = Config::default().max_connections)]
   max_connections:        usize,
   #[knead(child, unwrap(argument), default = Config::default().drain_timeout_secs)]
   drain_timeout_secs:     u64,
   #[knead(child, unwrap(argument), default = Config::default().proxy_protocol)]
   proxy_protocol:         bool,
   #[knead(child, unwrap(argument), default = Config::default().enable_firewall)]
   firewall:               bool,
   #[knead(child, unwrap(argument), default = Config::default().data_dir)]
   data_dir:               PathBuf,
   #[knead(child, unwrap(argument), default = Config::default().cache_dir)]
   cache_dir:              PathBuf,
   #[knead(child, default)]
   tarpit:                 TarpitInput,
   #[knead(child, default)]
   enforcement:            Enforcement,
   #[knead(child)]
   verified_crawlers:      Option<CrawlerList>,
   #[knead(child, default)]
   sources:                SourceList,
   #[knead(child, default)]
   listeners:              ListenerList,
   #[knead(child, default)]
   policies:               PolicyList,
}

#[derive(knead_derive::Decode)]
struct TarpitInput {
   #[knead(property, default = Config::default().min_delay_ms)]
   min_delay_ms:              u64,
   #[knead(property, default = Config::default().max_delay_ms)]
   max_delay_ms:              u64,
   #[knead(property(name = "max-secs"), default = Config::default().max_tarpit_secs)]
   max_tarpit_secs:           u64,
   #[knead(property(name = "chunk-min"), default = Config::default().tarpit_chunk_min_bytes)]
   tarpit_chunk_min_bytes:    usize,
   #[knead(property(name = "chunk-max"), default = Config::default().tarpit_chunk_max_bytes)]
   tarpit_chunk_max_bytes:    usize,
   #[knead(property(name = "write-timeout-secs"), default = Config::default().tarpit_write_timeout_secs)]
   tarpit_write_timeout_secs: u64,
   #[knead(property(name = "max-conns"), default = Config::default().max_tarpit_conns)]
   max_tarpit_conns:          usize,
   #[knead(property(name = "max-conns-per-ip"), default = Config::default().max_tarpit_conns_per_ip)]
   max_tarpit_conns_per_ip:   usize,
}

impl Default for TarpitInput {
   fn default() -> Self {
      let config = Config::default();
      Self {
         min_delay_ms:              config.min_delay_ms,
         max_delay_ms:              config.max_delay_ms,
         max_tarpit_secs:           config.max_tarpit_secs,
         tarpit_chunk_min_bytes:    config.tarpit_chunk_min_bytes,
         tarpit_chunk_max_bytes:    config.tarpit_chunk_max_bytes,
         tarpit_write_timeout_secs: config.tarpit_write_timeout_secs,
         max_tarpit_conns:          config.max_tarpit_conns,
         max_tarpit_conns_per_ip:   config.max_tarpit_conns_per_ip,
      }
   }
}

#[derive(Default, knead_derive::Decode)]
struct CrawlerList {
   #[knead(children(name = "crawler"))]
   crawlers: Vec<VerifiedCrawler>,
}

#[derive(Default, knead_derive::Decode)]
struct SourceList {
   #[knead(children(name = "source"))]
   sources: Vec<crate::decode::Named<crate::decode::Tagged<Source>>>,
}

#[derive(Default, knead_derive::Decode)]
struct ListenerList {
   #[knead(children(name = "ssh"))]
   ssh: Vec<Listener>,
}

#[derive(Default, knead_derive::Decode)]
struct PolicyList {
   #[knead(children(name = "policy"))]
   policies: Vec<crate::decode::Named<crate::decode::defense::PolicyInput>>,
}

pub(crate) fn children<'src>(node: &'src Node<'src>) -> &'src [Node<'src>] {
   node.children().map_or(&[], Document::nodes)
}

pub(crate) fn validate_dribble(
   ctx: &str,
   min_delay_ms: u64,
   max_delay_ms: u64,
   chunk_min: usize,
   chunk_max: usize,
) -> Result<()> {
   if min_delay_ms > max_delay_ms {
      return Err(Error::Config(format!(
         "{ctx}: min-delay-ms exceeds max-delay-ms"
      )));
   }
   if chunk_min == 0 {
      return Err(Error::Config(format!("{ctx}: chunk-min must not be zero")));
   }
   if chunk_min > chunk_max {
      return Err(Error::Config(format!("{ctx}: chunk-min exceeds chunk-max")));
   }
   Ok(())
}

#[cfg(test)]
mod tests {
   use super::*;
   use crate::{
      Action,
      Detector,
   };

   fn defense_node(text: &str) -> Document<'_> {
      knead::parse(text).expect("test KDL parses")
   }

   fn parse_text(text: &str) -> Config {
      let doc = defense_node(text);
      let node = doc
         .nodes()
         .iter()
         .find(|n| n.name().value() == "defense")
         .expect("defense node");
      parse_defense(node).expect("parse succeeds")
   }

   #[expect(
      clippy::panic,
      reason = "a helper that exists to unwrap the error case has no value to return when the \
                parse unexpectedly succeeds"
   )]
   fn parse_text_err(text: &str) -> String {
      let doc = defense_node(text);
      let node = doc
         .nodes()
         .iter()
         .find(|n| n.name().value() == "defense")
         .expect("defense node");
      match parse_defense(node) {
         Ok(_) => panic!("expected an error"),
         Err(Error::Config(message) | Error::ConfigAt { message, .. }) => message,
         Err(other) => panic!("wrong error kind: {other}"),
      }
   }

   #[test]
   fn sparse_defense_doc_keeps_defaults() {
      let config = parse_text(r#"defense { nft "/x/nft" }"#);
      assert_eq!(config.metrics_addr, Config::default().metrics_addr);
      assert_eq!(config.nft_path, PathBuf::from("/x/nft"));
      assert_eq!(config.journalctl_path, Config::default().journalctl_path);
      assert!(config.sources.is_empty());
      assert!(config.policies.is_empty());
      assert!(config.listeners.is_empty());
   }

   #[test]
   fn rejects_unknown_nodes_and_kinds() {
      let message = parse_text_err(r"defense { bogus 1 }");
      assert!(message.contains("bogus"), "{message}");

      let routed = crate::Bagel::parse(r"defense { bogus 1 }", std::path::Path::new("test.kdl"))
         .err()
         .expect("an unknown node under defense should not decode")
         .to_string();
      assert!(routed.contains(":1:"), "{routed}");

      for stale in [
         r#"defense { listen-addr "0.0.0.0:1" }"#,
         r#"defense { backend-addr "127.0.0.1:1" }"#,
         r"defense { block-threshold 3 }",
         r#"defense { real-ip-header "x-forwarded-for" }"#,
         r"defense { hit-ttl-secs 60 }",
         r"defense { max-tracked-ips 10 }",
         r#"defense { deception server="x" }"#,
         r"defense { rate-limit enabled=#true }",
      ] {
         let message = parse_text_err(stale);
         assert!(message.contains("unexpected node"), "{stale}: {message}");
      }

      let message = parse_text_err(r#"defense { sources { source "x" kind="nope" } }"#);
      assert!(message.contains("nope"), "{message}");

      let message = parse_text_err(
         r#"defense { policies { policy "p" source="s" { action kind="observe" } } }"#,
      );
      assert!(message.contains("detector"), "{message}");

      let message = parse_text_err(
         r#"defense { policies { policy "p" source="s" { detector kind="json" address-pointer="/a"; action kind="drop" protocol="tcp" } } }"#,
      );
      assert!(message.contains("ports"), "{message}");

      let message = parse_text_err(r#"defense { listeners { http "web" listen="127.0.0.1:1" } }"#);
      assert!(message.contains("unexpected node"), "{message}");
   }

   #[test]
   fn duplicate_sources_and_policies_are_rejected() {
      let message = parse_text_err(
         r#"defense { sources { source "web" kind="web"; source "web" kind="web" } }"#,
      );
      assert!(message.contains("duplicate"), "{message}");

      let message = parse_text_err(
         r#"defense {
                sources { source "s" kind="web" }
                policies {
                    policy "p" source="s" {
                        detector kind="regex" { pattern "from (?P<address>[0-9.]+)" }
                        action kind="observe"
                    }
                    policy "p" source="s" {
                        detector kind="regex" { pattern "from (?P<address>[0-9.]+)" }
                        action kind="observe"
                    }
                }
            }"#,
      );
      assert!(message.contains("duplicate"), "{message}");
   }

   #[test]
   fn kdl_defense_doc_validates_with_tarpit_defaults() {
      let config = parse_text(
         r#"
defense {
    listeners {
        ssh "ssh" listen="0.0.0.0:22" policy="ssh-abuse"
    }
    sources {
        source "listener-ssh" kind="listener" listener="ssh"
    }
    policies {
        policy "ssh-abuse" source="listener-ssh" {
            detector kind="regex" {
                pattern "(?P<address>[0-9A-Fa-f:.]+)"
            }
            action kind="drop-all"
        }
    }
    enforcement mode="required" table="bagel" chain-priority=-10 reconcile-interval-secs=15
}
"#,
      );
      config.validate().unwrap();
      assert_eq!(config.database_path, Config::default().database_path);
      assert_eq!(config.policies["ssh-abuse"].max_attempts, 7);
   }

   #[test]
   #[expect(
      clippy::panic,
      reason = "each let-else needs a diverging arm, and naming the expected variant beats an \
                opaque unwrap failure"
   )]
   fn parses_every_defense_node() {
      let config = parse_text(
         r#"
defense {
    tarpit min-delay-ms=10 max-delay-ms=20 max-secs=30 chunk-min=40 chunk-max=50 write-timeout-secs=7 max-conns=100 max-conns-per-ip=3
    enforcement mode="observe" table="custom" chain-priority=5 reconcile-interval-secs=30
    verified-crawlers {
        crawler "One" ua-pattern="(?i)Onebot" {
            networks "192.0.2.0/24"
        }
    }
    listeners {
        ssh "ssh" listen="0.0.0.0:22" policy="p-regex" max-tarpit-conns=11 min-delay-ms=12 max-delay-ms=13 max-tarpit-secs=14 line-length=15
    }
    sources {
        source "j" kind="journal" start="beginning" max-entry-bytes=100 {
            match _SYSTEMD_UNIT="sshd.service" SYSLOG_IDENTIFIER="sshd"
        }
        source "f" kind="file" path="/var/log/x" poll-interval-ms=10 max-line-bytes=20
        source "a" kind="address-set" path="/etc/set"
        source "listener-ssh" kind="listener" listener="ssh"
        source "w" kind="web"
    }
    policies {
        policy "p-regex" source="listener-ssh" max-attempts=3 findtime-secs=60 {
            ignore-networks "192.0.2.0/24"
            detector kind="regex" prefilter="(?P<content>failed)" max-context-lines=5 context-window-secs=60 timestamp-capture="ts" timestamp-format="rfc3339" {
                pattern "from (?P<address>[0-9.]+) at (?P<ts>[0-9]+)"
                context-pattern "conn (?P<address>[0-9.]+)"
                ignore-pattern "healthcheck"
            }
            ban duration-secs=600 factor=4 jitter-secs=6 max-duration-secs=7 overall=#true {
                multipliers 4 8
            }
            action kind="observe"
        }
        policy "p-json" source="w" {
            detector kind="json" address-pointer="/address" timestamp-pointer="/ts" timestamp-format="unix" {
                equals "/kind" "smear"
                equals "/app" "web"
            }
            action kind="tarpit-redirect" protocol="tcp" listener="ssh" {
                ports 22
            }
        }
    }
}
"#,
      );
      config.validate().unwrap();
      assert_eq!(config.min_delay_ms, 10);
      assert_eq!(config.tarpit_chunk_max_bytes, 50);
      assert_eq!(config.enforcement.mode, crate::EnforcementMode::Observe);
      assert_eq!(config.enforcement.table, "custom");
      assert_eq!(config.verified_crawlers[0].networks, vec!["192.0.2.0/24"]);
      assert_eq!(config.listeners[0].line_length, Some(15));
      assert_eq!(config.listeners[0].max_tarpit_secs, Some(14));
      let Source::Journal { match_groups, .. } = &config.sources["j"] else {
         panic!("expected a journal source");
      };
      assert_eq!(match_groups[0]["_SYSTEMD_UNIT"], "sshd.service");
      let Source::File {
         poll_interval_ms, ..
      } = &config.sources["f"]
      else {
         panic!("expected a file source");
      };
      assert_eq!(*poll_interval_ms, 10);
      let Source::AddressSet { path } = &config.sources["a"] else {
         panic!("expected an address-set source");
      };
      assert_eq!(path, &PathBuf::from("/etc/set"));
      let Detector::Json {
         equals,
         timestamp_pointer,
         ..
      } = &config.policies["p-json"].detector
      else {
         panic!("expected a json detector");
      };
      assert_eq!(equals["/kind"], "smear");
      assert_eq!(timestamp_pointer.as_deref(), Some("/ts"));
      assert_eq!(config.policies["p-regex"].ban.multipliers, vec![4, 8]);
      let Action::TarpitRedirect {
         ports, listener, ..
      } = &config.policies["p-json"].action
      else {
         panic!("expected a tarpit redirect");
      };
      assert_eq!(*ports, vec![22]);
      assert_eq!(listener, "ssh");
   }
}
