use std::{
   collections::HashMap,
   path::Path,
   sync::Arc,
   time::Duration,
};

use arc_swap::{
   ArcSwap,
   ArcSwapOption,
};
use bagel_deception::Deceiver;
use bagel_runtime::WebOffenseSource;
use hyper_util::client::legacy::{
   Client,
   connect::HttpConnector,
};
use rhai::Engine;
use ring::{
   rand::SystemRandom,
   signature::{
      Ed25519KeyPair,
      KeyPair as _,
   },
};
use tokio::sync::Semaphore;

use crate::{
   SourceNetwork,
   body::Body,
   cache::FileCache,
   challenge::ChallengeRegistry,
   config::{
      Config,
      CustomTheme,
   },
   error,
   maze::{
      self,
      MazeTable,
      memory::{
         self as poison_memory,
         PoisonStore,
      },
      renderer::ExternalRenderer,
   },
   net::{
      IpNetTrie,
      decay_map::DecayMap,
      loader::load_networks,
      rate::RateTracker,
   },
   proxy::{
      self,
      backend::BackendPool,
   },
   rule::{
      RuleState,
      action::Action,
      condition,
      scoring::ScoringState,
   },
   tag_fetcher::HtmlTag,
   template::Theme,
   tls::validate_bind,
};
#[cfg(feature = "fcrdns")]
use crate::{
   config::policy::CrawlerConfig,
   crawler::{
      CrawlerVerifier,
      SystemDns,
   },
};

static POLICY_REVISION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Immutable state snapshot. Swapped atomically via `ArcSwap` on reload.
pub struct StateInner {
   pub config:  Config,
   pub policy:  Policy,
   pub runtime: Runtime,
   pub keys:    Keys,
   pub hooks:   Arc<Hooks>,
}

/// What the operator configured, compiled.
pub struct Policy {
   pub rules:                Vec<RuleState>,
   pub scoring:              Option<ScoringState>,
   pub challenges:           ChallengeRegistry,
   pub networks:             HashMap<String, Arc<IpNetTrie>>,
   pub client_ip:            bagel_proto::ClientIpPolicy,
   pub revision:             u64,
   /// Per-host maze tables for exact backend hosts, built and
   /// collision-checked at load.
   pub maze_tables:          HashMap<String, Arc<MazeTable>>,
   /// Lazily built tables for hosts accepted through wildcard backends.
   /// `None` marks a host refused for a route prefix collision.
   pub wildcard_maze_tables: std::sync::Mutex<HashMap<String, Option<Arc<MazeTable>>>>,
}

/// Live machinery that survives reloads when its config is unchanged.
pub struct Runtime {
   pub backends:         BackendPool,
   pub http_client:      Client<HttpConnector, Body>,
   pub rhai_engine:      Engine,
   /// Shared across reloads unless the configured capacity changes.
   pub rate_tracker:     Arc<RateTracker>,
   /// Shared across reloads when its inputs are unchanged.
   pub poison:           Arc<PoisonStore>,
   /// Carried across reloads when the renderer config is unchanged.
   pub renderers:        HashMap<String, Arc<ExternalRenderer>>,
   /// Carried across reloads when the crawler config is unchanged.
   #[cfg(feature = "fcrdns")]
   pub crawler_verifier: Option<Arc<CrawlerVerifier>>,
   /// Carried across reloads when the deception config is unchanged.
   pub deceiver:         Arc<Deceiver>,
   /// Carried across reloads when max-concurrent is unchanged.
   pub smear_slots:      Arc<Semaphore>,
   pub theme:            Theme,
   /// Operator `challenge-template` overrides, cloned from config at load.
   pub custom_theme:     CustomTheme,
   pub file_cache:       Option<FileCache>,
   pub tag_cache:        DecayMap<String, Vec<HtmlTag>>,
}

/// Key material, fixed for the life of the seed.
pub struct Keys {
   pub signing_key:      Ed25519KeyPair,
   /// PKCS8 seed bytes, kept so we can reconstruct the keypair on reload.
   pub pkcs8_seed:       Vec<u8>,
   /// Raw public key bytes (32 bytes) for signature verification.
   pub public_key_bytes: Vec<u8>,
   pub key_fingerprint:  [u8; 32],
   pub poison_master:    [u8; 32],
   pub seed_persistent:  bool,
}

/// Handles the host daemon attaches once, shared across reloads.
#[derive(Default)]
pub struct Hooks {
   pub offenses:   ArcSwapOption<WebOffenseSource>,
   /// Bagel's signature classifier, attached by the daemon and exposed to
   /// conditions as the `trap` map.
   pub classifier: ArcSwapOption<bagel_traps::Classifier>,
   /// Active defense leases, attached by the daemon and exposed to conditions
   /// as `lease`.
   pub leases:     ArcSwapOption<bagel_runtime::ActiveLeases>,
}

struct Compiled {
   rhai_engine:       Engine,
   rules:             Vec<RuleState>,
   backends:          BackendPool,
   scoring:           Option<ScoringState>,
   challenges:        ChallengeRegistry,
   #[cfg(feature = "fcrdns")]
   crawler_providers: Vec<CrawlerConfig>,
   client_ip:         bagel_proto::ClientIpPolicy,
}

fn compile(config: &Config, seed_persistent: bool) -> error::Result<Compiled> {
   validate_bind(&config.bind)?;
   let rhai_engine = condition::build_engine();
   let named_conditions: HashMap<String, String> = config
      .policy
      .conditions
      .iter()
      .map(|cond| (cond.name.clone(), cond.expr.as_ref().to_owned()))
      .collect();
   let rules = RuleState::build_rules(
      &config.policy.rules,
      &rhai_engine,
      &named_conditions,
      config.challenge_http_code,
      "",
   )?;
   let backends = BackendPool::build(&config.backends)?;
   crate::state_validation::validate_proxy_backends(&rules, &backends)?;
   let scoring = config
      .policy
      .scoring
      .as_ref()
      .map(|scoring_config| {
         ScoringState::build(
            scoring_config,
            &rhai_engine,
            &named_conditions,
            config.challenge_http_code,
         )
      })
      .transpose()?;
   if let Some(ref scoring) = scoring {
      for card in &scoring.scorecards {
         for threshold in &card.thresholds {
            if let crate::rule::action::Action::Proxy { ref backend, .. } = threshold.action
               && backends.by_name(backend).is_none()
            {
               return Err(error::Error::Config(format!(
                  "scorecard '{}': threshold {} references unknown backend '{backend}'",
                  card.name, threshold.value
               )));
            }
         }
      }
   }
   crate::state_validation::validate_renderers(config)?;
   bagel_config::validate_web_trust(config)?;
   let client_ip = bagel_proto::ClientIpPolicy::new(
      config.client_ip_header.clone(),
      config.trusted_proxies.as_deref(),
   )
   .map_err(|err| error::Error::Config(format!("trusted-proxies: {err}")))?;
   #[cfg(feature = "fcrdns")]
   let crawler_providers = if config.policy.crawlers.is_empty() {
      Vec::new()
   } else {
      crate::state_validation::normalize_crawler_providers(config)?
   };
   #[cfg(not(feature = "fcrdns"))]
   if !config.policy.crawlers.is_empty() {
      return Err(error::Error::Config(
         "crawlers need the 'fcrdns' feature, which this build lacks, so no crawler would ever \
          verify"
            .into(),
      ));
   }
   config.deception.validate()?;
   config.smear.validate()?;
   crate::state_validation::validate_mazes(config, seed_persistent)?;
   crate::state_validation::validate_tarpit_references(
      &rules,
      scoring.as_ref(),
      &config.policy.mazes,
   )?;
   let challenges = ChallengeRegistry::build(&config.policy.challenges)?;
   validate_challenge_references(&rules, scoring.as_ref(), &challenges)?;
   Ok(Compiled {
      rhai_engine,
      rules,
      backends,
      scoring,
      challenges,
      #[cfg(feature = "fcrdns")]
      crawler_providers,
      client_ip,
   })
}

fn validate_challenge_references(
   rules: &[RuleState],
   scoring: Option<&ScoringState>,
   registry: &ChallengeRegistry,
) -> error::Result<()> {
   fn validate_action(
      action: &Action,
      site: &str,
      registry: &ChallengeRegistry,
   ) -> error::Result<()> {
      let (challenge_action, check) = match action {
         Action::Challenge(challenge_action) => (challenge_action, false),
         Action::Check(challenge_action) => (challenge_action, true),
         _ => return Ok(()),
      };
      for name in &challenge_action.challenges {
         let registration = registry.get(name).ok_or_else(|| {
            error::Error::Config(format!("{site} references unknown challenge '{name}'"))
         })?;
         if check
            && registration.class == crate::challenge::types::ChallengeClass::Blocking
            && !registration.runtime.supports_background()
         {
            return Err(error::Error::Config(format!(
               "{site} uses blocking challenge '{name}' with check"
            )));
         }
      }
      Ok(())
   }

   fn walk(rules: &[RuleState], registry: &ChallengeRegistry) -> error::Result<()> {
      for rule in rules {
         validate_action(&rule.action, &format!("rule '{}'", rule.name), registry)?;
         walk(&rule.children, registry)?;
      }
      Ok(())
   }

   walk(rules, registry)?;
   if let Some(scoring) = scoring {
      for card in &scoring.scorecards {
         for threshold in &card.thresholds {
            validate_action(
               &threshold.action,
               &format!("scorecard '{}' threshold {}", card.name, threshold.value),
               registry,
            )?;
         }
      }
   }
   Ok(())
}

fn build_renderers(
   config: &Config,
   prev: Option<&StateInner>,
   deceiver: &Arc<Deceiver>,
) -> error::Result<HashMap<String, Arc<ExternalRenderer>>> {
   let mut renderers = HashMap::new();
   for renderer_config in &config.policy.renderers {
      let carried = prev.and_then(|prev| {
         prev
            .runtime
            .renderers
            .get(&renderer_config.name)
            .filter(|existing| {
               existing.config == *renderer_config
                  && (renderer_config.kind != "markov"
                     || Arc::ptr_eq(&prev.runtime.deceiver, deceiver))
            })
            .map(Arc::clone)
      });
      let renderer = match carried {
         Some(renderer) => renderer,
         None if renderer_config.kind == "markov" => {
            Arc::new(ExternalRenderer::markov(
               renderer_config.clone(),
               Arc::clone(deceiver),
            ))
         },
         None => {
            Arc::new(ExternalRenderer::new(renderer_config.clone()).map_err(error::Error::Config)?)
         },
      };
      renderers.insert(renderer_config.name.clone(), renderer);
   }
   Ok(renderers)
}

fn build_maze_tables(
   poison_master: &[u8; 32],
   config: &Config,
) -> error::Result<HashMap<String, Arc<MazeTable>>> {
   let mut maze_tables = HashMap::new();
   if !config.policy.mazes.is_empty() {
      for backend in &config.backends {
         if backend.name == "*" || backend.name.starts_with("*.") {
            continue;
         }
         let host = crate::host::CanonicalHost::parse(&backend.name)
            .map_err(|err| error::Error::Config(format!("backend '{}': {err}", backend.name)))?;
         let table = maze::build_table(poison_master, host.as_str(), &config.policy.mazes)
            .map_err(error::Error::Config)?;
         maze_tables.insert(host.as_str().to_owned(), Arc::new(table));
      }
   }
   Ok(maze_tables)
}

impl StateInner {
   /// Resolve the client IP from the peer and configured forwarding header.
   #[must_use]
   pub fn client_ip(&self, peer: std::net::IpAddr, headers: &http::HeaderMap) -> std::net::IpAddr {
      let Some(name) = self.policy.client_ip.header_name() else {
         return self.policy.client_ip.resolve(peer, None);
      };
      let joined = headers
         .get_all(name)
         .iter()
         .filter_map(|value| value.to_str().ok())
         .collect::<Vec<_>>()
         .join(", ");
      self
         .policy
         .client_ip
         .resolve(peer, (!joined.is_empty()).then_some(joined.as_str()))
   }

   /// Build a new state from config, generating a fresh ephemeral Ed25519
   /// keypair. Maze support requires a persistent seed and fails here.
   pub async fn build(config: Config) -> error::Result<Self> {
      let rng = SystemRandom::new();
      let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
         .map_err(|_| error::Error::Config("failed to generate Ed25519 keypair".into()))?;
      Self::rebuild(config, pkcs8.as_ref().to_vec(), false, None).await
   }

   /// Build with an operator-supplied PKCS8 seed, which is persistent by
   /// definition.
   pub async fn build_with_seed(config: Config, pkcs8_seed: Vec<u8>) -> error::Result<Self> {
      Self::rebuild(config, pkcs8_seed, true, None).await
   }

   /// Build a fresh snapshot, carrying state that remains valid across reloads.
   pub async fn rebuild(
      config: Config,
      pkcs8_seed: Vec<u8>,
      seed_persistent: bool,
      prev: Option<&Self>,
   ) -> error::Result<Self> {
      let Compiled {
         rhai_engine,
         rules,
         backends,
         scoring,
         challenges,
         #[cfg(feature = "fcrdns")]
         crawler_providers,
         client_ip,
      } = compile(&config, seed_persistent)?;
      let signing_key = Ed25519KeyPair::from_pkcs8(&pkcs8_seed)
         .map_err(|_| error::Error::Config("invalid Ed25519 PKCS8 seed".into()))?;
      let public_key_bytes = signing_key.public_key().as_ref().to_vec();

      let http_client = proxy::build_http_client();

      let key_fingerprint: [u8; 32] =
         ring::digest::digest(&ring::digest::SHA256, &public_key_bytes)
            .as_ref()
            .try_into()
            .expect("sha256 output is 32 bytes");

      let rate_capacity = scoring
         .as_ref()
         .map_or(crate::net::rate::DEFAULT_CAPACITY, |scoring| {
            scoring.rate_capacity
         });
      let rate_tracker = prev
         .map(|prev| Arc::clone(&prev.runtime.rate_tracker))
         .filter(|tracker| tracker.capacity() == rate_capacity)
         .unwrap_or_else(|| Arc::new(RateTracker::new(rate_capacity)));

      let policy_revision = POLICY_REVISION.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;

      let deceiver = prev
         .filter(|prev| prev.config.deception == config.deception)
         .map_or_else(
            || {
               let corpora = config
                  .deception
                  .corpora
                  .as_deref()
                  .unwrap_or_else(|| Path::new("/nonexistent"));
               let scripts = config
                  .deception
                  .scripts
                  .as_deref()
                  .unwrap_or_else(|| Path::new("/nonexistent"));
               Arc::new(Deceiver::new(
                  corpora,
                  scripts,
                  &config.deception.server,
                  config.deception.not_found_pct,
                  config.deception.forbidden_pct,
               ))
            },
            |prev| Arc::clone(&prev.runtime.deceiver),
         );
      let smear_slots = prev
         .filter(|prev| prev.config.smear.max_concurrent == config.smear.max_concurrent)
         .map_or_else(
            || {
               Arc::new(Semaphore::new(
                  config.smear.max_concurrent.min(Semaphore::MAX_PERMITS),
               ))
            },
            |prev| Arc::clone(&prev.runtime.smear_slots),
         );
      let hooks = prev.map_or_else(
         || Arc::new(Hooks::default()),
         |prev| Arc::clone(&prev.hooks),
      );

      let renderers = build_renderers(&config, prev, &deceiver)?;
      let poison_master = maze::keys::poison_master(&pkcs8_seed);

      let maze_tables = build_maze_tables(&poison_master, &config)?;
      #[cfg(feature = "fcrdns")]
      let crawler_verifier = if config.policy.crawlers.is_empty() {
         None
      } else {
         let carried = prev.and_then(|prev| {
            prev
               .runtime
               .crawler_verifier
               .as_ref()
               .filter(|_| prev.config.policy.crawlers == config.policy.crawlers)
               .map(Arc::clone)
         });
         if let Some(verifier) = carried {
            Some(verifier)
         } else {
            let dns = SystemDns::new().map_err(error::Error::Config)?;
            Some(Arc::new(CrawlerVerifier::new(
               crawler_providers,
               Arc::new(dns),
            )))
         }
      };

      let file_cache = config.cache_dir.as_ref().and_then(|dir| {
         match FileCache::new(dir.into(), Duration::from_hours(24)) {
            Ok(fc) => Some(fc),
            Err(err) => {
               tracing::warn!(error = %err, "failed to initialize file cache");
               None
            },
         }
      });

      let networks = load_networks(&config.policy.networks, file_cache.as_ref()).await?;

      let theme = Theme::from(config.challenge_template_theme.as_deref());
      let custom_theme = config.challenge_template.clone();

      let tag_cache = DecayMap::new(Duration::from_hours(1));

      let poison = prev.map_or_else(
         || Arc::new(PoisonStore::new()),
         |prev| {
            let carried = Arc::clone(&prev.runtime.poison);
            for old in &prev.config.policy.mazes {
               let retained = config
                  .policy
                  .mazes
                  .iter()
                  .any(|new| new.name == old.name && new.memory_ttl == old.memory_ttl);
               if !retained {
                  carried.purge_maze(&old.name);
               }
            }
            carried
         },
      );

      Ok(Self {
         config,
         policy: Policy {
            rules,
            scoring,
            challenges,
            networks,
            client_ip,
            revision: policy_revision,
            maze_tables,
            wildcard_maze_tables: std::sync::Mutex::new(HashMap::new()),
         },
         runtime: Runtime {
            backends,
            http_client,
            rhai_engine,
            rate_tracker,
            poison,
            renderers,
            #[cfg(feature = "fcrdns")]
            crawler_verifier,
            deceiver,
            smear_slots,
            theme,
            custom_theme,
            file_cache,
            tag_cache,
         },
         keys: Keys {
            signing_key,
            pkcs8_seed,
            public_key_bytes,
            key_fingerprint,
            poison_master,
            seed_persistent,
         },
         hooks,
      })
   }

   /// Resolve the maze table for a canonical host. Wildcard entries cache on
   /// first use, and collisions fail.
   pub fn maze_lookup(&self, canonical_host: &str) -> MazeLookup {
      if self.config.policy.mazes.is_empty() {
         return MazeLookup::NoMazes;
      }
      if let Some(table) = self.policy.maze_tables.get(canonical_host) {
         return MazeLookup::Table(Arc::clone(table));
      }

      let mut cache = self
         .policy
         .wildcard_maze_tables
         .lock()
         .unwrap_or_else(std::sync::PoisonError::into_inner);
      if let Some(cached) = cache.get(canonical_host) {
         return cached.as_ref().map_or(MazeLookup::Refused, |table| {
            MazeLookup::Table(Arc::clone(table))
         });
      }
      if cache.len() >= 4_096 {
         cache.clear();
      }
      match maze::build_table(
         &self.keys.poison_master,
         canonical_host,
         &self.config.policy.mazes,
      ) {
         Ok(table) => {
            let table = Arc::new(table);
            cache.insert(canonical_host.to_owned(), Some(Arc::clone(&table)));
            MazeLookup::Table(table)
         },
         Err(err) => {
            tracing::error!(host = canonical_host, error = err, "maze host refused");
            cache.insert(canonical_host.to_owned(), None);
            MazeLookup::Refused
         },
      }
   }

   pub fn maze_by_name(&self, canonical_host: &str, name: &str) -> Option<Arc<maze::MazeRuntime>> {
      match self.maze_lookup(canonical_host) {
         MazeLookup::Table(table) => table.by_name(name),
         MazeLookup::NoMazes | MazeLookup::Refused => None,
      }
   }

   /// True when any configured maze for this host has an active poison entry
   /// for the source network.
   pub fn poison_returned(&self, canonical_host: &str, source: SourceNetwork) -> bool {
      match self.maze_lookup(canonical_host) {
         MazeLookup::Table(table) => {
            table.by_prefix.values().any(|runtime| {
               let id = poison_memory::memory_id(
                  &runtime.keys.memory_key,
                  canonical_host,
                  &runtime.name,
                  source,
               );
               self.runtime.poison.contains(&id)
            })
         },
         MazeLookup::NoMazes | MazeLookup::Refused => false,
      }
   }
}

pub enum MazeLookup {
   NoMazes,
   Table(Arc<MazeTable>),
   Refused,
}

pub fn validate_config(config: &Config, seed_persistent: bool) -> error::Result<()> {
   compile(config, seed_persistent).map(|_| ())
}

// Static assertion: StateInner must be Send + Sync for shared state.
#[allow(clippy::missing_const_for_fn, clippy::used_underscore_items)]
const _: fn() = || {
   fn assert_send_sync<T: Send + Sync>() {}
   assert_send_sync::<StateInner>();
};

pub type SharedState = Arc<ArcSwap<StateInner>>;

pub async fn new_shared_state(config: Config) -> error::Result<SharedState> {
   let inner = StateInner::build(config).await?;
   Ok(Arc::new(ArcSwap::from_pointee(inner)))
}
