//! Bagel daemon entry point: parse config, wire up components, and run the
//! tarpit, metrics, and admin servers until a shutdown signal arrives.

use std::{
   sync::Arc,
   time::{
      Duration,
      Instant,
   },
};

use bagel_config::{
   Bagel,
   Source,
};
use bagel_proto::TrustedProxies;
use bagel_runtime::{
   Classifier,
   State,
   admin,
   defense::Defense,
   metrics,
   server::{
      self,
      Handles,
   },
};
use tokio::{
   sync::Semaphore,
   task::JoinSet,
};
use tokio_util::{
   sync::CancellationToken,
   task::TaskTracker,
};

#[expect(
   clippy::print_stdout,
   reason = "the generated key seed goes to stdout so an operator can redirect it into a file"
)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
   let args = bagel_config::parse();
   let filter = tracing_subscriber::EnvFilter::try_from_default_env()
      .or_else(|_| tracing_subscriber::EnvFilter::try_new(&args.log_level))
      .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
   tracing_subscriber::fmt().with_env_filter(filter).init();

   if args.generate_key {
      let seed_hex = bagel_web::server::generate_key_seed_hex()
         .map_err(|error| anyhow::anyhow!("{error:#}"))?;
      println!("{seed_hex}");
      return Ok(());
   }

   let bagel = Bagel::resolve(&args)?;
   let seed_hex =
      bagel_web::server::key_seed_hex(args.key_seed.as_deref(), args.key_seed_file.as_deref())
         .map_err(|error| anyhow::anyhow!("{error:#}"))?;
   let web_enabled = !bagel.web.backends.is_empty();
   if !web_enabled
      && (!bagel.web.policy.rules.is_empty()
         || !bagel.web.policy.mazes.is_empty()
         || !bagel.web.policy.challenges.is_empty())
   {
      tracing::warn!("web plane has rules but no backends, so it will not start");
   }
   if args.check_config {
      bagel_web::state::validate_config(&bagel.web, seed_hex.is_some())
         .map_err(|error| anyhow::anyhow!("{error:#}"))?;
      return Ok(());
   }
   let config = bagel.defense;
   let web_config = bagel.web;
   let web = if web_enabled {
      Some(
         bagel_web::server::build_shared(web_config, seed_hex)
            .await
            .map_err(|error| anyhow::anyhow!("{error:#}"))?,
      )
   } else {
      None
   };
   config.ensure_dirs()?;
   tracing::info!(
      "bagel starting: listeners={} sources={} policies={} metrics={}",
      config.listeners.len(),
      config.sources.len(),
      config.policies.len(),
      if config.disable_metrics {
         "disabled".to_owned()
      } else {
         config.metrics_addr.clone()
      }
   );
   let config = Arc::new(config);

   let state = Arc::new(State::new());

   let verified_crawlers: Vec<(String, String, Vec<String>)> = config
      .verified_crawlers
      .iter()
      .map(|c| (c.name.clone(), c.ua_pattern.clone(), c.networks.clone()))
      .collect();
   let classifier = Arc::new(
      Classifier::new(
         &config.trap_patterns,
         &config.trap_user_agents,
         &config.whitelist_networks,
      )?
      .with_crawler_policy(&verified_crawlers, &config.no_block_networks)?,
   );
   let trusted = Arc::new(TrustedProxies::new(&config.trusted_proxies)?);
   let metrics_handle = if config.disable_metrics {
      None
   } else {
      Some(
         metrics_exporter_prometheus::PrometheusBuilder::new()
            .set_buckets_for_metric(
               metrics_exporter_prometheus::Matcher::Full("bagel_scoring_score".to_owned()),
               &bagel_web::metrics::SCORE_BUCKETS,
            )
            .map_err(|error| anyhow::anyhow!("{error:#}"))?
            .install_recorder()
            .map_err(|error| anyhow::anyhow!("{error:#}"))?,
      )
   };
   metrics::describe();
   metrics::register_defense(&config);
   let defense = Defense::open(Arc::clone(&config))?;
   defense.initialize().await?;
   if let Some(web) = &web {
      let web_source = config
         .sources
         .iter()
         .find(|(_, source)| matches!(source, Source::Web))
         .map(|(name, _)| defense.web_source(name))
         .transpose()?;
      if let Some(source) = web_source {
         web.load().hooks.offenses.store(Some(Arc::new(source)));
      } else {
         tracing::warn!("no web source configured, web verdicts will not reach defense");
      }
      web.load()
         .hooks
         .classifier
         .store(Some(Arc::clone(&classifier)));
      web.load().hooks.leases.store(Some(defense.active_leases()));
   }
   let endpoint_stats = server::endpoint_stats(&config);

   let started = Instant::now();
   let shutdown = CancellationToken::new();
   let tracker = TaskTracker::new();

   metrics::register_categories();
   metrics::register_endpoints(&config);
   spawn_signal_listener(shutdown.clone());
   let mut services = JoinSet::new();
   let service_defense = Arc::clone(&defense);
   let service_shutdown = shutdown.clone();
   services.spawn(async move {
      service_defense.run(service_shutdown).await?;
      Ok::<_, anyhow::Error>(())
   });

   if !config.disable_metrics {
      let address = config.metrics_addr.clone();
      let service_endpoints = Arc::clone(&endpoint_stats);
      let service_defense = Arc::clone(&defense);
      let service_shutdown = shutdown.clone();
      let service_handle = metrics_handle
         .clone()
         .expect("metrics recorder was installed");
      services.spawn(async move {
         metrics::serve(
            address,
            service_endpoints,
            service_defense,
            service_handle,
            service_shutdown,
         )
         .await?;
         Ok(())
      });
   }

   if let Some(web) = web.clone() {
      spawn_web_reload(args, Arc::clone(&web));
      let service_shutdown = shutdown.clone();
      services.spawn(async move {
         bagel_web::server::serve(web, service_shutdown)
            .await
            .map_err(|error| anyhow::anyhow!("{error:#}"))?;
         Ok(())
      });
   }

   if !config.disable_admin {
      let socket = config.admin_socket.clone();
      let service_state = Arc::clone(&state);
      let service_defense = Arc::clone(&defense);
      let service_endpoints = Arc::clone(&endpoint_stats);
      let service_shutdown = shutdown.clone();
      services.spawn(async move {
         admin::serve(
            socket,
            service_state,
            service_defense,
            started,
            service_endpoints,
            service_shutdown,
         )
         .await?;
         Ok(())
      });
   }

   let handles = Handles {
      config: Arc::clone(&config),
      state: Arc::clone(&state),
      classifier: Arc::clone(&classifier),
      defense: Arc::clone(&defense),
      trusted,
      conn_slots: Arc::new(Semaphore::new(config.max_connections)),
      endpoint_stats,
   };

   let service_tracker = tracker.clone();
   let service_shutdown = shutdown.clone();
   services.spawn(async move {
      server::run(handles, service_tracker, service_shutdown).await?;
      Ok(())
   });

   let service_result = services
      .join_next()
      .await
      .ok_or_else(|| anyhow::anyhow!("bagel started no services"))?
      .map_err(anyhow::Error::from)
      .and_then(|result| result);
   shutdown.cancel();

   // Drain in-flight connections, bounded so a stuck tarpit cannot hang exit.
   tracker.close();
   let drain = Duration::from_secs(config.drain_timeout_secs);
   if tokio::time::timeout(drain, tracker.wait()).await.is_err() {
      tracing::warn!("drain timed out after {drain:?}; abandoning in-flight connections");
   }

   let drain_result = tokio::time::timeout(drain, drain_services(&mut services))
      .await
      .unwrap_or_else(|_| Err(anyhow::anyhow!("service shutdown exceeded {drain:?}")));

   service_result.and(drain_result)?;
   tracing::info!("bagel stopped");
   Ok(())
}

async fn drain_services(services: &mut JoinSet<anyhow::Result<()>>) -> anyhow::Result<()> {
   let mut result = Ok(());
   while let Some(service) = services.join_next().await {
      let outcome = service
         .map_err(anyhow::Error::from)
         .and_then(|result| result);
      if let Err(error) = &outcome {
         tracing::error!(error = %error, "service failed during shutdown");
      }
      result = result.and(outcome);
   }
   result
}

/// Reload the web plane on SIGHUP while keeping the defense listeners and
/// store.
#[cfg(unix)]
fn spawn_web_reload(args: bagel_config::Args, web: bagel_web::state::SharedState) {
   tokio::spawn(async move {
      let mut hangup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
      {
         Ok(signal) => signal,
         Err(error) => {
            tracing::warn!("cannot listen for SIGHUP: {error}");
            return;
         },
      };
      loop {
         hangup.recv().await;
         match Bagel::resolve(&args) {
            Ok(bagel) => bagel_web::server::reload_shared(bagel.web, &web).await,
            Err(error) => tracing::error!("reload failed: {error}"),
         }
      }
   });
}

#[cfg(not(unix))]
fn spawn_web_reload(_args: bagel_config::Args, _web: bagel_web::state::SharedState) {}

/// Cancel the shutdown token on SIGINT or SIGTERM.
fn spawn_signal_listener(shutdown: CancellationToken) {
   tokio::spawn(async move {
      wait_for_signal().await;
      tracing::info!("shutdown signal received");
      shutdown.cancel();
   });
}

#[cfg(unix)]
async fn wait_for_signal() {
   use tokio::signal::unix::{
      SignalKind,
      signal,
   };
   let mut term = match signal(SignalKind::terminate()) {
      Ok(s) => s,
      Err(e) => {
         tracing::warn!("cannot listen for SIGTERM: {e}");
         let _ = tokio::signal::ctrl_c().await;
         return;
      },
   };
   tokio::select! {
       _ = tokio::signal::ctrl_c() => {}
       _ = term.recv() => {}
   }
}

#[cfg(not(unix))]
async fn wait_for_signal() {
   let _ = tokio::signal::ctrl_c().await;
}
