//! Eris daemon entry point: parse config, wire up components, and run the
//! tarpit, metrics, and admin servers until a shutdown signal arrives.

use eris_config::Config;
use eris_deception::Deceiver;
use eris_proto::TrustedProxies;
use eris_runtime::defense::Defense;
use eris_runtime::server::{self, Handles};
use eris_runtime::{Classifier, State, admin, metrics};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// How often background maintenance persists state and prunes the hit map.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(15);

/// Number of Lua VMs to warm at startup.
const LUA_POOL_SIZE: usize = 8;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = eris_config::parse();
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(args.log_level.clone()),
    )
    .format_timestamp_millis()
    .init();

    let config = Config::resolve(&args)?;
    if args.check_config {
        return Ok(());
    }
    config.ensure_dirs()?;
    log::info!(
        "eris starting: listeners={} sources={} policies={} metrics={}",
        config.listeners.len(),
        config.sources.len(),
        config.policies.len(),
        if config.disable_metrics {
            "disabled".to_string()
        } else {
            config.metrics_addr.clone()
        }
    );
    let config = Arc::new(config);

    let state = Arc::new(State::load(&config.data_dir, &config.cache_dir));

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
            &config.git_history_patterns,
            config.git_scan_weight,
            &config.git_expensive_patterns,
            config.git_expensive_weight,
        )?
        .with_crawler_policy(&verified_crawlers, &config.no_block_networks)?,
    );
    let trusted = Arc::new(TrustedProxies::new(&config.trusted_proxies)?);
    let deceiver = Arc::new(Deceiver::new(
        &config.corpora_dir,
        &config.scripts_dir,
        &config.deception_server,
        config.deception_not_found_pct,
        config.deception_forbidden_pct,
        LUA_POOL_SIZE,
    ));
    metrics::register_defense(&config);
    let defense = Defense::open(config.clone())?;
    defense.initialize().await?;
    let endpoint_stats = server::endpoint_stats(&config);

    let started = Instant::now();
    let shutdown = CancellationToken::new();
    let tracker = TaskTracker::new();

    metrics::register_categories();
    metrics::register_endpoints(&config);
    // Force the rate-limiter counter to register so it shows at zero.
    metrics::RATE_TRIPPED.get();
    spawn_signal_listener(shutdown.clone());
    spawn_maintenance(state.clone(), config.clone(), shutdown.clone());
    let mut services = JoinSet::new();
    let service_defense = defense.clone();
    let service_shutdown = shutdown.clone();
    services.spawn(async move {
        service_defense.run(service_shutdown).await?;
        Ok::<_, anyhow::Error>(())
    });

    if !config.disable_metrics {
        let address = config.metrics_addr.clone();
        let service_state = state.clone();
        let service_endpoints = endpoint_stats.clone();
        let service_defense = defense.clone();
        let service_shutdown = shutdown.clone();
        services.spawn(async move {
            metrics::serve(
                address,
                service_state,
                service_endpoints,
                service_defense,
                service_shutdown,
            )
            .await?;
            Ok(())
        });
    }

    if !config.disable_admin {
        let socket = config.admin_socket.clone();
        let service_state = state.clone();
        let service_defense = defense.clone();
        let service_endpoints = endpoint_stats.clone();
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
        config: config.clone(),
        state: state.clone(),
        classifier,
        deceiver,
        defense: defense.clone(),
        trusted,
        pattern_hits: Arc::new(metrics::pattern_counters(&config.trap_patterns)),
        ua_hits: Arc::new(metrics::ua_counters(&config.trap_user_agents)),
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
        .ok_or_else(|| anyhow::anyhow!("eris started no services"))?
        .map_err(anyhow::Error::from)
        .and_then(|result| result);
    shutdown.cancel();

    // Drain in-flight connections, bounded so a stuck tarpit cannot hang exit.
    tracker.close();
    let drain = Duration::from_secs(config.drain_timeout_secs);
    if tokio::time::timeout(drain, tracker.wait()).await.is_err() {
        log::warn!("drain timed out after {drain:?}; abandoning in-flight connections");
    }

    let _ = tokio::time::timeout(drain, async {
        while services.join_next().await.is_some() {}
    })
    .await;

    // Final synchronous flush so nothing is lost on shutdown.
    let flush = state.clone();
    tokio::task::spawn_blocking(move || flush.persist())
        .await
        .ok();
    service_result?;
    log::info!("eris stopped");
    Ok(())
}

/// Cancel the shutdown token on SIGINT or SIGTERM.
fn spawn_signal_listener(shutdown: CancellationToken) {
    tokio::spawn(async move {
        wait_for_signal().await;
        log::info!("shutdown signal received");
        shutdown.cancel();
    });
}

#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("cannot listen for SIGTERM: {e}");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
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

/// Periodically persist state and prune the hit map, and once more on shutdown.
fn spawn_maintenance(state: Arc<State>, config: Arc<Config>, shutdown: CancellationToken) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = tokio::time::sleep(MAINTENANCE_INTERVAL) => {
                    // Pruning sorts up to `max_tracked_ips` entries and persisting
                    // does blocking I/O; keep both off the async worker threads.
                    let state = state.clone();
                    let (ttl, max, threshold) =
                        (config.hit_ttl_secs, config.max_tracked_ips, config.block_threshold);
                    let rate_window = config.rate_limit_window_secs;
                    let _ = tokio::task::spawn_blocking(move || {
                        state.prune(ttl, max, threshold);
                        state.prune_rate(rate_window);
                        state.persist();
                    })
                    .await;
                }
            }
        }
    });
}
