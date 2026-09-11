//! Bounded, independently configured SSH tarpit endpoints.

use std::{
   net::IpAddr,
   sync::{
      Arc,
      atomic::{
         AtomicU64,
         AtomicUsize,
         Ordering,
      },
   },
   time::{
      Duration,
      Instant,
   },
};

use bagel_admin::EndpointStatus;
use bagel_config::{
   Config,
   Listener,
};
use bagel_proto::{
   proxy_protocol,
   realip::TrustedProxies,
};
use metrics::counter;
use tokio::{
   net::{
      TcpListener,
      TcpStream,
   },
   sync::{
      OwnedSemaphorePermit,
      Semaphore,
   },
};
use tokio_util::{
   sync::CancellationToken,
   task::TaskTracker,
};

use crate::{
   category,
   classify::Classifier,
   defense::Defense,
   state::State,
   tarpit,
};

const PROXY_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
const SSH_LINE_LENGTH: usize = 32;

/// Static endpoint identity plus bounded counters. No attacker-controlled
/// labels.
pub struct EndpointStats {
   name:            String,
   listen_addr:     String,
   capacity:        usize,
   policy:          Option<String>,
   ready:           std::sync::atomic::AtomicBool,
   accepted:        AtomicU64,
   active:          AtomicUsize,
   rejected:        AtomicU64,
   closed:          AtomicU64,
   bytes_sent:      AtomicU64,
   trapped_seconds: AtomicU64,
}

impl EndpointStats {
   fn new(listener: &Listener, capacity: usize) -> Self {
      Self {
         name: listener.name().to_owned(),
         listen_addr: listener.listen_addr().to_owned(),
         capacity,
         policy: listener.policy().map(str::to_owned),
         ready: std::sync::atomic::AtomicBool::new(false),
         accepted: AtomicU64::new(0),
         active: AtomicUsize::new(0),
         rejected: AtomicU64::new(0),
         closed: AtomicU64::new(0),
         bytes_sent: AtomicU64::new(0),
         trapped_seconds: AtomicU64::new(0),
      }
   }

   #[must_use]
   pub fn snapshot(&self) -> EndpointStatus {
      let active = self.active.load(Ordering::Relaxed);
      EndpointStatus {
         name: self.name.clone(),
         listen_addr: self.listen_addr.clone(),
         ready: self.ready.load(Ordering::Relaxed),
         accepted: self.accepted.load(Ordering::Relaxed),
         active,
         rejected: self.rejected.load(Ordering::Relaxed),
         closed: self.closed.load(Ordering::Relaxed),
         bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
         trapped_seconds: self.trapped_seconds.load(Ordering::Relaxed),
         tarpit_capacity: self.capacity,
         available_tarpit_capacity: self.capacity.saturating_sub(active),
      }
   }
}

/// Build static endpoint status slots before starting the control socket.
#[must_use]
pub fn endpoint_stats(config: &Config) -> Arc<[Arc<EndpointStats>]> {
   config
      .resolved_listeners()
      .iter()
      .map(|l| {
         Arc::new(EndpointStats::new(
            l,
            l.max_tarpit_conns(config.max_tarpit_conns),
         ))
      })
      .collect()
}

#[derive(Clone)]
pub struct Handles {
   pub config:         Arc<Config>,
   pub state:          Arc<State>,
   pub classifier:     Arc<Classifier>,
   pub defense:        Arc<Defense>,
   pub trusted:        Arc<TrustedProxies>,
   pub conn_slots:     Arc<Semaphore>,
   pub endpoint_stats: Arc<[Arc<EndpointStats>]>,
}

#[derive(Clone)]
struct EndpointCtx {
   handles:      Handles,
   stats:        Arc<EndpointStats>,
   tarpit_slots: Arc<Semaphore>,
   shutdown:     CancellationToken,
}

struct SshPacing {
   min_delay_ms:    u64,
   max_delay_ms:    u64,
   max_tarpit_secs: u64,
   line_length:     usize,
}

impl SshPacing {
   fn resolve(listener: &Listener, config: &Config) -> Self {
      Self {
         min_delay_ms:    listener.min_delay_ms.unwrap_or(config.min_delay_ms),
         max_delay_ms:    listener.max_delay_ms.unwrap_or(config.max_delay_ms),
         max_tarpit_secs: listener.max_tarpit_secs.unwrap_or(config.max_tarpit_secs),
         line_length:     listener.line_length.unwrap_or(SSH_LINE_LENGTH),
      }
   }
}

/// Bind all endpoints, then accept until shutdown. A failed bind starts none.
pub async fn run(
   handles: Handles,
   tracker: TaskTracker,
   shutdown: CancellationToken,
) -> std::io::Result<()> {
   let listeners = handles.config.resolved_listeners();
   let mut bound = Vec::with_capacity(listeners.len());
   for (index, listener) in listeners.into_iter().enumerate() {
      let socket = TcpListener::bind(listener.listen_addr()).await?;
      handles.endpoint_stats[index]
         .ready
         .store(true, Ordering::Relaxed);
      tracing::info!(
         "endpoint {} (ssh) listening on {}",
         listener.name(),
         listener.listen_addr()
      );
      bound.push((listener, socket, Arc::clone(&handles.endpoint_stats[index])));
   }
   for (listener, socket, stats) in bound {
      let handles = handles.clone();
      let shutdown = shutdown.clone();
      let tracker = tracker.clone();
      let child_tracker = tracker.clone();
      tracker.spawn(async move {
         accept_loop(handles, listener, socket, stats, shutdown, child_tracker).await;
      });
   }
   shutdown.cancelled().await;
   for stats in handles.endpoint_stats.iter() {
      stats.ready.store(false, Ordering::Relaxed);
   }
   Ok(())
}

async fn accept_loop(
   handles: Handles,
   listener: Listener,
   socket: TcpListener,
   stats: Arc<EndpointStats>,
   shutdown: CancellationToken,
   tracker: TaskTracker,
) {
   let tarpit_slots = Arc::new(Semaphore::new(
      listener.max_tarpit_conns(handles.config.max_tarpit_conns),
   ));
   loop {
      let permit = tokio::select! {
          () = shutdown.cancelled() => break,
          slot = Arc::clone(&handles.conn_slots).acquire_owned() => match slot { Ok(slot) => slot, Err(_) => break },
      };
      let (stream, peer) = tokio::select! {
          () = shutdown.cancelled() => break,
          accepted = socket.accept() => match accepted { Ok((stream, address)) => (stream, address.ip()), Err(error) => { tracing::warn!("accept error on {}: {error}", listener.name()); drop(permit); tokio::time::sleep(ACCEPT_BACKOFF).await; continue; } },
      };
      stats.accepted.fetch_add(1, Ordering::Relaxed);
      counter!("bagel_endpoint_accepted_total", "endpoint" => listener.name().to_owned())
         .increment(1);
      let ctx = EndpointCtx {
         handles:      handles.clone(),
         stats:        Arc::clone(&stats),
         tarpit_slots: Arc::clone(&tarpit_slots),
         shutdown:     shutdown.clone(),
      };
      let listener = listener.clone();
      tracker.spawn(async move {
         handle(ctx, listener, stream, peer, permit).await;
      });
   }
}

async fn handle(
   ctx: EndpointCtx,
   listener: Listener,
   mut stream: TcpStream,
   peer: IpAddr,
   _permit: OwnedSemaphorePermit,
) {
   let _ = stream.set_nodelay(true);
   counter!("bagel_connections_total").increment(1);
   let mut proxied_ip = None;
   if ctx.handles.config.proxy_protocol && ctx.handles.trusted.contains(peer) {
      match proxy_protocol::read(&mut stream, PROXY_HEADER_TIMEOUT).await {
         Ok((ip, _leftover)) => {
            proxied_ip = ip;
         },
         Err(error) => {
            tracing::debug!("PROXY header error from {peer}: {error}");
            return;
         },
      }
   }
   let ip = proxied_ip.unwrap_or(peer);
   let pacing = SshPacing::resolve(&listener, &ctx.handles.config);
   trap_ssh(ctx, stream, ip, pacing).await;
}

async fn trap_ssh(ctx: EndpointCtx, stream: TcpStream, ip: IpAddr, pacing: SshPacing) {
   if ctx.handles.classifier.is_whitelisted(ip) {
      return;
   }
   record_hit(&ctx.handles, &ctx.stats, ip, category::Category::Ssh).await;
   let Ok(slot) = ctx.tarpit_slots.try_acquire_owned() else {
      reject(&ctx.stats, "endpoint_capacity");
      return;
   };
   let Some(_state) = ctx
      .handles
      .state
      .try_enter_tarpit(ip, ctx.handles.config.max_tarpit_conns_per_ip)
   else {
      reject(&ctx.stats, "per_ip_capacity");
      return;
   };
   let _active = ActiveEndpoint::new(Arc::clone(&ctx.stats));
   let started = Instant::now();
   let bytes = tarpit::ssh(
      stream,
      pacing.min_delay_ms,
      pacing.max_delay_ms,
      pacing.max_tarpit_secs,
      pacing.line_length,
      ctx.handles.config.tarpit_write_timeout_secs,
      ctx.shutdown,
   )
   .await;
   finish(&ctx.stats, started, bytes);
   drop(slot);
}

async fn record_hit(
   handles: &Handles,
   stats: &EndpointStats,
   ip: IpAddr,
   category: category::Category,
) {
   counter!("bagel_hits_total").increment(1);
   counter!("bagel_category_hits_total", "category" => category.label()).increment(1);
   counter!("bagel_endpoint_hits_total", "endpoint" => stats.name.clone(), "category" => category.label()).increment(1);
   if let Some(policy) = &stats.policy
      && let Err(error) = handles.defense.record_listener(policy, ip).await
   {
      tracing::error!("listener policy {policy} failed: {error}");
   }
}

fn reject(stats: &EndpointStats, reason: &str) {
   stats.rejected.fetch_add(1, Ordering::Relaxed);
   counter!("bagel_tarpit_rejected_total").increment(1);
   counter!("bagel_endpoint_rejected_total", "endpoint" => stats.name.clone(), "reason" => reason.to_owned()).increment(1);
}
fn finish(stats: &EndpointStats, started: Instant, bytes: u64) {
   stats.closed.fetch_add(1, Ordering::Relaxed);
   stats.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
   stats
      .trapped_seconds
      .fetch_add(started.elapsed().as_secs(), Ordering::Relaxed);
   counter!("bagel_endpoint_closed_total", "endpoint" => stats.name.clone()).increment(1);
   counter!("bagel_endpoint_sent_bytes_total", "endpoint" => stats.name.clone()).increment(bytes);
   counter!("bagel_endpoint_trapped_seconds_total", "endpoint" => stats.name.clone())
      .increment(started.elapsed().as_secs());
}
struct ActiveEndpoint(Arc<EndpointStats>);
impl ActiveEndpoint {
   fn new(stats: Arc<EndpointStats>) -> Self {
      stats.active.fetch_add(1, Ordering::Relaxed);
      crate::metrics::endpoint_active(&stats.name, 1.0);
      Self(stats)
   }
}
impl Drop for ActiveEndpoint {
   fn drop(&mut self) {
      self.0.active.fetch_sub(1, Ordering::Relaxed);
      crate::metrics::endpoint_active(&self.0.name, -1.0);
   }
}
