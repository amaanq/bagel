//! Bounded, independently configured HTTP and SSH tarpit endpoints.

use crate::category;
use crate::classify::{self, Classifier, TrapReason, Verdict};
use crate::defense::Defense;
use crate::state::{RateAdmission, State};
use crate::{metrics, proxy, tarpit};
use eris_admin::EndpointStatus;
use eris_config::{Config, Listener};
use eris_deception::Deceiver;
use eris_proto::realip::TrustedProxies;
use eris_proto::{http, proxy_protocol};
use prometheus::Counter;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

const READ_IDLE: Duration = Duration::from_secs(5);
const PROXY_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
const SSH_LINE_LENGTH: usize = 32;

/// Static endpoint identity plus bounded counters. No attacker-controlled labels.
pub struct EndpointStats {
    name: String,
    protocol: String,
    listen_addr: String,
    capacity: usize,
    policy: Option<String>,
    ready: std::sync::atomic::AtomicBool,
    accepted: AtomicU64,
    active: AtomicUsize,
    rejected: AtomicU64,
    closed: AtomicU64,
    bytes_sent: AtomicU64,
    trapped_seconds: AtomicU64,
}

impl EndpointStats {
    fn new(listener: &Listener, capacity: usize) -> Self {
        Self {
            name: listener.name().to_string(),
            protocol: listener.protocol().to_string(),
            listen_addr: listener.listen_addr().to_string(),
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
            protocol: self.protocol.clone(),
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
pub fn endpoint_stats(config: &Config) -> Arc<Vec<Arc<EndpointStats>>> {
    Arc::new(
        config
            .resolved_listeners()
            .iter()
            .map(|l| {
                Arc::new(EndpointStats::new(
                    l,
                    l.max_tarpit_conns(config.max_tarpit_conns),
                ))
            })
            .collect(),
    )
}

#[derive(Clone)]
pub struct Handles {
    pub config: Arc<Config>,
    pub state: Arc<State>,
    pub classifier: Arc<Classifier>,
    pub deceiver: Arc<Deceiver>,
    pub defense: Arc<Defense>,
    pub trusted: Arc<TrustedProxies>,
    pub pattern_hits: Arc<Vec<Counter>>,
    pub ua_hits: Arc<Vec<Counter>>,
    pub conn_slots: Arc<Semaphore>,
    pub endpoint_stats: Arc<Vec<Arc<EndpointStats>>>,
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
        log::info!(
            "endpoint {} ({}) listening on {}",
            listener.name(),
            listener.protocol(),
            listener.listen_addr()
        );
        bound.push((listener, socket, handles.endpoint_stats[index].clone()));
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
            slot = handles.conn_slots.clone().acquire_owned() => match slot { Ok(slot) => slot, Err(_) => break },
        };
        let (stream, peer) = tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = socket.accept() => match accepted { Ok((stream, address)) => (stream, address.ip()), Err(error) => { log::warn!("accept error on {}: {error}", listener.name()); drop(permit); tokio::time::sleep(ACCEPT_BACKOFF).await; continue; } },
        };
        stats.accepted.fetch_add(1, Ordering::Relaxed);
        metrics::endpoint_accepted(listener.name(), listener.protocol());
        let handles = handles.clone();
        let listener = listener.clone();
        let stats = stats.clone();
        let shutdown = shutdown.clone();
        let tarpit_slots = tarpit_slots.clone();
        tracker.spawn(async move {
            handle(
                handles,
                listener,
                stats,
                tarpit_slots,
                shutdown,
                stream,
                peer,
                permit,
            )
            .await;
        });
    }
}

async fn handle(
    handles: Handles,
    listener: Listener,
    stats: Arc<EndpointStats>,
    tarpit_slots: Arc<Semaphore>,
    shutdown: CancellationToken,
    mut stream: TcpStream,
    peer: IpAddr,
    _permit: OwnedSemaphorePermit,
) {
    let _ = stream.set_nodelay(true);
    metrics::CONNECTIONS.inc();
    let mut prefix = Vec::new();
    let mut proxied_ip = None;
    if handles.config.proxy_protocol && handles.trusted.contains(peer) {
        match proxy_protocol::read(&mut stream, PROXY_HEADER_TIMEOUT).await {
            Ok((ip, leftover)) => {
                proxied_ip = ip;
                prefix = leftover;
            }
            Err(error) => {
                log::debug!("PROXY header error from {peer}: {error}");
                return;
            }
        }
    }
    let ip = proxied_ip.unwrap_or(peer);
    match listener {
        Listener::Http { backend_addr, .. } => {
            let backend_addr = backend_addr.unwrap_or_else(|| handles.config.backend_addr.clone());
            handle_http(
                handles,
                stats,
                tarpit_slots,
                shutdown,
                stream,
                peer,
                ip,
                prefix,
                backend_addr,
            )
            .await
        }
        Listener::Ssh {
            min_delay_ms,
            max_delay_ms,
            max_tarpit_secs,
            line_length,
            ..
        } => {
            let min_delay = min_delay_ms.unwrap_or(handles.config.min_delay_ms);
            let max_delay = max_delay_ms.unwrap_or(handles.config.max_delay_ms);
            let max_secs = max_tarpit_secs.unwrap_or(handles.config.max_tarpit_secs);
            trap_ssh(
                handles,
                stats,
                tarpit_slots,
                shutdown,
                stream,
                ip,
                min_delay,
                max_delay,
                max_secs,
                line_length.unwrap_or(SSH_LINE_LENGTH),
            )
            .await;
        }
    }
}

async fn handle_http(
    handles: Handles,
    stats: Arc<EndpointStats>,
    tarpit_slots: Arc<Semaphore>,
    shutdown: CancellationToken,
    mut stream: TcpStream,
    peer: IpAddr,
    proxied_ip: IpAddr,
    prefix: Vec<u8>,
    backend_addr: String,
) {
    let head = match http::read_head_full(
        &mut stream,
        READ_IDLE,
        Duration::from_secs(handles.config.header_timeout_secs),
        prefix,
    )
    .await
    {
        Ok(Some(head)) => head,
        _ => return,
    };
    let client_ip = if handles.config.proxy_protocol {
        proxied_ip
    } else {
        handles
            .trusted
            .client_ip(peer, head.header(&handles.config.real_ip_header))
    };
    let user_agent = head.header("user-agent");
    // Signature traps first (path, then user agent). If nothing fired, the
    // rate limiter gets a say: it charges the request (weighting git-history
    // enumeration heavily) and trips a source that is flooding or scanning.
    let verdict = match handles
        .classifier
        .classify(&head.path, user_agent, client_ip)
    {
        Verdict::Tarpit(reason) => Verdict::Tarpit(reason),
        // A verified crawler already passed classification from a valid range;
        // it must also skip the rate limiter, or a thorough (but legitimate)
        // index crawl would be tarpitted and search coverage would suffer.
        Verdict::Proxy
            if handles.config.enable_rate_limit
                && !handles.classifier.is_whitelisted(client_ip)
                && !handles
                    .classifier
                    .is_verified_crawler(user_agent, client_ip) =>
        {
            let decoded = classify::decode_path(&head.path);
            let cost = handles.classifier.request_cost(&decoded);
            match handles.state.rate_admit(
                client_ip,
                cost,
                handles.config.rate_limit_window_secs,
                handles.config.rate_limit_max_requests,
                handles.config.max_tracked_ips,
            ) {
                RateAdmission::Admitted => Verdict::Proxy,
                RateAdmission::Exceeded | RateAdmission::Full => Verdict::Tarpit(TrapReason::Rate),
            }
        }
        Verdict::Proxy => Verdict::Proxy,
    };
    match verdict {
        Verdict::Proxy => {
            if let Err(error) = proxy::proxy(
                stream,
                &head,
                &backend_addr,
                Duration::from_secs(handles.config.backend_connect_timeout_secs),
                Duration::from_secs(handles.config.proxy_idle_timeout_secs),
            )
            .await
            {
                log::debug!("proxy error for {client_ip}: {error}");
            }
        }
        Verdict::Tarpit(reason) => {
            trap_http(
                handles,
                stats,
                tarpit_slots,
                shutdown,
                stream,
                client_ip,
                &head,
                reason,
            )
            .await
        }
    }
}

async fn trap_http(
    handles: Handles,
    stats: Arc<EndpointStats>,
    tarpit_slots: Arc<Semaphore>,
    shutdown: CancellationToken,
    stream: TcpStream,
    ip: IpAddr,
    head: &http::Head,
    reason: TrapReason,
) {
    let user_agent = head.header("user-agent").unwrap_or("unknown");
    let decoded = classify::decode_path(&head.path);
    // The report category follows why the request was trapped: a path probe
    // keeps its fine-grained signature bucket; a UA trap is a scraper; a rate
    // trip is a flood, or git_scan when the triggering path is git history.
    let category = match reason {
        TrapReason::Path(_) => category::categorize(&decoded),
        TrapReason::UserAgent(_) | TrapReason::Impersonator(_) => category::Category::Scraper,
        TrapReason::Rate if handles.classifier.is_git_history(&decoded) => {
            category::Category::GitScan
        }
        TrapReason::Rate => category::Category::Flood,
    };
    record_hit(&handles, &stats, ip, category, &decoded, user_agent).await;
    match reason {
        TrapReason::Path(idx) => {
            if let Some(counter) = handles.pattern_hits.get(idx) {
                counter.inc();
            }
        }
        TrapReason::UserAgent(idx) => {
            if let Some(counter) = handles.ua_hits.get(idx) {
                counter.inc();
            }
        }
        TrapReason::Rate => metrics::RATE_TRIPPED.inc(),
        TrapReason::Impersonator(idx) => {
            metrics::IMPERSONATORS
                .with_label_values(&[handles.classifier.impersonator_label(idx)])
                .inc();
        }
    }
    let Ok(slot) = tarpit_slots.try_acquire_owned() else {
        reject(&stats, "endpoint_capacity");
        return;
    };
    let Some(_state) = handles
        .state
        .try_enter_tarpit(ip, handles.config.max_tarpit_conns_per_ip)
    else {
        reject(&stats, "per_ip_capacity");
        return;
    };
    let _active = ActiveEndpoint::new(stats.clone());
    let response = handles
        .deceiver
        .response(&head.path, user_agent, category.label());
    let started = Instant::now();
    let bytes = tarpit::tarpit(
        stream,
        response,
        handles.config.min_delay_ms,
        handles.config.max_delay_ms,
        handles.config.max_tarpit_secs,
        handles.config.tarpit_chunk_min_bytes,
        handles.config.tarpit_chunk_max_bytes,
        handles.config.tarpit_write_timeout_secs,
        shutdown,
    )
    .await;
    finish(&stats, started, bytes);
    drop(slot);
}

async fn trap_ssh(
    handles: Handles,
    stats: Arc<EndpointStats>,
    tarpit_slots: Arc<Semaphore>,
    shutdown: CancellationToken,
    stream: TcpStream,
    ip: IpAddr,
    min_delay: u64,
    max_delay: u64,
    max_secs: u64,
    line_length: usize,
) {
    if handles.classifier.is_whitelisted(ip) {
        return;
    }
    record_hit(
        &handles,
        &stats,
        ip,
        category::Category::Ssh,
        "ssh",
        "unknown",
    )
    .await;
    let Ok(slot) = tarpit_slots.try_acquire_owned() else {
        reject(&stats, "endpoint_capacity");
        return;
    };
    let Some(_state) = handles
        .state
        .try_enter_tarpit(ip, handles.config.max_tarpit_conns_per_ip)
    else {
        reject(&stats, "per_ip_capacity");
        return;
    };
    let _active = ActiveEndpoint::new(stats.clone());
    let started = Instant::now();
    let bytes = tarpit::ssh(
        stream,
        min_delay,
        max_delay,
        max_secs,
        line_length,
        handles.config.tarpit_write_timeout_secs,
        shutdown,
    )
    .await;
    finish(&stats, started, bytes);
    drop(slot);
}

async fn record_hit(
    handles: &Handles,
    stats: &EndpointStats,
    ip: IpAddr,
    category: category::Category,
    path: &str,
    user_agent: &str,
) {
    metrics::HITS.inc();
    metrics::CATEGORY_HITS
        .with_label_values(&[category.label()])
        .inc();
    metrics::endpoint_hit(&stats.name, &stats.protocol, category.label());
    handles.state.record_hit(ip, category, path, user_agent);
    if let Some(policy) = &stats.policy
        && let Err(error) = handles.defense.record_listener(policy, ip).await
    {
        log::error!("listener policy {policy} failed: {error}");
    }
}

fn reject(stats: &EndpointStats, reason: &str) {
    stats.rejected.fetch_add(1, Ordering::Relaxed);
    metrics::TARPIT_REJECTED.inc();
    metrics::endpoint_rejected(&stats.name, &stats.protocol, reason);
}
fn finish(stats: &EndpointStats, started: Instant, bytes: u64) {
    stats.closed.fetch_add(1, Ordering::Relaxed);
    stats.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    stats
        .trapped_seconds
        .fetch_add(started.elapsed().as_secs(), Ordering::Relaxed);
    metrics::endpoint_closed(
        &stats.name,
        &stats.protocol,
        bytes,
        started.elapsed().as_secs_f64(),
    );
}
struct ActiveEndpoint(Arc<EndpointStats>);
impl ActiveEndpoint {
    fn new(stats: Arc<EndpointStats>) -> Self {
        stats.active.fetch_add(1, Ordering::Relaxed);
        metrics::endpoint_active(&stats.name, &stats.protocol, 1.0);
        Self(stats)
    }
}
impl Drop for ActiveEndpoint {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
        metrics::endpoint_active(&self.0.name, &self.0.protocol, -1.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_status_is_static_and_protocol_aware() {
        let config = Config {
            listeners: vec![
                Listener::Http {
                    name: "web".into(),
                    listen_addr: "127.0.0.1:8080".into(),
                    policy: None,
                    backend_addr: None,
                    max_tarpit_conns: Some(2),
                },
                Listener::Ssh {
                    name: "ssh".into(),
                    listen_addr: "127.0.0.1:2222".into(),
                    policy: None,
                    max_tarpit_conns: Some(3),
                    min_delay_ms: None,
                    max_delay_ms: None,
                    max_tarpit_secs: None,
                    line_length: None,
                },
            ],
            ..Config::default()
        };
        let status = endpoint_stats(&config);
        let rows: Vec<_> = status.iter().map(|endpoint| endpoint.snapshot()).collect();
        assert_eq!(rows[0].protocol, "http");
        assert_eq!(rows[1].protocol, "ssh");
        assert_eq!(rows[1].tarpit_capacity, 3);
    }
}
