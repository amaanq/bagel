//! Prometheus metrics and a tiny HTTP server exposing `/metrics` and `/status`.

use crate::defense::Defense;
use crate::server::EndpointStats;
use crate::state::State;
use eris_config::Config;
use eris_proto::http;
use prometheus::{
    Counter, CounterVec, Encoder, Gauge, GaugeVec, TextEncoder, register_counter,
    register_counter_vec, register_gauge, register_gauge_vec,
};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

/// Total connections accepted.
pub static CONNECTIONS: LazyLock<Counter> =
    LazyLock::new(|| register_counter!("eris_connections_total", "Connections accepted").unwrap());

/// Total tarpit hits.
pub static HITS: LazyLock<Counter> =
    LazyLock::new(|| register_counter!("eris_hits_total", "Total tarpit hits").unwrap());

/// Tarpit hits by matched trap pattern (bounded cardinality).
pub static PATTERN_HITS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "eris_pattern_hits_total",
        "Tarpit hits by pattern",
        &["pattern"]
    )
    .unwrap()
});

/// Tarpit hits by matched user-agent trap pattern (bounded cardinality).
pub static UA_HITS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "eris_ua_hits_total",
        "Tarpit hits by matched user-agent pattern",
        &["pattern"]
    )
    .unwrap()
});

/// Requests trapped for exceeding the per-IP rate budget.
pub static RATE_TRIPPED: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "eris_rate_tripped_total",
        "Requests tarpitted by the per-IP rate limiter"
    )
    .unwrap()
});

/// Forged-crawler traps, by the crawler whose identity was forged.
pub static IMPERSONATORS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "eris_impersonators_total",
        "Requests forging a verified crawler's user-agent, by crawler",
        &["crawler"]
    )
    .unwrap()
});

/// Threshold-exceeding sources spared a firewall block because they sit in a
/// tarpit-only (shared-infrastructure) network.
pub static NO_BLOCK_SPARED: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "eris_no_block_spared_total",
        "Sources tarpitted past the block threshold but spared a firewall block"
    )
    .unwrap()
});

/// Tarpit hits by report category (fixed, bounded cardinality).
pub static CATEGORY_HITS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "eris_category_hits_total",
        "Tarpit hits by report category",
        &["category"]
    )
    .unwrap()
});

/// Tarpit hits split by static endpoint identity and report category.
pub static ENDPOINT_HITS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "eris_endpoint_hits_total",
        "Tarpit hits by endpoint and category",
        &["endpoint", "protocol", "category"]
    )
    .unwrap()
});

/// Blocklist additions by their bounded origin.
pub static BLOCKS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "eris_blocks_total",
        "IPs newly added to the blocklist",
        &["reason"]
    )
    .unwrap()
});

/// Pre-register every category series so each shows in `/metrics` at zero
/// before its first hit.
pub fn register_categories() {
    for category in crate::category::Category::ALL {
        CATEGORY_HITS.with_label_values(&[category.label()]);
    }
}

/// Connections refused because the tarpit capacity was reached.
pub static TARPIT_REJECTED: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "eris_tarpit_rejected_total",
        "Tarpit connections dropped at capacity"
    )
    .unwrap()
});

/// Pre-resolve one counter per trap pattern so the hot path can increment a
/// cached handle instead of doing a locked label lookup on every hit. Also
/// pre-registers each series so it shows in `/metrics` at zero.
#[must_use]
pub fn pattern_counters(patterns: &[String]) -> Vec<Counter> {
    patterns
        .iter()
        .map(|p| PATTERN_HITS.with_label_values(&[p.as_str()]))
        .collect()
}

/// Pre-resolve one counter per user-agent trap pattern, mirroring
/// [`pattern_counters`], so the hot path increments a cached handle.
#[must_use]
pub fn ua_counters(patterns: &[String]) -> Vec<Counter> {
    patterns
        .iter()
        .map(|p| UA_HITS.with_label_values(&[p.as_str()]))
        .collect()
}

/// Number of IPs currently blocked.
pub static BLOCKED_IPS: LazyLock<Gauge> =
    LazyLock::new(|| register_gauge!("eris_blocked_ips", "IPs currently blocked").unwrap());

/// Whether Eris successfully installed its nftables blocklist.
pub static FIREWALL_READY: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!("eris_firewall_ready", "nftables blocklist is ready").unwrap()
});

pub static SOURCE_RECORDS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "eris_source_records_total",
        "Defense source records by bounded outcome",
        &["source", "outcome"]
    )
    .unwrap()
});

pub static SOURCE_LAG: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        "eris_source_lag_seconds",
        "Age of the most recently processed source record",
        &["source"]
    )
    .unwrap()
});

pub static SOURCE_READY: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        "eris_source_ready",
        "Whether a configured defense source is live",
        &["source"]
    )
    .unwrap()
});

pub static POLICY_MATCHES: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "eris_policy_matches_total",
        "Detector matches by static policy and disposition",
        &["policy", "disposition"]
    )
    .unwrap()
});

pub static ACTIVE_LEASES: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        "eris_active_leases",
        "Active durable enforcement leases by policy",
        &["policy"]
    )
    .unwrap()
});

pub static RECONCILES: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "eris_reconciliations_total",
        "nftables reconciliation attempts by result",
        &["result"]
    )
    .unwrap()
});

pub fn register_defense(config: &Config) {
    for source in config.sources.keys() {
        SOURCE_READY.with_label_values(&[source]).set(0.0);
        SOURCE_LAG.with_label_values(&[source]).set(0.0);
        for outcome in ["matched", "unmatched", "oversized"] {
            SOURCE_RECORDS.with_label_values(&[source, outcome]);
        }
    }
    for policy in config.policies.keys() {
        ACTIVE_LEASES.with_label_values(&[policy]).set(0.0);
        for disposition in ["accepted", "ignored", "protected"] {
            POLICY_MATCHES.with_label_values(&[policy, disposition]);
        }
    }
    ACTIVE_LEASES.with_label_values(&["__manual__"]).set(0.0);
    for result in ["success", "failure"] {
        RECONCILES.with_label_values(&[result]);
    }
}

/// Number of connections currently held in the tarpit.
pub static ACTIVE_CONNECTIONS: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!("eris_active_connections", "Connections held in the tarpit").unwrap()
});

/// Lifecycle totals split only by configured endpoint and protocol.
pub static ENDPOINT_ACCEPTED: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "eris_endpoint_accepted_total",
        "Accepted connections by endpoint",
        &["endpoint", "protocol"]
    )
    .unwrap()
});
pub static ENDPOINT_REJECTED: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "eris_endpoint_rejected_total",
        "Tarpit capacity rejections by endpoint",
        &["endpoint", "protocol", "reason"]
    )
    .unwrap()
});
pub static ENDPOINT_CLOSED: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "eris_endpoint_closed_total",
        "Closed tarpit connections by endpoint",
        &["endpoint", "protocol"]
    )
    .unwrap()
});
pub static ENDPOINT_BYTES: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "eris_endpoint_sent_bytes_total",
        "Bytes sent by endpoint",
        &["endpoint", "protocol"]
    )
    .unwrap()
});
pub static ENDPOINT_SECONDS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "eris_endpoint_trapped_seconds_total",
        "Tarpit seconds by endpoint",
        &["endpoint", "protocol"]
    )
    .unwrap()
});
pub static ENDPOINT_ACTIVE: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        "eris_endpoint_active_connections",
        "Active tarpits by endpoint",
        &["endpoint", "protocol"]
    )
    .unwrap()
});
pub static ENDPOINT_CAPACITY: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        "eris_endpoint_tarpit_capacity",
        "Configured concurrent tarpit capacity by endpoint",
        &["endpoint", "protocol"]
    )
    .unwrap()
});

pub fn endpoint_accepted(name: &str, protocol: &str) {
    ENDPOINT_ACCEPTED.with_label_values(&[name, protocol]).inc();
}

/// Pre-register static endpoint series so an idle endpoint is still visible.
pub fn register_endpoints(config: &Config) {
    for endpoint in config.resolved_listeners() {
        let labels = &[endpoint.name(), endpoint.protocol()];
        ENDPOINT_ACCEPTED.with_label_values(labels);
        for reason in ["endpoint_capacity", "per_ip_capacity"] {
            ENDPOINT_REJECTED.with_label_values(&[labels[0], labels[1], reason]);
        }
        ENDPOINT_CLOSED.with_label_values(labels);
        ENDPOINT_BYTES.with_label_values(labels);
        ENDPOINT_SECONDS.with_label_values(labels);
        ENDPOINT_ACTIVE.with_label_values(labels);
        ENDPOINT_CAPACITY
            .with_label_values(labels)
            .set(endpoint.max_tarpit_conns(config.max_tarpit_conns) as f64);
        for category in crate::category::Category::ALL {
            ENDPOINT_HITS.with_label_values(&[labels[0], labels[1], category.label()]);
        }
    }
}
pub fn endpoint_hit(name: &str, protocol: &str, category: &str) {
    ENDPOINT_HITS
        .with_label_values(&[name, protocol, category])
        .inc();
}
pub fn endpoint_rejected(name: &str, protocol: &str, reason: &str) {
    ENDPOINT_REJECTED
        .with_label_values(&[name, protocol, reason])
        .inc();
}
pub fn endpoint_active(name: &str, protocol: &str, delta: f64) {
    ENDPOINT_ACTIVE
        .with_label_values(&[name, protocol])
        .add(delta);
}
pub fn endpoint_closed(name: &str, protocol: &str, bytes: u64, seconds: f64) {
    let labels = &[name, protocol];
    ENDPOINT_CLOSED.with_label_values(labels).inc();
    ENDPOINT_BYTES
        .with_label_values(labels)
        .inc_by(bytes as f64);
    ENDPOINT_SECONDS.with_label_values(labels).inc_by(seconds);
}

/// Serve `/metrics` and `/status` until `shutdown` is cancelled.
pub async fn serve(
    addr: String,
    state: Arc<State>,
    endpoints: Arc<Vec<Arc<EndpointStats>>>,
    defense: Arc<Defense>,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    log::info!("metrics server listening on {addr}");

    let handlers = Arc::new(Semaphore::new(128));
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let Ok(permit) = handlers.clone().try_acquire_owned() else {
                            continue;
                        };
                        let state = state.clone();
                        let endpoints = endpoints.clone();
                        let defense = defense.clone();
                        tokio::spawn(handle(stream, state, endpoints, defense, permit));
                    }
                    Err(e) => log::warn!("metrics accept error: {e}"),
                }
            }
        }
    }
    Ok(())
}

async fn handle(
    mut stream: TcpStream,
    state: Arc<State>,
    endpoints: Arc<Vec<Arc<EndpointStats>>>,
    defense: Arc<Defense>,
    _permit: OwnedSemaphorePermit,
) {
    let Ok(Some(head)) = http::read_head(&mut stream, Duration::from_secs(5)).await else {
        return;
    };

    let path = head.path.split('?').next().unwrap_or("/");
    let ready = defense.is_ready() && endpoints.iter().all(|endpoint| endpoint.snapshot().ready);
    let (status, content_type, body) = match path {
        "/metrics" => ("200 OK", "text/plain; version=0.0.4", render()),
        "/status" => match defense.bans().await {
            Ok(bans) => (
                "200 OK",
                "application/json",
                status_json(&state, &endpoints, &bans),
            ),
            Err(error) => (
                "500 Internal Server Error",
                "text/plain",
                format!("cannot query defense state: {error}\n"),
            ),
        },
        "/healthz" => ("200 OK", "text/plain", "ok\n".to_string()),
        "/readyz" if ready => ("200 OK", "text/plain", "ready\n".to_string()),
        "/readyz" => (
            "503 Service Unavailable",
            "text/plain",
            "not ready\n".to_string(),
        ),
        "/" => ("200 OK", "text/plain", "eris tarpit running\n".to_string()),
        _ => ("404 Not Found", "text/plain", "not found\n".to_string()),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn render() -> String {
    let mut buf = Vec::new();
    let encoder = TextEncoder::new();
    if let Err(e) = encoder.encode(&prometheus::gather(), &mut buf) {
        log::error!("failed to encode metrics: {e}");
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn status_json(
    state: &State,
    endpoints: &[Arc<EndpointStats>],
    bans: &[eris_admin::Ban],
) -> String {
    serde_json::json!({
        "status": "running",
        "version": env!("CARGO_PKG_VERSION"),
        "blocked_ips": bans.iter()
            .filter(|ban| ban.apply_state == "applied" && ban.blocking)
            .map(|ban| &ban.network)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        "active_bans": bans.len(),
        "active_connections": state.active_count(),
        "tracked_ips": state.tracked_count(),
        "endpoints": endpoints.iter().map(|endpoint| endpoint.snapshot()).collect::<Vec<_>>(),
    })
    .to_string()
}
