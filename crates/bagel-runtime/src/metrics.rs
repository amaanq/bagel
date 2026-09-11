//! Prometheus metrics and a tiny HTTP server exposing `/metrics` and `/status`.

use std::{
   sync::Arc,
   time::Duration,
};

use bagel_config::Config;
use bagel_proto::http;
use metrics::{
   counter,
   describe_counter,
   describe_gauge,
   gauge,
};
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::{
   io::AsyncWriteExt,
   net::{
      TcpListener,
      TcpStream,
   },
   sync::{
      OwnedSemaphorePermit,
      Semaphore,
   },
};
use tokio_util::sync::CancellationToken;

use crate::{
   defense::Defense,
   server::EndpointStats,
};

/// Record one threshold-exceeding source spared a firewall block because it
/// sits in a tarpit-only network.
pub fn record_no_block_spared() {
   counter!("bagel_no_block_spared_total").increment(1);
}

/// Pre-register every category series so each shows in `/metrics` at zero
/// before its first hit.
pub fn register_categories() {
   for category in crate::category::Category::ALL {
      counter!("bagel_category_hits_total", "category" => category.label()).increment(0);
   }
}

pub fn set_source_ready(source: &str, ready: f64) {
   gauge!("bagel_source_ready", "source" => source.to_owned()).set(ready);
}

pub fn record_policy_match(policy: &str, disposition: &'static str) {
   counter!("bagel_policy_matches_total", "policy" => policy.to_owned(), "disposition" => disposition)
        .increment(1);
}

pub fn set_active_leases(policy: &str, count: f64) {
   gauge!("bagel_active_leases", "policy" => policy.to_owned()).set(count);
}

pub fn register_defense(config: &Config) {
   for source in config.sources.keys() {
      set_source_ready(source, 0.0);
      gauge!("bagel_source_lag_seconds", "source" => source.to_owned()).set(0.0);
      for outcome in ["matched", "unmatched", "oversized"] {
         counter!("bagel_source_records_total", "source" => source.to_owned(), "outcome" => outcome)
            .increment(0);
      }
   }
   for policy in config.policies.keys() {
      set_active_leases(policy, 0.0);
      for disposition in ["accepted", "ignored", "protected"] {
         counter!("bagel_policy_matches_total", "policy" => policy.to_owned(), "disposition" => disposition)
                .increment(0);
      }
   }
   set_active_leases("__manual__", 0.0);
   for result in ["success", "failure"] {
      counter!("bagel_reconciliations_total", "result" => result).increment(0);
   }
}

pub fn set_active_connections(count: f64) {
   gauge!("bagel_active_connections").set(count);
}

const COUNTERS: &[(&str, &str)] = &[
   ("bagel_connections_total", "Connections accepted"),
   ("bagel_hits_total", "Total tarpit hits"),
   (
      "bagel_no_block_spared_total",
      "Sources tarpitted past the block threshold but spared a firewall block",
   ),
   (
      "bagel_category_hits_total",
      "Tarpit hits by report category",
   ),
   (
      "bagel_endpoint_hits_total",
      "Tarpit hits by endpoint and category",
   ),
   (
      "bagel_tarpit_rejected_total",
      "Tarpit connections dropped at capacity",
   ),
   (
      "bagel_source_records_total",
      "Defense source records by bounded outcome",
   ),
   (
      "bagel_policy_matches_total",
      "Detector matches by static policy and disposition",
   ),
   (
      "bagel_reconciliations_total",
      "nftables reconciliation attempts by result",
   ),
   (
      "bagel_endpoint_accepted_total",
      "Accepted connections by endpoint",
   ),
   (
      "bagel_endpoint_rejected_total",
      "Tarpit capacity rejections by endpoint",
   ),
   (
      "bagel_endpoint_closed_total",
      "Closed tarpit connections by endpoint",
   ),
   ("bagel_endpoint_sent_bytes_total", "Bytes sent by endpoint"),
   (
      "bagel_endpoint_trapped_seconds_total",
      "Tarpit seconds by endpoint",
   ),
];

const GAUGES: &[(&str, &str)] = &[
   ("bagel_blocked_ips", "IPs currently blocked"),
   ("bagel_firewall_ready", "nftables blocklist is ready"),
   (
      "bagel_source_lag_seconds",
      "Age of the most recently processed source record",
   ),
   (
      "bagel_source_ready",
      "Whether a configured defense source is live",
   ),
   (
      "bagel_active_leases",
      "Active durable enforcement leases by policy",
   ),
   ("bagel_active_connections", "Connections held in the tarpit"),
   (
      "bagel_endpoint_active_connections",
      "Active tarpits by endpoint",
   ),
   (
      "bagel_endpoint_tarpit_capacity",
      "Configured concurrent tarpit capacity by endpoint",
   ),
];

pub fn describe() {
   for (name, help) in COUNTERS {
      describe_counter!(*name, *help);
   }
   for (name, help) in GAUGES {
      describe_gauge!(*name, *help);
   }
}

/// Pre-register static endpoint series so an idle endpoint is still visible.
#[expect(
   clippy::cast_precision_loss,
   reason = "the tarpit capacity is a configured connection count, far below 2^53"
)]
pub fn register_endpoints(config: &Config) {
   for endpoint in config.resolved_listeners() {
      let name = endpoint.name().to_owned();
      counter!("bagel_endpoint_accepted_total", "endpoint" => name.clone()).increment(0);
      for reason in ["endpoint_capacity", "per_ip_capacity"] {
         counter!("bagel_endpoint_rejected_total", "endpoint" => name.clone(), "reason" => reason)
            .increment(0);
      }
      counter!("bagel_endpoint_closed_total", "endpoint" => name.clone()).increment(0);
      counter!("bagel_endpoint_sent_bytes_total", "endpoint" => name.clone()).increment(0);
      counter!("bagel_endpoint_trapped_seconds_total", "endpoint" => name.clone()).increment(0);
      gauge!("bagel_endpoint_active_connections", "endpoint" => name.clone()).set(0.0);
      gauge!("bagel_endpoint_tarpit_capacity", "endpoint" => name.clone())
         .set(endpoint.max_tarpit_conns(config.max_tarpit_conns) as f64);
      for category in crate::category::Category::ALL {
         counter!("bagel_endpoint_hits_total", "endpoint" => name.clone(), "category" => category.label())
                .increment(0);
      }
   }
}
pub fn endpoint_active(name: &str, delta: f64) {
   let active = gauge!("bagel_endpoint_active_connections", "endpoint" => name.to_owned());
   if delta >= 0.0 {
      active.increment(delta);
   } else {
      #[expect(
         clippy::float_arithmetic,
         reason = "the negative delta is converted to a gauge decrement"
      )]
      let decrement = -delta;
      active.decrement(decrement);
   }
}
/// Serve `/metrics` and `/status` until `shutdown` is cancelled.
pub async fn serve(
   addr: String,
   endpoints: Arc<[Arc<EndpointStats>]>,
   defense: Arc<Defense>,
   handle: PrometheusHandle,
   shutdown: CancellationToken,
) -> std::io::Result<()> {
   let listener = TcpListener::bind(&addr).await?;
   tracing::info!("metrics server listening on {addr}");

   let handlers = Arc::new(Semaphore::new(128));
   loop {
      tokio::select! {
          () = shutdown.cancelled() => break,
          accepted = listener.accept() => {
              match accepted {
                  Ok((stream, _)) => {
                      let Ok(permit) = Arc::clone(&handlers).try_acquire_owned() else {
                          continue;
                      };
                      let endpoints = Arc::clone(&endpoints);
                      let defense = Arc::clone(&defense);
                      let handle = handle.clone();
                      tokio::spawn(handle_conn(stream, endpoints, defense, handle, permit));
                  }
                  Err(e) => tracing::warn!("metrics accept error: {e}"),
              }
          }
      }
   }
   Ok(())
}

async fn handle_conn(
   mut stream: TcpStream,
   endpoints: Arc<[Arc<EndpointStats>]>,
   defense: Arc<Defense>,
   handle: PrometheusHandle,
   _permit: OwnedSemaphorePermit,
) {
   let Ok(Some(head)) = http::read_head(&mut stream, Duration::from_secs(5)).await else {
      return;
   };

   let path = head.path.split('?').next().unwrap_or("/");
   let ready = defense.is_ready() && endpoints.iter().all(|endpoint| endpoint.snapshot().ready);
   let (status, content_type, body) = match path {
      "/metrics" => ("200 OK", "text/plain; version=0.0.4", handle.render()),
      "/status" => {
         match defense.bans().await {
            Ok(bans) => ("200 OK", "application/json", status_json(&endpoints, &bans)),
            Err(error) => {
               (
                  "500 Internal Server Error",
                  "text/plain",
                  format!("cannot query defense state: {error}\n"),
               )
            },
         }
      },
      "/healthz" => ("200 OK", "text/plain", "ok\n".to_owned()),
      "/readyz" if ready => ("200 OK", "text/plain", "ready\n".to_owned()),
      "/readyz" => {
         (
            "503 Service Unavailable",
            "text/plain",
            "not ready\n".to_owned(),
         )
      },
      "/" => ("200 OK", "text/plain", "bagel tarpit running\n".to_owned()),
      _ => ("404 Not Found", "text/plain", "not found\n".to_owned()),
   };

   let response = format!(
      "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: \
       close\r\n\r\n{body}",
      body.len()
   );
   let _ = stream.write_all(response.as_bytes()).await;
   let _ = stream.shutdown().await;
}

fn status_json(endpoints: &[Arc<EndpointStats>], bans: &[bagel_admin::Ban]) -> String {
   serde_json::json!({
        "status": "running",
        "version": env!("CARGO_PKG_VERSION"),
        "blocked_ips": bans.iter()
            .filter(|ban| ban.apply_state == "applied" && ban.blocking)
            .map(|ban| &ban.network)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        "active_bans": bans.len(),
        "active_connections": endpoints.iter().map(|endpoint| endpoint.snapshot().active).sum::<usize>(),
        "endpoints": endpoints.iter().map(|endpoint| endpoint.snapshot()).collect::<Vec<_>>(),
    })
    .to_string()
}
