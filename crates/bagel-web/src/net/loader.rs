use std::{
   borrow::ToOwned,
   collections::HashMap,
   fs,
   sync::Arc,
   time::Duration,
};

use http_body_util::{
   BodyExt as _,
   Limited,
};
use hyper_rustls::ConfigBuilderExt as _;
use hyper_util::{
   client::legacy::{
      Client,
      connect::HttpConnector,
   },
   rt::TokioExecutor,
};
use regex::Regex;
use serde_json::Value;

use crate::{
   cache::FileCache,
   config::policy::{
      NetworkConfig,
      NetworkFilter,
      NetworkSource,
   },
   net::{
      IpNetTrie,
      radb::query_asn_routes,
   },
};

type HttpClient =
   Client<hyper_rustls::HttpsConnector<HttpConnector>, http_body_util::Empty<bytes::Bytes>>;

const NETWORK_SOURCE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_NETWORK_SOURCE_BODY: usize = 16 * 1024 * 1024;

fn build_https_client() -> bagel_core::Result<HttpClient> {
   let tls = rustls::ClientConfig::builder()
      .with_native_roots()
      .map_err(|err| {
         bagel_core::Error::Config(format!("native root certificates unavailable: {err}"))
      })?
      .with_no_client_auth();
   let https = hyper_rustls::HttpsConnectorBuilder::new()
      .with_tls_config(tls)
      .https_or_http()
      .enable_http1()
      .build();
   Ok(Client::builder(TokioExecutor::new()).build(https))
}

/// Load all configured networks into `IpNetTrie` instances.
pub async fn load_networks(
   configs: &[NetworkConfig],
   file_cache: Option<&FileCache>,
) -> bagel_core::Result<HashMap<String, Arc<IpNetTrie>>> {
   let http_client = build_https_client()?;
   let mut networks = HashMap::new();

   for cfg in configs {
      let mut all_prefixes = Vec::new();

      for source in &cfg.sources {
         let prefixes = load_source(source, file_cache, &http_client)
            .await
            .map_err(|err| {
               bagel_core::Error::Config(format!(
                  "network '{}': failed to load source: {err}",
                  cfg.name
               ))
            })?;
         all_prefixes.extend(prefixes);
      }

      tracing::info!(
         network = cfg.name,
         prefixes = all_prefixes.len(),
         "loaded network"
      );

      for prefix in &all_prefixes {
         if prefix.parse::<ip_network::IpNetwork>().is_err()
            && prefix.parse::<std::net::IpAddr>().is_err()
         {
            return Err(bagel_core::Error::Config(format!(
               "network '{}': invalid IP prefix {prefix:?}",
               cfg.name
            )));
         }
      }

      networks.insert(
         cfg.name.clone(),
         Arc::new(IpNetTrie::from_prefixes(&all_prefixes)),
      );
   }

   Ok(networks)
}

async fn load_source(
   source: &NetworkSource,
   file_cache: Option<&FileCache>,
   http_client: &HttpClient,
) -> bagel_core::Result<Vec<String>> {
   match source {
      NetworkSource::Url { url, filter } => {
         if let Some(cache) = file_cache
            && let Some(cached) = cache.get(url)
         {
            return apply_filter(&cached, filter);
         }

         let req = hyper::Request::get(url)
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .map_err(|err| bagel_core::Error::Other(format!("request: {err}").into()))?;
         let body_bytes = tokio::time::timeout(NETWORK_SOURCE_TIMEOUT, async {
            let resp = http_client
               .request(req)
               .await
               .map_err(|err| bagel_core::Error::Other(format!("request: {err}").into()))?;
            if !resp.status().is_success() {
               return Err(bagel_core::Error::Other(
                  format!("network source returned HTTP {}", resp.status()).into(),
               ));
            }
            Limited::new(resp.into_body(), MAX_NETWORK_SOURCE_BODY)
               .collect()
               .await
               .map(http_body_util::Collected::to_bytes)
               .map_err(|err| bagel_core::Error::Other(format!("body: {err}").into()))
         })
         .await
         .map_err(|_| bagel_core::Error::Other("network source timed out".into()))??;
         let body = String::from_utf8_lossy(&body_bytes).into_owned();

         if let Some(cache) = file_cache {
            let _ = cache.set(url, &body);
         }

         apply_filter(&body, filter)
      },
      NetworkSource::File { path, filter } => {
         let body = fs::read_to_string(path)?;
         apply_filter(&body, filter)
      },
      NetworkSource::Asn(asn) => {
         let cache_key = format!("asn:{asn}");
         if let Some(cache) = file_cache
            && let Some(cached) = cache.get(&cache_key)
         {
            return Ok(cached.lines().map(ToOwned::to_owned).collect());
         }

         let asn_val = *asn;
         let prefixes = tokio::task::spawn_blocking(move || query_asn_routes(asn_val))
            .await
            .map_err(|err| bagel_core::Error::Other(format!("join error: {err}").into()))??;

         if let Some(cache) = file_cache {
            let _ = cache.set(&cache_key, &prefixes.join("\n"));
         }

         Ok(prefixes)
      },
      NetworkSource::Inline(prefixes) => Ok(prefixes.clone()),
   }
}

fn apply_filter(body: &str, filter: &NetworkFilter) -> bagel_core::Result<Vec<String>> {
   match filter {
      NetworkFilter::None => {
         Ok(body
            .lines()
            .map(|line| line.trim().to_owned())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect())
      },
      NetworkFilter::Regex(pattern) => {
         let re = match Regex::new(pattern) {
            Ok(compiled) => compiled,
            Err(err) => {
               tracing::error!(pattern, error = %err, "invalid network filter regex");
               return Err(bagel_core::Error::Config(format!(
                  "invalid network filter regex: {err}"
               )));
            },
         };

         let mut prefixes = Vec::new();
         for cap in re.captures_iter(body) {
            if let Some(mat) = cap.name("prefix") {
               prefixes.push(mat.as_str().to_owned());
            } else if let Some(mat) = cap.get(1) {
               prefixes.push(mat.as_str().to_owned());
            }
         }
         Ok(prefixes)
      },
      NetworkFilter::Jq(path) => {
         let json = serde_json::from_str::<Value>(body).map_err(|err| {
            bagel_core::Error::Config(format!("network source body is not valid JSON: {err}"))
         })?;
         Ok(extract_jq_path(&json, path))
      },
   }
}

/// Simple jq-like path extraction.
/// Supports patterns like: `.prefixes[].ip_prefix`, `.field`, `.array[]`.
fn extract_jq_path(value: &Value, path: &str) -> Vec<String> {
   let path = path.trim_start_matches('.');
   let mut results = vec![value.clone()];

   for segment in split_jq_segments(path) {
      let mut next = Vec::new();
      for val in &results {
         if let Some(field) = segment.strip_suffix("[]") {
            let target = if field.is_empty() {
               val.clone()
            } else {
               val.get(field).cloned().unwrap_or(Value::Null)
            };
            if let Value::Array(arr) = target {
               next.extend(arr);
            }
         } else if let Some(sub) = val.get(segment) {
            next.push(sub.clone());
         }
      }
      results = next;
   }

   results
      .into_iter()
      .filter_map(|val| {
         match val {
            Value::String(str_val) => Some(str_val),
            _ => None,
         }
      })
      .collect()
}

fn split_jq_segments(path: &str) -> Vec<&str> {
   // Split on '.' but keep '[]' attached to the preceding segment
   let mut segments = Vec::new();
   let mut start = 0;
   let bytes = path.as_bytes();
   let mut idx = 0;

   while idx < bytes.len() {
      if bytes[idx] == b'.' && idx > start {
         segments.push(&path[start..idx]);
         start = idx + 1;
      } else if bytes[idx] == b'.' && idx == start {
         start = idx + 1;
      }
      idx += 1;
   }

   if start < path.len() {
      segments.push(&path[start..]);
   }

   segments
}
