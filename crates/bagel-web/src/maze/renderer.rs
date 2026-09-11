use std::{
   collections::HashMap,
   sync::{
      Arc,
      Mutex,
   },
   time::Instant,
};

use bytes::Bytes;
use http_body_util::{
   BodyExt as _,
   Full,
   Limited,
};
use hyper_util::{
   client::legacy::{
      Client,
      connect::HttpConnector,
   },
   rt::TokioExecutor,
};
use tokio::sync::Semaphore;

use crate::{
   SourceNetwork,
   config::policy::RendererConfig,
};

/// Where a renderer's pages come from. Both kinds share the same budgets,
/// cooldowns and concurrency limit.
pub enum Backend {
   Iocaine(Box<Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>>),
   Markov(Arc<bagel_deception::Deceiver>),
}

const BUDGET_CAPACITY: usize = 65_536;

/// Renderer budget identity, canonical host plus maze name plus the source
/// network (or the transport peer network, or one shared unknown bucket).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BudgetKey {
   pub host:   String,
   pub maze:   String,
   pub source: Option<SourceNetwork>,
}

#[derive(Clone, Copy)]
pub struct TokenBucket {
   tokens: f64,
   last:   Instant,
}

impl TokenBucket {
   const fn new(burst: f64, now: Instant) -> Self {
      Self {
         tokens: burst,
         last:   now,
      }
   }

   #[expect(
      clippy::float_arithmetic,
      reason = "token accounting uses a fractional bucket"
   )]
   fn take(&mut self, rate: f64, burst: f64, now: Instant) -> bool {
      let elapsed = now.duration_since(self.last).as_secs_f64();
      self.tokens = (elapsed.mul_add(rate, self.tokens)).min(burst);
      self.last = now;
      if self.tokens >= 1.0_f64 {
         self.tokens -= 1.0_f64;
         true
      } else {
         false
      }
   }
}

#[derive(Clone, Copy)]
pub struct Buckets {
   general: TokenBucket,
   decoy:   TokenBucket,
}

/// Sanitized payload for the external renderer. Nothing else about the
/// request may reach it.
pub struct RenderPayload<'a> {
   pub seed:  String,
   pub host:  &'a str,
   pub path:  &'a str,
   pub links: &'a [String],
}

pub enum RenderAttempt {
   Body(String),
   Fallback(&'static str),
}

/// One configured low-rate renderer with its budgets, cooldowns, and global
/// concurrency limit. Never a classifier, token authority, or security
/// boundary.
pub struct ExternalRenderer {
   pub config:    RendererConfig,
   pub semaphore: Arc<Semaphore>,
   pub backend:   Backend,
   pub buckets:   Mutex<HashMap<BudgetKey, Buckets>>,
   pub cooldowns: Mutex<HashMap<BudgetKey, Instant>>,
}

impl ExternalRenderer {
   pub fn new(config: RendererConfig) -> Result<Self, String> {
      let connector = hyper_rustls::HttpsConnectorBuilder::new()
         .with_native_roots()
         .map_err(|err| format!("renderer '{}': TLS roots unavailable: {err}", config.name))?
         .https_or_http()
         .enable_http1()
         .build();
      let client = Client::builder(TokioExecutor::new()).build(connector);
      Ok(Self::with_backend(
         config,
         Backend::Iocaine(Box::new(client)),
      ))
   }

   /// An in-process renderer backed by bagel's Deceiver, with no network hop.
   #[must_use]
   pub fn markov(config: RendererConfig, deceiver: Arc<bagel_deception::Deceiver>) -> Self {
      Self::with_backend(config, Backend::Markov(deceiver))
   }

   fn with_backend(config: RendererConfig, backend: Backend) -> Self {
      Self {
         semaphore: Arc::new(Semaphore::new(config.max_concurrency)),
         backend,
         config,
         buckets: Mutex::new(HashMap::new()),
         cooldowns: Mutex::new(HashMap::new()),
      }
   }

   /// The metrics label for this renderer's kind.
   #[must_use]
   pub const fn kind(&self) -> &'static str {
      match self.backend {
         Backend::Iocaine(_) => "iocaine",
         Backend::Markov(_) => "markov",
      }
   }

   fn in_cooldown(&self, key: &BudgetKey) -> bool {
      self
         .cooldowns
         .lock()
         .unwrap_or_else(std::sync::PoisonError::into_inner)
         .get(key)
         .is_some_and(|until| *until > Instant::now())
   }

   fn start_cooldown(&self, key: &BudgetKey) {
      let mut cooldowns = self
         .cooldowns
         .lock()
         .unwrap_or_else(std::sync::PoisonError::into_inner);
      let now = Instant::now();
      if cooldowns.len() >= BUDGET_CAPACITY {
         cooldowns.retain(|_, until| *until > now);
      }
      if cooldowns.len() >= BUDGET_CAPACITY
         && let Some(key) = cooldowns
            .iter()
            .min_by_key(|(_, until)| **until)
            .map(|(key, _)| key.clone())
      {
         cooldowns.remove(&key);
      }
      cooldowns.insert(key.clone(), now + self.config.cooldown);
   }

   /// Consume budget tokens. Authenticated requests draw from the general
   /// bucket, decoys draw from both.
   fn take_budget(&self, key: &BudgetKey, decoy: bool) -> bool {
      let mut buckets = self
         .buckets
         .lock()
         .unwrap_or_else(std::sync::PoisonError::into_inner);
      let now = Instant::now();
      if buckets.len() >= BUDGET_CAPACITY && !buckets.contains_key(key) {
         buckets.retain(|_, bucket| now.duration_since(bucket.general.last).as_secs() < 600);
      }
      if buckets.len() >= BUDGET_CAPACITY
         && !buckets.contains_key(key)
         && let Some(oldest) = buckets
            .iter()
            .min_by_key(|(_, bucket)| bucket.general.last)
            .map(|(key, _)| key.clone())
      {
         buckets.remove(&oldest);
      }
      let bucket = buckets.entry(key.clone()).or_insert_with(|| {
         Buckets {
            general: TokenBucket::new(f64::from(self.config.burst), now),
            decoy:   TokenBucket::new(f64::from(self.config.decoy_burst), now),
         }
      });

      let general_ok = bucket.general.take(
         f64::from(self.config.rate),
         f64::from(self.config.burst),
         now,
      );
      let decoy_ok = !decoy
         || bucket.decoy.take(
            f64::from(self.config.decoy_rate),
            f64::from(self.config.decoy_burst),
            now,
         );
      general_ok && decoy_ok
   }

   /// Attempt one external render. Every failure other than global
   /// concurrency exhaustion moves this source key into built-in mode for
   /// the cooldown.
   pub async fn render(
      &self,
      key: &BudgetKey,
      payload: &RenderPayload<'_>,
      decoy: bool,
   ) -> RenderAttempt {
      if self.in_cooldown(key) {
         return RenderAttempt::Fallback("cooldown");
      }
      if !self.take_budget(key, decoy) {
         self.start_cooldown(key);
         return RenderAttempt::Fallback("over_budget");
      }
      let Ok(_permit) = Arc::clone(&self.semaphore).try_acquire_owned() else {
         return RenderAttempt::Fallback("concurrency");
      };

      match tokio::time::timeout(self.config.timeout, self.request(payload)).await {
         Ok(Ok(body)) => RenderAttempt::Body(body),
         Ok(Err(label)) => {
            self.start_cooldown(key);
            RenderAttempt::Fallback(label)
         },
         Err(_) => {
            self.start_cooldown(key);
            RenderAttempt::Fallback("timeout")
         },
      }
   }

   async fn request(&self, payload: &RenderPayload<'_>) -> Result<String, &'static str> {
      let client = match &self.backend {
         Backend::Iocaine(client) => client,
         Backend::Markov(deceiver) => {
            let page = deceiver.maze_page(&payload.seed, payload.path, payload.links);
            if page.len() > self.config.max_body {
               return Err("oversized");
            }
            return Ok(page);
         },
      };
      let json = serde_json::json!({
         "mode": "maze",
         "seed": payload.seed,
         "host": payload.host,
         "path": payload.path,
         "links": payload.links,
      });

      let request = http::Request::post(&self.config.endpoint)
         .header(http::header::CONTENT_TYPE, "application/json")
         .body(Full::new(Bytes::from(json.to_string())))
         .map_err(|_| "error")?;

      let response = client.request(request).await.map_err(|err| {
         tracing::debug!(renderer = self.config.name, error = %err, "renderer request failed");
         "error"
      })?;
      if !response.status().is_success() {
         return Err("status");
      }

      let body = Limited::new(response.into_body(), self.config.max_body);
      let bytes = body.collect().await.map_err(|_| "oversized")?.to_bytes();
      String::from_utf8(bytes.to_vec()).map_err(|_| "utf8")
   }
}

#[cfg(test)]
mod tests {
   use std::{
      path::Path,
      sync::Arc,
   };

   use super::*;
   use crate::config::policy::RendererConfig;

   #[tokio::test]
   async fn markov_pages_over_max_body_fall_back() {
      let links: Vec<String> = (0..200)
         .map(|i| format!("/abcdefghijklmnopqrst/token{i}/p{i}"))
         .collect();
      let config = RendererConfig {
         name: "mk".into(),
         kind: "markov".into(),
         max_body: 1_024,
         ..RendererConfig::default()
      };
      let deceiver = Arc::new(bagel_deception::Deceiver::new(
         Path::new("/nonexistent"),
         Path::new("/nonexistent"),
         "nginx/1.24.0",
         0,
         0,
      ));
      let renderer = ExternalRenderer::markov(config, deceiver);
      let key = BudgetKey {
         host:   "example.test".into(),
         maze:   "m".into(),
         source: None,
      };
      let payload = RenderPayload {
         seed:  "seed".into(),
         host:  "example.test",
         path:  "/",
         links: &links,
      };
      assert!(matches!(
         renderer.render(&key, &payload, false).await,
         RenderAttempt::Fallback("oversized")
      ));

      let small_links: Vec<String> = (0..4)
         .map(|i| format!("/abcdefghijklmnopqrst/token{i}/p{i}"))
         .collect();
      let big_config = RendererConfig {
         name: "mk".into(),
         kind: "markov".into(),
         max_body: 8_388_608,
         ..RendererConfig::default()
      };
      let big_deceiver = Arc::new(bagel_deception::Deceiver::new(
         Path::new("/nonexistent"),
         Path::new("/nonexistent"),
         "nginx/1.24.0",
         0,
         0,
      ));
      let big_renderer = ExternalRenderer::markov(big_config, big_deceiver);
      let big_key = BudgetKey {
         host:   "example.test".into(),
         maze:   "m".into(),
         source: None,
      };
      let big_payload = RenderPayload {
         seed:  "seed".into(),
         host:  "example.test",
         path:  "/",
         links: &small_links,
      };
      assert!(matches!(
         big_renderer.render(&big_key, &big_payload, false).await,
         RenderAttempt::Body(_)
      ));
   }
}
