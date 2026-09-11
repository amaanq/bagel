use std::{
   collections::HashMap,
   net::{
      IpAddr,
      SocketAddr,
   },
   sync::Arc,
};

use http::{
   Request,
   Version,
};
use rhai::{
   Dynamic,
   Engine,
   Scope,
   packages::{
      ArithmeticPackage,
      BasicArrayPackage,
      BasicMapPackage,
      BasicStringPackage,
      LanguageCorePackage,
      LogicPackage,
      MoreStringPackage,
      Package,
   },
};

use crate::{
   body::Body,
   net::{
      IpNetTrie,
      rate::RateSnapshot,
   },
   tls::TlsFingerprint,
};

#[must_use]
pub fn build_engine() -> Engine {
   let mut engine = Engine::new_raw();

   for package in [
      LanguageCorePackage::new().as_shared_module(),
      ArithmeticPackage::new().as_shared_module(),
      LogicPackage::new().as_shared_module(),
      BasicStringPackage::new().as_shared_module(),
      MoreStringPackage::new().as_shared_module(),
      BasicArrayPackage::new().as_shared_module(),
      BasicMapPackage::new().as_shared_module(),
   ] {
      engine.register_global_module(package);
   }

   engine.set_max_expr_depths(64, 32);
   engine.set_max_operations(10_000);
   engine.set_max_string_size(4096);

   engine
}

/// Variables available during condition evaluation.
#[derive(Clone)]
pub struct ConditionContext {
   pub host:             String,
   pub method:           String,
   pub path:             String,
   pub query:            String,
   pub user_agent:       String,
   pub remote_address:   String,
   pub remote_ip:        Option<IpAddr>,
   pub http_version:     String,
   pub headers:          HashMap<String, String>,
   pub fp:               HashMap<String, String>,
   /// Pre-computed network membership results: `network_name` -> bool.
   pub network_results:  HashMap<String, bool>,
   /// Normal rate snapshot, `None` when no client network resolved.
   pub rate:             Option<RateSnapshot>,
   pub poison_returned:  bool,
   pub crawler_verified: bool,
   pub lease_active:     bool,
   /// Bagel trap classification, `None` until the daemon attaches a classifier.
   pub trap:             Option<TrapVerdict>,
}

/// What bagel's signature classifier said about the request. `reason` is
/// `path`, `user_agent` or `impersonator`, and `category` is the report
/// bucket of a path trap.
#[derive(Clone, Default)]
pub struct TrapVerdict {
   pub reason:   Option<&'static str>,
   pub category: Option<&'static str>,
}

impl ConditionContext {
   #[must_use]
   pub fn scope(&self) -> Scope<'static> {
      let mut scope = Scope::new();

      scope.push_constant("host", self.host.clone());
      scope.push_constant("method", self.method.clone());
      scope.push_constant("path", self.path.clone());
      scope.push_constant("query", self.query.clone());
      scope.push_constant("user_agent", self.user_agent.clone());
      scope.push_constant("remote_address", self.remote_address.clone());
      scope.push_constant("http_version", self.http_version.clone());

      let headers_map: rhai::Map = self
         .headers
         .iter()
         .map(|(key, val)| (key.clone().into(), Dynamic::from(val.clone())))
         .collect();
      scope.push_constant("headers", headers_map);

      let fp_map: rhai::Map = self
         .fp
         .iter()
         .map(|(key, val)| (key.clone().into(), Dynamic::from(val.clone())))
         .collect();
      scope.push_constant("fp", fp_map);

      let net_map: rhai::Map = self
         .network_results
         .iter()
         .map(|(key, val)| (key.clone().into(), Dynamic::from(*val)))
         .collect();
      scope.push_constant("networks", net_map);

      let (rate_second, rate_ten_seconds, rate_minute) = self.rate.map_or((0, 0, 0), |snap| {
         (
            i64::from(snap.last_1s),
            i64::from(snap.last_10s),
            i64::from(snap.last_60s),
         )
      });
      let mut rate_map = rhai::Map::new();
      rate_map.insert("available".into(), Dynamic::from(self.rate.is_some()));
      rate_map.insert("1s".into(), Dynamic::from(rate_second));
      rate_map.insert("10s".into(), Dynamic::from(rate_ten_seconds));
      rate_map.insert("60s".into(), Dynamic::from(rate_minute));
      scope.push_constant("rate", rate_map);

      let mut poison_map = rhai::Map::new();
      poison_map.insert("returned".into(), Dynamic::from(self.poison_returned));
      scope.push_constant("poison", poison_map);

      let mut lease_map = rhai::Map::new();
      lease_map.insert("active".into(), Dynamic::from(self.lease_active));
      scope.push_constant("lease", lease_map);

      let mut crawler_map = rhai::Map::new();
      crawler_map.insert("verified".into(), Dynamic::from(self.crawler_verified));
      scope.push_constant("crawler", crawler_map);

      let trap = self.trap.clone().unwrap_or_default();
      let mut trap_map = rhai::Map::new();
      trap_map.insert("available".into(), Dynamic::from(self.trap.is_some()));
      trap_map.insert("any".into(), Dynamic::from(trap.reason.is_some()));
      for reason in ["path", "user_agent", "impersonator"] {
         trap_map.insert(reason.into(), Dynamic::from(trap.reason == Some(reason)));
      }
      trap_map.insert(
         "category".into(),
         Dynamic::from(trap.category.unwrap_or("").to_owned()),
      );
      scope.push_constant("trap", trap_map);

      scope
   }

   pub fn from_request(req: &Request<Body>) -> Self {
      // HeaderName is already lowercase-normalized by the http crate
      let headers: HashMap<String, String> = req
         .headers()
         .iter()
         .map(|(name, val)| {
            (
               name.as_str().to_owned(),
               val.to_str().unwrap_or("").to_owned(),
            )
         })
         .collect();

      let user_agent = headers.get("user-agent").cloned().unwrap_or_default();
      let host = headers.get("host").cloned().unwrap_or_default();

      let remote_address = req
         .extensions()
         .get::<SocketAddr>()
         .map(|sa| sa.ip().to_string())
         .unwrap_or_default();

      let remote_ip = req.extensions().get::<SocketAddr>().map(SocketAddr::ip);

      let http_version = match req.version() {
         Version::HTTP_09 => "HTTP/0.9",
         Version::HTTP_10 => "HTTP/1.0",
         Version::HTTP_11 => "HTTP/1.1",
         Version::HTTP_2 => "HTTP/2.0",
         Version::HTTP_3 => "HTTP/3.0",
         _ => "unknown",
      };

      let fp = req
         .extensions()
         .get::<TlsFingerprint>()
         .map(|tls_fp| {
            let mut map = HashMap::new();
            if !tls_fp.ja4.is_empty() {
               map.insert("ja4".to_owned(), tls_fp.ja4.clone());
            }
            map
         })
         .unwrap_or_default();

      Self {
         host,
         method: req.method().as_str().to_owned(),
         path: req.uri().path().to_owned(),
         query: req.uri().query().unwrap_or("").to_owned(),
         user_agent,
         remote_address,
         remote_ip,
         http_version: http_version.to_owned(),
         headers,
         fp,
         network_results: HashMap::new(),
         rate: None,
         poison_returned: false,
         crawler_verified: false,
         lease_active: false,
         trap: None,
      }
   }

   /// Clone this context with `context` rule request headers merged in, so
   /// the subtree evaluates against the mutated request.
   #[must_use]
   pub fn with_request_headers(&self, headers: &http::HeaderMap) -> Self {
      let mut ctx = self.clone();
      for (name, value) in headers {
         ctx.headers.insert(
            name.as_str().to_owned(),
            value.to_str().unwrap_or("").to_owned(),
         );
      }
      if let Some(ua) = ctx.headers.get("user-agent") {
         ctx.user_agent = ua.clone();
      }
      if let Some(host) = ctx.headers.get("host") {
         ctx.host = host.clone();
      }
      ctx
   }

   #[expect(
      clippy::iter_over_hash_type,
      reason = "network membership does not depend on map iteration order"
   )]
   pub fn compute_network_membership(&mut self, networks: &HashMap<String, Arc<IpNetTrie>>) {
      if let Some(ip) = self.remote_ip {
         for (name, trie) in networks {
            self.network_results.insert(name.clone(), trie.contains(ip));
         }
      }
   }
}

/// Expand `($name)` references in a condition expression with the named
/// condition's expression.
#[must_use]
#[expect(
   clippy::iter_over_hash_type,
   reason = "macro expansion does not depend on map iteration order"
)]
pub fn expand_condition_macros<S: std::hash::BuildHasher>(
   expr: &str,
   conditions: &HashMap<String, String, S>,
) -> String {
   let mut result = expr.to_owned();
   for (name, replacement) in conditions {
      let pattern = format!("(${name})");
      if result.contains(&pattern) {
         result = result.replace(&pattern, &format!("({replacement})"));
      }
   }
   result
}
