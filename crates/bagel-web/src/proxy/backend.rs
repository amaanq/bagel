use std::{
   collections::HashSet,
   sync::Arc,
};

use http::{
   HeaderName,
   HeaderValue,
   Uri,
   uri::Scheme,
};

use crate::{
   config::BackendConfig,
   error::Error,
   host::CanonicalHost,
};

/// A resolved backend: the config plus its target URI.
#[derive(Clone)]
pub struct Backend {
   pub config:    BackendConfig,
   pub target:    hyper::Uri,
   pub host:      Option<HeaderValue>,
   pub ip_header: Option<HeaderName>,
}

/// Pool of backends keyed by host pattern.
/// Lookup order: exact match -> wildcard (*.domain) -> fallback ("*").
#[derive(Clone)]
pub struct BackendPool {
   exact:    Vec<(String, Arc<Backend>)>,
   /// Wildcard patterns like `*.example.com` stored as `.example.com` suffix.
   wildcard: Vec<(String, Arc<Backend>)>,
   fallback: Option<Arc<Backend>>,
}

impl BackendPool {
   pub fn build(configs: &[BackendConfig]) -> Result<Self, Error> {
      let mut exact = Vec::new();
      let mut wildcard = Vec::new();
      let mut fallback = None;
      let mut seen = HashSet::new();

      for cfg in configs {
         let target: Uri = cfg
            .url
            .as_ref()
            .parse()
            .map_err(|err| Error::Config(format!("invalid backend URL {}: {err}", cfg.url)))?;

         if target.scheme() != Some(&Scheme::HTTP) || target.host().is_none() {
            return Err(Error::Config(format!(
               "backend '{}' requires an absolute HTTP URL, upstream TLS is not implemented",
               cfg.name,
            )));
         }
         if target.path() != "/" || target.query().is_some() {
            return Err(Error::Config(format!(
               "backend '{}' URL cannot contain a path prefix or query",
               cfg.name,
            )));
         }

         let host = cfg
            .host
            .as_deref()
            .map(HeaderValue::from_str)
            .transpose()
            .map_err(|error| {
               Error::Config(format!(
                  "backend '{}' has an invalid host header, {error}",
                  cfg.name
               ))
            })?;
         let ip_header = cfg
            .ip_header
            .as_deref()
            .map(|name| HeaderName::from_bytes(name.as_bytes()))
            .transpose()
            .map_err(|error| {
               Error::Config(format!(
                  "backend '{}' has an invalid ip-header name, {error}",
                  cfg.name
               ))
            })?;

         let backend = Arc::new(Backend {
            config: cfg.clone(),
            target,
            host,
            ip_header,
         });

         // Patterns are canonicalized here so they match the CanonicalHost
         // string built at request entry.
         match cfg.name.as_str() {
            "*" => {
               if !seen.insert("*".to_owned()) {
                  return Err(Error::Config("duplicate backend pattern '*'".to_owned()));
               }
               fallback = Some(backend);
            },
            name if name.starts_with("*.") => {
               let canonical = CanonicalHost::parse(&name[2..])
                  .map_err(|err| Error::Config(format!("backend pattern '{name}': {err}")))?;
               let pattern = format!(".{canonical}");
               if !seen.insert(pattern.clone()) {
                  return Err(Error::Config(format!("duplicate backend pattern '{name}'")));
               }
               wildcard.push((pattern, backend));
            },
            name => {
               let canonical = CanonicalHost::parse(name)
                  .map_err(|err| Error::Config(format!("backend pattern '{name}': {err}")))?;
               let pattern = canonical.as_str().to_owned();
               if !seen.insert(pattern.clone()) {
                  return Err(Error::Config(format!("duplicate backend pattern '{name}'")));
               }
               exact.push((pattern, backend));
            },
         }
      }

      wildcard.sort_by_key(|(pattern, _)| std::cmp::Reverse(pattern.len()));

      Ok(Self {
         exact,
         wildcard,
         fallback,
      })
   }

   /// `host` is already canonical, so it carries no port and renders an IPv6
   /// literal unbracketed. Splitting it on `:` would reduce `::1` to nothing.
   pub fn select(&self, host: &str) -> Option<Arc<Backend>> {
      for (pattern, backend) in &self.exact {
         if pattern == host {
            return Some(Arc::clone(backend));
         }
      }

      for (suffix, backend) in &self.wildcard {
         if host.ends_with(suffix.as_str()) {
            return Some(Arc::clone(backend));
         }
      }

      self.fallback.as_ref().map(Arc::clone)
   }

   /// Look up a backend by its configured name (exact string match against
   /// the pattern, including `*` and `*.domain` patterns).
   #[must_use]
   pub fn by_name(&self, name: &str) -> Option<Arc<Backend>> {
      self
         .exact
         .iter()
         .chain(&self.wildcard)
         .map(|(_, backend)| backend)
         .chain(&self.fallback)
         .find(|backend| backend.config.name == name)
         .map(Arc::clone)
   }

   #[must_use]
   pub const fn is_empty(&self) -> bool {
      self.exact.is_empty() && self.wildcard.is_empty() && self.fallback.is_none()
   }
}
