use std::{
   collections::HashSet,
   net::IpAddr,
   pin::Pin,
   sync::{
      Arc,
      Mutex,
   },
   time::Duration,
};

use tokio::sync::Semaphore;

use crate::{
   config::policy::CrawlerConfig,
   net::decay_map::DecayMap,
};

pub const POSITIVE_TTL: Duration = Duration::from_hours(1);
pub const NEGATIVE_TTL: Duration = Duration::from_mins(5);
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum request wait for an uncached verdict.
const WAIT_BUDGET: Duration = Duration::from_millis(500);
const MAX_CONCURRENT_LOOKUPS: usize = 64;

type BoxedFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// DNS backend for forward-confirmed reverse DNS. Failures surface as empty
/// results, which always mean unverified.
pub trait ReverseDns: Send + Sync {
   fn reverse(&self, ip: IpAddr) -> BoxedFuture<'_, Vec<String>>;
   fn forward<'a>(&'a self, name: &'a str) -> BoxedFuture<'a, Vec<IpAddr>>;
}

pub struct SystemDns(hickory_resolver::TokioResolver);

impl SystemDns {
   pub fn new() -> Result<Self, String> {
      let builder = hickory_resolver::TokioResolver::builder_tokio()
         .map_err(|err| format!("failed to read system resolver config: {err}"))?;
      let resolver = builder
         .build()
         .map_err(|err| format!("failed to build system resolver: {err}"))?;
      Ok(Self(resolver))
   }
}

impl ReverseDns for SystemDns {
   fn reverse(&self, ip: IpAddr) -> BoxedFuture<'_, Vec<String>> {
      Box::pin(async move {
         match self.0.reverse_lookup(ip).await {
            Ok(lookup) => {
               lookup
                  .answers()
                  .iter()
                  .filter_map(|record| {
                     match &record.data {
                        hickory_resolver::proto::rr::RData::PTR(ptr) => Some(ptr.0.to_utf8()),
                        _ => None,
                     }
                  })
                  .collect()
            },
            Err(err) => {
               tracing::debug!(%ip, error = %err, "PTR lookup failed");
               Vec::new()
            },
         }
      })
   }

   fn forward<'a>(&'a self, name: &'a str) -> BoxedFuture<'a, Vec<IpAddr>> {
      Box::pin(async move {
         match self.0.lookup_ip(name).await {
            Ok(lookup) => lookup.iter().collect(),
            Err(err) => {
               tracing::debug!(name, error = %err, "forward lookup failed");
               Vec::new()
            },
         }
      })
   }
}

/// Forward-confirmed reverse-DNS verification for configured providers.
pub struct CrawlerVerifier {
   providers: Arc<[CrawlerConfig]>,
   dns:       Arc<dyn ReverseDns>,
   cache:     Arc<DecayMap<IpAddr, bool>>,
   lookups:   Arc<Semaphore>,
   pending:   Arc<Mutex<HashSet<IpAddr>>>,
}

impl CrawlerVerifier {
   #[must_use]
   pub fn new(providers: Vec<CrawlerConfig>, dns: Arc<dyn ReverseDns>) -> Self {
      Self {
         providers: Arc::from(providers),
         dns,
         cache: Arc::new(DecayMap::new(POSITIVE_TTL)),
         lookups: Arc::new(Semaphore::new(MAX_CONCURRENT_LOOKUPS)),
         pending: Arc::new(Mutex::new(HashSet::new())),
      }
   }

   /// Return a cached verdict or wait up to the lookup budget.
   pub async fn verify(&self, ip: IpAddr) -> bool {
      if let Some(cached) = self.cache.get(&ip) {
         return cached;
      }

      {
         let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
         if !pending.insert(ip) {
            return false;
         }
      }

      let Ok(permit) = Arc::clone(&self.lookups).try_acquire_owned() else {
         self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&ip);
         return false;
      };

      let providers = Arc::clone(&self.providers);
      let dns = Arc::clone(&self.dns);
      let cache = Arc::clone(&self.cache);
      let pending = Arc::clone(&self.pending);
      let task = tokio::spawn(async move {
         let verified = tokio::time::timeout(LOOKUP_TIMEOUT, check(&providers, &*dns, ip))
            .await
            .unwrap_or(false);
         if verified {
            cache.set(ip, true);
         } else {
            cache.set_with_ttl(ip, false, NEGATIVE_TTL);
         }
         pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&ip);
         drop(permit);
         verified
      });

      match tokio::time::timeout(WAIT_BUDGET, task).await {
         Ok(Ok(verified)) => verified,
         Ok(Err(_)) | Err(_) => false,
      }
   }
}

async fn check(providers: &[CrawlerConfig], dns: &dyn ReverseDns, ip: IpAddr) -> bool {
   for name in dns.reverse(ip).await {
      let name = name.trim_end_matches('.').to_lowercase();
      let matches = providers.iter().any(|provider| {
         provider
            .suffixes
            .iter()
            .any(|suffix| suffix_matches(&name, suffix))
      });
      if matches && dns.forward(&name).await.contains(&ip) {
         return true;
      }
   }
   false
}

/// Match a DNS suffix at a label boundary.
fn suffix_matches(name: &str, suffix: &str) -> bool {
   name.ends_with(suffix) || name == &suffix[1..]
}

#[cfg(test)]
mod tests {
   use std::{
      collections::HashMap,
      net::Ipv4Addr,
      sync::Mutex,
   };

   use super::*;

   #[derive(Default)]
   struct MockDns {
      ptr:     HashMap<IpAddr, Vec<String>>,
      forward: HashMap<String, Vec<IpAddr>>,
      lookups: Mutex<usize>,
   }

   impl ReverseDns for MockDns {
      fn reverse(&self, ip: IpAddr) -> BoxedFuture<'_, Vec<String>> {
         *self.lookups.lock().unwrap() += 1;
         let result = self.ptr.get(&ip).cloned().unwrap_or_default();
         Box::pin(async move { result })
      }

      fn forward<'a>(&'a self, name: &'a str) -> BoxedFuture<'a, Vec<IpAddr>> {
         let result = self.forward.get(name).cloned().unwrap_or_default();
         Box::pin(async move { result })
      }
   }

   fn ip(last: u8) -> IpAddr {
      IpAddr::V4(Ipv4Addr::new(66, 249, 66, last))
   }

   fn provider() -> CrawlerConfig {
      CrawlerConfig {
         name:     "googlebot".to_owned(),
         suffixes: vec![".googlebot.com".to_owned()],
      }
   }

   fn verifier(dns: MockDns) -> CrawlerVerifier {
      CrawlerVerifier::new(vec![provider()], Arc::new(dns))
   }

   #[tokio::test]
   async fn forward_must_contain_the_original_ip() {
      let mut dns = MockDns::default();
      dns.ptr
         .insert(ip(1), vec!["crawl.googlebot.com".to_owned()]);
      dns.forward
         .insert("crawl.googlebot.com".to_owned(), vec![ip(2)]);
      assert!(!verifier(dns).verify(ip(1)).await);
   }

   #[tokio::test]
   async fn suffix_matches_only_at_label_boundaries() {
      let mut dns = MockDns::default();
      dns.ptr.insert(ip(1), vec!["evilgooglebot.com".to_owned()]);
      dns.forward
         .insert("evilgooglebot.com".to_owned(), vec![ip(1)]);
      assert!(!verifier(dns).verify(ip(1)).await);

      let mut dns = MockDns::default();
      dns.ptr.insert(ip(2), vec!["googlebot.com".to_owned()]);
      dns.forward.insert("googlebot.com".to_owned(), vec![ip(2)]);
      assert!(verifier(dns).verify(ip(2)).await);
   }

   #[tokio::test]
   async fn results_are_cached() {
      let mut dns = MockDns::default();
      dns.ptr
         .insert(ip(1), vec!["crawl.googlebot.com".to_owned()]);
      dns.forward
         .insert("crawl.googlebot.com".to_owned(), vec![ip(1)]);
      let dns = Arc::new(dns);
      let verifier =
         CrawlerVerifier::new(vec![provider()], Arc::clone(&dns) as Arc<dyn ReverseDns>);

      assert!(verifier.verify(ip(1)).await);
      assert!(verifier.verify(ip(1)).await);
      assert!(!verifier.verify(ip(2)).await);
      assert!(!verifier.verify(ip(2)).await);
      assert_eq!(*dns.lookups.lock().unwrap(), 2);
   }
}
