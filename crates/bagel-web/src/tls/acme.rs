//! ACME TLS support via `rustls-acme`.

use std::sync::Arc;

use futures::StreamExt as _;
use rustls_acme::{
   AcmeConfig,
   caches::DirCache,
};

/// Handles returned by `build_acme_state()`.
pub struct AcmeHandles {
   /// TLS config for normal traffic (auto-updated as certs renew).
   pub default_config:   Arc<rustls::ServerConfig>,
   /// TLS config for ACME TLS-ALPN-01 challenge connections.
   pub challenge_config: Arc<rustls::ServerConfig>,
}

/// Build ACME state, spawn the background driver task, and return TLS configs.
pub fn build_acme_state(
   domains: &[String],
   contact: &[String],
   directory_url: &str,
   cache_dir: Option<&str>,
) -> AcmeHandles {
   let mut config = AcmeConfig::new(domains.iter().map(std::string::String::as_str));

   for contact_entry in contact {
      let addr = if contact_entry.starts_with("mailto:") {
         contact_entry.clone()
      } else {
         format!("mailto:{contact_entry}")
      };
      config = config.contact_push(addr);
   }

   config = config.directory(directory_url);

   if let Some(dir) = cache_dir {
      let cache_path = std::path::PathBuf::from(dir).join("acme");
      tracing::info!(
          domains = ?domains,
          cache = %cache_path.display(),
          "ACME TLS enabled (certs cached)"
      );
      let state = config.cache(DirCache::new(cache_path)).state();
      let mut default_config = state.default_rustls_config();
      Arc::make_mut(&mut default_config).alpn_protocols =
         vec![b"h2".to_vec(), b"http/1.1".to_vec()];
      let challenge_config = state.challenge_rustls_config();
      tokio::spawn(drive_acme_state(state));
      AcmeHandles {
         default_config,
         challenge_config,
      }
   } else {
      tracing::info!(domains = ?domains, "ACME TLS enabled (no cache)");
      let state = config.state();
      let mut default_config = state.default_rustls_config();
      Arc::make_mut(&mut default_config).alpn_protocols =
         vec![b"h2".to_vec(), b"http/1.1".to_vec()];
      let challenge_config = state.challenge_rustls_config();
      tokio::spawn(drive_acme_state(state));
      AcmeHandles {
         default_config,
         challenge_config,
      }
   }
}

/// Background driver for the ACME state machine.
/// Must be polled continuously to handle cert acquisition and renewal.
async fn drive_acme_state<EC: std::fmt::Debug + 'static, EA: std::fmt::Debug + 'static>(
   mut state: rustls_acme::AcmeState<EC, EA>,
) {
   loop {
      match state.next().await {
         Some(Ok(ok)) => {
            tracing::info!(event = ?ok, "ACME event");
         },
         Some(Err(err)) => {
            tracing::error!(error = ?err, "ACME error");
         },
         None => {
            tracing::warn!("ACME state stream ended unexpectedly");
            break;
         },
      }
   }
}

pub use rustls_acme::is_tls_alpn_challenge;
