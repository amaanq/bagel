pub mod fingerprint;
pub mod peek;

#[cfg(feature = "acme")] pub mod acme;

use std::{
   fs::File,
   io,
   path::Path,
   sync::Arc,
};

use bagel_config::web::bind::{
   BindConfig,
   BindNetwork,
   TlsConfig,
};
use bagel_core::Error;
pub use fingerprint::TlsFingerprint;
use http::Uri;
pub use peek::PeekStream;
use rustls::pki_types::CertificateDer;

pub fn validate_bind(config: &BindConfig) -> Result<(), Error> {
   let TlsConfig::Acme {
      directory_url,
      domains,
      ..
   } = &config.tls
   else {
      return Ok(());
   };

   if !cfg!(feature = "acme") {
      return Err(Error::Config("ACME TLS requires the acme feature".into()));
   }
   if config.network != BindNetwork::Tcp {
      return Err(Error::Config("ACME TLS requires a TCP listener".into()));
   }
   if domains.is_empty() {
      return Err(Error::Config(
         "ACME TLS requires at least one domain".into(),
      ));
   }

   let directory: Uri = directory_url.parse().map_err(|error| {
      Error::Config(format!(
         "invalid ACME directory URL {directory_url}, {error}"
      ))
   })?;
   if !matches!(directory.scheme_str(), Some("http" | "https")) || directory.host().is_none() {
      return Err(Error::Config(
         "ACME directory requires an absolute HTTP or HTTPS URL".into(),
      ));
   }
   Ok(())
}

/// Build a rustls `ServerConfig` from cert and key PEM files.
pub fn build_server_config(cert_path: &Path, key_path: &Path) -> io::Result<rustls::ServerConfig> {
   let cert_file = &mut io::BufReader::new(File::open(cert_path)?);
   let key_file = &mut io::BufReader::new(File::open(key_path)?);

   let certs: Vec<CertificateDer<'static>> =
      rustls_pemfile::certs(cert_file).collect::<Result<Vec<_>, _>>()?;

   let key = rustls_pemfile::private_key(key_file)?.ok_or_else(|| {
      io::Error::new(
         io::ErrorKind::InvalidData,
         "no private key found in PEM file",
      )
   })?;

   let mut config = rustls::ServerConfig::builder()
      .with_no_client_auth()
      .with_single_cert(certs, key)
      .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
   config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

   Ok(config)
}

pub fn build_tls_acceptor(
   cert_path: &Path,
   key_path: &Path,
) -> io::Result<tokio_rustls::TlsAcceptor> {
   let config = build_server_config(cert_path, key_path)?;
   Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}
