//! Shared errors and constants.

use std::path::PathBuf;

/// Default path of the daemon's admin control socket. Shared by the daemon
/// (server) and the CLI (client) so they agree without duplication.
pub const DEFAULT_ADMIN_SOCKET: &str = "/run/bagel/admin.sock";

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
   #[error("config error: {0}")]
   Config(String),

   /// Semantic error at a known byte offset in the source text.
   #[error("config error at byte {offset}: {message}")]
   ConfigAt { offset: usize, message: String },

   /// The configuration file failed to parse. The source keeps the parser's
   /// own diagnostic without tying this crate to a config format.
   #[error("failed to parse config at {path}: {source}")]
   ConfigParse {
      path:   PathBuf,
      source: Box<dyn std::error::Error + Send + Sync + 'static>,
   },

   #[error(transparent)]
   Io(#[from] std::io::Error),

   #[error("invalid trap pattern: {0}")]
   Pattern(String),

   #[error("invalid network: {0}")]
   Network(String),

   #[error("TLS error: {0}")]
   Tls(String),

   #[error("proxy error: {0}")]
   Proxy(String),

   #[error("challenge error: {0}")]
   Challenge(String),

   #[error("template error: {0}")]
   Template(String),

   /// Key derivation, signing, or random generation failed.
   #[error("crypto error: {0}")]
   Crypto(String),

   #[error(transparent)]
   Other(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl Error {
   /// Build a semantic error located at a byte offset in the source text.
   pub fn config_at<Message: Into<String>>(node_offset: usize, message: Message) -> Self {
      Self::ConfigAt {
         offset:  node_offset,
         message: message.into(),
      }
   }
}
