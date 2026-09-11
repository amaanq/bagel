use std::{
   path::PathBuf,
   str::FromStr,
};

use bagel_core::Error;
use knead::{
   decode::{
      Decode,
      DecodeScalar,
      Decoder,
   },
   errors::{
      Error as DecodeError,
      ErrorKind,
   },
   span::Spanned,
};
use knead_derive::Decode;

#[derive(Clone, PartialEq, Eq)]
pub enum TlsConfig {
   None,
   Acme {
      directory_url: String,
      domains:       Vec<String>,
      contact:       Vec<String>,
   },
   Manual {
      cert_path: PathBuf,
      key_path:  PathBuf,
   },
}

#[derive(Decode)]
enum TlsInput {
   None,
   Acme {
      #[knead(argument, default = "https://acme-v02.api.letsencrypt.org/directory".to_owned())]
      directory_url: String,
      #[knead(child, unwrap(arguments))]
      domains:       Vec<String>,
      #[knead(child, unwrap(arguments), default)]
      contact:       Vec<String>,
   },
   Manual {
      #[knead(property(name = "cert"))]
      cert_path: PathBuf,
      #[knead(property(name = "key"))]
      key_path:  PathBuf,
   },
}

impl Decode for TlsConfig {
   fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
      let kind = decoder.argument().ok_or_else(|| {
         DecodeError::new(
            ErrorKind::Missing,
            decoder.span(),
            "tls requires a kind argument",
         )
      })?;
      let name = String::decode(kind)?;
      decoder.set_name(Spanned::new(name, kind.span));

      match TlsInput::decode(decoder)? {
         TlsInput::None => Ok(Self::None),
         TlsInput::Acme {
            directory_url,
            domains,
            contact,
         } => {
            Ok(Self::Acme {
               directory_url,
               domains,
               contact,
            })
         },
         TlsInput::Manual {
            cert_path,
            key_path,
         } => {
            Ok(Self::Manual {
               cert_path,
               key_path,
            })
         },
      }
   }
}

/// Network type for bind address.
#[derive(Clone, PartialEq, Eq, knead_derive::DecodeScalar)]
pub enum BindNetwork {
   Tcp,
   Unix,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SocketMode(u32);

impl FromStr for SocketMode {
   type Err = Error;

   fn from_str(value: &str) -> Result<Self, Self::Err> {
      let mode = u32::from_str_radix(value, 8)
         .map_err(|_| Error::Config("socket-mode must be an octal string".into()))?;
      if mode > 0o7777 {
         return Err(Error::Config(
            "socket-mode must be between 0000 and 7777".into(),
         ));
      }
      Ok(Self(mode))
   }
}

impl From<SocketMode> for u32 {
   fn from(mode: SocketMode) -> Self {
      mode.0
   }
}

#[derive(Clone)]
pub struct BindConfig {
   pub network:        BindNetwork,
   pub address:        String,
   /// Unix socket file mode (e.g. 0o770). Only used when network = Unix.
   pub socket_mode:    Option<SocketMode>,
   pub tls:            TlsConfig,
   pub proxy_protocol: bool,
   pub passthrough:    bool,
}

#[derive(Decode)]
struct BindInput {
   #[knead(child, unwrap(argument), default = BindConfig::default().network)]
   network:        BindNetwork,
   #[knead(child, unwrap(argument), default = BindConfig::default().address)]
   address:        String,
   #[knead(child, unwrap(argument, str))]
   socket_mode:    Option<SocketMode>,
   #[knead(child, default = BindConfig::default().tls)]
   tls:            TlsConfig,
   #[knead(child, unwrap(argument), default = BindConfig::default().proxy_protocol)]
   proxy_protocol: bool,
   #[knead(child, unwrap(argument), default = BindConfig::default().passthrough)]
   passthrough:    bool,
}

impl Decode for BindConfig {
   fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
      let input = BindInput::decode(decoder)?;
      if input.socket_mode.is_some() && input.network != BindNetwork::Unix {
         return Err(DecodeError::new(
            ErrorKind::Unexpected,
            decoder.name().span,
            "socket-mode requires a Unix listener",
         ));
      }
      Ok(Self {
         network:        input.network,
         address:        input.address,
         socket_mode:    input.socket_mode,
         tls:            input.tls,
         proxy_protocol: input.proxy_protocol,
         passthrough:    input.passthrough,
      })
   }
}

impl Default for BindConfig {
   fn default() -> Self {
      Self {
         network:        BindNetwork::Tcp,
         address:        ":8080".into(),
         socket_mode:    None,
         tls:            TlsConfig::None,
         proxy_protocol: false,
         passthrough:    false,
      }
   }
}

impl BindConfig {
   /// Resolve the address to a `SocketAddr` string.
   /// Handles `:port` shorthand by prepending `0.0.0.0`.
   /// For Unix sockets, returns the socket path as-is.
   #[must_use]
   pub fn socket_addr(&self) -> String {
      match self.network {
         BindNetwork::Unix => self.address.clone(),
         BindNetwork::Tcp => {
            if self.address.starts_with(':') {
               format!("0.0.0.0{}", self.address)
            } else {
               self.address.clone()
            }
         },
      }
   }
}
