use std::{
   fmt,
   str::FromStr,
};

use bagel_core::Error;
use knead::{
   ast::Value,
   decode::DecodeScalar,
   errors::{
      Error as DecodeError,
      ErrorKind,
   },
};
use knead_derive::Decode;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocolVersion {
   V1,
   V2,
}

impl TryFrom<u8> for ProxyProtocolVersion {
   type Error = Error;

   fn try_from(version: u8) -> Result<Self, Self::Error> {
      match version {
         1 => Ok(Self::V1),
         2 => Ok(Self::V2),
         _ => Err(Error::Config("proxy-protocol-out must be 1 or 2".into())),
      }
   }
}

impl DecodeScalar for ProxyProtocolVersion {
   fn type_check(value: &Value) -> Result<(), DecodeError> {
      u8::type_check(value)
   }

   fn decode(value: &Value) -> Result<Self, DecodeError> {
      let version = u8::decode(value)?;
      Self::try_from(version)
         .map_err(|error| DecodeError::new(ErrorKind::Conversion, value.span, error.to_string()))
   }
}

#[derive(Clone)]
pub struct BackendUrl(String);

impl FromStr for BackendUrl {
   type Err = Error;

   fn from_str(value: &str) -> Result<Self, Self::Err> {
      if value.is_empty() {
         return Err(Error::Config("backend url must not be empty".into()));
      }
      Ok(Self(value.to_owned()))
   }
}

impl AsRef<str> for BackendUrl {
   fn as_ref(&self) -> &str {
      &self.0
   }
}

impl fmt::Display for BackendUrl {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.write_str(&self.0)
   }
}

/// A backend node:
/// ```kdl
/// backend "git.example.com" {
///     url "http://forgejo:3000"
///     ip-header "X-Real-Ip"
/// }
/// ```
#[derive(Clone, Decode)]
pub struct BackendConfig {
   #[knead(argument)]
   pub name:               String,
   #[knead(child, unwrap(argument, str))]
   pub url:                BackendUrl,
   #[knead(child, unwrap(argument))]
   pub host:               Option<String>,
   #[knead(child, unwrap(argument))]
   pub ip_header:          Option<String>,
   #[knead(child, unwrap(argument))]
   pub proxy_protocol_out: Option<ProxyProtocolVersion>,
}
