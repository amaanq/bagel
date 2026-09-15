use std::{
   collections::{
      HashMap,
      HashSet,
   },
   fmt::{
      Display,
      Formatter,
      Result as FmtResult,
   },
   str::FromStr,
   sync::Arc,
};

use ring::digest::{
   SHA256,
   digest,
};

use crate::{
   fingerprint::{
      Capture,
      CaptureError,
   },
   hex_encode,
   wire::Cursor,
};

/// TLS `ClientHello` fingerprint data.
#[derive(Clone, Debug, Default)]
pub struct TlsFingerprint {
   native:  Capture<Arc<ClientHello>>,
   /// Digest of what a trusted TLS-terminating proxy relayed about the
   /// handshake, empty when none did.
   proxied: Capture<ProxiedFingerprint>,
}

impl From<Capture<Arc<ClientHello>>> for TlsFingerprint {
   fn from(native: Capture<Arc<ClientHello>>) -> Self {
      Self {
         native,
         proxied: Capture::Unavailable,
      }
   }
}

impl TlsFingerprint {
   #[must_use]
   pub const fn native(&self) -> &Capture<Arc<ClientHello>> {
      &self.native
   }

   pub fn set_proxied(&mut self, proxied: Capture<ProxiedFingerprint>) {
      self.proxied = proxied;
   }

   #[must_use]
   pub fn policy_fields(&self) -> HashMap<String, String> {
      let native = !matches!(self.native, Capture::Unavailable);
      let proxied = matches!(self.proxied, Capture::Complete(_));
      let source = match (native, proxied) {
         (true, true) => "native+proxy",
         (true, false) => "native",
         (false, true) => "proxy",
         (false, false) => "none",
      };
      let mut fields = HashMap::from([
         ("source".to_owned(), source.to_owned()),
         ("tls_status".to_owned(), self.native.to_string()),
         ("proxied_status".to_owned(), self.proxied.to_string()),
      ]);
      if let Capture::Complete(hello) = &self.native {
         for (key, value) in [
            ("ja4", hello.ja4.clone()),
            ("tls_version", hello.tls_version.to_string()),
            ("ciphers", hello.cipher_suites.to_string()),
            ("extensions", hello.extensions.to_string()),
            ("groups", hello.elliptic_curves.to_string()),
            (
               "signature_algorithms",
               hello.signature_algorithms.to_string(),
            ),
            (
               "alpn",
               hello
                  .alpn
                  .iter()
                  .map(|protocol| hex_encode(protocol))
                  .collect::<Vec<_>>()
                  .join(","),
            ),
         ] {
            fields.insert(key.to_owned(), value);
         }
      }
      if let Capture::Complete(relayed) = &self.proxied {
         for (key, value) in [
            ("proxied_version", relayed.version.to_string()),
            ("proxied_ciphers", relayed.ciphers.to_string()),
            ("proxied_curves", relayed.curves.to_string()),
            ("proxied_alpn", relayed.alpn.clone()),
            ("proxied_resumed", relayed.resumed.to_string()),
         ] {
            fields.insert(key.to_owned(), value);
         }
         if let Some(value) = relayed.digest() {
            fields.insert("proxied".to_owned(), value);
         } else {
            fields.insert("proxied_status".to_owned(), "partial".to_owned());
         }
      }
      fields
   }
}

#[derive(Clone, Debug)]
pub struct ProxiedFingerprint {
   version: TlsVersion,
   ciphers: ProxiedList,
   curves:  ProxiedList,
   alpn:    String,
   resumed: bool,
}

impl ProxiedFingerprint {
   fn digest(&self) -> Option<String> {
      if self.curves.0.is_empty() {
         return None;
      }
      Some(format!(
         "p{}{:02}{:02}{}_{}_{}",
         self.version,
         self.ciphers.0.len().min(99),
         self.curves.0.len().min(99),
         alpn_tag(self.alpn.as_bytes()),
         truncated_hash(&self.ciphers.to_string()),
         truncated_hash(&self.curves.to_string()),
      ))
   }
}

/// Digest a `protocol;ciphers;curves;alpn;reused` header relayed by the proxy.
///
/// The value is what nginx renders from `$ssl_protocol`, `$ssl_ciphers`,
/// `$ssl_curves`, `$ssl_alpn_protocol` and `$ssl_session_reused`. GREASE
/// entries are dropped because Chrome randomizes them per handshake.
impl FromStr for ProxiedFingerprint {
   type Err = CaptureError;

   fn from_str(value: &str) -> Result<Self, Self::Err> {
      if value.len() > 8192 {
         return Err(CaptureError::Limited);
      }
      let mut parts = value.split(';');
      let protocol = parts.next().ok_or(CaptureError::Invalid)?.trim();
      let ciphers: ProxiedList = parts.next().ok_or(CaptureError::Invalid)?.parse()?;
      let curves = parts.next().ok_or(CaptureError::Invalid)?.parse()?;
      let alpn = parts.next().ok_or(CaptureError::Invalid)?.trim();
      let resumed = match parts.next().map(str::trim) {
         Some("r") => true,
         Some(".") => false,
         _ => return Err(CaptureError::Invalid),
      };
      if parts.next().is_some()
         || ciphers.0.is_empty()
         || alpn.len() > 255
         || !alpn.bytes().all(|byte| byte.is_ascii_graphic())
      {
         return Err(CaptureError::Invalid);
      }
      let version = match protocol {
         "TLSv1.3" => TlsVersion::Tls13,
         "TLSv1.2" => TlsVersion::Tls12,
         "TLSv1.1" => TlsVersion::Tls11,
         "TLSv1" => TlsVersion::Tls10,
         _ => return Err(CaptureError::Invalid),
      };
      Ok(Self {
         version,
         ciphers,
         curves,
         alpn: alpn.to_owned(),
         resumed,
      })
   }
}

#[derive(Clone, Debug)]
struct ProxiedList(Vec<String>);

impl FromStr for ProxiedList {
   type Err = CaptureError;

   fn from_str(list: &str) -> Result<Self, Self::Err> {
      let mut items = Vec::new();
      if list.trim().is_empty() {
         return Ok(Self(items));
      }
      for item in list.split(':').map(str::trim) {
         if item.is_empty()
            || item.len() > 128
            || !item
               .bytes()
               .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
         {
            return Err(CaptureError::Invalid);
         }
         if let Some(hex) = item.strip_prefix("0x").or_else(|| item.strip_prefix("0X")) {
            let value = u16::from_str_radix(hex, 16).map_err(|_| CaptureError::Invalid)?;
            if !is_grease(value) {
               items.push(format!("0x{value:04x}"));
            }
         } else {
            items.push(item.to_owned());
         }
         if items.len() > 256 {
            return Err(CaptureError::Limited);
         }
      }
      if items.iter().map(|item| item.len() + 1).sum::<usize>() > 4096 {
         return Err(CaptureError::Limited);
      }
      Ok(Self(items))
   }
}

impl Display for ProxiedList {
   #[expect(
      clippy::renamed_function_params,
      reason = "formatter keeps the argument name descriptive"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
      formatter.write_str(&self.0.join(":"))
   }
}

#[derive(Clone, Copy, Debug)]
enum TlsVersion {
   Ssl2,
   Ssl3,
   Tls10,
   Tls11,
   Tls12,
   Tls13,
   Unknown,
}

impl From<u16> for TlsVersion {
   fn from(version: u16) -> Self {
      match version {
         0x0304 => Self::Tls13,
         0x0303 => Self::Tls12,
         0x0302 => Self::Tls11,
         0x0301 => Self::Tls10,
         0x0300 => Self::Ssl3,
         0x0002 => Self::Ssl2,
         _ => Self::Unknown,
      }
   }
}

impl Display for TlsVersion {
   #[expect(
      clippy::renamed_function_params,
      reason = "formatter keeps the argument name descriptive"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
      formatter.write_str(match self {
         Self::Tls13 => "13",
         Self::Tls12 => "12",
         Self::Tls11 => "11",
         Self::Tls10 => "10",
         Self::Ssl3 => "s3",
         Self::Ssl2 => "s2",
         Self::Unknown => "00",
      })
   }
}

#[derive(Clone, Debug, Default)]
struct Identifiers(Vec<u16>);

impl TryFrom<&[u8]> for Identifiers {
   type Error = CaptureError;

   fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
      let (pairs, tail) = data.as_chunks::<2>();
      if !tail.is_empty() {
         return Err(CaptureError::Invalid);
      }
      if data.len() > 1024 {
         return Err(CaptureError::Limited);
      }
      Ok(Self(
         pairs
            .iter()
            .copied()
            .map(u16::from_be_bytes)
            .filter(|value| !is_grease(*value))
            .collect(),
      ))
   }
}

impl Display for Identifiers {
   #[expect(
      clippy::renamed_function_params,
      reason = "formatter keeps the argument name descriptive"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
      for (index, value) in self.0.iter().enumerate() {
         if index != 0 {
            formatter.write_str(",")?;
         }
         write!(formatter, "{value:04x}")?;
      }
      Ok(())
   }
}

#[derive(Clone, Copy)]
enum ExtensionKind {
   ServerName,
   SupportedGroups,
   PointFormats,
   SignatureAlgorithms,
   Alpn,
   SupportedVersions,
   Unknown,
}

impl From<u16> for ExtensionKind {
   fn from(kind: u16) -> Self {
      match kind {
         0x0000 => Self::ServerName,
         0x000A => Self::SupportedGroups,
         0x000B => Self::PointFormats,
         0x000D => Self::SignatureAlgorithms,
         0x0010 => Self::Alpn,
         0x002B => Self::SupportedVersions,
         _ => Self::Unknown,
      }
   }
}

/// Parsed fields from a TLS `ClientHello` needed for fingerprinting.
#[derive(Clone, Debug)]
pub struct ClientHello {
   ja4:                  String,
   tls_version:          TlsVersion,
   cipher_suites:        Identifiers,
   extensions:           Identifiers,
   elliptic_curves:      Identifiers,
   ec_point_formats:     Vec<u8>,
   sni:                  String,
   alpn:                 Vec<Vec<u8>>,
   signature_algorithms: Identifiers,
}

impl ClientHello {
   pub const MAX_CAPTURE: usize = 64 * 1024;

   #[must_use]
   pub fn ja4(&self) -> &str {
      &self.ja4
   }

   /// Compute JA4 fingerprint.
   /// Format: `{t|q}{version}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}`.
   fn compute_ja4(&self) -> String {
      let proto = "t";
      let ver = self.tls_version;
      let sni_flag = if self.extensions.0.contains(&0) {
         "d"
      } else {
         "i"
      };
      let cipher_count = format!("{:02}", self.cipher_suites.0.len().min(99));
      let ext_count = format!("{:02}", self.extensions.0.len().min(99));
      let alpn = alpn_tag(self.alpn.first().map_or(&[], Vec::as_slice));

      // Cipher hash uses six SHA-256 bytes of the sorted cipher suites
      let mut sorted_ciphers = self.cipher_suites.clone();
      sorted_ciphers.0.sort_unstable();
      let cipher_hash = truncated_hash(&sorted_ciphers.to_string());

      // JA4 excludes SNI and ALPN, then appends ordered signatures
      let mut sorted_exts = Identifiers(
         self
            .extensions
            .0
            .iter()
            .copied()
            .filter(|extension| !matches!(extension, 0 | 16))
            .collect(),
      );
      sorted_exts.0.sort_unstable();
      let mut ext_str = sorted_exts.to_string();
      if !ext_str.is_empty() && !self.signature_algorithms.0.is_empty() {
         ext_str.push('_');
         ext_str.push_str(&self.signature_algorithms.to_string());
      }
      let ext_hash = truncated_hash(&ext_str);
      format!("{proto}{ver}{sni_flag}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}")
   }

   fn decode(body: &[u8]) -> Result<Self, CaptureError> {
      let mut input = Cursor::from(body);
      // Client version (2 bytes)
      let tls_version = TlsVersion::from(input.u16()?);
      // Random (32 bytes)
      input.take(32)?;
      // Session ID
      if input.vector_u8()?.len() > 32 {
         return Err(CaptureError::Invalid);
      }
      // Cipher suites
      let cipher_bytes = input.vector_u16()?;
      if cipher_bytes.is_empty() {
         return Err(CaptureError::Invalid);
      }
      let cipher_suites = Identifiers::try_from(cipher_bytes)?;
      // Compression methods
      if input.vector_u8()?.is_empty() {
         return Err(CaptureError::Invalid);
      }

      let mut hello = Self {
         ja4: String::new(),
         tls_version,
         cipher_suites,
         extensions: Identifiers::default(),
         elliptic_curves: Identifiers::default(),
         ec_point_formats: Vec::new(),
         sni: String::new(),
         alpn: Vec::new(),
         signature_algorithms: Identifiers::default(),
      };

      // Extensions
      if !input.is_empty() {
         let mut extensions = Cursor::from(input.vector_u16()?);
         input.finish()?;
         let mut seen = HashSet::new();
         while !extensions.is_empty() {
            let kind = extensions.u16()?;
            let data = extensions.vector_u16()?;
            if !seen.insert(kind) {
               return Err(CaptureError::Invalid);
            }
            if seen.len() > 512 {
               return Err(CaptureError::Limited);
            }
            if !is_grease(kind) {
               hello.extensions.0.push(kind);
            }
            hello.extension(ExtensionKind::from(kind), data)?;
         }
      }
      hello.ja4 = hello.compute_ja4();
      Ok(hello)
   }

   fn extension(&mut self, kind: ExtensionKind, data: &[u8]) -> Result<(), CaptureError> {
      let mut input = Cursor::from(data);
      let payload = match kind {
         ExtensionKind::ServerName
         | ExtensionKind::SupportedGroups
         | ExtensionKind::SignatureAlgorithms
         | ExtensionKind::Alpn => input.vector_u16()?,
         ExtensionKind::PointFormats | ExtensionKind::SupportedVersions => input.vector_u8()?,
         ExtensionKind::Unknown => return Ok(()),
      };
      input.finish()?;
      if payload.is_empty() {
         return Err(CaptureError::Invalid);
      }

      match kind {
         // SNI
         ExtensionKind::ServerName => {
            let mut names = Cursor::from(payload);
            let mut name_types = HashSet::new();
            while !names.is_empty() {
               let name_type = names.byte()?;
               let name = names.vector_u16()?;
               if name.is_empty() || !name_types.insert(name_type) {
                  return Err(CaptureError::Invalid);
               }
               if name_type == 0 {
                  std::str::from_utf8(name)
                     .map_err(|_| CaptureError::Invalid)?
                     .clone_into(&mut self.sni);
               }
            }
         },
         // Supported groups (elliptic curves)
         ExtensionKind::SupportedGroups => self.elliptic_curves = Identifiers::try_from(payload)?,
         // EC point formats
         ExtensionKind::PointFormats => self.ec_point_formats = payload.to_vec(),
         ExtensionKind::SignatureAlgorithms => {
            self.signature_algorithms = Identifiers::try_from(payload)?;
         },
         // ALPN
         ExtensionKind::Alpn => {
            if data.len() > 2048 {
               return Err(CaptureError::Limited);
            }
            let mut protocols = Cursor::from(payload);
            while !protocols.is_empty() {
               let protocol = protocols.vector_u8()?;
               if protocol.is_empty() {
                  return Err(CaptureError::Invalid);
               }
               let grease = protocol
                  .first_chunk::<2>()
                  .filter(|_| protocol.len() == 2)
                  .is_some_and(|bytes| is_grease(u16::from_be_bytes(*bytes)));
               if !grease {
                  self.alpn.push(protocol.to_vec());
               }
            }
         },
         // Supported versions
         ExtensionKind::SupportedVersions => {
            // Use the highest supported version for the actual TLS version
            let versions = Identifiers::try_from(payload)?;
            self.tls_version =
               TlsVersion::from(versions.0.into_iter().max().ok_or(CaptureError::Invalid)?);
         },
         ExtensionKind::Unknown => {},
      }
      Ok(())
   }
}

/// Parses whatever the peer sent first, so every length is checked against
/// the buffer before it is trusted.
impl TryFrom<&[u8]> for ClientHello {
   type Error = CaptureError;

   fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
      // Minimum TLS record: 5 byte header + 4 byte handshake header + ...
      if data.len() < 11 {
         return Err(CaptureError::Incomplete);
      }
      let mut records = Cursor::from(data);
      let mut handshake = Vec::new();
      while records.remaining().len() >= 5 {
         if records.byte()? != 0x16 {
            return Err(CaptureError::Invalid);
         }
         records.take(2)?;
         let length = usize::from(records.u16()?);
         if !(1..=16384).contains(&length) {
            return Err(CaptureError::Invalid);
         }
         let consumed = data.len() - records.remaining().len();
         if consumed + length > Self::MAX_CAPTURE {
            return Err(CaptureError::Limited);
         }
         handshake.extend_from_slice(records.take(length).map_err(|_| CaptureError::Incomplete)?);
         if handshake.len() < 4 {
            continue;
         }
         let mut message = Cursor::from(handshake.as_slice());
         // Handshake type: ClientHello = 1
         if message.byte()? != 1 {
            return Err(CaptureError::Invalid);
         }
         let body_length = message.u24()?;
         if body_length + 4 > Self::MAX_CAPTURE {
            return Err(CaptureError::Limited);
         }
         if message.remaining().len() >= body_length {
            return Self::decode(message.take(body_length)?);
         }
      }
      Err(CaptureError::Incomplete)
   }
}

fn alpn_tag(protocol: &[u8]) -> String {
   let Some((&first, &last)) = protocol.first().zip(protocol.last()) else {
      return "00".to_owned();
   };
   if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
      format!("{}{}", char::from(first), char::from(last))
   } else {
      format!("{:x}{:x}", first >> 4, last & 0x0F)
   }
}

fn truncated_hash(value: &str) -> String {
   if value.is_empty() {
      return "000000000000".to_owned();
   }
   hex_encode(&digest(&SHA256, value.as_bytes()).as_ref()[..6])
}

const fn is_grease(value: u16) -> bool {
   // GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa
   value & 0x0F0F == 0x0A0A && value >> 8 == value & 0xFF
}
