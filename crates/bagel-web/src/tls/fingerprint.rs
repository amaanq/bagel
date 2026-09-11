/// TLS `ClientHello` fingerprint data.
#[derive(Clone, Default)]
pub struct TlsFingerprint {
   pub ja4: String,
}

/// Parsed fields from a TLS `ClientHello` needed for fingerprinting.
#[derive(Default)]
pub struct ClientHelloFields {
   pub tls_version:      u16,
   pub cipher_suites:    Vec<u16>,
   pub extensions:       Vec<u16>,
   pub elliptic_curves:  Vec<u16>,
   pub ec_point_formats: Vec<u8>,
   pub sni:              String,
   pub alpn:             Vec<String>,
}

impl ClientHelloFields {
   /// Compute JA4 fingerprint.
   /// Format: `{t|q}{version}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}`.
   #[must_use]
   pub fn compute_ja4(&self) -> String {
      let proto = if self.tls_version >= 0x0304 { "t" } else { "q" };

      let ver = match self.tls_version {
         0x0303 => "12",
         0x0304 => "13",
         _ => "00",
      };

      let sni_flag = if self.sni.is_empty() { "i" } else { "d" };

      let cipher_count = format!("{:02}", self.cipher_suites.len().min(99));
      let ext_count = format!("{:02}", self.extensions.len().min(99));

      let alpn = self.alpn.first().map_or_else(
         || "00".to_owned(),
         |proto| {
            if proto.len() >= 2 {
               proto[..2].to_string()
            } else {
               format!("{proto:0<2}")
            }
         },
      );

      // Cipher hash: first 6 hex chars of SHA-256 of sorted cipher suites
      let mut sorted_ciphers = self.cipher_suites.clone();
      sorted_ciphers.sort_unstable();
      let cipher_str = join_u16(&sorted_ciphers);
      let cipher_hash =
         &hex_encode(ring::digest::digest(&ring::digest::SHA256, cipher_str.as_bytes()).as_ref())
            [..12];

      // Extension hash: first 6 hex chars of SHA-256 of sorted extensions
      let mut sorted_exts = self.extensions.clone();
      sorted_exts.sort_unstable();
      let ext_str = join_u16(&sorted_exts);
      let ext_hash =
         &hex_encode(ring::digest::digest(&ring::digest::SHA256, ext_str.as_bytes()).as_ref())
            [..12];

      format!("{proto}{ver}{sni_flag}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}")
   }
}

fn join_u16(items: &[u16]) -> String {
   items
      .iter()
      .map(ToString::to_string)
      .collect::<Vec<_>>()
      .join("-")
}

use std::string::ToString;

use crate::hex_encode;

/// Parses whatever the peer sent first, so every length is checked against
/// the buffer before it is trusted.
#[allow(clippy::missing_asserts_for_indexing)]
#[must_use]
pub fn parse_client_hello(data: &[u8]) -> Option<ClientHelloFields> {
   // Minimum TLS record: 5 byte header + 4 byte handshake header + ...
   if data.len() < 11 {
      return None;
   }

   let mut hs = Vec::new();
   let mut record_pos = 0;
   while record_pos + 5 <= data.len() {
      if data[record_pos] != 0x16 {
         return None;
      }
      let record_length = u16::from_be_bytes([data[record_pos + 3], data[record_pos + 4]]) as usize;
      let record_end = record_pos + 5 + record_length;
      if data.len() < record_end {
         return None;
      }
      hs.extend_from_slice(&data[record_pos + 5..record_end]);
      record_pos = record_end;
      if hs.len() >= 4 {
         let hs_length = u24_be(&hs[1..4]) as usize;
         if hs.len() >= 4 + hs_length {
            break;
         }
      }
   }

   // Handshake type: ClientHello = 1
   if hs.is_empty() || hs[0] != 1 {
      return None;
   }

   if hs.len() < 4 {
      return None;
   }
   let hs_length = u24_be(&hs[1..4]) as usize;
   if hs.len() < 4 + hs_length {
      return None;
   }

   let ch = &hs[4..4 + hs_length];
   let mut pos = 0;

   // Client version (2 bytes)
   if ch.len() < pos + 2 {
      return None;
   }
   let client_version = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
   pos += 2;

   // Random (32 bytes)
   pos += 32;
   if ch.len() < pos {
      return None;
   }

   // Session ID
   if ch.len() < pos + 1 {
      return None;
   }
   let session_id_len = ch[pos] as usize;
   pos += 1 + session_id_len;

   // Cipher suites
   if ch.len() < pos + 2 {
      return None;
   }
   let cs_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
   pos += 2;
   if ch.len() < pos + cs_len {
      return None;
   }
   let mut cipher_suites = Vec::new();
   let cs_end = pos + cs_len;
   while pos + 1 < cs_end {
      let cs = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
      if !is_grease(cs) {
         cipher_suites.push(cs);
      }
      pos += 2;
   }
   pos = cs_end;

   // Compression methods
   if ch.len() < pos + 1 {
      return None;
   }
   let compression_len = ch[pos] as usize;
   pos += 1 + compression_len;

   let mut fields = ClientHelloFields {
      tls_version: client_version,
      cipher_suites,
      ..Default::default()
   };

   // Extensions
   if ch.len() >= pos + 2 {
      let ext_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
      pos += 2;
      let ext_end = (pos + ext_len).min(ch.len());

      while pos + 3 < ext_end {
         let ext_type = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
         let ext_data_len = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
         pos += 4;

         if pos + ext_data_len > ext_end {
            break;
         }

         let ext_data = &ch[pos..pos + ext_data_len];

         if !is_grease(ext_type) {
            fields.extensions.push(ext_type);
         }

         match ext_type {
            // SNI
            0x0000
               if ext_data.len() >= 5 && ext_data[2] == 0 => {
                  let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                  if ext_data.len() >= 5 + name_len {
                     fields.sni = String::from_utf8_lossy(&ext_data[5..5 + name_len]).to_string();
                  }
               },
            // Supported groups (elliptic curves)
            0x000A
               if ext_data.len() >= 2 => {
                  let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                  let mut i = 2;
                  while i + 1 < 2 + list_len && i + 1 < ext_data.len() {
                     let group = u16::from_be_bytes([ext_data[i], ext_data[i + 1]]);
                     if !is_grease(group) {
                        fields.elliptic_curves.push(group);
                     }
                     i += 2;
                  }
               },
            // EC point formats
            0x000B
               if !ext_data.is_empty() => {
                  let fmt_len = ext_data[0] as usize;
                  for &fmt in ext_data.get(1..1 + fmt_len).unwrap_or(&[]) {
                     fields.ec_point_formats.push(fmt);
                  }
               },
            // ALPN
            0x0010
               if ext_data.len() >= 2 => {
                  let mut i = 2;
                  while i < ext_data.len() {
                     let proto_len = ext_data[i] as usize;
                     i += 1;
                     if i + proto_len <= ext_data.len() {
                        fields
                           .alpn
                           .push(String::from_utf8_lossy(&ext_data[i..i + proto_len]).to_string());
                     }
                     i += proto_len;
                  }
               },
            // Supported versions
            0x002B
               // Use the highest supported version for the actual TLS version
               if ext_data.len() >= 3 => {
                  let list_len = ext_data[0] as usize;
                  let mut max_ver = 0_u16;
                  let mut i = 1;
                  while i + 1 < 1 + list_len && i + 1 < ext_data.len() {
                     let ver = u16::from_be_bytes([ext_data[i], ext_data[i + 1]]);
                     if !is_grease(ver) && ver > max_ver {
                        max_ver = ver;
                     }
                     i += 2;
                  }
                  if max_ver > 0 {
                     fields.tls_version = max_ver;
                  }
               },
            _ => {},
         }

         pos += ext_data_len;
      }
   }

   Some(fields)
}

#[allow(clippy::missing_asserts_for_indexing)]
fn u24_be(buf: &[u8]) -> u32 {
   (u32::from(buf[0]) << 16) | (u32::from(buf[1]) << 8) | u32::from(buf[2])
}

const fn is_grease(val: u16) -> bool {
   // GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa
   val & 0x0F0F == 0x0A0A
}
