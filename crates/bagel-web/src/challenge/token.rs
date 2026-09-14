use std::{
   collections::HashMap,
   io::{
      Read as _,
      Write as _,
   },
   time::{
      SystemTime,
      UNIX_EPOCH,
   },
};

use data_encoding::BASE64URL_NOPAD;
use flate2::{
   Compression,
   read::DeflateDecoder,
   write::DeflateEncoder,
};
use ring::{
   aead::{
      AES_256_GCM,
      Aad,
      LessSafeKey,
      Nonce,
      UnboundKey,
   },
   rand::{
      SecureRandom as _,
      SystemRandom,
   },
   signature::{
      ED25519,
      Ed25519KeyPair,
      UnparsedPublicKey,
   },
};
use serde::{
   Deserialize,
   Serialize,
};

use crate::error::{
   self,
   Error,
};

/// A single challenge's state within the token.
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenChallenge {
   #[serde(with = "base64_bytes")]
   pub key:    Vec<u8>,
   /// Optional verification result data.
   #[serde(with = "base64_bytes", default, skip_serializing_if = "Vec::is_empty")]
   pub result: Vec<u8>,
   /// Difficulty this pass was verified at, zero for challenges without one.
   #[serde(default, skip_serializing_if = "is_zero")]
   pub level:  u32,
   pub ok:     bool,
   /// Expiry time (Unix epoch seconds).
   pub exp:    i64,
   /// Not-before time (Unix epoch seconds).
   pub nbf:    i64,
   /// Issued-at time (Unix epoch seconds).
   pub iat:    i64,
}

#[expect(
   clippy::trivially_copy_pass_by_ref,
   reason = "serde skip_serializing_if hands over a reference"
)]
const fn is_zero(level: &u32) -> bool {
   *level == 0
}

/// The full token payload stored in the encrypted cookie.
#[derive(Clone, Serialize, Deserialize)]
pub struct Token {
   pub state: HashMap<String, TokenChallenge>,
   /// Token expiry (Unix epoch seconds).
   pub exp:   i64,
   /// Token not-before (Unix epoch seconds).
   pub nbf:   i64,
   /// Token issued-at (Unix epoch seconds).
   pub iat:   i64,
}

/// Encrypt and sign a Token into a cookie value.
pub fn seal_token(
   token: &Token,
   signing_key: &Ed25519KeyPair,
   cookie_encryption_key: &[u8; 32],
) -> error::Result<String> {
   let json =
      serde_json::to_vec(token).map_err(|err| Error::Crypto(format!("token serialize: {err}")))?;

   let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
   encoder
      .write_all(&json)
      .map_err(|err| Error::Crypto(format!("deflate write: {err}")))?;
   let compressed = encoder
      .finish()
      .map_err(|err| Error::Crypto(format!("deflate finish: {err}")))?;

   let signature = signing_key.sign(&compressed);

   let key = LessSafeKey::new(
      UnboundKey::new(&AES_256_GCM, cookie_encryption_key)
         .map_err(|_| Error::Crypto("invalid AES key".into()))?,
   );
   // Deriving this nonce from the payload would reuse it across identical
   // plaintexts, which breaks AES-GCM outright.
   let rng = SystemRandom::new();
   let mut nonce_bytes = [0_u8; 12];
   rng.fill(&mut nonce_bytes)
      .map_err(|_| Error::Crypto("failed to generate random nonce".into()))?;
   let nonce = Nonce::assume_unique_for_key(nonce_bytes);
   let mut in_out = compressed;
   key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
      .map_err(|_| Error::Crypto("AES-GCM encrypt failed".into()))?;

   // Encode: signature.nonce.ciphertext
   let sig_b64 = BASE64URL_NOPAD.encode(signature.as_ref());
   let ct_b64 = BASE64URL_NOPAD.encode(&in_out);
   let nonce_b64 = BASE64URL_NOPAD.encode(&nonce_bytes);

   Ok(format!("{sig_b64}.{nonce_b64}.{ct_b64}"))
}

pub fn open_token(
   cookie_value: &str,
   public_key_bytes: &[u8],
   cookie_encryption_key: &[u8; 32],
) -> error::Result<Token> {
   let parts: Vec<&str> = cookie_value.splitn(3, '.').collect();
   if parts.len() != 3 {
      return Err(Error::Crypto(
         "invalid token format: expected 3 parts".into(),
      ));
   }

   let sig_bytes = BASE64URL_NOPAD
      .decode(parts[0].as_bytes())
      .map_err(|err| Error::Crypto(format!("signature decode: {err}")))?;
   let nonce_bytes = BASE64URL_NOPAD
      .decode(parts[1].as_bytes())
      .map_err(|err| Error::Crypto(format!("nonce decode: {err}")))?;
   let ciphertext = BASE64URL_NOPAD
      .decode(parts[2].as_bytes())
      .map_err(|err| Error::Crypto(format!("ciphertext decode: {err}")))?;

   if nonce_bytes.len() != 12 {
      return Err(Error::Crypto("invalid nonce length".into()));
   }

   let key = LessSafeKey::new(
      UnboundKey::new(&AES_256_GCM, cookie_encryption_key)
         .map_err(|_| Error::Crypto("invalid AES key".into()))?,
   );
   let nonce_arr: [u8; 12] = nonce_bytes
      .as_slice()
      .try_into()
      .map_err(|_| Error::Crypto("invalid nonce length".into()))?;
   let nonce = Nonce::assume_unique_for_key(nonce_arr);
   let mut in_out = ciphertext;
   let compressed = key
      .open_in_place(nonce, Aad::empty(), &mut in_out)
      .map_err(|_| Error::Crypto("AES-GCM decrypt failed".into()))?;

   let peer_public_key = UnparsedPublicKey::new(&ED25519, public_key_bytes);
   peer_public_key
      .verify(compressed, &sig_bytes)
      .map_err(|_| Error::Crypto("signature verification failed".into()))?;

   let mut decoder = DeflateDecoder::new(&*compressed);
   let mut json = Vec::new();
   decoder
      .read_to_end(&mut json)
      .map_err(|err| Error::Crypto(format!("deflate decompress: {err}")))?;

   let token: Token =
      serde_json::from_slice(&json).map_err(|err| Error::Crypto(format!("token parse: {err}")))?;

   let now = unix_timestamp();
   if token.exp < now {
      return Err(Error::Crypto("token expired".into()));
   }
   if token.nbf > now {
      return Err(Error::Crypto("token not yet valid".into()));
   }

   Ok(token)
}

/// Derive the AES-256-GCM key for cookie encryption.
/// `SHA-256(host + network_prefix + server_private_key_bytes + "1.0/DEFLATE")`.
#[must_use]
pub fn derive_cookie_key(host: &str, network_prefix: &str, server_key_bytes: &[u8]) -> [u8; 32] {
   let mut buf =
      Vec::with_capacity(host.len() + network_prefix.len() + server_key_bytes.len() + 11);
   buf.extend_from_slice(host.as_bytes());
   buf.extend_from_slice(network_prefix.as_bytes());
   buf.extend_from_slice(server_key_bytes);
   buf.extend_from_slice(b"1.0/DEFLATE");
   ring::digest::digest(&ring::digest::SHA256, &buf)
      .as_ref()
      .try_into()
      .expect("sha256 output is 32 bytes")
}

/// Compute the cookie name from host hash.
/// `.bagel-{hex(sha256(host)[:6])}-state`.
#[must_use]
pub fn cookie_name(host: &str) -> String {
   let hash = ring::digest::digest(&ring::digest::SHA256, host.as_bytes());
   let hex = crate::hex_encode(&hash.as_ref()[..3]);
   format!(".bagel-{hex}-state")
}

#[must_use]
pub fn unix_timestamp() -> i64 {
   SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap()
      .as_secs() as i64
}

/// Format a Unix timestamp as an HTTP date (RFC 7231),
/// e.g. `Thu, 01 Jan 1970 00:00:00 GMT`.
#[must_use]
pub fn format_http_date(epoch_secs: i64) -> String {
   const DAYS_PER_MONTH: [[i64; 12]; 2] = [[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31], [
      31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
   ]];
   const WDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
   const MONTHS: [&str; 12] = [
      "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
   ];

   let secs = epoch_secs;
   let wday = ((secs.rem_euclid(86400 * 7)) / 86400) as usize;
   let time_of_day = secs.rem_euclid(86400);
   let hr = time_of_day / 3600;
   let min = time_of_day.rem_euclid(3600) / 60;
   let sec = time_of_day.rem_euclid(60);

   let mut days = secs.div_euclid(86400);
   let mut year: i64 = 1970;
   loop {
      let days_in_year = if is_leap(year) { 366 } else { 365 };
      if days < days_in_year {
         break;
      }
      days -= days_in_year;
      year += 1;
   }
   let leap = usize::from(is_leap(year));
   let mut month = 0;
   while month < 11 && days >= DAYS_PER_MONTH[leap][month] {
      days -= DAYS_PER_MONTH[leap][month];
      month += 1;
   }
   let day = days + 1;

   format!(
      "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
      WDAYS[wday], day, MONTHS[month], year, hr, min, sec
   )
}

const fn is_leap(yr: i64) -> bool {
   yr % 4 == 0 && (yr % 100 != 0 || yr % 400 == 0)
}

mod base64_bytes {
   use data_encoding::BASE64URL_NOPAD;
   use serde::{
      self,
      Deserialize as _,
      Deserializer,
      Serializer,
   };

   pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
   where
      S: Serializer,
   {
      let encoded = BASE64URL_NOPAD.encode(bytes);
      serializer.serialize_str(&encoded)
   }

   pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
   where
      D: Deserializer<'de>,
   {
      let str_val = String::deserialize(deserializer)?;
      BASE64URL_NOPAD
         .decode(str_val.as_bytes())
         .map_err(serde::de::Error::custom)
   }
}

#[cfg(test)]
mod tests {
   use ring::{
      rand::SystemRandom,
      signature::KeyPair,
   };

   use super::*;

   #[test]
   fn seal_open_roundtrip() {
      let rng = SystemRandom::new();
      let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
      let signing_key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
      let public_key_bytes = signing_key.public_key().as_ref().to_vec();
      let cookie_key = [42u8; 32];

      let now = unix_timestamp();
      let token = Token {
         state: HashMap::new(),
         exp:   now + 3600,
         nbf:   now - 60,
         iat:   now,
      };

      let sealed = seal_token(&token, &signing_key, &cookie_key).unwrap();
      let opened = open_token(&sealed, &public_key_bytes, &cookie_key).unwrap();

      assert_eq!(token.exp, opened.exp);
      assert_eq!(token.iat, opened.iat);
   }
}
