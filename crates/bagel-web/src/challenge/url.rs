/// Build the verify URL for a challenge.
/// `GET /__bagel/{challenge_name}/verify?__bagel_token={token_hex}&
/// __bagel_redirect={redirect}`.
#[must_use]
pub fn verify_url(challenge_name: &str, token_hex: &str, redirect: &str) -> String {
   let encoded_redirect = percent_encode(redirect);
   format!(
      "/__bagel/{challenge_name}/verify?__bagel_token={token_hex}&\
       __bagel_redirect={encoded_redirect}"
   )
}

/// Build the challenge redirect and preserve the original page for return.
pub fn redirect_url(request_uri: &http::Uri, challenge_name: &str, token_hex: &str) -> String {
   let original = request_uri.to_string();
   verify_url(challenge_name, token_hex, &original)
}

fn percent_encode(input: &str) -> String {
   let mut out = String::with_capacity(input.len());
   for byte in input.bytes() {
      match byte {
         b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
            out.push(byte as char);
         },
         _ => {
            out.push('%');
            out.push(HEX_CHARS[(byte >> 4) as usize] as char);
            out.push(HEX_CHARS[(byte & 0xF) as usize] as char);
         },
      }
   }
   out
}

const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";

#[must_use]
pub fn percent_decode(input: &str) -> String {
   let bytes = input.as_bytes();
   let mut out = Vec::with_capacity(bytes.len());
   let mut idx = 0;
   while idx < bytes.len() {
      if bytes[idx] == b'%'
         && idx + 2 < bytes.len()
         && let (Some(hi), Some(lo)) = (hex_nibble(bytes[idx + 1]), hex_nibble(bytes[idx + 2]))
      {
         out.push((hi << 4) | lo);
         idx += 3;
         continue;
      }
      out.push(bytes[idx]);
      idx += 1;
   }
   String::from_utf8_lossy(&out).into_owned()
}

const fn hex_nibble(ch: u8) -> Option<u8> {
   match ch {
      b'0'..=b'9' => Some(ch - b'0'),
      b'a'..=b'f' => Some(ch - b'a' + 10),
      b'A'..=b'F' => Some(ch - b'A' + 10),
      _ => None,
   }
}

#[must_use]
pub fn parse_query_params(query: &str) -> Vec<(&str, &str)> {
   query
      .split('&')
      .filter(|seg| !seg.is_empty())
      .filter_map(|pair| {
         let (key, val) = pair.split_once('=')?;
         Some((key, val))
      })
      .collect()
}

pub fn strip_bagel_params(uri: &http::Uri) -> http::Uri {
   let Some(query) = uri.query() else {
      return uri.clone();
   };

   let cleaned: Vec<&str> = query
      .split('&')
      .filter(|pair| !pair.starts_with("__bagel_"))
      .collect();

   let path = uri.path();
   if cleaned.is_empty() {
      let mut builder = http::Uri::builder();
      if let Some(scheme) = uri.scheme() {
         builder = builder.scheme(scheme.clone());
      }
      if let Some(authority) = uri.authority() {
         builder = builder.authority(authority.clone());
      }
      builder
         .path_and_query(path)
         .build()
         .unwrap_or_else(|_| uri.clone())
   } else {
      let new_query = cleaned.join("&");
      let pq = format!("{path}?{new_query}");
      let mut builder = http::Uri::builder();
      if let Some(scheme) = uri.scheme() {
         builder = builder.scheme(scheme.clone());
      }
      if let Some(authority) = uri.authority() {
         builder = builder.authority(authority.clone());
      }
      builder
         .path_and_query(pq)
         .build()
         .unwrap_or_else(|_| uri.clone())
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn strip_bagel_params_works() {
      let uri: http::Uri = "/path?__bagel_token=abc&foo=bar&__bagel_redirect=x"
         .parse()
         .unwrap();
      let cleaned = strip_bagel_params(&uri);
      assert_eq!(cleaned.path(), "/path");
      assert_eq!(cleaned.query(), Some("foo=bar"));
   }
}
