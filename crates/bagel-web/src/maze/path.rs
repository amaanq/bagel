pub const MAX_PATH_BYTES: usize = 192;
pub const MAX_SEGMENTS: usize = 8;
pub const MAX_SEGMENT_BYTES: usize = 32;

#[derive(Clone, PartialEq, Eq)]
pub struct ParsedRoute<'a> {
   pub token:     &'a str,
   pub maze_path: &'a str,
}

/// Split and validate a raw `/<token>/<maze_path>` suffix.
#[must_use]
pub fn parse_route(after_prefix: &str) -> Option<ParsedRoute<'_>> {
   let rest = after_prefix.strip_prefix('/')?;
   let (token, raw_path) = rest.split_once('/')?;
   if token.is_empty() {
      return None;
   }
   let maze_path = normalize_maze_path(raw_path)?;
   Some(ParsedRoute { token, maze_path })
}

/// Validate a raw maze path without decoding and strip at most one trailing
/// slash.
#[must_use]
pub fn normalize_maze_path(raw: &str) -> Option<&str> {
   let path = raw.strip_suffix('/').unwrap_or(raw);
   if path.is_empty() || path.len() > MAX_PATH_BYTES {
      return None;
   }

   let mut segments = 0_usize;
   for segment in path.split('/') {
      segments += 1;
      if segments > MAX_SEGMENTS
         || segment.is_empty()
         || segment.len() > MAX_SEGMENT_BYTES
         || !segment
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
      {
         return None;
      }
   }

   Some(path)
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn at_most_one_trailing_slash_is_stripped() {
      assert_eq!(
         parse_route("/tok/foo/bar/").unwrap().maze_path,
         parse_route("/tok/foo/bar").unwrap().maze_path
      );
      assert!(parse_route("/tok/foo/bar//").is_none());
   }

   #[test]
   fn missing_token_or_path_segments_are_malformed() {
      for partial in ["", "/", "/tok", "/tok/", "//foo"] {
         assert!(parse_route(partial).is_none(), "{partial}");
      }
   }

   #[test]
   fn grammar_violations_are_malformed() {
      for bad in [
         "Foo",
         "foo bar",
         "foo/../bar",
         ".",
         "foo/%2e",
         "foo\\bar",
         "foo\u{1}bar",
         "foo//bar",
         "a/b/c/d/e/f/g/h/i",
      ] {
         assert!(normalize_maze_path(bad).is_none(), "{bad}");
      }
      let long_segment = "a".repeat(33);
      assert!(normalize_maze_path(&long_segment).is_none());
      let long_path = ["ab"; 65].join("/");
      assert!(normalize_maze_path(&long_path).is_none());
   }
}
